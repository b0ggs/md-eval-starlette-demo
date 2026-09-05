from __future__ import annotations

import copy
import json
from base64 import b64decode, b64encode
from collections.abc import Iterator, Mapping
from typing import Any, Literal

import itsdangerous
from itsdangerous.exc import BadSignature

from starlette.datastructures import MutableHeaders, Secret
from starlette.requests import HTTPConnection
from starlette.types import ASGIApp, Message, Receive, Scope, Send

_MISSING = object()


class _Session(dict[str, Any]):
    def __init__(self, data: Mapping[str, Any]) -> None:
        super().__init__(data)
        self.accessed = False
        self.modified = False

    def _mark_accessed(self) -> None:
        self.accessed = True

    def __getitem__(self, key: str) -> Any:
        self.accessed = True
        return super().__getitem__(key)

    def __setitem__(self, key: str, value: Any) -> None:
        self.accessed = True
        if key not in self or dict.__getitem__(self, key) != value:
            self.modified = True
        super().__setitem__(key, value)

    def __delitem__(self, key: str) -> None:
        self.accessed = True
        super().__delitem__(key)
        self.modified = True

    def __contains__(self, key: object) -> bool:
        self.accessed = True
        return super().__contains__(key)

    def __iter__(self) -> Iterator[str]:
        self.accessed = True
        return super().__iter__()

    def __len__(self) -> int:
        self.accessed = True
        return super().__len__()

    def __bool__(self) -> bool:
        self.accessed = True
        return bool(dict.__len__(self))

    def __repr__(self) -> str:
        self.accessed = True
        return super().__repr__()

    def __eq__(self, other: object) -> bool:
        self.accessed = True
        return super().__eq__(other)

    def __ne__(self, other: object) -> bool:
        self.accessed = True
        return super().__ne__(other)

    def get(self, key: str, default: Any = None) -> Any:
        self.accessed = True
        return super().get(key, default)

    def keys(self) -> Any:
        self.accessed = True
        return super().keys()

    def items(self) -> Any:
        self.accessed = True
        return super().items()

    def values(self) -> Any:
        self.accessed = True
        return super().values()

    def copy(self) -> dict[str, Any]:
        self.accessed = True
        return super().copy()

    def setdefault(self, key: str, default: Any = None) -> Any:
        self.accessed = True
        if not dict.__contains__(self, key):
            self.modified = True
        return super().setdefault(key, default)

    def pop(self, key: str, default: Any = _MISSING) -> Any:
        self.accessed = True
        if dict.__contains__(self, key):
            self.modified = True
        if default is _MISSING:
            return super().pop(key)
        return super().pop(key, default)

    def popitem(self) -> tuple[str, Any]:
        self.accessed = True
        item = super().popitem()
        self.modified = True
        return item

    def clear(self) -> None:
        self.accessed = True
        if dict.__len__(self):
            self.modified = True
        super().clear()

    def update(self, *args: Any, **kwargs: Any) -> None:
        self.accessed = True
        before = dict.copy(self)
        super().update(*args, **kwargs)
        if not dict.__eq__(self, before):
            self.modified = True

    def __ior__(self, other: Any) -> _Session:
        self.update(other)
        return self


def _add_cookie_to_vary(headers: MutableHeaders) -> None:
    vary_values = headers.getlist("vary")
    if any(item.strip().lower() == "cookie" for value in vary_values for item in value.split(",")):
        return

    existing = ", ".join(vary_values)
    headers["vary"] = f"{existing}, Cookie" if existing else "Cookie"


class SessionMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        secret_key: str | Secret,
        session_cookie: str = "session",
        max_age: int | None = 14 * 24 * 60 * 60,  # 14 days, in seconds
        path: str = "/",
        same_site: Literal["lax", "strict", "none"] = "lax",
        https_only: bool = False,
        domain: str | None = None,
    ) -> None:
        self.app = app
        self.signer = itsdangerous.TimestampSigner(str(secret_key))
        self.session_cookie = session_cookie
        self.max_age = max_age
        self.path = path
        self.security_flags = "httponly; samesite=" + same_site
        if https_only:  # Secure flag can be used with HTTPS only
            self.security_flags += "; secure"
        if domain is not None:
            self.security_flags += f"; domain={domain}"

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):  # pragma: no cover
            await self.app(scope, receive, send)
            return

        connection = HTTPConnection(scope)
        initial_session_was_empty = True
        session_data: dict[str, Any] = {}

        if self.session_cookie in connection.cookies:
            data = connection.cookies[self.session_cookie].encode("utf-8")
            try:
                data = self.signer.unsign(data, max_age=self.max_age)
                session_data = json.loads(b64decode(data))
                initial_session_was_empty = False
            except BadSignature:
                pass

        initial_session = copy.deepcopy(session_data)
        session = _Session(session_data)
        scope["session"] = session

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                current_session = scope["session"]
                if current_session is session:
                    session_was_modified = session.modified or not dict.__eq__(session, initial_session)
                    session_was_accessed = session.accessed
                else:
                    session_was_modified = current_session != initial_session
                    session_was_accessed = True

                headers: MutableHeaders | None = None
                if session_was_modified and current_session:
                    # We have session data to persist.
                    data = b64encode(json.dumps(current_session).encode("utf-8"))
                    data = self.signer.sign(data)
                    message.setdefault("headers", [])
                    headers = MutableHeaders(scope=message)
                    header_value = "{session_cookie}={data}; path={path}; {max_age}{security_flags}".format(
                        session_cookie=self.session_cookie,
                        data=data.decode("utf-8"),
                        path=self.path,
                        max_age=f"Max-Age={self.max_age}; " if self.max_age else "",
                        security_flags=self.security_flags,
                    )
                    headers.append("Set-Cookie", header_value)
                elif session_was_modified and not initial_session_was_empty:
                    # The session has been cleared.
                    message.setdefault("headers", [])
                    headers = MutableHeaders(scope=message)
                    header_value = "{session_cookie}={data}; path={path}; {expires}{security_flags}".format(
                        session_cookie=self.session_cookie,
                        data="null",
                        path=self.path,
                        expires="expires=Thu, 01 Jan 1970 00:00:00 GMT; ",
                        security_flags=self.security_flags,
                    )
                    headers.append("Set-Cookie", header_value)

                if session_was_accessed:
                    if headers is None:
                        message.setdefault("headers", [])
                        headers = MutableHeaders(scope=message)
                    _add_cookie_to_vary(headers)
            await send(message)

        await self.app(scope, receive, send_wrapper)
