from __future__ import annotations

import functools
import ipaddress
import re
import sys
from collections.abc import AsyncGenerator, Awaitable, Callable, Generator
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Any, Generic, Protocol, TypeVar, overload

import anyio.abc

from starlette.types import Scope

if sys.version_info >= (3, 13):  # pragma: no cover
    from inspect import iscoroutinefunction
    from typing import TypeIs
else:  # pragma: no cover
    from asyncio import iscoroutinefunction

    from typing_extensions import TypeIs

if sys.version_info < (3, 11):  # pragma: no cover
    try:
        from exceptiongroup import BaseExceptionGroup
    except ImportError:

        class BaseExceptionGroup(BaseException):  # type: ignore[no-redef]
            pass


T = TypeVar("T")
AwaitableCallable = Callable[..., Awaitable[T]]

# RFC 3986 ``reg-name`` and IPvFuture syntax. A literal ``%`` in a
# registered name is only valid as part of a percent-encoded triplet.
_REG_NAME_RE = re.compile(r"(?:[A-Za-z0-9._~!$&'()*+,;=\-]|%[0-9A-Fa-f]{2})+")
_IPV_FUTURE_RE = re.compile(r"v[0-9A-Fa-f]+\.[A-Za-z0-9._~!$&'()*+,;=:\-]+")
_ZONE_ID_RE = re.compile(r"(?:[A-Za-z0-9._~\-]|%[0-9A-Fa-f]{2})+")
_PORT_RE = re.compile(r"[0-9]+")


@overload
def is_async_callable(obj: AwaitableCallable[T]) -> TypeIs[AwaitableCallable[T]]: ...


@overload
def is_async_callable(obj: Any) -> TypeIs[AwaitableCallable[Any]]: ...


def is_async_callable(obj: Any) -> Any:
    while isinstance(obj, functools.partial):
        obj = obj.func

    return iscoroutinefunction(obj) or (callable(obj) and iscoroutinefunction(obj.__call__))


T_co = TypeVar("T_co", covariant=True)


class AwaitableOrContextManager(
    Awaitable[T_co], AbstractAsyncContextManager[T_co], Protocol[T_co]
): ...  # pragma: no branch


class SupportsAsyncClose(Protocol):
    async def close(self) -> None: ...  # pragma: no cover


SupportsAsyncCloseType = TypeVar("SupportsAsyncCloseType", bound=SupportsAsyncClose, covariant=False)


class AwaitableOrContextManagerWrapper(Generic[SupportsAsyncCloseType]):
    __slots__ = ("aw", "entered")

    def __init__(self, aw: Awaitable[SupportsAsyncCloseType]) -> None:
        self.aw = aw

    def __await__(self) -> Generator[Any, None, SupportsAsyncCloseType]:
        return self.aw.__await__()

    async def __aenter__(self) -> SupportsAsyncCloseType:
        self.entered = await self.aw
        return self.entered

    async def __aexit__(self, *args: Any) -> None | bool:
        await self.entered.close()
        return None


@asynccontextmanager
async def create_collapsing_task_group() -> AsyncGenerator[anyio.abc.TaskGroup, None]:
    try:
        async with anyio.create_task_group() as tg:
            yield tg
    except BaseExceptionGroup as excs:
        if len(excs.exceptions) != 1:
            raise

        exc = excs.exceptions[0]
        context = None if exc.__suppress_context__ else exc.__context__
        raise exc from exc.__cause__ or context


def _is_ipv6_literal(value: str) -> bool:
    address = value
    if "%25" in value:
        address, _, zone_id = value.partition("%25")
        if _ZONE_ID_RE.fullmatch(zone_id) is None:
            return False
    elif "%" in value:
        return False

    try:
        return isinstance(ipaddress.ip_address(address), ipaddress.IPv6Address)
    except ValueError:
        return False


def _port_in_range(port: str) -> bool:
    significant_digits = port.lstrip("0") or "0"
    return len(significant_digits) < 5 or (len(significant_digits) == 5 and significant_digits <= "65535")


def parse_host_authority(
    authority: str,
    *,
    require_valid_port: bool = False,
) -> tuple[str, str | None] | None:
    """Parse a Host authority into its host and optional decimal port.

    Brackets are retained around IP literals. ``require_valid_port`` also
    constrains the port to the range accepted in a URL (0 through 65535).
    """
    if authority.startswith("["):
        closing_bracket = authority.find("]")
        if closing_bracket == -1:
            return None

        host = authority[: closing_bracket + 1]
        literal = host[1:-1]
        remainder = authority[closing_bracket + 1 :]
        if _IPV_FUTURE_RE.fullmatch(literal) is None and not _is_ipv6_literal(literal):
            return None
        if not remainder:
            port = None
        elif remainder.startswith(":"):
            port = remainder[1:]
        else:
            return None
    else:
        if "[" in authority or "]" in authority:
            return None
        host, separator, port = authority.rpartition(":")
        if not separator:
            host = authority
            port = None
        if _REG_NAME_RE.fullmatch(host) is None:
            return None

    if port is not None:
        if _PORT_RE.fullmatch(port) is None:
            return None
        if require_valid_port and not _port_in_range(port):
            return None

    return host, port


def parse_host_header(host_header: str, *, require_valid_port: bool = False) -> str | None:
    """Parse ``host_header`` into its host component, excluding any port."""
    parsed = parse_host_authority(host_header, require_valid_port=require_valid_port)
    return parsed[0] if parsed is not None else None


def get_scope_authority(scope: Scope) -> str | None:
    """Return a URL-safe authority from an ASGI scope, if one is available."""
    for key, value in scope.get("headers", []):
        if key == b"host":
            host_header = value.decode("latin-1")
            if parse_host_authority(host_header, require_valid_port=True) is not None:
                return host_header
            break

    server = scope.get("server")
    if server is None:
        return None

    try:
        host, port = server
    except (TypeError, ValueError):
        return None

    if not isinstance(host, str):
        return None

    if ":" in host and not host.startswith("["):
        if not _is_ipv6_literal(host):
            return None
        url_host = f"[{host}]"
    else:
        parsed_server_host = parse_host_authority(host, require_valid_port=True)
        if parsed_server_host is None or parsed_server_host[1] is not None:
            return None
        url_host = host

    if port is None:
        return url_host
    if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
        return None

    default_port = {"http": 80, "https": 443, "ws": 80, "wss": 443}.get(scope.get("scheme", "http"))
    return url_host if port == default_port else f"{url_host}:{port}"


def get_route_path(scope: Scope) -> str:
    path: str = scope["path"]
    root_path = scope.get("root_path", "")
    if not root_path:
        return path

    if not path.startswith(root_path):
        return path

    if path == root_path:
        return ""

    if path[len(root_path)] == "/":
        return path[len(root_path) :]

    return path
