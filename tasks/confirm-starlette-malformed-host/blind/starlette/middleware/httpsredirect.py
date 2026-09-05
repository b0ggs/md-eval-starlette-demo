from starlette._utils import get_scope_authority, parse_host_authority
from starlette.datastructures import URL
from starlette.responses import PlainTextResponse, RedirectResponse
from starlette.types import ASGIApp, Receive, Scope, Send


class HTTPSRedirectMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] in ("http", "websocket") and scope["scheme"] in ("http", "ws"):
            authority = get_scope_authority(scope)
            if authority is None:
                await PlainTextResponse("Invalid host header", status_code=400)(scope, receive, send)
                return

            url = URL(scope=scope)
            redirect_scheme = {"http": "https", "ws": "wss"}[scope["scheme"]]
            parsed_authority = parse_host_authority(authority, require_valid_port=True)
            assert parsed_authority is not None
            host, port = parsed_authority
            normalized_port = None if port is None else port.lstrip("0") or "0"
            netloc = host if normalized_port in ("80", "443") else authority
            url = url.replace(scheme=redirect_scheme, netloc=netloc)
            response = RedirectResponse(url, status_code=307)
            await response(scope, receive, send)
        else:
            await self.app(scope, receive, send)
