from __future__ import annotations

import pytest

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.types import Message, Receive, Scope, Send
from tests.types import TestClientFactory


def test_https_redirect_middleware(test_client_factory: TestClientFactory) -> None:
    def homepage(request: Request) -> PlainTextResponse:
        return PlainTextResponse("OK", status_code=200)

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[Middleware(HTTPSRedirectMiddleware)],
    )

    client = test_client_factory(app, base_url="https://testserver")
    response = client.get("/")
    assert response.status_code == 200

    client = test_client_factory(app)
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"] == "https://testserver/"

    client = test_client_factory(app, base_url="http://testserver:80")
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"] == "https://testserver/"

    client = test_client_factory(app, base_url="http://testserver:443")
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"] == "https://testserver/"

    client = test_client_factory(app, base_url="http://testserver:123")
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"] == "https://testserver:123/"


@pytest.mark.parametrize("port", ["00080", "000443"])
def test_https_redirect_strips_zero_padded_default_port(test_client_factory: TestClientFactory, port: str) -> None:
    app = Starlette(middleware=[Middleware(HTTPSRedirectMiddleware)])
    client = test_client_factory(app)
    response = client.get("/", headers={"host": f"testserver:{port}"}, follow_redirects=False)
    assert response.headers["location"] == "https://testserver/"


def test_https_redirect_falls_back_to_ipv6_server(test_client_factory: TestClientFactory) -> None:
    app = Starlette(middleware=[Middleware(HTTPSRedirectMiddleware)])
    client = test_client_factory(app, base_url="http://[::1]:8000")
    response = client.get("/", headers={"host": "invalid/path"}, follow_redirects=False)
    assert response.headers["location"] == "https://[::1]:8000/"


@pytest.mark.anyio
async def test_https_redirect_without_valid_authority() -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:  # pragma: no cover
        raise AssertionError("The wrapped application should not be called")

    messages: list[Message] = []

    async def receive() -> Message:
        return {"type": "http.request", "body": b""}

    async def send(message: Message) -> None:
        messages.append(message)

    scope: Scope = {
        "type": "http",
        "scheme": "http",
        "path": "/",
        "query_string": b"",
        "headers": [(b"host", b"invalid/path")],
    }
    await HTTPSRedirectMiddleware(app)(scope, receive, send)

    assert messages[0]["status"] == 400
    assert messages[1]["body"] == b"Invalid host header"
