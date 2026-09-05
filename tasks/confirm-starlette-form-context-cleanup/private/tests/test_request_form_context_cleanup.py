from __future__ import annotations

from starlette.datastructures import UploadFile
from starlette.requests import Request
from starlette.types import Message, Scope

import pytest


BODY = (
    b"--boundary\r\n"
    b'Content-Disposition: form-data; name="upload"; filename="data.txt"\r\n'
    b"Content-Type: text/plain\r\n\r\n"
    b"payload\r\n"
    b"--boundary--\r\n"
)


def make_request() -> Request:
    sent = False

    async def receive() -> Message:
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": BODY, "more_body": False}

    scope: Scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "root_path": "",
        "headers": [(b"content-type", b"multipart/form-data; boundary=boundary")],
        "client": ("127.0.0.1", 50000),
        "server": ("testserver", 80),
    }
    return Request(scope, receive)


@pytest.mark.anyio
async def test_form_context_closes_upload_when_body_raises() -> None:
    class ContextFailure(Exception):
        pass

    request = make_request()
    upload: UploadFile | None = None
    with pytest.raises(ContextFailure):
        async with request.form() as form:
            value = form["upload"]
            assert isinstance(value, UploadFile)
            upload = value
            assert upload.file.closed is False
            raise ContextFailure

    assert upload is not None
    assert upload.file.closed is True


@pytest.mark.anyio
async def test_form_remains_directly_awaitable() -> None:
    request = make_request()
    form = await request.form()
    upload = form["upload"]
    assert isinstance(upload, UploadFile)
    assert await upload.read() == b"payload"
    await form.close()
    assert upload.file.closed is True
