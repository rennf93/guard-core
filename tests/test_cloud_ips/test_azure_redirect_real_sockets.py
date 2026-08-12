from collections.abc import AsyncIterator

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer

from guard_core.handlers.cloud_handler import _download_azure_service_tags

LEGIT_PAYLOAD = {"values": [{"properties": {"addressPrefixes": ["20.20.0.0/16"]}}]}
ATTACKER_PAYLOAD = {"values": [{"properties": {"addressPrefixes": ["203.0.113.0/24"]}}]}


@pytest.fixture
async def attacker_server() -> AsyncIterator[tuple[TestServer, list[int]]]:
    hits: list[int] = []
    app = web.Application()

    async def handler(request: web.Request) -> web.Response:
        hits.append(1)
        return web.json_response(ATTACKER_PAYLOAD)

    app.router.add_get("/attacker-controlled-payload.json", handler)
    server = TestServer(app)
    await server.start_server()
    try:
        yield server, hits
    finally:
        await server.close()


async def test_redirect_to_a_different_origin_is_never_followed(
    attacker_server: tuple[TestServer, list[int]],
) -> None:
    attacker, hits = attacker_server
    app = web.Application()

    async def redirect_handler(request: web.Request) -> web.Response:
        raise web.HTTPFound(
            location=str(attacker.make_url("/attacker-controlled-payload.json"))
        )

    app.router.add_get("/download/x/ServiceTags_Public_20250101.json", redirect_handler)
    target = TestServer(app)
    await target.start_server()
    try:
        trusted_looking_url = str(
            target.make_url("/download/x/ServiceTags_Public_20250101.json")
        )

        with pytest.raises(ValueError, match="redirect"):
            await _download_azure_service_tags(trusted_looking_url)

        assert hits == []
    finally:
        await target.close()


async def test_non_redirecting_response_still_downloads_normally() -> None:
    app = web.Application()

    async def ok_handler(request: web.Request) -> web.Response:
        return web.json_response(LEGIT_PAYLOAD)

    app.router.add_get("/download/x/ServiceTags_Public_20250101.json", ok_handler)
    target = TestServer(app)
    await target.start_server()
    try:
        url = str(target.make_url("/download/x/ServiceTags_Public_20250101.json"))

        data = await _download_azure_service_tags(url)

        assert data == LEGIT_PAYLOAD
    finally:
        await target.close()
