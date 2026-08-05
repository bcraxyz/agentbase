"""Local IAP simulator for development only.

Mints an ES256 JWT in the shape IAP produces, serves the matching public key,
injects it as X-Goog-Iap-Jwt-Assertion, and proxies to a local Streamlit app.
The app verifies it exactly as it verifies a real IAP assertion, so the auth
path is genuinely exercised rather than bypassed.

    pip install -r requirements-dev.txt

    export IAP_AUDIENCE=/projects/1/locations/us-central1/services/agentbase
    export IAP_CERTS_URL=http://localhost:8080/public_key
    export GOOGLE_CLOUD_PROJECT=your-project

    streamlit run streamlit_app.py --server.port 8501 --server.headless true &
    python devauth.py

Open the forwarded port 8080, not 8501 -- traffic must pass through the proxy
for the header to be present. Never run this against a remote upstream, and
never point a deployed app's IAP_CERTS_URL at it.
"""

import asyncio
import datetime
import os

import aiohttp
from aiohttp import web
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from google.auth import jwt
from google.auth.crypt import es256

LISTEN_PORT = int(os.getenv("DEVAUTH_PORT", "8080"))
UPSTREAM = os.getenv("DEVAUTH_UPSTREAM", "http://localhost:8501")
EMAIL = os.getenv("DEVAUTH_EMAIL", "dev@example.com")
TTL_SECONDS = int(os.getenv("DEVAUTH_TTL", str(60 * 60 * 12)))
AUDIENCE = os.getenv("IAP_AUDIENCE", "")
KEY_ID = "devauth"
HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
}


def build_identity():
    key = ec.generate_private_key(ec.SECP256R1())
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    signer = es256.ES256Signer.from_string(private_pem, KEY_ID)
    token = jwt.encode(
        signer,
        {
            "iss": "https://cloud.google.com/iap",
            "aud": AUDIENCE,
            "email": EMAIL,
            "sub": f"accounts.google.com:{EMAIL}",
            "iat": now,
            "exp": now + TTL_SECONDS,
        },
    ).decode()
    return token, public_pem


TOKEN, PUBLIC_PEM = build_identity()


async def public_key(_request):
    return web.json_response({KEY_ID: PUBLIC_PEM})


def upstream_headers(request):
    headers = {
        k: v for k, v in request.headers.items() if k.lower() not in HOP_BY_HOP
    }
    headers["X-Goog-Iap-Jwt-Assertion"] = TOKEN
    headers["X-Goog-Authenticated-User-Email"] = f"accounts.google.com:{EMAIL}"
    return headers


async def proxy_websocket(request):
    client = web.WebSocketResponse()
    await client.prepare(request)
    target = UPSTREAM.replace("http", "ws", 1) + request.rel_url.path_qs

    async with aiohttp.ClientSession() as session:
        async with session.ws_connect(
            target, headers=upstream_headers(request)
        ) as server:

            async def pump(src, dst):
                async for msg in src:
                    if msg.type == aiohttp.WSMsgType.TEXT:
                        await dst.send_str(msg.data)
                    elif msg.type == aiohttp.WSMsgType.BINARY:
                        await dst.send_bytes(msg.data)
                    else:
                        break

            await asyncio.gather(
                pump(client, server), pump(server, client), return_exceptions=True
            )
    return client


async def proxy(request):
    if request.headers.get("Upgrade", "").lower() == "websocket":
        return await proxy_websocket(request)

    async with aiohttp.ClientSession(auto_decompress=False) as session:
        async with session.request(
            request.method,
            UPSTREAM + request.rel_url.path_qs,
            headers=upstream_headers(request),
            data=await request.read() if request.can_read_body else None,
            allow_redirects=False,
        ) as upstream:
            response = web.StreamResponse(
                status=upstream.status,
                headers={
                    k: v
                    for k, v in upstream.headers.items()
                    if k.lower() not in HOP_BY_HOP
                },
            )
            await response.prepare(request)
            async for block in upstream.content.iter_chunked(64 * 1024):
                await response.write(block)
            await response.write_eof()
            return response


def main():
    if not AUDIENCE:
        raise SystemExit("Set IAP_AUDIENCE to the value the app expects.")
    if not UPSTREAM.startswith(("http://localhost", "http://127.0.0.1")):
        raise SystemExit("DEVAUTH_UPSTREAM must be a local address.")

    app = web.Application()
    app.router.add_get("/public_key", public_key)
    app.router.add_route("*", "/{path:.*}", proxy)

    print(f"devauth: {EMAIL} -> {UPSTREAM}, listening on :{LISTEN_PORT}")
    web.run_app(app, host="0.0.0.0", port=LISTEN_PORT, print=None)


if __name__ == "__main__":
    main()
