# pairkit: notes for Claude

Reusable QR-code device pairing, extracted from [ScribbleScan](https://github.com/LyricScripts/ScribbleScan) so other apps can use it. Two directions with one state machine:

- `grant_to="scanner"`: a signed-in desktop lends limited access to a phone (phone as camera). Used by ScribbleScan today.
- `grant_to="shower"`: a signed-in phone signs a desktop in (WhatsApp Web style). For a future native app.

## Rules for changes

- **The core stays framework-free and auth-agnostic.** The app's auth is touched only through `PairingHooks.issue_grant` / `revoke_grant`. Framework code lives in adapters (`fastapi.py`).
- **Security properties are the product; keep every one** (each has a test): single-use secrets that expire after 2 minutes, stored hashed; the secret goes in the URL fragment; per-side private keys (`shower_key`, `claimer_key`), so a photographed QR is useless after the real scan; approval only by the side that has access; compare-and-set state changes (`Store.swap`); uncollected grants revoked on expiry; rate-limited claims.
- `MemoryStore` and the in-process `EventBus` are for tests and single-process apps. Production stores (Redis, Postgres) must implement `swap` as a real compare-and-set on `version`.
- Every route in `fastapi.py` declares a response model (apps generate client types from the OpenAPI spec); `test_openapi_describes_every_response` enforces it. `Collected` allows extra fields because apps put their own data in `Grant.data`.
- Don't add `from __future__ import annotations` to `fastapi.py`: FastAPI can't resolve the `Annotated` aliases defined inside `pairing_router`.

## Commands

```bash
uv sync
uv run pytest        # 20 tests: both flows, permissions, replay, races, expiry, SSE, HTTP API, OpenAPI contract
uv run ruff check .
uv run --with "fastapi[standard]" --with segno python examples/camera_demo.py   # phone-as-camera demo on your Wi-Fi
```

ScribbleScan installs pairkit straight from this repo (`[tool.uv.sources]`), so pushing to `main` changes what ScribbleScan gets on its next `uv sync`/lock update. Keep the public API stable.

## Roadmap

Postgres store and event bus (LISTEN/NOTIFY; ScribbleScan already runs Postgres) · `@pairkit/client` JS package (QR display, waiting state, phone helpers) · Django adapter · publish to PyPI.
