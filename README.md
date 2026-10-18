# pairkit

QR-code device pairing for any app, in two directions:

- **Phone as camera**: a signed-in desktop shows a QR; the phone scans it and gets limited, upload-only access. No app install needed on the phone.
- **WhatsApp Web style login**: a desktop shows a QR; a signed-in phone scans it and signs the desktop in.

One small, framework-free core handles both. Your app keeps its own auth; pairkit only asks it to issue (and revoke) a token through a hook.

## How it works

Every pairing has a device that **shows** the QR, a device that **scans** it, and an **approver** (whichever of the two already has access). `grant_to` says who ends up with new access.

```
PENDING --scan--> CLAIMED --approve--> APPROVED --collect--> COLLECTED
                     \--deny--> DENIED          (any step) --> EXPIRED
```

| | Phone as camera | WhatsApp Web login |
|---|---|---|
| `grant_to` | `"scanner"` | `"shower"` |
| Signed in at the start | Desktop | Phone |
| Approves | Desktop: "iPhone wants to send photos here" | Phone: "Sign in on Chrome on Windows?" |
| Receives the token | Phone | Desktop |

## Security model

- **QR secrets** are 192-bit random, single-use, and expire after 2 minutes. They sit in the URL fragment (`#…`), which browsers never send to servers, so they stay out of logs.
- **A photo of the QR is useless.** Each side gets its own private key when it joins (`shower_key`, `claimer_key`); reading an offer or collecting a grant needs the right one. Once the real phone has scanned, the QR is dead.
- **Nothing is granted without a human approving** on the device that already has access, after seeing which device is asking.
- **Scopes:** lend `upload` only, never the whole account. You can restrict allowed scopes in config.
- **Secrets are stored hashed**, the token is held only until collected, and an approved grant that's never collected is revoked automatically.
- **Races are safe:** every state change is compare-and-set, so ten phones scanning one code at once yields exactly one winner (tested).
- **Rate-limited claims** and a **linked devices** list with revoke.

## Use it

```python
from pairkit import Grant, PairingHooks, PairingService
from pairkit.fastapi import pairing_router

async def issue_grant(user_id, scopes, device):
    return Grant(token=my_auth.create_token(user_id, scopes, device_id=device.id))

async def revoke_grant(device):
    my_auth.revoke_tokens(device_id=device.id)

service = PairingService(PairingHooks(issue_grant, revoke_grant))
app.include_router(pairing_router(service, current_user, scan_url="https://app.example.com/scan"))
```

`current_user` is your existing FastAPI dependency that returns the signed-in user's id, or `None`.

| Endpoint | Who calls it |
|---|---|
| `POST /pair/offers` | Shower: create a QR (returns `qr_url`, `shower_key`) |
| `POST /pair/claim` | Scanner: send the QR secret (returns `claimer_key`) |
| `GET /pair/offers/{id}` · `/events` | Either side: status, or live updates (SSE) |
| `POST /pair/offers/{id}/approve` · `/deny` | Approver (signed in) |
| `POST /pair/offers/{id}/collect` | Receiving device: picks up its token once |
| `GET /pair/devices` · `DELETE /pair/devices/{id}` | User: list and unlink devices |

The core (`PairingService`) has no web framework dependency; other adapters can wrap it the same way.

## Try the demo

Your phone becomes a camera for your PC. Phone and PC must be on the same Wi-Fi.

```bash
uv sync
uv run --with "fastapi[standard]" --with segno python examples/camera_demo.py
```

Open the printed address on your PC, scan the QR with your phone's camera, click **Allow**, and take photos. They appear on the PC instantly.

## Develop

```bash
uv sync
uv run pytest     # flows, permissions, replay, races, expiry, live events, HTTP API
uv run ruff check .
```

## Storage and scaling

`MemoryStore` and the in-process `EventBus` are for tests and single-process apps. For several server processes, implement `Store` on Redis or Postgres (the `swap` method is a compare-and-set on `version`) and back `EventBus` with Redis pub/sub.

## Roadmap

- Redis store and event bus
- `@pairkit/client` JavaScript package: QR display, waiting state, phone-side helpers
- Django adapter
