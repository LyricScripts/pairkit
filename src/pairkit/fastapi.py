"""FastAPI adapter: ``app.include_router(pairing_router(service, current_user))``.

``current_user`` is your app's own dependency. It must return the signed-in
user's id, or ``None`` for an anonymous request. That is the only thing
pairkit needs to know about your auth.

Endpoints (under the prefix, default ``/pair``):

    POST   /offers                  shower creates a QR offer
    POST   /claim                   scanner claims it with the QR secret
    GET    /offers/{id}             status            (header X-Pairkit-Key)
    GET    /offers/{id}/events      live updates, SSE (?key=..., EventSource can't set headers)
    POST   /offers/{id}/approve     approver says yes (signed in)
    POST   /offers/{id}/deny        approver says no  (signed in)
    POST   /offers/{id}/collect     receiving device picks up its grant (header X-Pairkit-Key)
    GET    /devices                 linked devices    (signed in)
    DELETE /devices/{id}            unlink a device   (signed in)
"""


import json
from collections.abc import Callable
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from .models import DeviceInfo, GrantTo, LinkedDevice
from .service import OfferView, PairingError, PairingService

STATUS = {
    "invalid": 404,
    "not_found": 404,
    "expired": 410,
    "already_used": 409,
    "conflict": 409,
    "wrong_state": 409,
    "not_allowed": 403,
    "rate_limited": 429,
    "invalid_scopes": 422,
}


class CreateOfferIn(BaseModel):
    grant_to: GrantTo
    scopes: list[str] = Field(min_length=1)
    device_label: str = Field("", max_length=100)


class ClaimIn(BaseModel):
    secret: str = Field(min_length=10, max_length=200)
    device_label: str = Field("", max_length=100)


def _device(request: Request, label: str) -> DeviceInfo:
    return DeviceInfo(
        label=label,
        user_agent=request.headers.get("user-agent", "")[:300],
        ip=request.client.host if request.client else "",
    )


def _view(v: OfferView) -> dict[str, Any]:
    return {
        "offer_id": v.offer_id,
        "state": v.state.value,
        "grant_to": v.grant_to.value,
        "scopes": list(v.scopes),
        "expires_at": v.expires_at.isoformat(),
        "shower": v.shower.describe(),
        "scanner": v.scanner.describe() if v.scanner else None,
    }


def _linked(d: LinkedDevice) -> dict[str, Any]:
    return {
        "id": d.id,
        "device": d.device.describe(),
        "scopes": list(d.scopes),
        "linked_at": d.linked_at.isoformat(),
        "via": d.via.value,
        "active": d.active,
    }


def _fail(e: PairingError) -> HTTPException:
    return HTTPException(STATUS.get(e.code, 400), detail={"code": e.code, "message": str(e)})


def pairing_router(
    service: PairingService,
    current_user: Callable[..., Any],
    *,
    prefix: str = "/pair",
    scan_url: str | None = None,
) -> APIRouter:
    """``scan_url`` is the page the phone opens, e.g. ``https://app.example.com/scan``.
    When set, offers include a ready-to-encode ``qr_url``."""
    router = APIRouter(prefix=prefix, tags=["pairing"])
    OptionalUser = Annotated[str | None, Depends(current_user)]

    def required(user: OptionalUser) -> str:
        if not user:
            raise HTTPException(401, detail={"code": "sign_in_required", "message": "sign in first"})
        return user

    User = Annotated[str, Depends(required)]
    Key = Annotated[str, Header(alias="X-Pairkit-Key")]

    @router.post("/offers", status_code=201)
    async def create_offer(body: CreateOfferIn, request: Request, user: OptionalUser):
        try:
            o = await service.create_offer(body.grant_to, body.scopes, _device(request, body.device_label), user)
        except PairingError as e:
            raise _fail(e) from None
        out = {"offer_id": o.offer_id, "secret": o.secret, "shower_key": o.shower_key,
               "expires_at": o.expires_at.isoformat()}
        if scan_url:
            out["qr_url"] = o.qr_payload(scan_url)
        return out

    @router.post("/claim")
    async def claim(body: ClaimIn, request: Request, user: OptionalUser):
        device = _device(request, body.device_label)
        try:
            c = await service.claim(body.secret, device, user, client_key=device.ip)
        except PairingError as e:
            raise _fail(e) from None
        return {"offer_id": c.offer_id, "claimer_key": c.claimer_key, "grant_to": c.grant_to.value,
                "scopes": list(c.scopes), "shower": c.shower.describe(), "expires_at": c.expires_at.isoformat()}

    @router.get("/offers/{offer_id}")
    async def status(offer_id: str, key: Key):
        try:
            return _view(await service.status(offer_id, key))
        except PairingError as e:
            raise _fail(e) from None

    @router.get("/offers/{offer_id}/events")
    async def events(offer_id: str, key: Annotated[str, Query()]):
        try:
            await service.status(offer_id, key)  # fail fast with a proper status code
        except PairingError as e:
            raise _fail(e) from None

        async def stream():
            async for ev in service.watch(offer_id, key):
                yield f"event: {ev.type}\ndata: {json.dumps(ev.data)}\n\n"

        return StreamingResponse(stream(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})

    @router.post("/offers/{offer_id}/approve")
    async def approve(offer_id: str, user: User):
        try:
            return _view(await service.approve(offer_id, user))
        except PairingError as e:
            raise _fail(e) from None

    @router.post("/offers/{offer_id}/deny")
    async def deny(offer_id: str, user: User):
        try:
            return _view(await service.deny(offer_id, user))
        except PairingError as e:
            raise _fail(e) from None

    @router.post("/offers/{offer_id}/collect")
    async def collect(offer_id: str, key: Key):
        try:
            g = await service.collect(offer_id, key)
        except PairingError as e:
            raise _fail(e) from None
        return {"token": g.token, "expires_at": g.expires_at.isoformat() if g.expires_at else None, **g.data}

    @router.get("/devices")
    async def devices(user: User):
        return [_linked(d) for d in await service.list_devices(user)]

    @router.delete("/devices/{device_id}")
    async def unlink(device_id: str, user: User):
        try:
            return _linked(await service.revoke_device(device_id, user))
        except PairingError as e:
            raise _fail(e) from None

    return router
