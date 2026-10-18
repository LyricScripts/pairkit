import pytest
from fastapi import FastAPI, Header
from fastapi.testclient import TestClient

from pairkit import Grant, PairingHooks, PairingService
from pairkit.fastapi import pairing_router


async def issue(user_id, scopes, device):
    return Grant(token=f"token-for-{user_id}", data={"scopes": list(scopes)})


def current_user(x_user: str | None = Header(None)):
    """Stand-in for an app's real auth dependency."""
    return x_user


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(pairing_router(PairingService(PairingHooks(issue)), current_user,
                                      scan_url="https://app.example.com/scan"))
    return TestClient(app)


ALMAS = {"X-User": "almas"}


def test_phone_as_camera_over_http(client):
    r = client.post("/pair/offers", json={"grant_to": "scanner", "scopes": ["upload"],
                                          "device_label": "Chrome on Windows"}, headers=ALMAS)
    assert r.status_code == 201
    offer = r.json()
    assert offer["qr_url"] == f"https://app.example.com/scan#{offer['secret']}"

    claim = client.post("/pair/claim", json={"secret": offer["secret"], "device_label": "Phone"}).json()
    assert claim["shower"] == "Chrome on Windows"

    status = client.get(f"/pair/offers/{offer['offer_id']}", headers={"X-Pairkit-Key": offer["shower_key"]})
    assert status.json()["state"] == "claimed" and status.json()["scanner"] == "Phone"

    assert client.post(f"/pair/offers/{offer['offer_id']}/approve", headers=ALMAS).status_code == 200
    grant = client.post(f"/pair/offers/{offer['offer_id']}/collect",
                        headers={"X-Pairkit-Key": claim["claimer_key"]}).json()
    assert grant == {"token": "token-for-almas", "expires_at": None, "scopes": ["upload"]}

    with client.stream("GET", f"/pair/offers/{offer['offer_id']}/events",
                       params={"key": offer["shower_key"]}) as r:
        body = r.read().decode()
    assert r.headers["content-type"].startswith("text/event-stream")
    assert 'event: state\ndata: {"state": "collected"}' in body

    [dev] = client.get("/pair/devices", headers=ALMAS).json()
    assert dev["device"] == "Phone"
    assert client.delete(f"/pair/devices/{dev['id']}", headers=ALMAS).json()["active"] is False
    assert client.get("/pair/devices", headers=ALMAS).json() == []


def test_whatsapp_web_login_over_http(client):
    offer = client.post("/pair/offers", json={"grant_to": "shower", "scopes": ["session"]}).json()
    claim = client.post("/pair/claim", json={"secret": offer["secret"]}, headers=ALMAS).json()
    client.post(f"/pair/offers/{claim['offer_id']}/approve", headers=ALMAS)
    grant = client.post(f"/pair/offers/{offer['offer_id']}/collect",
                        headers={"X-Pairkit-Key": offer["shower_key"]}).json()
    assert grant["token"] == "token-for-almas"


def test_error_codes(client):
    assert client.post("/pair/offers", json={"grant_to": "scanner", "scopes": ["upload"]}).status_code == 403
    offer = client.post("/pair/offers", json={"grant_to": "scanner", "scopes": ["upload"]}, headers=ALMAS).json()
    assert client.post("/pair/claim", json={"secret": "x" * 20}).status_code == 404
    client.post("/pair/claim", json={"secret": offer["secret"]})
    second = client.post("/pair/claim", json={"secret": offer["secret"]})
    assert second.status_code == 409 and second.json()["detail"]["code"] == "already_used"
    assert client.post(f"/pair/offers/{offer['offer_id']}/approve").status_code == 401
    assert client.get(f"/pair/offers/{offer['offer_id']}", headers={"X-Pairkit-Key": "nope"}).status_code == 404
