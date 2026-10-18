import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from pairkit import (
    DeviceInfo,
    Grant,
    GrantTo,
    PairingConfig,
    PairingError,
    PairingHooks,
    PairingService,
    State,
)

DESKTOP = DeviceInfo(label="Chrome on Windows", ip="10.0.0.2")
PHONE = DeviceInfo(label="Safari on iPhone", ip="10.0.0.3")


class Clock:
    def __init__(self):
        self.t = datetime(2026, 10, 18, 12, 0, tzinfo=UTC)

    def __call__(self):
        return self.t

    def advance(self, **kw):
        self.t += timedelta(**kw)


class Auth:
    """Stands in for the app's own auth system."""

    def __init__(self):
        self.issued, self.revoked = [], []

    async def issue(self, user_id, scopes, device):
        self.issued.append((user_id, scopes, device.id))
        return Grant(token=f"tok-{len(self.issued)}", data={"user": user_id})

    async def revoke(self, device):
        self.revoked.append(device.id)


@pytest.fixture
def env():
    clock, auth = Clock(), Auth()
    svc = PairingService(PairingHooks(auth.issue, auth.revoke), now=clock,
                         config=PairingConfig(allowed_scopes=frozenset({"upload", "session"}), watch_poll_s=0.02))
    return svc, auth, clock


async def code(svc, grant_to, scopes=("upload",), user=None):
    return await svc.create_offer(grant_to, scopes, DESKTOP, user)


# ---- the two flows --------------------------------------------------------


async def test_phone_as_camera(env):
    """Signed-in desktop lends upload-only access to an anonymous phone."""
    svc, auth, _ = env
    o = await code(svc, GrantTo.SCANNER, user="almas")
    c = await svc.claim(o.secret, PHONE)
    assert c.shower.label == "Chrome on Windows" and c.scopes == ("upload",)
    view = await svc.status(o.offer_id, o.shower_key)
    assert view.state is State.CLAIMED and view.scanner.label == "Safari on iPhone"

    await svc.approve(o.offer_id, "almas")  # the desktop's user approves
    grant = await svc.collect(o.offer_id, c.claimer_key)  # the phone collects
    assert grant.token == "tok-1"
    assert auth.issued[0][:2] == ("almas", ("upload",))
    [dev] = await svc.list_devices("almas")
    assert dev.device.label == "Safari on iPhone" and dev.via is GrantTo.SCANNER


async def test_whatsapp_web_login(env):
    """Anonymous desktop gets signed in by a signed-in phone."""
    svc, _, _ = env
    o = await code(svc, GrantTo.SHOWER, scopes=("session",))
    c = await svc.claim(o.secret, PHONE, user_id="almas")
    await svc.approve(c.offer_id, "almas")  # the phone's user approves
    grant = await svc.collect(o.offer_id, o.shower_key)  # the desktop collects
    assert grant.data == {"user": "almas"}
    [dev] = await svc.list_devices("almas")
    assert dev.device.label == "Chrome on Windows" and dev.via is GrantTo.SHOWER


# ---- who may do what ------------------------------------------------------


async def test_direction_rules(env):
    svc, _, _ = env
    with pytest.raises(PairingError, match="signed-in shower"):
        await code(svc, GrantTo.SCANNER)  # can't lend what you don't have
    with pytest.raises(PairingError, match="cannot ask to be signed in"):
        await code(svc, GrantTo.SHOWER, user="almas")
    o = await code(svc, GrantTo.SHOWER, scopes=("session",))
    with pytest.raises(PairingError, match="sign in"):
        await svc.claim(o.secret, PHONE)  # an anonymous phone can't sign anyone in


async def test_scopes_are_checked(env):
    svc, _, _ = env
    with pytest.raises(PairingError) as e:
        await code(svc, GrantTo.SCANNER, scopes=("admin",), user="almas")
    assert e.value.code == "invalid_scopes"


async def test_only_the_owner_can_approve(env):
    svc, _, _ = env
    o = await code(svc, GrantTo.SCANNER, user="almas")
    await svc.claim(o.secret, PHONE)
    with pytest.raises(PairingError) as e:
        await svc.approve(o.offer_id, "mallory")
    assert e.value.code == "not_found"  # doesn't even confirm it exists


async def test_qr_secret_alone_is_useless(env):
    """Someone who photographed the QR can't read the offer or take the grant."""
    svc, _, _ = env
    o = await code(svc, GrantTo.SCANNER, user="almas")
    c = await svc.claim(o.secret, PHONE)
    await svc.approve(o.offer_id, "almas")
    for wrong in (o.secret, o.shower_key, "guess"):
        with pytest.raises(PairingError):
            await svc.collect(o.offer_id, wrong)
    with pytest.raises(PairingError):
        await svc.status(o.offer_id, o.secret)
    assert (await svc.collect(o.offer_id, c.claimer_key)).token


async def test_single_use_everywhere(env):
    svc, _, _ = env
    o = await code(svc, GrantTo.SCANNER, user="almas")
    c = await svc.claim(o.secret, PHONE)
    with pytest.raises(PairingError) as e:
        await svc.claim(o.secret, DeviceInfo(label="Attacker"))
    assert e.value.code == "already_used"
    await svc.approve(o.offer_id, "almas")
    await svc.collect(o.offer_id, c.claimer_key)
    with pytest.raises(PairingError):
        await svc.collect(o.offer_id, c.claimer_key)  # token handed out once only


async def test_concurrent_claims_only_one_wins(env):
    svc, _, _ = env
    o = await code(svc, GrantTo.SCANNER, user="almas")
    results = await asyncio.gather(
        *(svc.claim(o.secret, DeviceInfo(label=f"phone {i}")) for i in range(10)), return_exceptions=True
    )
    assert sum(not isinstance(r, Exception) for r in results) == 1


async def test_deny(env):
    svc, auth, _ = env
    o = await code(svc, GrantTo.SCANNER, user="almas")
    c = await svc.claim(o.secret, PHONE)
    assert (await svc.deny(o.offer_id, "almas")).state is State.DENIED
    with pytest.raises(PairingError):
        await svc.collect(o.offer_id, c.claimer_key)
    assert auth.issued == []


# ---- time --------------------------------------------------------------------


async def test_unscanned_code_expires(env):
    svc, _, clock = env
    o = await code(svc, GrantTo.SCANNER, user="almas")
    clock.advance(minutes=3)
    with pytest.raises(PairingError) as e:
        await svc.claim(o.secret, PHONE)
    assert e.value.code == "expired"


async def test_uncollected_grant_is_revoked_on_expiry(env):
    svc, auth, clock = env
    o = await code(svc, GrantTo.SCANNER, user="almas")
    c = await svc.claim(o.secret, PHONE)
    await svc.approve(o.offer_id, "almas")
    clock.advance(minutes=2)
    with pytest.raises(PairingError):
        await svc.collect(o.offer_id, c.claimer_key)
    assert len(auth.revoked) == 1 and await svc.list_devices("almas") == []


# ---- devices and events -------------------------------------------------------


async def test_revoke_device(env):
    svc, auth, _ = env
    o = await code(svc, GrantTo.SCANNER, user="almas")
    c = await svc.claim(o.secret, PHONE)
    await svc.approve(o.offer_id, "almas")
    await svc.collect(o.offer_id, c.claimer_key)
    [dev] = await svc.list_devices("almas")
    with pytest.raises(PairingError):
        await svc.revoke_device(dev.id, "mallory")
    await svc.revoke_device(dev.id, "almas")
    assert auth.revoked == [dev.id] and await svc.list_devices("almas") == []


async def test_rate_limit(env):
    svc, _, _ = env
    errors = []
    for _ in range(25):
        try:
            await svc.claim("wrong-secret-xxxxxxxx", PHONE)
        except PairingError as e:
            errors.append(e.code)
    assert errors[:20] == ["invalid"] * 20 and set(errors[20:]) == {"rate_limited"}


async def test_watch_streams_until_done(env):
    svc, _, _ = env
    o = await code(svc, GrantTo.SCANNER, user="almas")
    seen = []

    async def desktop():
        async for ev in svc.watch(o.offer_id, o.shower_key):
            seen.append(ev.type)

    task = asyncio.create_task(desktop())
    await asyncio.sleep(0.01)
    c = await svc.claim(o.secret, PHONE)
    await svc.approve(o.offer_id, "almas")
    await svc.collect(o.offer_id, c.claimer_key)
    await asyncio.wait_for(task, 1)
    assert seen == ["state", "claimed", "approved", "collected"]


async def test_watch_reports_expiry(env):
    svc, _, clock = env
    o = await code(svc, GrantTo.SCANNER, user="almas")
    clock.advance(minutes=3)  # nobody scans in time
    seen = [ev.type async for ev in svc.watch(o.offer_id, o.shower_key)]
    assert seen == ["state"]  # already expired: current state, then done
    o2 = await code(svc, GrantTo.SCANNER, user="almas")
    seen = []

    async def desktop():
        async for ev in svc.watch(o2.offer_id, o2.shower_key):
            seen.append(ev.type)

    task = asyncio.create_task(desktop())
    await asyncio.sleep(0.01)
    clock.advance(minutes=3)
    await asyncio.wait_for(task, 1)
    assert seen == ["state", "expired"]
