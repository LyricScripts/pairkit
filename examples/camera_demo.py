"""Phone-as-camera demo: scan a QR on your PC, take a photo, watch it appear.

    uv run --with "fastapi[standard]" --with segno python examples/camera_demo.py

Then open http://<this computer's IP>:8000 on the PC (the address is printed),
scan the QR with your phone's camera, approve on the PC, and take photos.
Phone and PC must be on the same Wi-Fi. Demo only: one fake signed-in user,
everything in memory.
"""

import asyncio
import json
import secrets
import socket
from typing import Annotated

import segno
import uvicorn
from fastapi import FastAPI, Header, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, Response, StreamingResponse

from pairkit import Grant, PairingHooks, PairingService
from pairkit.fastapi import pairing_router

USER = "demo-user"  # pretend the PC browser is signed in as this user
tokens: dict[str, str] = {}  # upload token -> linked device id
photos: dict[str, bytes] = {}
listeners: set[asyncio.Queue] = set()


async def issue(user_id, scopes, device):
    token = secrets.token_urlsafe(24)
    tokens[token] = device.id
    return Grant(token=token)


async def revoke(device):
    for t, d in list(tokens.items()):
        if d == device.id:
            del tokens[t]


def lan_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


PORT = 8000
BASE = f"http://{lan_ip()}:{PORT}"
service = PairingService(PairingHooks(issue, revoke))
app = FastAPI()


def current_user(request: Request) -> str | None:
    # A real app reads its session cookie here. In the demo, only the PC page
    # (which sends this header) counts as signed in; the phone is anonymous.
    return USER if request.headers.get("X-Demo-Desktop") == "1" else None


app.include_router(pairing_router(service, current_user, scan_url=f"{BASE}/scan"))


@app.get("/qr.svg")
def qr(data: str):
    return Response(segno.make(data, error="m").svg_inline(scale=6, border=2), media_type="image/svg+xml")


@app.post("/upload")
async def upload(file: UploadFile, authorization: Annotated[str, Header()] = ""):
    token = authorization.removeprefix("Bearer ")
    if token not in tokens:
        raise HTTPException(401, "not paired")
    pid = secrets.token_urlsafe(8)
    photos[pid] = await file.read()
    for q in list(listeners):
        q.put_nowait(pid)
    return {"id": pid}


@app.get("/photos/{pid}")
def photo(pid: str):
    if pid not in photos:
        raise HTTPException(404)
    return Response(photos[pid], media_type="image/jpeg")


@app.get("/photo-events")
async def photo_events():
    q: asyncio.Queue = asyncio.Queue()
    listeners.add(q)

    async def stream():
        try:
            while True:
                yield f"data: {json.dumps(await q.get())}\n\n"
        finally:
            listeners.discard(q)

    return StreamingResponse(stream(), media_type="text/event-stream")


DESKTOP = """<!doctype html><meta name=viewport content="width=device-width,initial-scale=1">
<title>pairkit demo</title>
<style>body{font:15px system-ui;margin:32px;max-width:900px}button{font:inherit;padding:8px 16px;margin-right:8px}
#photos img{height:220px;margin:6px;border-radius:8px}#qr svg{width:240px;height:240px}.muted{color:#777}</style>
<h1>Phone as camera</h1><p class=muted>Scan with your phone's camera. Phone and PC must share a Wi-Fi.</p>
<div id=qr></div><p id=msg>Creating code…</p><div id=ask hidden>
<button id=yes>Allow</button><button id=no>Deny</button></div><div id=photos></div>
<script>
const H={"Content-Type":"application/json","X-Demo-Desktop":"1"};
async function start(){
  const o=await (await fetch("/pair/offers",{method:"POST",headers:H,
    body:JSON.stringify({grant_to:"scanner",scopes:["upload"],device_label:"This PC"})})).json();
  document.getElementById("qr").innerHTML=await (await fetch("/qr.svg?data="+encodeURIComponent(o.qr_url))).text();
  msg.textContent="Waiting for your phone… (code expires in 2 minutes)";
  const es=new EventSource(`/pair/offers/${o.offer_id}/events?key=${o.shower_key}`);
  es.addEventListener("claimed",e=>{const d=JSON.parse(e.data);msg.textContent=`"${d.scanner}" wants to send photos here.`;ask.hidden=false;
    yes.onclick=()=>{fetch(`/pair/offers/${o.offer_id}/approve`,{method:"POST",headers:H});ask.hidden=true;};
    no.onclick=()=>{fetch(`/pair/offers/${o.offer_id}/deny`,{method:"POST",headers:H});ask.hidden=true;};});
  es.addEventListener("collected",()=>{msg.textContent="Phone connected. Take photos!";document.getElementById("qr").innerHTML="";es.close();});
  es.addEventListener("denied",()=>{msg.textContent="Denied.";es.close();});
  es.addEventListener("expired",()=>{es.close();start();});
}
new EventSource("/photo-events").onmessage=e=>{const i=new Image();i.src="/photos/"+JSON.parse(e.data);photos.prepend(i);};
start();
</script>"""

PHONE = """<!doctype html><meta name=viewport content="width=device-width,initial-scale=1">
<title>pairkit camera</title>
<style>body{font:17px system-ui;margin:24px;text-align:center}label{display:block;padding:28px;margin-top:24px;
background:#2f6fd6;color:#fff;border-radius:14px;font-size:20px}</style>
<h2>pairkit camera</h2><p id=msg>Connecting…</p>
<label id=snap hidden>📷 Take photo<input id=cam type=file accept="image/*" capture=environment hidden></label>
<p id=count></p>
<script>
let token=null,n=0;
(async()=>{
  const secret=location.hash.slice(1); history.replaceState(null,"",location.pathname); // keep it out of history
  const r=await fetch("/pair/claim",{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({secret,device_label:navigator.userAgent.includes("iPhone")?"iPhone":"Phone"})});
  if(!r.ok){msg.textContent="This code is no longer valid. Scan again.";return;}
  const c=await r.json(); msg.textContent=`Confirm on "${c.shower}"…`;
  const es=new EventSource(`/pair/offers/${c.offer_id}/events?key=${c.claimer_key}`);
  es.addEventListener("approved",async()=>{
    const g=await (await fetch(`/pair/offers/${c.offer_id}/collect`,{method:"POST",headers:{"X-Pairkit-Key":c.claimer_key}})).json();
    token=g.token; es.close(); msg.textContent="Connected. Photos go to your PC."; snap.hidden=false;});
  es.addEventListener("denied",()=>{msg.textContent="The PC said no.";es.close();});
  es.addEventListener("expired",()=>{msg.textContent="Timed out. Scan again.";es.close();});
})();
cam.onchange=async()=>{const f=new FormData();f.append("file",cam.files[0]);
  const r=await fetch("/upload",{method:"POST",headers:{Authorization:"Bearer "+token},body:f});
  count.textContent=r.ok?`Sent ${++n} photo${n>1?"s":""}`:"Upload failed";cam.value="";};
</script>"""


@app.get("/", response_class=HTMLResponse)
def desktop():
    return DESKTOP


@app.get("/scan", response_class=HTMLResponse)
def scan():
    return PHONE


if __name__ == "__main__":
    print(f"\n  Open on this PC:  {BASE}\n")
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="warning")
