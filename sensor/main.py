"""Network sensor: sees the connections a web server never sees.

A port scan against a closed port never reaches the web app, so in a real network a
firewall or IDS logs it. This process plays that role for the simulated server subnet:
it listens on the server's service ports and logs one network event per TCP connection,
with the peer address as observed by the kernel.

  open service   -> sends its banner, logged as status "success"
  closed port    -> connection reset immediately, logged as status "denied"
                    (what a firewall reports for a blocked attempt)

Hosts: 127.0.10.1 is the server (the web app also lives there, on 8002);
127.0.10.2-21 are workstations exposing RDP, the target of host sweeps.
Only ports >= 1024 are used so no root is needed.

Run:  uvicorn sensor.main:app --host 127.0.0.1 --port 8004   (8004 = control API only)
"""
import asyncio
import logging
import socket
import struct
from contextlib import asynccontextmanager

from fastapi import FastAPI
from pydantic import BaseModel

from shipper import LogShipper, make_event

SERVER = "127.0.10.1"
OPEN = {2222: b"SSH-2.0-OpenSSH_9.6\r\n", 3306: b"5.7.44-log\x00", 6379: b"-NOAUTH\r\n",
        8080: b"HTTP/1.1 400 Bad Request\r\n\r\n", 9200: b"HTTP/1.1 401\r\n\r\n"}
CLOSED = [1433, 1521, 2049, 2375, 3389, 5000, 5601, 5900, 8443, 8888, 9000, 11211, 27017, 50000, 61616]
WORKSTATIONS = [f"127.0.10.{i}" for i in range(2, 22)]
RDP = 3389

log = logging.getLogger("sensor")
shipper = LogShipper("sensor")


def _listener(host: str, port: int, banner: bytes | None):
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")[0]
        shipper.emit(make_event("network", peer, "success" if banner else "denied", f"{host}:{port}",
                                raw={"protocol": "tcp", "port_state": "open" if banner else "closed"}))
        if banner:
            writer.write(banner)
            await writer.drain()
        else:   # RST instead of FIN, as a closed/filtered port would answer
            writer.get_extra_info("socket").setsockopt(
                socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        writer.close()
    return asyncio.start_server(handle, host, port)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await shipper.start()
    plan = [(SERVER, p, b) for p, b in OPEN.items()] + [(SERVER, p, None) for p in CLOSED] + \
           [(h, RDP, b"\x03\x00\x00\x13") for h in WORKSTATIONS]
    servers = []
    for host, port, banner in plan:
        try:
            servers.append(await _listener(host, port, banner))
        except OSError as exc:
            log.warning("cannot listen on %s:%s (%s), skipping", host, port, exc)
    log.info("sensor listening on %d endpoints", len(servers))
    yield
    for s in servers:
        s.close()
    await shipper.stop()


app = FastAPI(title="Network sensor", lifespan=lifespan)


@app.get("/health")
async def health():
    return {"status": "ok", "shipper": dict(shipper.stats), "chaos": shipper.chaos}


class Toggle(BaseModel):
    enabled: bool


@app.post("/chaos")
async def chaos(t: Toggle):
    shipper.chaos = t.enabled
    return {"chaos": shipper.chaos}
