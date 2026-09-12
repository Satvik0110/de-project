import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from simulator.models import SimulatorConfig, AttackTriggerRequest, SecurityEvent
from simulator.engine import SimulatorEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("simulator")

engine = SimulatorEngine()
mock_received_events = []

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting Cybersecurity Attack Simulator Engine...")
    await engine.dispatcher.start()
    await engine.scenario_engine.start()   # open shared httpx client for real attacks
    yield
    logger.info("Shutting down Attack Simulator Engine...")
    engine.stop_loop()
    await engine.scenario_engine.stop()    # close httpx client gracefully
    await engine.dispatcher.stop()

app = FastAPI(
    title="Real-Time Cybersecurity Attack Simulator API",
    version="1.0.0",
    description="Simulates authentication, network, and API security events conforming to the Group 4 Data Model.",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/health")
def health_check():
    return {"status": "ok", "service": "Cybersecurity Attack Simulator"}

@app.get("/api/stats")
def get_stats():
    return engine.get_stats()

@app.get("/api/config")
def get_config():
    return engine.config

@app.post("/api/config")
async def update_config(config: SimulatorConfig):
    await engine.update_config(config)
    return {"status": "updated", "config": engine.config, "stats": engine.get_stats()}

@app.post("/api/start")
async def start_simulation():
    engine.start_loop()
    return {"status": "started", "stats": engine.get_stats()}

@app.post("/api/pause")
async def pause_simulation():
    engine.stop_loop()
    return {"status": "paused", "stats": engine.get_stats()}

@app.post("/api/stop")
async def stop_simulation():
    engine.stop_loop()
    return {"status": "stopped", "stats": engine.get_stats()}

@app.post("/api/reset")
async def reset_simulation():
    await engine.reset_state()
    return {"status": "reset", "stats": engine.get_stats()}

@app.post("/api/attack")
async def trigger_attack(request: AttackTriggerRequest):
    logger.info(f"Triggering attack scenario: {request.scenario} (burst: {request.burst_count})")
    events = await engine.trigger_attack(request)
    return {
        "status": "triggered",
        "scenario": request.scenario,
        "burst_count": len(events),
        "events": [e.model_dump(by_alias=True) for e in events],
        "stats": engine.get_stats()
    }

@app.post("/api/mock-receiver/events")
async def mock_receiver(event: dict):
    """
    Mock Event API receiver endpoint matching the friend's Event API specification.
    Allows local end-to-end testing of HTTP forwarding without needing Kafka running.
    """
    mock_received_events.append(event)
    if len(mock_received_events) > 100:
        mock_received_events.pop(0)
    return {"status": "accepted", "event_id": event.get("event_id")}

@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    await engine.register_subscriber(websocket)
    try:
        while True:
            # Keep connection alive; can receive client control messages
            data = await websocket.receive_text()
            # client ping or command
    except WebSocketDisconnect:
        engine.unregister_subscriber(websocket)
    except Exception:
        engine.unregister_subscriber(websocket)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("simulator.main:app", host="0.0.0.0", port=8001, reload=True)
