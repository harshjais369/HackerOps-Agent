from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging

from app.config import settings
from app.database import init_db
from app.api.routes import router
from app.core.agent import manager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("hackerops.main")

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing HackerOps database...")
    await init_db()
    logger.info("HackerOps Backend ready.")
    yield

app = FastAPI(
    title=settings.app_name,
    description="Autonomous Web Vulnerability Assessment & Auto-Remediation System",
    version="1.0.0",
    lifespan=lifespan
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(router)

@app.websocket("/ws/scans/{scan_id}")
async def websocket_scan_endpoint(websocket: WebSocket, scan_id: str):
    """Real-time streaming channel for agent reasoning logs, graph nodes/edges, and patches."""
    await manager.connect(scan_id, websocket)
    try:
        while True:
            # Keep socket alive and listen for client pings or control messages
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(scan_id, websocket)
    except Exception as e:
        logger.debug(f"WebSocket client disconnected: {e}")
        manager.disconnect(scan_id, websocket)
