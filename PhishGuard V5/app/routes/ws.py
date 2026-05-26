# app/routes/ws.py

import time
import json
import uuid
import asyncio
import logging
from typing import Dict, Set, Optional
from collections import defaultdict, deque

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status

from app.auth.jwt_hardening import verify_jwt  # assumed hardened JWT validator

router = APIRouter()
logger = logging.getLogger("ws_gateway")

# =========================
# CONFIG SECURITY LIMITS
# =========================

MAX_CONNECTIONS_PER_IP = 5
MAX_MSG_SIZE = 8_192  # 8KB
RATE_LIMIT_WINDOW = 60  # seconds
MAX_MSG_PER_WINDOW = 30

HEARTBEAT_TIMEOUT = 60

# =========================
# CONNECTION MODEL
# =========================

class ConnectionContext:
    def __init__(self, websocket: WebSocket, user_id: str, ip: str):
        self.connection_id = str(uuid.uuid4())
        self.websocket = websocket
        self.user_id = user_id
        self.ip = ip
        self.connected_at = time.time()
        self.last_activity = time.time()
        self.messages_per_minute = 0
        self.authenticated = True
        self.channels: Set[str] = set()


# =========================
# RATE LIMIT ENGINE
# =========================

class RateLimitEngine:
    def __init__(self):
        self.user_buckets = defaultdict(lambda: deque())

    def allow(self, key: str) -> bool:
        now = time.time()
        window = self.user_buckets[key]

        while window and now - window[0] > RATE_LIMIT_WINDOW:
            window.popleft()

        if len(window) >= MAX_MSG_PER_WINDOW:
            return False

        window.append(now)
        return True


# =========================
# CONNECTION TRACKER
# =========================

class ConnectionTracker:
    def __init__(self):
        self.ip_connections = defaultdict(set)
        self.user_connections = defaultdict(set)

    def can_connect(self, ip: str) -> bool:
        return len(self.ip_connections[ip]) < MAX_CONNECTIONS_PER_IP

    def add(self, ctx: ConnectionContext):
        self.ip_connections[ctx.ip].add(ctx.connection_id)
        self.user_connections[ctx.user_id].add(ctx.connection_id)

    def remove(self, ctx: ConnectionContext):
        self.ip_connections[ctx.ip].discard(ctx.connection_id)
        self.user_connections[ctx.user_id].discard(ctx.connection_id)


# =========================
# WEB SOCKET MANAGER
# =========================

class WebSocketManager:
    def __init__(self):
        self.connections: Dict[str, ConnectionContext] = {}
        self.lock = asyncio.Lock()

    async def register(self, ctx: ConnectionContext):
        async with self.lock:
            self.connections[ctx.connection_id] = ctx

    async def unregister(self, ctx: ConnectionContext):
        async with self.lock:
            self.connections.pop(ctx.connection_id, None)

    async def broadcast(self, message: dict, channel: Optional[str] = None):
        payload = json.dumps(message)

        async with self.lock:
            for ctx in list(self.connections.values()):
                if channel and channel not in ctx.channels:
                    continue

                try:
                    await ctx.websocket.send_text(payload)
                except Exception:
                    await self.unregister(ctx)


# =========================
# GLOBAL INSTANCES
# =========================

manager = WebSocketManager()
tracker = ConnectionTracker()
rate_limiter = RateLimitEngine()


# =========================
# AUTH HANDSHAKE (ZERO TRUST)
# =========================

async def authenticate(websocket: WebSocket) -> dict:
    token = websocket.headers.get("Authorization") or websocket.query_params.get("token")

    if not token:
        return None

    try:
        payload = verify_jwt(token)

        required_fields = ["sub", "exp", "iss", "aud", "jti"]
        if not all(field in payload for field in required_fields):
            return None

        return payload

    except Exception:
        return None


# =========================
# VALIDATION LAYER
# =========================

def validate_message(data: str) -> dict:
    if len(data) > MAX_MSG_SIZE:
        raise ValueError("Payload too large")

    try:
        msg = json.loads(data)
    except Exception:
        raise ValueError("Invalid JSON")

    if not isinstance(msg, dict):
        raise ValueError("Invalid schema")

    return msg


# =========================
# MAIN WEBSOCKET GATEWAY
# =========================

@router.websocket("/ws/telemetry")
async def telemetry_socket(websocket: WebSocket):

    ip = websocket.client.host

    # ❌ IP CONNECTION LIMIT
    if not tracker.can_connect(ip):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # 🔐 AUTH BEFORE ACCEPT (ZERO TRUST)
    auth_payload = await authenticate(websocket)

    if not auth_payload:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept()

    ctx = ConnectionContext(
        websocket=websocket,
        user_id=auth_payload["sub"],
        ip=ip
    )

    tracker.add(ctx)
    await manager.register(ctx)

    logger.info(json.dumps({
        "event": "ws_connected",
        "connection_id": ctx.connection_id,
        "user_id": ctx.user_id,
        "ip": ctx.ip
    }))

    try:
        while True:

            raw = await websocket.receive_text()

            ctx.last_activity = time.time()

            # 🚨 RATE LIMIT PER USER
            if not rate_limiter.allow(ctx.user_id):
                await websocket.send_text(json.dumps({
                    "error": "rate_limit_exceeded"
                }))
                continue

            # 🚨 VALIDATION
            try:
                msg = validate_message(raw)
            except Exception:
                continue

            # 🚨 CHANNEL ISOLATION
            channel = msg.get("channel", "default")

            message_out = {
                "connection_id": ctx.connection_id,
                "user_id": ctx.user_id,
                "channel": channel,
                "data": msg.get("data"),
                "ts": time.time()
            }

            await manager.broadcast(message_out, channel=channel)

    except WebSocketDisconnect:

        await manager.unregister(ctx)
        tracker.remove(ctx)

        logger.info(json.dumps({
            "event": "ws_disconnected",
            "connection_id": ctx.connection_id,
            "user_id": ctx.user_id
        }))

    except Exception as e:

        await manager.unregister(ctx)
        tracker.remove(ctx)

        logger.error(json.dumps({
            "event": "ws_error",
            "error": str(e),
            "connection_id": ctx.connection_id
        }))
