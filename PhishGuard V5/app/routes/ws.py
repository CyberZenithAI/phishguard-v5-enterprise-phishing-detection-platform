# app/routes/ws.py

from fastapi import APIRouter
from fastapi import WebSocket
from fastapi import WebSocketDisconnect

router = APIRouter()

clients = set()


@router.websocket("/ws/telemetry")
async def telemetry_socket(websocket: WebSocket):

    await websocket.accept()

    clients.add(websocket)

    try:

        while True:

            data = await websocket.receive_text()

            for client in list(clients):

                try:

                    await client.send_text(
                        f"telemetry:{data}"
                    )

                except Exception:
                    clients.remove(client)

    except WebSocketDisconnect:

        clients.remove(websocket)
