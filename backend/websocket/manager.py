import json
import asyncio
from typing import Dict, Set
from fastapi import WebSocket
import logging

logger = logging.getLogger(__name__)


class WebSocketManager:
    """
    Manages WebSocket connections grouped by api_key_id (one "room" per company).

    Dashboard connects to:  ws://host/ws/{api_key_id}
    When an alert fires, ws_manager.broadcast(api_key_id, payload) pushes to
    every browser tab open for that company — instantly, no refresh.
    """

    def __init__(self):
        # api_key_id → set of connected WebSocket objects
        self._rooms: Dict[str, Set[WebSocket]] = {}
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, api_key_id: str):
        await websocket.accept()
        async with self._lock:
            self._rooms.setdefault(api_key_id, set()).add(websocket)
        logger.info("WS connected  room=%s  total=%d",
                    api_key_id, len(self._rooms[api_key_id]))

    async def disconnect(self, websocket: WebSocket, api_key_id: str):
        async with self._lock:
            room = self._rooms.get(api_key_id, set())
            room.discard(websocket)
            if not room:
                self._rooms.pop(api_key_id, None)
        logger.info("WS disconnected  room=%s", api_key_id)

    async def broadcast(self, api_key_id: str, payload: dict):
        """Send payload to every client in the room. Dead sockets are cleaned up."""
        text = json.dumps(payload)
        room = list(self._rooms.get(api_key_id, set()))
        dead: list[WebSocket] = []

        for ws in room:
            try:
                await ws.send_text(text)
            except Exception:
                dead.append(ws)

        for ws in dead:
            await self.disconnect(ws, api_key_id)

    async def broadcast_all(self, payload: dict):
        """Broadcast to every connected client (used for system-wide notifications)."""
        for api_key_id in list(self._rooms.keys()):
            await self.broadcast(api_key_id, payload)

    def room_size(self, api_key_id: str) -> int:
        return len(self._rooms.get(api_key_id, set()))


# Singleton shared across the app
ws_manager = WebSocketManager()