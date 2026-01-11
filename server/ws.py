from typing import Dict
from uuid import UUID
from fastapi import WebSocket

# manages active WebSocket connections for presence tracking
class Presence:
    def __init__(self):
        self._sockets: Dict[UUID, WebSocket] = {}

    async def connect(self, device_id: UUID, ws: WebSocket):
        await ws.accept()
        self._sockets[device_id] = ws

    def disconnect(self, device_id: UUID):
        self._sockets.pop(device_id, None)

    def get(self, device_id: UUID) -> WebSocket | None:
        return self._sockets.get(device_id)

presence = Presence()
