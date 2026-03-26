"""
WebSocket presence management.

Tracks which devices are currently connected via WebSocket
for real-time message delivery and online status.
"""

from typing import Dict
from uuid import UUID
from fastapi import WebSocket


class Presence:
    """Manages active WebSocket connections indexed by device ID."""

    def __init__(self):
        self._sockets: Dict[UUID, WebSocket] = {}

    async def connect(self, device_id: UUID, ws: WebSocket):
        """Accept and register a new WebSocket connection for a device."""
        await ws.accept()
        self._sockets[device_id] = ws

    def disconnect(self, device_id: UUID, ws: WebSocket = None):
        """
        Remove a device's WebSocket connection.

        Only removes if it's the same WebSocket that registered,
        otherwise a newer connection's entry would be wiped out.
        """
        if ws is None or self._sockets.get(device_id) is ws:
            self._sockets.pop(device_id, None)

    def get(self, device_id: UUID) -> WebSocket | None:
        """Retrieve the active WebSocket for a device, or None if offline."""
        return self._sockets.get(device_id)

presence = Presence()
