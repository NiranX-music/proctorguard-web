from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional, Set
from fastapi import WebSocket

logger = logging.getLogger("webrtc.signaling")


class SignalingManager:
    """
    Manages WebRTC signaling routing and WebSocket connections for candidates,
    proctors (admins), and native companion agents across exam sessions.
    """

    def __init__(self):
        # session_id -> { candidate_id -> WebSocket }
        self._candidate_connections: Dict[str, Dict[str, WebSocket]] = {}
        # session_id -> Set of proctor WebSockets
        self._admin_connections: Dict[str, Set[WebSocket]] = {}
        # session_id -> { candidate_id -> WebSocket }
        self._companion_connections: Dict[str, Dict[str, WebSocket]] = {}
        self._lock = asyncio.Lock()

    # ---------------- Connection Management ----------------

    async def register_candidate(self, session_id: str, candidate_id: str, websocket: WebSocket):
        async with self._lock:
            if session_id not in self._candidate_connections:
                self._candidate_connections[session_id] = {}
            self._candidate_connections[session_id][candidate_id] = websocket

        # Notify connected admins that candidate joined / came online
        await self.broadcast_to_admins(session_id, {
            "type": "candidate_connected",
            "sessionId": session_id,
            "candidateId": candidate_id,
        })
        logger.info(f"Registered candidate connection: session={session_id}, candidate={candidate_id}")

    async def unregister_candidate(self, session_id: str, candidate_id: str):
        async with self._lock:
            if session_id in self._candidate_connections:
                self._candidate_connections[session_id].pop(candidate_id, None)
                if not self._candidate_connections[session_id]:
                    del self._candidate_connections[session_id]

        # Notify admins
        await self.broadcast_to_admins(session_id, {
            "type": "candidate_disconnected",
            "sessionId": session_id,
            "candidateId": candidate_id,
        })
        logger.info(f"Unregistered candidate: session={session_id}, candidate={candidate_id}")

    async def register_admin(self, session_id: str, websocket: WebSocket):
        async with self._lock:
            if session_id not in self._admin_connections:
                self._admin_connections[session_id] = set()
            self._admin_connections[session_id].add(websocket)
        logger.info(f"Registered admin connection for session={session_id}")

    async def unregister_admin(self, session_id: str, websocket: WebSocket):
        async with self._lock:
            if session_id in self._admin_connections:
                self._admin_connections[session_id].discard(websocket)
                if not self._admin_connections[session_id]:
                    del self._admin_connections[session_id]
        logger.info(f"Unregistered admin connection for session={session_id}")

    async def register_companion(self, session_id: str, candidate_id: str, websocket: WebSocket):
        async with self._lock:
            if session_id not in self._companion_connections:
                self._companion_connections[session_id] = {}
            self._companion_connections[session_id][candidate_id] = websocket

        await self.broadcast_to_admins(session_id, {
            "type": "companion_connected",
            "sessionId": session_id,
            "candidateId": candidate_id,
        })
        logger.info(f"Registered companion for session={session_id}, candidate={candidate_id}")

    async def unregister_companion(self, session_id: str, candidate_id: str):
        async with self._lock:
            if session_id in self._companion_connections:
                self._companion_connections[session_id].pop(candidate_id, None)
                if not self._companion_connections[session_id]:
                    del self._companion_connections[session_id]

        await self.broadcast_to_admins(session_id, {
            "type": "companion_disconnected",
            "sessionId": session_id,
            "candidateId": candidate_id,
        })
        logger.info(f"Unregistered companion: session={session_id}, candidate={candidate_id}")

    # ---------------- Signaling Routing ----------------

    async def route_candidate_signaling(
        self,
        session_id: str,
        candidate_id: str,
        data: Dict[str, Any],
    ):
        """
        Forwards WebRTC signaling and live media telemetry from candidate to admin/proctors.
        """
        payload = {
            **data,
            "type": data.get("type"),
            "sessionId": session_id,
            "candidateId": candidate_id,
        }
        await self.broadcast_to_admins(session_id, payload)

    async def route_admin_signaling(
        self,
        session_id: str,
        target_candidate_id: str,
        data: Dict[str, Any],
    ):
        """
        Forwards WebRTC offer, answer, or ice-candidate from proctor to target candidate.
        """
        payload = {
            "type": data.get("type"),
            "sessionId": session_id,
            "candidateId": target_candidate_id,
            "sdp": data.get("sdp"),
            "candidate": data.get("candidate"),
            "streamType": data.get("streamType", "webcam"),
        }
        await self.send_to_candidate(session_id, target_candidate_id, payload)

    # ---------------- Direct & Broadcast Delivery ----------------

    async def send_to_candidate(self, session_id: str, candidate_id: str, message: Dict[str, Any]) -> bool:
        ws = None
        async with self._lock:
            ws = self._candidate_connections.get(session_id, {}).get(candidate_id)

        if ws:
            try:
                await ws.send_text(json.dumps(message))
                return True
            except Exception as e:
                logger.warning(f"Error sending message to candidate {candidate_id}: {e}")
        return False

    async def send_to_companion(self, session_id: str, candidate_id: str, message: Dict[str, Any]) -> bool:
        ws = None
        async with self._lock:
            ws = self._companion_connections.get(session_id, {}).get(candidate_id)

        if ws:
            try:
                await ws.send_text(json.dumps(message))
                return True
            except Exception as e:
                logger.warning(f"Error sending message to companion {candidate_id}: {e}")
        return False

    async def broadcast_to_admins(self, session_id: str, message: Dict[str, Any]):
        admins_to_send: List[WebSocket] = []
        async with self._lock:
            admins_to_send = list(self._admin_connections.get(session_id, []))

        if not admins_to_send:
            return

        msg_text = json.dumps(message)
        dead_sockets: List[WebSocket] = []

        for ws in admins_to_send:
            try:
                await ws.send_text(msg_text)
            except Exception as e:
                logger.debug(f"Failed sending to admin ws: {e}")
                dead_sockets.append(ws)

        if dead_sockets:
            async with self._lock:
                admin_set = self._admin_connections.get(session_id)
                if admin_set:
                    for dead in dead_sockets:
                        admin_set.discard(dead)

    async def broadcast_candidate_command(
        self,
        session_id: str,
        candidate_id: str,
        action: str,
        reason: Optional[str] = None,
        message: Optional[str] = None,
    ):
        """
        Sends an enforcement action (LOCK, UNLOCK, TERMINATE, WARN, BLOCK_EVENT)
        to the candidate, their native companion, and notifies admin dashboards.
        """
        payload = {
            "type": "command",
            "action": action,
            "sessionId": session_id,
            "candidateId": candidate_id,
            "reason": reason,
            "message": message,
        }
        await self.send_to_candidate(session_id, candidate_id, payload)
        await self.send_to_companion(session_id, candidate_id, payload)
        await self.broadcast_to_admins(session_id, {
            "type": "action_executed",
            **payload
        })
