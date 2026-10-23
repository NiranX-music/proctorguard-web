from __future__ import annotations

from typing import Any, Dict, List, Optional
from src.database.db import Database


class SessionManager:
    """
    Coordinator for exam sessions and candidate lifecycles.
    """

    def __init__(self, db: Database):
        self.db = db

    def create_session(self, session_id: str, name: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self.db.create_session(session_id, name, config)

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        return self.db.get_session(session_id)

    def list_sessions(self) -> List[Dict[str, Any]]:
        return self.db.list_sessions()

    def get_candidates(self, session_id: str) -> List[Dict[str, Any]]:
        return self.db.list_candidates(session_id)
