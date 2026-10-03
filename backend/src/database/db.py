from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional
from src.incidents.event_schema import IncidentEvent, Severity


class Database:
    """
    SQLite persistence layer for exam sessions, candidates, and incident audit logs.
    """

    def __init__(self, db_path: str = "proctor.db"):
        self.db_path = db_path
        self._mem_conn = None
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        else:
            self._mem_conn = sqlite3.connect(":memory:", timeout=30.0, check_same_thread=False)
            self._mem_conn.row_factory = sqlite3.Row
        self.init_db()

    @contextmanager
    def get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        if self._mem_conn is not None:
            try:
                yield self._mem_conn
                self._mem_conn.commit()
            except Exception:
                self._mem_conn.rollback()
                raise
        else:
            conn = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    def init_db(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode = WAL;")
            cursor.execute("PRAGMA foreign_keys = ON;")

            # Sessions table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                config TEXT DEFAULT '{}'
            );
            """)

            # Candidates table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS candidates (
                id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                name TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                risk_score INTEGER DEFAULT 0,
                warning_count INTEGER DEFAULT 0,
                high_warning_count INTEGER DEFAULT 0,
                connected_at TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                lock_reason TEXT,
                PRIMARY KEY (session_id, id),
                FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
            );
            """)

            # Incidents audit log table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                candidate_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                event_type TEXT NOT NULL,
                weight INTEGER NOT NULL DEFAULT 0,
                metadata TEXT DEFAULT '{}',
                snapshot_frame TEXT,
                auto_action TEXT,
                FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
            );
            """)

            # Create indexing for high-frequency real-time querying
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_session ON incidents(session_id);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_candidate ON incidents(session_id, candidate_id);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_event_type ON incidents(event_type);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_timestamp ON incidents(timestamp);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_candidates_session ON candidates(session_id);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_candidates_status ON candidates(status);")

    # ------------------ Session Management ------------------

    def create_session(self, session_id: str, name: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        created_at = datetime.now(timezone.utc).isoformat()
        cfg_json = json.dumps(config or {})
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO sessions (id, name, created_at, status, config)
            VALUES (?, ?, ?, 'ACTIVE', ?)
            ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                config = excluded.config
            """, (session_id, name, created_at, cfg_json))
        return self.get_session(session_id) or {}

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM sessions WHERE id = ?", (session_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "sessionId": row["id"],
                "name": row["name"],
                "createdAt": row["created_at"],
                "status": row["status"],
                "config": json.loads(row["config"] or "{}"),
            }

    def list_sessions(self) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM sessions ORDER BY created_at DESC")
            rows = cursor.fetchall()
            return [
                {
                    "sessionId": r["id"],
                    "name": r["name"],
                    "createdAt": r["created_at"],
                    "status": r["status"],
                    "config": json.loads(r["config"] or "{}"),
                }
                for r in rows
            ]

    # ------------------ Candidate Management ------------------

    def upsert_candidate(
        self,
        session_id: str,
        candidate_id: str,
        name: Optional[str] = None,
        status: Optional[str] = None,
    ) -> Dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        display_name = name or f"Candidate {candidate_id[:8]}"
        initial_status = status or "ACTIVE"

        with self.get_connection() as conn:
            cursor = conn.cursor()
            # Ensure parent session exists
            cursor.execute("SELECT id FROM sessions WHERE id = ?", (session_id,))
            if not cursor.fetchone():
                cursor.execute("""
                INSERT INTO sessions (id, name, created_at, status, config)
                VALUES (?, ?, ?, 'ACTIVE', '{}')
                """, (session_id, f"Session {session_id[:8]}", now))

            cursor.execute("""
            INSERT INTO candidates (id, session_id, name, status, risk_score, warning_count, high_warning_count, connected_at, last_seen)
            VALUES (?, ?, ?, ?, 0, 0, 0, ?, ?)
            ON CONFLICT(session_id, id) DO UPDATE SET
                last_seen = excluded.last_seen,
                name = COALESCE(?, candidates.name),
                status = COALESCE(?, candidates.status)
            """, (candidate_id, session_id, display_name, initial_status, now, now, name, status))

        return self.get_candidate(session_id, candidate_id) or {}

    def get_candidate(self, session_id: str, candidate_id: str) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM candidates WHERE session_id = ? AND id = ?",
                (session_id, candidate_id),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "candidateId": row["id"],
                "sessionId": row["session_id"],
                "name": row["name"],
                "status": row["status"],
                "riskScore": row["risk_score"],
                "warningCount": row["warning_count"],
                "highWarningCount": row["high_warning_count"],
                "connectedAt": row["connected_at"],
                "lastSeen": row["last_seen"],
                "lockReason": row["lock_reason"],
            }

    def list_candidates(self, session_id: str) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM candidates WHERE session_id = ? ORDER BY risk_score DESC, connected_at ASC",
                (session_id,),
            )
            rows = cursor.fetchall()
            return [
                {
                    "candidateId": r["id"],
                    "sessionId": r["session_id"],
                    "name": r["name"],
                    "status": r["status"],
                    "riskScore": r["risk_score"],
                    "warningCount": r["warning_count"],
                    "highWarningCount": r["high_warning_count"],
                    "connectedAt": r["connected_at"],
                    "lastSeen": r["last_seen"],
                    "lockReason": r["lock_reason"],
                }
                for r in rows
            ]

    def update_candidate_status(
        self,
        session_id: str,
        candidate_id: str,
        status: str,
        lock_reason: Optional[str] = None,
    ):
        now = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            UPDATE candidates
            SET status = ?,
                lock_reason = ?,
                last_seen = ?
            WHERE session_id = ? AND id = ?
            """, (status, lock_reason, now, session_id, candidate_id))

    def update_candidate_score(
        self,
        session_id: str,
        candidate_id: str,
        risk_score: int,
        warning_count: int,
        high_warning_count: int,
        lock_reason: Optional[str] = None,
        status: Optional[str] = None,
    ):
        now = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if status is not None:
                cursor.execute("""
                UPDATE candidates
                SET risk_score = ?,
                    warning_count = ?,
                    high_warning_count = ?,
                    status = ?,
                    lock_reason = COALESCE(?, lock_reason),
                    last_seen = ?
                WHERE session_id = ? AND id = ?
                """, (risk_score, warning_count, high_warning_count, status, lock_reason, now, session_id, candidate_id))
            else:
                cursor.execute("""
                UPDATE candidates
                SET risk_score = ?,
                    warning_count = ?,
                    high_warning_count = ?,
                    lock_reason = COALESCE(?, lock_reason),
                    last_seen = ?
                WHERE session_id = ? AND id = ?
                """, (risk_score, warning_count, high_warning_count, lock_reason, now, session_id, candidate_id))

    # ------------------ Incidents & Audit Logs ------------------

    def record_incident(
        self,
        event: IncidentEvent,
        auto_action: Optional[str] = None,
        weight: int = 0,
    ) -> Dict[str, Any]:
        meta_str = json.dumps(event.metadata or {})
        sev_str = event.severity.value if isinstance(event.severity, Severity) else str(event.severity)
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO incidents (
                session_id, candidate_id, timestamp, severity,
                event_type, weight, metadata, snapshot_frame, auto_action
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.session_id,
                event.candidate_id,
                event.timestamp,
                sev_str,
                event.event_type,
                weight,
                meta_str,
                event.snapshot_frame,
                auto_action,
            ))
            incident_id = cursor.lastrowid

        return {
            "id": incident_id,
            "sessionId": event.session_id,
            "candidateId": event.candidate_id,
            "timestamp": event.timestamp,
            "severity": sev_str,
            "eventType": event.event_type,
            "weight": weight,
            "metadata": event.metadata,
            "snapshotFrame": event.snapshot_frame,
            "autoAction": auto_action,
        }

    def get_candidate_event_counts(self, session_id: str, candidate_id: str) -> Dict[str, int]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT event_type, COUNT(*) as cnt
            FROM incidents
            WHERE session_id = ? AND candidate_id = ?
            GROUP BY event_type
            """, (session_id, candidate_id))
            rows = cursor.fetchall()
            return {r["event_type"]: r["cnt"] for r in rows}

    def get_incidents(
        self,
        session_id: str,
        candidate_id: Optional[str] = None,
        severity: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 500,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        query = "SELECT * FROM incidents WHERE session_id = ?"
        params: List[Any] = [session_id]

        if candidate_id:
            query += " AND candidate_id = ?"
            params.append(candidate_id)
        if severity:
            query += " AND severity = ?"
            params.append(severity.upper())
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)

        query += " ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [
                {
                    "id": r["id"],
                    "sessionId": r["session_id"],
                    "candidateId": r["candidate_id"],
                    "timestamp": r["timestamp"],
                    "severity": r["severity"],
                    "eventType": r["event_type"],
                    "weight": r["weight"],
                    "metadata": json.loads(r["metadata"] or "{}"),
                    "snapshotFrame": r["snapshot_frame"],
                    "autoAction": r["auto_action"],
                }
                for r in rows
            ]

    def export_audit_log(self, session_id: str) -> Dict[str, Any]:
        session = self.get_session(session_id)
        candidates = self.list_candidates(session_id)

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT * FROM incidents
            WHERE session_id = ?
            ORDER BY timestamp ASC, id ASC
            """, (session_id,))
            incident_rows = cursor.fetchall()

        timeline = [
            {
                "id": r["id"],
                "sessionId": r["session_id"],
                "candidateId": r["candidate_id"],
                "timestamp": r["timestamp"],
                "severity": r["severity"],
                "eventType": r["event_type"],
                "weight": r["weight"],
                "metadata": json.loads(r["metadata"] or "{}"),
                "snapshotFrame": r["snapshot_frame"],
                "autoAction": r["auto_action"],
            }
            for r in incident_rows
        ]

        critical_count = sum(1 for inc in timeline if inc["severity"] == "CRITICAL")
        high_count = sum(1 for inc in timeline if inc["severity"] == "HIGH")

        return {
            "sessionId": session_id,
            "session": session,
            "exportedAt": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "totalCandidates": len(candidates),
                "totalIncidents": len(timeline),
                "criticalIncidents": critical_count,
                "highIncidents": high_count,
            },
            "candidates": candidates,
            "timeline": timeline,
        }

    def clear_session_data(self, session_id: str) -> None:
        """Clear all recorded incidents and reset candidate scores for a session."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM incidents WHERE session_id = ?;", (session_id,))
            cursor.execute("""
            UPDATE candidates
            SET risk_score = 0, warning_count = 0, high_warning_count = 0,
                status = 'ACTIVE', lock_reason = NULL
            WHERE session_id = ?;
            """, (session_id,))

    def delete_session(self, session_id: str) -> bool:
        """Delete an entire session and all associated cascade data."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM sessions WHERE id = ?;", (session_id,))
            return cursor.rowcount > 0
