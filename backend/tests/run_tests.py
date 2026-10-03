import sys
import unittest
from pathlib import Path

# Ensure backend root is on sys.path
backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

from src.incidents.event_schema import IncidentEvent, EventType, Severity
from src.incidents.scoring_engine import ScoringEngine
from src.database.db import Database
from fastapi.testclient import TestClient
from src.server import app

class TestScoringEngine(unittest.TestCase):
    def test_weights(self):
        self.assertEqual(ScoringEngine.get_weight(EventType.PROCESS_BLACKLIST_HIT.value), 50)
        self.assertEqual(ScoringEngine.get_weight(EventType.INJECTED_DLL_DETECTED.value), 50)
        self.assertEqual(ScoringEngine.get_weight(EventType.MULTIPLE_DISPLAYS_DETECTED.value), 40)
        self.assertEqual(ScoringEngine.get_weight(EventType.VIRTUAL_CAMERA_DETECTED.value), 35)
        self.assertEqual(ScoringEngine.get_weight(EventType.TAB_BLUR.value), 15)
        self.assertEqual(ScoringEngine.get_weight(EventType.FULLSCREEN_EXIT.value), 15)
        self.assertEqual(ScoringEngine.get_weight(EventType.ZERO_FACE_DETECTED.value), 20)
        self.assertEqual(ScoringEngine.get_weight(EventType.SUSPICIOUS_AUDIO_LEVEL.value), 10)
        self.assertEqual(ScoringEngine.get_weight(EventType.CLIPBOARD_VIOLATION.value), 5)

    def test_accumulation_and_limits(self):
        engine = ScoringEngine(max_warning_limit=3)
        sid, cid = "test-sess", "cand-1"

        ev1 = IncidentEvent(
            sessionId=sid,
            candidateId=cid,
            severity=Severity.HIGH,
            eventType=EventType.TAB_BLUR.value
        )
        r1 = engine.evaluate_incident(ev1)
        self.assertEqual(r1.risk_score, 15)
        self.assertFalse(r1.should_lock)

        ev2 = IncidentEvent(
            sessionId=sid,
            candidateId=cid,
            severity=Severity.CRITICAL,
            eventType=EventType.PROCESS_BLACKLIST_HIT.value
        )
        r2 = engine.evaluate_incident(ev2)
        self.assertEqual(r2.risk_score, 65)
        self.assertTrue(r2.should_lock)

class TestDatabase(unittest.TestCase):
    def setUp(self):
        self.db = Database(db_path=":memory:")

    def test_sessions_and_incidents(self):
        s = self.db.create_session("sess-ut", "Unit Test Exam")
        self.assertEqual(s["sessionId"], "sess-ut")
        c = self.db.upsert_candidate("sess-ut", "cand-ut", name="Test Student")
        self.assertEqual(c["name"], "Test Student")

        ev = IncidentEvent(
            sessionId="sess-ut",
            candidateId="cand-ut",
            severity=Severity.CRITICAL,
            eventType=EventType.INJECTED_DLL_DETECTED.value,
            metadata={"dll": "hook.dll"}
        )
        inc = self.db.record_incident(ev, auto_action="LOCK_EXAM", weight=50)
        self.assertEqual(inc["severity"], "CRITICAL")
        self.assertEqual(len(self.db.get_incidents("sess-ut")), 1)

class TestFastAPIEndpoints(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_health_and_session(self):
        r = self.client.get("/api/health")
        self.assertEqual(r.status_code, 200)

        r_create = self.client.post("/api/sessions", json={"sessionId": "fastapi-ut", "name": "API Suite"})
        self.assertEqual(r_create.status_code, 201)

        r_inc = self.client.post("/api/sessions/fastapi-ut/incidents", json={
            "sessionId": "fastapi-ut",
            "candidateId": "cand-api-test",
            "severity": "CRITICAL",
            "eventType": "PROCESS_BLACKLIST_HIT",
            "metadata": {"process": "cheatengine.exe"}
        })
        self.assertEqual(r_inc.status_code, 201)
        self.assertTrue(r_inc.json()["evaluation"]["shouldLock"])

if __name__ == "__main__":
    unittest.main()
