import os
import pytest
from src.database.db import Database
from src.incidents.event_schema import IncidentEvent, EventType, Severity

@pytest.fixture
def test_db(tmp_path):
    db_file = str(tmp_path / "test_proctor.db")
    db = Database(db_path=db_file)
    return db

def test_session_lifecycle(test_db):
    session = test_db.create_session("sess-100", "CS 101 Midterm", {"duration": 60})
    assert session["sessionId"] == "sess-100"
    assert session["name"] == "CS 101 Midterm"
    
    fetched = test_db.get_session("sess-100")
    assert fetched is not None
    assert fetched["name"] == "CS 101 Midterm"
    
    sessions = test_db.list_sessions()
    assert len(sessions) == 1

def test_candidate_upsert_and_score(test_db):
    test_db.create_session("sess-100", "Final Exam")
    cand = test_db.upsert_candidate("sess-100", "cand-1", name="Alice Smith")
    assert cand["name"] == "Alice Smith"
    assert cand["status"] == "ACTIVE"
    
    # Update score
    updated = test_db.update_candidate_score(
        session_id="sess-100",
        candidate_id="cand-1",
        risk_score=35,
        warning_count=1,
        high_warning_count=1,
        lock_reason=None,
        status="ACTIVE"
    )
    assert updated["riskScore"] == 35
    assert updated["warningCount"] == 1

def test_incident_recording_and_query(test_db):
    test_db.create_session("sess-100", "Final Exam")
    test_db.upsert_candidate("sess-100", "cand-1")
    
    ev = IncidentEvent(
        sessionId="sess-100",
        candidateId="cand-1",
        severity=Severity.CRITICAL,
        eventType=EventType.PROCESS_BLACKLIST_HIT.value,
        metadata={"process": "cheatengine.exe"},
        snapshotFrame="data:image/jpeg;base64,mock"
    )
    
    inc = test_db.record_incident(ev, auto_action="LOCK_EXAM", weight=50)
    assert inc["id"] is not None
    assert inc["severity"] == "CRITICAL"
    assert inc["eventType"] == EventType.PROCESS_BLACKLIST_HIT.value
    assert inc["autoAction"] == "LOCK_EXAM"
    
    # Fetch incidents with filters
    incidents = test_db.get_incidents(session_id="sess-100", severity="CRITICAL")
    assert len(incidents) == 1
    assert incidents[0]["candidateId"] == "cand-1"
    
    # Count checks
    counts = test_db.get_candidate_event_counts("sess-100", "cand-1")
    assert counts[EventType.PROCESS_BLACKLIST_HIT.value] == 1

def test_audit_export_and_reset(test_db):
    test_db.create_session("sess-200", "Audit Test")
    test_db.upsert_candidate("sess-200", "cand-9")
    
    ev = IncidentEvent(
        sessionId="sess-200",
        candidateId="cand-9",
        severity=Severity.HIGH,
        eventType=EventType.TAB_BLUR.value,
    )
    test_db.record_incident(ev, auto_action="WARN", weight=15)
    
    report = test_db.export_audit_log("sess-200")
    assert report["sessionId"] == "sess-200"
    assert report["summary"]["totalIncidents"] == 1
    assert len(report["timeline"]) == 1
    
    # Test clear
    test_db.clear_session_data("sess-200")
    cleared_report = test_db.export_audit_log("sess-200")
    assert cleared_report["summary"]["totalIncidents"] == 0
