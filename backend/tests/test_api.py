import pytest
from fastapi.testclient import TestClient
from src.server import app, db, scoring_engine

client = TestClient(app)

def test_api_health():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"

def test_session_crud():
    sess_id = "test-api-session"
    res = client.post("/api/sessions", json={"sessionId": sess_id, "name": "API Testing Session"})
    assert res.status_code == 201
    
    res = client.get("/api/sessions")
    assert res.status_code == 200
    sessions = res.json()
    assert any(s["sessionId"] == sess_id for s in sessions)
    
    res = client.get(f"/api/sessions/{sess_id}")
    assert res.status_code == 200
    assert res.json()["name"] == "API Testing Session"

def test_submit_incident_via_rest():
    sess_id = "test-api-session-incidents"
    client.post("/api/sessions", json={"sessionId": sess_id, "name": "Incident API Test"})
    
    incident_payload = {
        "sessionId": sess_id,
        "candidateId": "cand-api-1",
        "severity": "CRITICAL",
        "eventType": "PROCESS_BLACKLIST_HIT",
        "metadata": {"detectedProcess": "obs64.exe", "pid": 9999}
    }
    res = client.post(f"/api/sessions/{sess_id}/incidents", json=incident_payload)
    assert res.status_code == 201
    data = res.json()
    assert data["evaluation"]["riskScore"] == 50
    assert data["evaluation"]["shouldLock"] is True
    
    # Verify candidate state updated
    cand_res = client.get(f"/api/sessions/{sess_id}/candidates/cand-api-1")
    assert cand_res.status_code == 200
    assert cand_res.json()["status"] == "LOCKED"
    assert cand_res.json()["riskScore"] == 50

def test_candidate_actions():
    sess_id = "test-api-session-actions"
    cand_id = "cand-actions-1"
    client.post("/api/sessions", json={"sessionId": sess_id, "name": "Actions Test"})
    client.post(f"/api/sessions/{sess_id}/candidates", json={"candidateId": cand_id, "name": "Test User"})
    
    # 1. Warn candidate
    res_warn = client.post(f"/api/sessions/{sess_id}/candidates/{cand_id}/warn", json={"message": "First warning"})
    assert res_warn.status_code == 200
    assert res_warn.json()["highWarningCount"] == 1
    
    # 2. Lock candidate
    res_lock = client.post(f"/api/sessions/{sess_id}/candidates/{cand_id}/lock", json={"reason": "Manual review"})
    assert res_lock.status_code == 200
    assert res_lock.json()["status"] == "LOCKED"
    
    # 3. Unlock candidate
    res_unlock = client.post(f"/api/sessions/{sess_id}/candidates/{cand_id}/unlock")
    assert res_unlock.status_code == 200
    assert res_unlock.json()["status"] == "ACTIVE"
    
    # 4. Terminate candidate
    res_term = client.post(f"/api/sessions/{sess_id}/candidates/{cand_id}/terminate", json={"reason": "Disqualified"})
    assert res_term.status_code == 200
    assert res_term.json()["status"] == "TERMINATED"
