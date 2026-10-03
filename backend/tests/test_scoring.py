import pytest
from src.incidents.event_schema import IncidentEvent, EventType, Severity
from src.incidents.scoring_engine import ScoringEngine, EVENT_WEIGHTS

def test_scoring_weights():
    # Verify critical weights
    assert ScoringEngine.get_weight(EventType.PROCESS_BLACKLIST_HIT.value) == 50
    assert ScoringEngine.get_weight(EventType.INJECTED_DLL_DETECTED.value) == 50
    assert ScoringEngine.get_weight(EventType.MULTIPLE_DISPLAYS_DETECTED.value) == 40
    assert ScoringEngine.get_weight(EventType.VIRTUAL_CAMERA_DETECTED.value) == 35
    
    # Verify high weights
    assert ScoringEngine.get_weight(EventType.TAB_BLUR.value) == 15
    assert ScoringEngine.get_weight(EventType.FULLSCREEN_EXIT.value) == 15
    assert ScoringEngine.get_weight(EventType.ZERO_FACE_DETECTED.value) == 20
    assert ScoringEngine.get_weight(EventType.MULTIPLE_FACES_DETECTED.value) == 20
    
    # Verify medium & low weights
    assert ScoringEngine.get_weight(EventType.SUSPICIOUS_AUDIO_LEVEL.value) == 10
    assert ScoringEngine.get_weight(EventType.CLIPBOARD_VIOLATION.value) == 5
    assert ScoringEngine.get_weight(EventType.CONTEXT_MENU_ATTEMPT.value) == 5

def test_risk_score_formula_accumulation():
    engine = ScoringEngine()
    session_id = "test-sess-1"
    candidate_id = "cand-001"
    
    # 1. First event: TAB_BLUR (15 pts)
    ev1 = IncidentEvent(
        sessionId=session_id,
        candidateId=candidate_id,
        severity=Severity.HIGH,
        eventType=EventType.TAB_BLUR.value,
        metadata={"blur": True}
    )
    res1 = engine.evaluate_incident(ev1)
    assert res1.risk_score == 15
    assert res1.auto_action == "WARN_CANDIDATE"
    assert res1.high_warning_count == 1
    assert not res1.should_lock
    
    # 2. Second event: SUSPICIOUS_AUDIO_LEVEL (10 pts) -> Total = 25
    ev2 = IncidentEvent(
        sessionId=session_id,
        candidateId=candidate_id,
        severity=Severity.MEDIUM,
        eventType=EventType.SUSPICIOUS_AUDIO_LEVEL.value,
        metadata={"level": 45}
    )
    res2 = engine.evaluate_incident(ev2)
    assert res2.risk_score == 25
    assert res2.auto_action == "MARK_TIMELINE_TIMESTAMP"
    
    # 3. Third event: CRITICAL PROCESS_BLACKLIST_HIT (50 pts) -> Total = 75
    ev3 = IncidentEvent(
        sessionId=session_id,
        candidateId=candidate_id,
        severity=Severity.CRITICAL,
        eventType=EventType.PROCESS_BLACKLIST_HIT.value,
        metadata={"detectedProcess": "cheatengine-x86_64.exe"}
    )
    res3 = engine.evaluate_incident(ev3)
    assert res3.risk_score == 75
    assert res3.should_lock is True
    assert res3.auto_action == "PROMPT_LOCK_AND_NOTIFY_ADMIN"

def test_score_caps_at_100():
    engine = ScoringEngine()
    session_id = "test-sess-2"
    candidate_id = "cand-002"
    
    # Two critical events (50 + 50 = 100) + 1 high (15) -> capped at 100
    for _ in range(3):
        ev = IncidentEvent(
            sessionId=session_id,
            candidateId=candidate_id,
            severity=Severity.CRITICAL,
            eventType=EventType.PROCESS_BLACKLIST_HIT.value,
        )
        res = engine.evaluate_incident(ev)
        
    assert res.risk_score == 100

def test_warning_limit_triggers_lock():
    engine = ScoringEngine(max_warning_limit=3)
    session_id = "test-sess-3"
    candidate_id = "cand-003"
    
    # Trigger 3 TAB_BLUR warnings
    for i in range(1, 4):
        ev = IncidentEvent(
            sessionId=session_id,
            candidateId=candidate_id,
            severity=Severity.HIGH,
            eventType=EventType.TAB_BLUR.value,
        )
        res = engine.evaluate_incident(ev)
        if i < 3:
            assert res.should_lock is False
            assert res.max_warnings_exceeded is False
        else:
            assert res.max_warnings_exceeded is True
            assert res.should_lock is True

def test_low_severity_block_event():
    engine = ScoringEngine()
    session_id = "test-sess-4"
    candidate_id = "cand-004"
    
    ev = IncidentEvent(
        sessionId=session_id,
        candidateId=candidate_id,
        severity=Severity.LOW,
        eventType=EventType.CLIPBOARD_VIOLATION.value,
    )
    res = engine.evaluate_incident(ev)
    assert res.should_block_event is True
    assert res.auto_action == "BLOCK_EVENT"
    assert res.risk_score == 5
