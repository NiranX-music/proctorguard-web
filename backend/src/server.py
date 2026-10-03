from __future__ import annotations

import json
import logging
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from src.database.db import Database
from src.incidents.event_schema import (
    CandidateStatusRequest,
    CandidateWarningRequest,
    EventType,
    IncidentEvent,
    SessionCreateRequest,
    Severity,
)
from src.incidents.scoring_engine import ScoringEngine
from src.webrtc.signaling import SignalingManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("server")

BASE_DIR = Path(__file__).resolve().parent.parent
ROOT_DIR = BASE_DIR.parent
WEB_UI_DIR = ROOT_DIR / "web-ui"
if not WEB_UI_DIR.exists():
    WEB_UI_DIR = BASE_DIR / "web-ui"
DB_PATH = os.environ.get("PROCTOR_DB_PATH", str(BASE_DIR / "proctor.db"))

import httpx

# Global configuration store for Gemini AI and proctor settings
GEMINI_KEY_FILE = BASE_DIR / ".gemini_key"

def load_persisted_gemini_key() -> str:
    env_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if env_key:
        return env_key
    if GEMINI_KEY_FILE.exists():
        try:
            return GEMINI_KEY_FILE.read_text(encoding="utf-8").strip()
        except Exception:
            pass
    return ""

GLOBAL_CONFIG: Dict[str, Any] = {
    "gemini_api_key": load_persisted_gemini_key(),
}

db = Database(db_path=DB_PATH)
scoring_engine = ScoringEngine()
signaling = SignalingManager()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Starting Proctoring Server (DB: {DB_PATH})...")
    # Pre-sync candidate states from existing incidents if any
    try:
        sessions = db.list_sessions()
        for sess in sessions:
            cands = db.list_candidates(sess["sessionId"])
            for cand in cands:
                counts = db.get_candidate_event_counts(sess["sessionId"], cand["candidateId"])
                scoring_engine.set_candidate_state(
                    session_id=sess["sessionId"],
                    candidate_id=cand["candidateId"],
                    event_counts=counts,
                    warning_count=cand.get("warningCount", 0),
                    high_warning_count=cand.get("highWarningCount", 0),
                    is_locked=(cand.get("status") == "LOCKED"),
                    lock_reason=cand.get("lockReason"),
                )
    except Exception as e:
        logger.warning(f"Error during state pre-sync: {e}")
    yield
    logger.info("Shutting down Proctoring Server...")


app = FastAPI(
    title="Real-Time Event-Driven Proctoring Backend",
    description="Central coordination backend with WebRTC signaling, real-time incident scoring, and exam control.",
    version="1.0.0",
    lifespan=lifespan,
)

# Enable CORS for all origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Helper: process an incoming incident
async def process_incoming_incident(event: IncidentEvent, source_channel: str = "candidate") -> Dict[str, Any]:
    # 1. Evaluate incident using the real-time scoring engine
    evaluation = scoring_engine.evaluate_incident(event)

    # 2. Persist incident to SQLite with indexed metadata
    db_incident = db.record_incident(
        event=event,
        auto_action=evaluation.auto_action,
        weight=evaluation.weight,
    )

    # 3. Update candidate score & warning counters in DB
    new_status = "LOCKED" if evaluation.should_lock else None
    db.update_candidate_score(
        session_id=event.session_id,
        candidate_id=event.candidate_id,
        risk_score=evaluation.risk_score,
        warning_count=evaluation.warning_count,
        high_warning_count=evaluation.high_warning_count,
        lock_reason=evaluation.lock_reason if evaluation.should_lock else None,
        status=new_status,
    )

    # 4. If auto-lock triggered: dispatch lock command to candidate and companion
    if evaluation.should_lock:
        await signaling.broadcast_candidate_command(
            session_id=event.session_id,
            candidate_id=event.candidate_id,
            action="LOCK",
            reason=evaluation.lock_reason,
            message=evaluation.message,
        )
    # 5. If warn candidate triggered: dispatch warning command
    elif evaluation.should_warn:
        await signaling.send_to_candidate(
            session_id=event.session_id,
            candidate_id=event.candidate_id,
            message={
                "type": "command",
                "action": "WARN",
                "warningCount": evaluation.high_warning_count,
                "warningLimit": scoring_engine.max_warning_limit,
                "message": evaluation.message,
                "eventType": event.event_type,
            },
        )
    # 6. If low-severity event blocked: dispatch block event notice
    elif evaluation.should_block_event:
        await signaling.send_to_candidate(
            session_id=event.session_id,
            candidate_id=event.candidate_id,
            message={
                "type": "command",
                "action": "BLOCK_EVENT",
                "eventType": event.event_type,
                "message": evaluation.message,
            },
        )

    # 7. Broadcast incident, score, and evaluation to connected Admin Proctor dashboards
    broadcast_payload = {
        "type": "incident_reported",
        "sessionId": event.session_id,
        "candidateId": event.candidate_id,
        "sourceChannel": source_channel,
        "incident": db_incident,
        "evaluation": evaluation.to_dict(),
        "riskScore": evaluation.risk_score,
        "candidateStatus": "LOCKED" if evaluation.should_lock else "ACTIVE",
    }
    await signaling.broadcast_to_admins(event.session_id, broadcast_payload)

    return {
        "incident": db_incident,
        "evaluation": evaluation.to_dict(),
    }


# ============================================================================
# REST API Endpoints
# ============================================================================

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "db": DB_PATH,
    }


@app.post("/api/sessions", status_code=status.HTTP_201_CREATED)
async def create_session(request: SessionCreateRequest):
    session_id = request.session_id or uuid.uuid4().hex[:12]
    created = db.create_session(
        session_id=session_id,
        name=request.name,
        config=request.config,
    )
    return created


@app.get("/api/sessions")
async def list_sessions():
    sessions = db.list_sessions()
    # Augment with candidate count
    for sess in sessions:
        candidates = db.list_candidates(sess["sessionId"])
        sess["candidateCount"] = len(candidates)
        sess["criticalRiskCandidates"] = sum(1 for c in candidates if c.get("riskScore", 0) >= 50)
    return sessions


@app.get("/api/sessions/{session_id}")
async def get_session_detail(session_id: str):
    session = db.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    candidates = db.list_candidates(session_id)
    incidents = db.get_incidents(session_id=session_id, limit=100)
    return {
        **session,
        "candidates": candidates,
        "recentIncidents": incidents,
        "candidateCount": len(candidates),
        "totalIncidentsRecorded": len(incidents),
    }


@app.post("/api/sessions/{session_id}/candidates/{candidate_id}/terminate")
async def terminate_candidate(
    session_id: str,
    candidate_id: str,
    payload: Optional[CandidateStatusRequest] = None,
):
    reason = (payload and payload.reason) or "Terminated by proctor administrator"
    message = (payload and payload.message) or "Your examination session has been terminated."

    db.update_candidate_status(session_id, candidate_id, status="TERMINATED", lock_reason=reason)
    scoring_engine.terminate_candidate(session_id, candidate_id)

    # Broadcast command to candidate, companion, and admin
    await signaling.broadcast_candidate_command(
        session_id=session_id,
        candidate_id=candidate_id,
        action="TERMINATE",
        reason=reason,
        message=message,
    )
    return {
        "success": True,
        "sessionId": session_id,
        "candidateId": candidate_id,
        "status": "TERMINATED",
        "reason": reason,
    }


@app.post("/api/sessions/{session_id}/candidates/{candidate_id}/lock")
async def lock_candidate(
    session_id: str,
    candidate_id: str,
    payload: Optional[CandidateStatusRequest] = None,
):
    reason = (payload and payload.reason) or "Locked by proctor administrator"
    message = (payload and payload.message) or "Your exam interface has been locked by the proctor."

    db.update_candidate_status(session_id, candidate_id, status="LOCKED", lock_reason=reason)
    scoring_engine.lock_candidate(session_id, candidate_id, reason=reason)

    await signaling.broadcast_candidate_command(
        session_id=session_id,
        candidate_id=candidate_id,
        action="LOCK",
        reason=reason,
        message=message,
    )
    return {
        "success": True,
        "sessionId": session_id,
        "candidateId": candidate_id,
        "status": "LOCKED",
        "reason": reason,
    }


@app.post("/api/sessions/{session_id}/candidates/{candidate_id}/unlock")
async def unlock_candidate(
    session_id: str,
    candidate_id: str,
    payload: Optional[CandidateStatusRequest] = None,
):
    db.update_candidate_status(session_id, candidate_id, status="ACTIVE", lock_reason=None)
    scoring_engine.unlock_candidate(session_id, candidate_id)

    await signaling.broadcast_candidate_command(
        session_id=session_id,
        candidate_id=candidate_id,
        action="UNLOCK",
        reason=None,
        message=(payload and payload.message) or "Your exam interface has been unlocked.",
    )
    return {
        "success": True,
        "sessionId": session_id,
        "candidateId": candidate_id,
        "status": "ACTIVE",
    }


@app.post("/api/sessions/{session_id}/candidates/{candidate_id}/warn")
async def warn_candidate(
    session_id: str,
    candidate_id: str,
    payload: CandidateWarningRequest,
):
    warn_result = scoring_engine.manual_warn(session_id, candidate_id, payload.message)

    cand = db.get_candidate(session_id, candidate_id)
    new_status = "LOCKED" if warn_result["shouldLock"] else (cand.get("status") if cand else "ACTIVE")

    db.update_candidate_score(
        session_id=session_id,
        candidate_id=candidate_id,
        risk_score=cand.get("riskScore", 0) if cand else 0,
        warning_count=warn_result["warningCount"],
        high_warning_count=warn_result["highWarningCount"],
        lock_reason=warn_result["lockReason"],
        status=new_status,
    )

    if warn_result["shouldLock"]:
        await signaling.broadcast_candidate_command(
            session_id=session_id,
            candidate_id=candidate_id,
            action="LOCK",
            reason=warn_result["lockReason"],
            message="Maximum warning limit exceeded. Exam interface locked.",
        )
    else:
        await signaling.send_to_candidate(
            session_id=session_id,
            candidate_id=candidate_id,
            message={
                "type": "command",
                "action": "WARN",
                "warningCount": warn_result["highWarningCount"],
                "warningLimit": scoring_engine.max_warning_limit,
                "message": payload.message,
                "reason": payload.reason,
            },
        )
        await signaling.broadcast_to_admins(session_id, {
            "type": "warning_issued",
            "sessionId": session_id,
            "candidateId": candidate_id,
            "warningCount": warn_result["highWarningCount"],
            "warningLimit": scoring_engine.max_warning_limit,
            "message": payload.message,
        })

    return {
        "success": True,
        "sessionId": session_id,
        "candidateId": candidate_id,
        "warningCount": warn_result["warningCount"],
        "highWarningCount": warn_result["highWarningCount"],
        "status": new_status,
        "locked": warn_result["shouldLock"],
    }


@app.get("/api/sessions/{session_id}/incidents")
async def list_incidents(
    session_id: str,
    candidate_id: Optional[str] = Query(None, alias="candidateId"),
    severity: Optional[str] = None,
    event_type: Optional[str] = Query(None, alias="eventType"),
    limit: int = 100,
    offset: int = 0,
):
    incidents = db.get_incidents(
        session_id=session_id,
        candidate_id=candidate_id,
        severity=severity,
        event_type=event_type,
        limit=limit,
        offset=offset,
    )
    return incidents


@app.get("/api/sessions/{session_id}/export")
async def export_audit_log(session_id: str):
    session = db.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    report = db.export_audit_log(session_id)
    return JSONResponse(
        content=report,
        headers={"Content-Disposition": f"attachment; filename=audit-log-{session_id}.json"},
    )


@app.post("/api/sessions/{session_id}/incidents", status_code=status.HTTP_201_CREATED)
async def submit_incident(
    session_id: str,
    event_data: Dict[str, Any],
):
    """
    HTTP REST endpoint to ingest an incident event.
    Enables cheat simulation harnesses or external monitors to post incidents.
    """
    event_data.setdefault("sessionId", session_id)
    if "candidateId" not in event_data:
        raise HTTPException(status_code=400, detail="Missing candidateId in event payload")
    
    # Ensure candidate exists in DB
    db.upsert_candidate(session_id, event_data["candidateId"], status="ACTIVE")

    try:
        event = IncidentEvent.model_validate(event_data)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Validation error: {e}")

    result = await process_incoming_incident(event, source_channel="rest_api")
    return result


@app.get("/api/sessions/{session_id}/candidates")
async def get_session_candidates(session_id: str):
    """List all registered candidates in a session with current score and status."""
    return db.list_candidates(session_id)


@app.get("/api/sessions/{session_id}/candidates/{candidate_id}")
async def get_candidate_detail(session_id: str, candidate_id: str):
    """Retrieve details, status, and event counts for a specific candidate."""
    cand = db.get_candidate(session_id, candidate_id)
    if not cand:
        raise HTTPException(status_code=404, detail="Candidate not found")
    counts = db.get_candidate_event_counts(session_id, candidate_id)
    incidents = db.get_incidents(session_id=session_id, candidate_id=candidate_id, limit=50)
    return {
        **cand,
        "eventCounts": counts,
        "recentIncidents": incidents,
    }


@app.post("/api/sessions/{session_id}/candidates", status_code=status.HTTP_201_CREATED)
async def register_candidate(
    session_id: str,
    payload: Dict[str, Any],
):
    """Register or initialize a candidate in a session."""
    cand_id = payload.get("candidateId") or uuid.uuid4().hex[:8]
    name = payload.get("name") or f"Candidate {cand_id}"
    cand = db.upsert_candidate(session_id, cand_id, name=name, status="ACTIVE")
    return cand


@app.post("/api/sessions/{session_id}/reset")
async def reset_session(session_id: str):
    """Reset all incidents and candidate scores for a test session."""
    session = db.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    db.clear_session_data(session_id)
    scoring_engine.reset_session(session_id)

    # Broadcast reset to connected admins and candidates
    await signaling.broadcast_to_admins(session_id, {
        "type": "session_reset",
        "sessionId": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    return {"success": True, "sessionId": session_id, "message": "Session reset successfully"}


# ============================================================================
# Gemini AI Live Proctoring & Audio Verification Endpoints
# ============================================================================

@app.get("/api/config/gemini")
async def get_gemini_config():
    """Check if Gemini AI API key is configured globally."""
    key = GLOBAL_CONFIG.get("gemini_api_key") or os.environ.get("GEMINI_API_KEY", "")
    is_configured = bool(key and len(key.strip()) > 5)
    masked = f"{key[:6]}...{key[-4:]}" if is_configured else None
    return {
        "configured": is_configured,
        "maskedKey": masked,
        "model": "gemini-3.8-flash",
    }


@app.post("/api/config/gemini")
async def set_gemini_config(payload: Dict[str, Any]):
    """Set and verify the global Google Gemini API key."""
    new_key = (payload.get("apiKey") or "").strip()
    if not new_key:
        raise HTTPException(status_code=400, detail="Gemini API key is required.")

    # Validate key against Gemini API with lightweight test request
    test_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent?key={new_key}"
    test_payload = {
        "contents": [{"parts": [{"text": "Reply with 'ready'"}]}],
        "generationConfig": {"maxOutputTokens": 5}
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(test_url, json=test_payload)
            if resp.status_code != 200:
                err_detail = "Invalid API Key"
                try:
                    err_json = resp.json()
                    err_detail = err_json.get("error", {}).get("message", resp.text)
                except Exception:
                    pass
                raise HTTPException(status_code=400, detail=f"Gemini API authentication failed: {err_detail}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Network error testing Gemini API: {str(e)}")

    GLOBAL_CONFIG["gemini_api_key"] = new_key
    os.environ["GEMINI_API_KEY"] = new_key
    try:
        GEMINI_KEY_FILE.write_text(new_key, encoding="utf-8")
    except Exception as e:
        logger.warning(f"Could not persist gemini key file: {e}")

    logger.info("Global Gemini API Key successfully configured and activated.")
    return {
        "success": True,
        "message": "Gemini API key verified and activated for live audio monitoring!",
        "configured": True,
        "maskedKey": f"{new_key[:6]}...{new_key[-4:]}",
    }


@app.post("/api/ai/verify-audio-explanation")
async def verify_audio_explanation(payload: Dict[str, Any]):
    """
    Multimodal Gemini AI evaluation of background audio and candidate explanation.
    Evaluates whether recorded noise is benign (waiving warning) or suspicious (upholding strike).
    """
    session_id = payload.get("sessionId", "default")
    candidate_id = payload.get("candidateId", "unknown")
    explanation = (payload.get("explanation") or "").strip()
    audio_base64 = payload.get("audioBase64") or ""
    mime_type = payload.get("mimeType", "audio/webm")
    noise_level = payload.get("noiseLevel", 45)

    api_key = GLOBAL_CONFIG.get("gemini_api_key") or os.environ.get("GEMINI_API_KEY", "")

    if not api_key:
        return {
            "verdict": "PENDING_PROCTOR_REVIEW",
            "confidence": 0.5,
            "soundClassification": "Awaiting Human Proctor Review",
            "transcription": "[Gemini API key not configured yet]",
            "analysis": "No global Gemini API key is configured. Explanation recorded and forwarded to proctor console.",
            "candidateFeedback": "Your explanation has been recorded. Live proctor has been notified for manual review.",
            "waiveStrike": False,
            "apiKeyMissing": True,
        }

    # Strip data URI prefix if present
    if "," in audio_base64:
        audio_base64 = audio_base64.split(",", 1)[1]

    prompt = (
        f"You are ProctorGuard AI Audio Auditor analyzing background sound during an examination.\n"
        f"The candidate's microphone captured an acoustic spike of {noise_level} dB.\n"
        f"The candidate submitted the following explanation:\n"
        f"\"{explanation}\"\n\n"
        f"Listen to the attached audio clip recorded during this sound event:\n"
        f"1. Transcribe any audible human speech or identify non-speech acoustic patterns (e.g. coughing, throat clearing, paper shuffling, chair dragging, door knock, keyboard typing, human whisper, someone reading questions/answers, secondary voice speaking).\n"
        f"2. Evaluate whether the candidate's explanation is truthful, plausible, and consistent with the sound.\n"
        f"3. Decide whether to ACCEPT the explanation (benign, inadvertent sound, no evidence of cheating) or REJECT it (indicates cheating, prompting, answers being read, or fraudulent explanation).\n\n"
        f"Respond ONLY with a valid JSON object matching this schema:\n"
        f"{{\n"
        f"  \"verdict\": \"ACCEPTED\" | \"REJECTED\",\n"
        f"  \"confidence\": 0.0 to 1.0,\n"
        f"  \"soundClassification\": \"Concise description of the sound source\",\n"
        f"  \"transcription\": \"transcribed words if any, or [No speech detected]\",\n"
        f"  \"analysis\": \"1-2 sentences reasoning explaining why explanation matches or contradicts audio\",\n"
        f"  \"candidateFeedback\": \"Friendly explanation directly to student\",\n"
        f"  \"waiveStrike\": true | false\n"
        f"}}"
    )

    parts: List[Dict[str, Any]] = [{"text": prompt}]
    if audio_base64:
        clean_mime = mime_type.split(";")[0].strip() or "audio/webm"
        parts.append({
            "inlineData": {
                "mimeType": clean_mime,
                "data": audio_base64,
            }
        })

    body = {
        "contents": [{"parts": parts}],
        "generationConfig": {
            "temperature": 0.2,
            "responseMimeType": "application/json"
        }
    }

    models_to_try = ["gemini-3.8-flash", "gemini-2.0-flash", "gemini-1.5-flash"]
    eval_result = None
    last_err = ""

    try:
        async with httpx.AsyncClient(timeout=25.0) as client:
            for model_name in models_to_try:
                gemini_url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"
                try:
                    resp = await client.post(gemini_url, json=body)
                    if resp.status_code == 200:
                        res_json = resp.json()
                        raw_text = res_json["candidates"][0]["content"]["parts"][0]["text"]
                        eval_result = json.loads(raw_text)
                        logger.info(f"Gemini evaluation succeeded using {model_name}")
                        break
                    else:
                        last_err = f"{resp.status_code}: {resp.text}"
                        logger.warning(f"Gemini {model_name} returned {resp.status_code}, trying fallback...")
                except Exception as e:
                    last_err = str(e)
                    logger.warning(f"Gemini {model_name} connection error: {e}")

            if not eval_result:
                logger.error(f"All Gemini models exhausted. Last error: {last_err}")
                return {
                    "verdict": "PENDING_PROCTOR_REVIEW",
                    "confidence": 0.5,
                    "soundClassification": "Upstream Gemini error",
                    "transcription": "[API Error]",
                    "analysis": f"Gemini temporary error: {last_err}",
                    "candidateFeedback": "AI audio verification temporarily busy. Your explanation was logged for manual review.",
                    "waiveStrike": False,
                }

            # Broadcast AI verdict live to connected Admin Dashboards
            await signaling.broadcast_to_admins(session_id, {
                "type": "ai_audio_verdict",
                "sessionId": session_id,
                "candidateId": candidate_id,
                "verdict": eval_result.get("verdict"),
                "confidence": eval_result.get("confidence"),
                "soundClassification": eval_result.get("soundClassification"),
                "transcription": eval_result.get("transcription"),
                "explanation": explanation,
                "analysis": eval_result.get("analysis"),
                "waiveStrike": eval_result.get("waiveStrike", False),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

            return eval_result

    except Exception as e:
        logger.error(f"Failed calling Gemini audio analysis: {e}", exc_info=True)
        return {
            "verdict": "PENDING_PROCTOR_REVIEW",
            "confidence": 0.5,
            "soundClassification": "Processing error",
            "transcription": "[Error]",
            "analysis": f"Error: {str(e)}",
            "candidateFeedback": "Unable to complete AI review. Forwarded to proctor.",
            "waiveStrike": False,
        }




# ============================================================================
# WebSocket Endpoints
# ============================================================================

@app.websocket("/ws/candidate/{session_id}/{candidate_id}")
async def candidate_websocket_endpoint(
    websocket: WebSocket,
    session_id: str,
    candidate_id: str,
):
    """
    WebSocket endpoint for candidate telemetry, incidents, and WebRTC signaling.
    """
    await websocket.accept()
    # Upsert candidate into persistence
    db.upsert_candidate(session_id, candidate_id, status="ACTIVE")
    await signaling.register_candidate(session_id, candidate_id, websocket)

    # Send initial welcome / status sync
    cand = db.get_candidate(session_id, candidate_id)
    await websocket.send_text(json.dumps({
        "type": "sync_status",
        "sessionId": session_id,
        "candidateId": candidate_id,
        "status": cand.get("status", "ACTIVE") if cand else "ACTIVE",
        "riskScore": cand.get("riskScore", 0) if cand else 0,
        "warningCount": cand.get("highWarningCount", 0) if cand else 0,
        "warningLimit": scoring_engine.max_warning_limit,
    }))

    try:
        while True:
            raw_msg = await websocket.receive_text()
            try:
                data = json.loads(raw_msg)
            except json.JSONDecodeError:
                logger.warning(f"Invalid JSON received from candidate {candidate_id}")
                continue

            msg_type = data.get("type")

            # 1. Heartbeat
            if msg_type == "ping":
                await websocket.send_text(json.dumps({
                    "type": "pong",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }))
                continue

            # 2. WebRTC signaling relay (offer, answer, ice-candidate, stream_status)
            if msg_type in ("offer", "answer", "ice-candidate", "stream_status"):
                await signaling.route_candidate_signaling(session_id, candidate_id, data)
                continue

            # 3. Incident Event ingestion
            # Format can be { "type": "incident", "data": { ... } } or direct PRD event schema
            incident_data = data.get("data") if msg_type == "incident" else data
            if isinstance(incident_data, dict) and (
                "eventType" in incident_data or "event_type" in incident_data
            ):
                try:
                    # Fill default session_id and candidate_id if missing
                    incident_data.setdefault("sessionId", session_id)
                    incident_data.setdefault("candidateId", candidate_id)
                    incident_data.setdefault("timestamp", datetime.now(timezone.utc).isoformat())

                    event = IncidentEvent.model_validate(incident_data)
                    await process_incoming_incident(event, source_channel="candidate")
                except Exception as e:
                    logger.error(f"Error processing candidate incident: {e}", exc_info=True)
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": f"Malformed incident schema: {str(e)}",
                    }))

    except WebSocketDisconnect:
        logger.info(f"Candidate disconnected: {candidate_id} from {session_id}")
    except Exception as e:
        logger.warning(f"Candidate ws error: {e}")
    finally:
        await signaling.unregister_candidate(session_id, candidate_id)
        # Update last seen / mark disconnected unless locked/terminated
        cand = db.get_candidate(session_id, candidate_id)
        if cand and cand.get("status") not in ("LOCKED", "TERMINATED"):
            db.update_candidate_status(session_id, candidate_id, status="DISCONNECTED")


@app.websocket("/ws/admin/{session_id}")
async def admin_websocket_endpoint(websocket: WebSocket, session_id: str):
    """
    WebSocket endpoint for live proctor dashboard with broadcast channel.
    """
    await websocket.accept()
    await signaling.register_admin(session_id, websocket)

    # Send initial full state snapshot to proctor
    session = db.get_session(session_id) or {"sessionId": session_id, "name": f"Session {session_id}"}
    candidates = db.list_candidates(session_id)
    recent_incidents = db.get_incidents(session_id=session_id, limit=50)

    await websocket.send_text(json.dumps({
        "type": "session_snapshot",
        "sessionId": session_id,
        "session": session,
        "candidates": candidates,
        "incidents": recent_incidents,
        "serverTime": datetime.now(timezone.utc).isoformat(),
    }))

    try:
        while True:
            raw_msg = await websocket.receive_text()
            try:
                data = json.loads(raw_msg)
            except json.JSONDecodeError:
                continue

            msg_type = data.get("type")

            # 1. Heartbeat
            if msg_type == "ping":
                await websocket.send_text(json.dumps({
                    "type": "pong",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }))
                continue

            # 2. WebRTC signaling relay to specific candidate
            if msg_type in ("offer", "answer", "ice-candidate"):
                target = data.get("target") or data.get("candidateId")
                if target:
                    await signaling.route_admin_signaling(session_id, target, data)
                continue

            # 3. Proctor command dispatched from dashboard
            if msg_type == "command":
                target_candidate = data.get("target") or data.get("candidateId")
                action = (data.get("action") or "").upper()
                reason = data.get("reason")
                msg = data.get("message")

                if target_candidate and action:
                    if action == "TERMINATE":
                        db.update_candidate_status(session_id, target_candidate, status="TERMINATED", lock_reason=reason)
                        scoring_engine.terminate_candidate(session_id, target_candidate)
                    elif action == "LOCK":
                        db.update_candidate_status(session_id, target_candidate, status="LOCKED", lock_reason=reason)
                        scoring_engine.lock_candidate(session_id, target_candidate, reason=reason or "Admin lock")
                    elif action == "UNLOCK":
                        db.update_candidate_status(session_id, target_candidate, status="ACTIVE", lock_reason=None)
                        scoring_engine.unlock_candidate(session_id, target_candidate)

                    await signaling.broadcast_candidate_command(
                        session_id=session_id,
                        candidate_id=target_candidate,
                        action=action,
                        reason=reason,
                        message=msg,
                    )
                continue

            # 4. State snapshot refresh request
            if msg_type == "refresh":
                refreshed_candidates = db.list_candidates(session_id)
                refreshed_incidents = db.get_incidents(session_id=session_id, limit=50)
                await websocket.send_text(json.dumps({
                    "type": "session_snapshot",
                    "sessionId": session_id,
                    "session": db.get_session(session_id),
                    "candidates": refreshed_candidates,
                    "incidents": refreshed_incidents,
                }))

    except WebSocketDisconnect:
        logger.info(f"Admin disconnected from session {session_id}")
    except Exception as e:
        logger.warning(f"Admin ws error: {e}")
    finally:
        await signaling.unregister_admin(session_id, websocket)


@app.websocket("/ws/companion/{session_id}/{candidate_id}")
async def companion_websocket_endpoint(
    websocket: WebSocket,
    session_id: str,
    candidate_id: str,
):
    """
    WebSocket endpoint for native host companion agent (desktop monitor agent).
    Receives OS-level security telemetry (processes, DLLs, secondary displays, etc.)
    """
    await websocket.accept()
    await signaling.register_companion(session_id, candidate_id, websocket)

    # Initial handshake
    await websocket.send_text(json.dumps({
        "type": "companion_handshake_ack",
        "sessionId": session_id,
        "candidateId": candidate_id,
        "status": "READY",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }))

    try:
        while True:
            raw_msg = await websocket.receive_text()
            try:
                data = json.loads(raw_msg)
            except json.JSONDecodeError:
                continue

            msg_type = data.get("type")

            if msg_type == "ping":
                await websocket.send_text(json.dumps({
                    "type": "pong",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }))
                continue

            # Companion sending telemetry incident (e.g. PROCESS_BLACKLIST_HIT, INJECTED_DLL_DETECTED)
            incident_data = data.get("data") if msg_type == "incident" else data
            if isinstance(incident_data, dict) and (
                "eventType" in incident_data or "event_type" in incident_data
            ):
                try:
                    incident_data.setdefault("sessionId", session_id)
                    incident_data.setdefault("candidateId", candidate_id)
                    incident_data.setdefault("timestamp", datetime.now(timezone.utc).isoformat())

                    event = IncidentEvent.model_validate(incident_data)
                    await process_incoming_incident(event, source_channel="companion")
                except Exception as e:
                    logger.error(f"Error processing companion incident: {e}", exc_info=True)

    except WebSocketDisconnect:
        logger.info(f"Companion disconnected: {candidate_id} from {session_id}")
    except Exception as e:
        logger.warning(f"Companion ws error: {e}")
    finally:
        await signaling.unregister_companion(session_id, candidate_id)


# ============================================================================
# Static Files & UI Serving
# ============================================================================

# Mount static web-ui directory at /app
if not WEB_UI_DIR.exists():
    WEB_UI_DIR.mkdir(parents=True, exist_ok=True)

app.mount("/app", StaticFiles(directory=str(WEB_UI_DIR), html=True), name="static")


@app.get("/")
async def root():
    return RedirectResponse(url="/app/")


@app.get("/index.html")
async def index_html():
    return RedirectResponse(url="/app/index.html")


@app.get("/candidate")
@app.get("/candidate/")
async def candidate_root():
    return RedirectResponse(url="/app/candidate/index.html")


@app.get("/exam")
@app.get("/exam/")
async def exam_root():
    return RedirectResponse(url="/app/candidate/exam.html")


@app.get("/admin")
@app.get("/admin/")
async def admin_root():
    return RedirectResponse(url="/app/admin/dashboard.html")


@app.get("/review")
@app.get("/review/")
async def review_root():
    return RedirectResponse(url="/app/admin/review.html")


@app.get("/simulator")
@app.get("/simulator/")
async def simulator_root():
    return RedirectResponse(url="/app/admin/simulator.html")


@app.get("/favicon.ico")
async def favicon():
    return HTMLResponse(content="", status_code=204)

