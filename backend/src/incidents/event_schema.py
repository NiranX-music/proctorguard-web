from __future__ import annotations

from enum import Enum
from typing import Any, Dict, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, ConfigDict, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class EventType(str, Enum):
    # CRITICAL
    PROCESS_BLACKLIST_HIT = "PROCESS_BLACKLIST_HIT"
    INJECTED_DLL_DETECTED = "INJECTED_DLL_DETECTED"
    MULTIPLE_DISPLAYS_DETECTED = "MULTIPLE_DISPLAYS_DETECTED"
    DISPLAY_TOPOLOGY_CHANGED = "DISPLAY_TOPOLOGY_CHANGED"
    VIRTUAL_CAMERA_DETECTED = "VIRTUAL_CAMERA_DETECTED"

    # HIGH
    TAB_BLUR = "TAB_BLUR"
    FULLSCREEN_EXIT = "FULLSCREEN_EXIT"
    ZERO_FACE_DETECTED = "ZERO_FACE_DETECTED"
    MULTIPLE_FACES_DETECTED = "MULTIPLE_FACES_DETECTED"
    HEAD_POSE_AWAY = "HEAD_POSE_AWAY"

    # MEDIUM
    SUSPICIOUS_AUDIO_LEVEL = "SUSPICIOUS_AUDIO_LEVEL"

    # LOW
    CLIPBOARD_VIOLATION = "CLIPBOARD_VIOLATION"
    CONTEXT_MENU_ATTEMPT = "CONTEXT_MENU_ATTEMPT"


class IncidentEvent(BaseModel):
    """
    Exact PRD Event Schema:
    {
      "sessionId": str,
      "candidateId": str,
      "timestamp": str,
      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
      "eventType": str,
      "metadata": dict,
      "snapshotFrame": Optional[str]
    }
    """
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    session_id: str = Field(..., alias="sessionId")
    candidate_id: str = Field(..., alias="candidateId")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        alias="timestamp"
    )
    severity: Severity = Field(..., alias="severity")
    event_type: str = Field(..., alias="eventType")
    metadata: Dict[str, Any] = Field(default_factory=dict, alias="metadata")
    snapshot_frame: Optional[str] = Field(None, alias="snapshotFrame")

    def to_prd_dict(self) -> Dict[str, Any]:
        """Return the dictionary formatted with exact PRD keys."""
        return {
            "sessionId": self.session_id,
            "candidateId": self.candidate_id,
            "timestamp": self.timestamp,
            "severity": self.severity.value if isinstance(self.severity, Severity) else str(self.severity),
            "eventType": self.event_type,
            "metadata": self.metadata,
            "snapshotFrame": self.snapshot_frame,
        }


class SessionCreateRequest(BaseModel):
    session_id: Optional[str] = Field(None, alias="sessionId")
    name: str = "Examination Session"
    config: Optional[Dict[str, Any]] = Field(default_factory=dict)

    model_config = ConfigDict(populate_by_name=True)


class CandidateStatusRequest(BaseModel):
    reason: Optional[str] = None
    message: Optional[str] = None


class CandidateWarningRequest(BaseModel):
    message: str = "Warning: Examination integrity policy violation detected."
    reason: Optional[str] = "Proctor Warning"


class WebRTCSignalingMessage(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    type: str  # offer, answer, ice-candidate, join, leave, stream_status
    sender: Optional[str] = None
    target: Optional[str] = None
    sdp: Optional[str] = None
    candidate: Optional[Any] = None
    stream_type: Optional[str] = Field("webcam", alias="streamType")
    metadata: Optional[Dict[str, Any]] = None
