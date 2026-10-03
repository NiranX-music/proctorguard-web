from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from src.incidents.event_schema import IncidentEvent, Severity, EventType


# Standard weights per event type according to specification
EVENT_WEIGHTS: Dict[str, int] = {
    # CRITICAL
    EventType.PROCESS_BLACKLIST_HIT.value: 50,
    EventType.INJECTED_DLL_DETECTED.value: 50,
    EventType.MULTIPLE_DISPLAYS_DETECTED.value: 40,
    EventType.DISPLAY_TOPOLOGY_CHANGED.value: 40,
    EventType.VIRTUAL_CAMERA_DETECTED.value: 35,

    # HIGH
    EventType.TAB_BLUR.value: 15,
    EventType.FULLSCREEN_EXIT.value: 15,
    EventType.ZERO_FACE_DETECTED.value: 20,
    EventType.MULTIPLE_FACES_DETECTED.value: 20,
    EventType.HEAD_POSE_AWAY.value: 15,

    # MEDIUM
    EventType.SUSPICIOUS_AUDIO_LEVEL.value: 10,

    # LOW
    EventType.CLIPBOARD_VIOLATION.value: 5,
    EventType.CONTEXT_MENU_ATTEMPT.value: 5,
}

# Fallback weights by severity if event_type is custom
SEVERITY_DEFAULT_WEIGHTS: Dict[str, int] = {
    Severity.CRITICAL.value: 35,
    Severity.HIGH.value: 15,
    Severity.MEDIUM.value: 10,
    Severity.LOW.value: 5,
}

# Standard auto actions according to specification
EVENT_AUTO_ACTIONS: Dict[str, str] = {
    EventType.PROCESS_BLACKLIST_HIT.value: "PROMPT_LOCK_AND_NOTIFY_ADMIN",
    EventType.INJECTED_DLL_DETECTED.value: "PROMPT_LOCK_AND_NOTIFY_ADMIN",
    EventType.MULTIPLE_DISPLAYS_DETECTED.value: "LOCK_EXAM_INTERFACE",
    EventType.DISPLAY_TOPOLOGY_CHANGED.value: "LOCK_EXAM_INTERFACE",
    EventType.VIRTUAL_CAMERA_DETECTED.value: "BLOCK_STREAM_STARTUP",
    EventType.TAB_BLUR.value: "WARN_CANDIDATE",
    EventType.FULLSCREEN_EXIT.value: "WARN_CANDIDATE",
    EventType.ZERO_FACE_DETECTED.value: "FLAG_FRAME_FOR_REVIEW",
    EventType.MULTIPLE_FACES_DETECTED.value: "FLAG_FRAME_FOR_REVIEW",
    EventType.HEAD_POSE_AWAY.value: "FLAG_FRAME_FOR_REVIEW",
    EventType.SUSPICIOUS_AUDIO_LEVEL.value: "MARK_TIMELINE_TIMESTAMP",
    EventType.CLIPBOARD_VIOLATION.value: "BLOCK_EVENT",
    EventType.CONTEXT_MENU_ATTEMPT.value: "BLOCK_EVENT",
}

WARNING_TRIGGER_EVENTS = {
    EventType.TAB_BLUR.value,
    EventType.FULLSCREEN_EXIT.value,
}

CRITICAL_LOCK_EVENTS = {
    EventType.PROCESS_BLACKLIST_HIT.value,
    EventType.INJECTED_DLL_DETECTED.value,
    EventType.MULTIPLE_DISPLAYS_DETECTED.value,
    EventType.DISPLAY_TOPOLOGY_CHANGED.value,
}

MAX_WARNING_LIMIT = 3


@dataclass
class ScoringEvaluation:
    risk_score: int
    weight: int
    auto_action: str
    should_lock: bool
    should_warn: bool
    should_block_event: bool
    warning_count: int
    high_warning_count: int
    max_warnings_exceeded: bool
    lock_reason: Optional[str]
    message: str
    event_counts: Dict[str, int]
    breakdown: Dict[str, Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "riskScore": self.risk_score,
            "weight": self.weight,
            "autoAction": self.auto_action,
            "shouldLock": self.should_lock,
            "shouldWarn": self.should_warn,
            "shouldBlockEvent": self.should_block_event,
            "warningCount": self.warning_count,
            "highWarningCount": self.high_warning_count,
            "maxWarningsExceeded": self.max_warnings_exceeded,
            "lockReason": self.lock_reason,
            "message": self.message,
            "eventCounts": self.event_counts,
            "breakdown": self.breakdown,
        }


@dataclass
class CandidateScoreState:
    session_id: str
    candidate_id: str
    event_counts: Dict[str, int] = field(default_factory=dict)
    warning_count: int = 0
    high_warning_count: int = 0
    is_locked: bool = False
    lock_reason: Optional[str] = None
    is_terminated: bool = False


class ScoringEngine:
    """
    Real-time Incident Scoring Engine implementing:
    Risk Score = min(100, sum(w_i * N_i))
    """

    def __init__(self, max_warning_limit: int = MAX_WARNING_LIMIT):
        self.max_warning_limit = max_warning_limit
        # In-memory candidate states keyed by (session_id, candidate_id)
        self._states: Dict[tuple[str, str], CandidateScoreState] = {}

    def get_or_create_state(self, session_id: str, candidate_id: str) -> CandidateScoreState:
        key = (session_id, candidate_id)
        if key not in self._states:
            self._states[key] = CandidateScoreState(
                session_id=session_id,
                candidate_id=candidate_id,
                event_counts={},
                warning_count=0,
                high_warning_count=0,
            )
        return self._states[key]

    def set_candidate_state(
        self,
        session_id: str,
        candidate_id: str,
        event_counts: Dict[str, int],
        warning_count: int = 0,
        high_warning_count: int = 0,
        is_locked: bool = False,
        lock_reason: Optional[str] = None,
    ) -> CandidateScoreState:
        key = (session_id, candidate_id)
        state = CandidateScoreState(
            session_id=session_id,
            candidate_id=candidate_id,
            event_counts=dict(event_counts),
            warning_count=warning_count,
            high_warning_count=high_warning_count,
            is_locked=is_locked,
            lock_reason=lock_reason,
        )
        self._states[key] = state
        return state

    @staticmethod
    def get_weight(event_type: str, severity: Optional[Severity | str] = None) -> int:
        if event_type in EVENT_WEIGHTS:
            return EVENT_WEIGHTS[event_type]
        if severity:
            sev_str = severity.value if isinstance(severity, Severity) else str(severity)
            return SEVERITY_DEFAULT_WEIGHTS.get(sev_str, 5)
        return 5

    @classmethod
    def calculate_score(cls, event_counts: Dict[str, int]) -> int:
        """
        Pure calculation of Risk Score = min(100, sum(w_i * N_i))
        """
        raw_score = sum(cls.get_weight(etype) * count for etype, count in event_counts.items())
        return min(100, max(0, raw_score))

    def evaluate_incident(self, incident: IncidentEvent) -> ScoringEvaluation:
        """
        Evaluates incoming incident event against current candidate state.
        Updates counters, recalculates score, and determines auto-actions.
        """
        state = self.get_or_create_state(incident.session_id, incident.candidate_id)
        event_type = incident.event_type
        weight = self.get_weight(event_type, incident.severity)

        # Update event occurrences N_i
        state.event_counts[event_type] = state.event_counts.get(event_type, 0) + 1

        # Calculate exact formula Risk Score = min(100, sum(w_i * N_i))
        raw_sum = 0
        breakdown: Dict[str, Dict[str, Any]] = {}
        for etype, count in state.event_counts.items():
            w = self.get_weight(etype)
            subtotal = w * count
            raw_sum += subtotal
            breakdown[etype] = {
                "weight": w,
                "count": count,
                "subtotal": subtotal,
            }

        risk_score = min(100, raw_sum)

        # Determine auto actions & warning tracking
        auto_action = EVENT_AUTO_ACTIONS.get(event_type, "FLAG_FOR_REVIEW")
        should_lock = False
        should_warn = False
        should_block_event = False
        max_warnings_exceeded = False
        lock_reason: Optional[str] = None
        message = f"Recorded {event_type} (weight {weight}). Current risk score: {risk_score}."

        # High warning events (e.g. TAB_BLUR, FULLSCREEN_EXIT)
        if event_type in WARNING_TRIGGER_EVENTS or (
            incident.severity in (Severity.HIGH, Severity.HIGH.value) and auto_action == "WARN_CANDIDATE"
        ):
            state.warning_count += 1
            state.high_warning_count += 1

            if state.high_warning_count > self.max_warning_limit:
                max_warnings_exceeded = True
                should_lock = True
                auto_action = "AUTO_LOCK"
                lock_reason = (
                    f"Exceeded maximum warning limit ({self.max_warning_limit} warnings reached) "
                    f"after {event_type}"
                )
                message = f"Candidate locked: exceeded {self.max_warning_limit} warnings limit."
            else:
                should_warn = True
                message = (
                    f"Warning {state.high_warning_count}/{self.max_warning_limit}: "
                    f"{event_type} detected. Please stay inside the exam interface."
                )

        # Critical lock triggers
        elif event_type in CRITICAL_LOCK_EVENTS or incident.severity in (Severity.CRITICAL, Severity.CRITICAL.value):
            if event_type in (EventType.PROCESS_BLACKLIST_HIT.value, EventType.INJECTED_DLL_DETECTED.value):
                should_lock = True
                auto_action = "PROMPT_LOCK_AND_NOTIFY_ADMIN"
                lock_reason = f"Critical security violation detected: {event_type}"
                message = f"Immediate exam lock triggered: {event_type} detected."
            elif event_type in (EventType.MULTIPLE_DISPLAYS_DETECTED.value, EventType.DISPLAY_TOPOLOGY_CHANGED.value):
                should_lock = True
                auto_action = "LOCK_EXAM_INTERFACE"
                lock_reason = f"Display configuration violation: {event_type}"
                message = f"Secondary monitor or display topology violation: exam locked."
            elif event_type == EventType.VIRTUAL_CAMERA_DETECTED.value:
                auto_action = "BLOCK_STREAM_STARTUP"
                message = "Virtual camera software detected. Video stream startup blocked."
            else:
                should_lock = True
                auto_action = "PROMPT_LOCK_AND_NOTIFY_ADMIN"
                lock_reason = f"Critical incident: {event_type}"

        # Visual flags
        elif event_type in (
            EventType.ZERO_FACE_DETECTED.value,
            EventType.MULTIPLE_FACES_DETECTED.value,
            EventType.HEAD_POSE_AWAY.value,
        ):
            auto_action = "FLAG_FRAME_FOR_REVIEW"
            message = f"Frame flagged for proctor review: {event_type}."

        # Audio threshold
        elif event_type == EventType.SUSPICIOUS_AUDIO_LEVEL.value:
            auto_action = "MARK_TIMELINE_TIMESTAMP"
            message = "Suspicious audio level (>3s) detected. Timeline marker recorded."

        # Low clipboard & context menu attempts
        elif event_type in (EventType.CLIPBOARD_VIOLATION.value, EventType.CONTEXT_MENU_ATTEMPT.value):
            should_block_event = True
            auto_action = "BLOCK_EVENT"
            message = f"Blocked forbidden user interaction: {event_type}."

        # Update state lock if triggered
        if should_lock:
            state.is_locked = True
            state.lock_reason = lock_reason

        return ScoringEvaluation(
            risk_score=risk_score,
            weight=weight,
            auto_action=auto_action,
            should_lock=should_lock,
            should_warn=should_warn,
            should_block_event=should_block_event,
            warning_count=state.warning_count,
            high_warning_count=state.high_warning_count,
            max_warnings_exceeded=max_warnings_exceeded,
            lock_reason=lock_reason or state.lock_reason,
            message=message,
            event_counts=dict(state.event_counts),
            breakdown=breakdown,
        )

    def manual_warn(self, session_id: str, candidate_id: str, custom_message: Optional[str] = None) -> Dict[str, Any]:
        state = self.get_or_create_state(session_id, candidate_id)
        state.warning_count += 1
        state.high_warning_count += 1

        exceeded = state.high_warning_count > self.max_warning_limit
        should_lock = False
        lock_reason = None
        if exceeded:
            should_lock = True
            state.is_locked = True
            lock_reason = f"Exceeded maximum warning limit ({self.max_warning_limit})"
            state.lock_reason = lock_reason

        return {
            "warningCount": state.warning_count,
            "highWarningCount": state.high_warning_count,
            "maxWarningsExceeded": exceeded,
            "shouldLock": should_lock,
            "lockReason": lock_reason,
            "message": custom_message or f"Proctor issued warning #{state.high_warning_count}.",
        }

    def unlock_candidate(self, session_id: str, candidate_id: str):
        state = self.get_or_create_state(session_id, candidate_id)
        state.is_locked = False
        state.lock_reason = None

    def lock_candidate(self, session_id: str, candidate_id: str, reason: str = "Locked by proctor"):
        state = self.get_or_create_state(session_id, candidate_id)
        state.is_locked = True
        state.lock_reason = reason

    def terminate_candidate(self, session_id: str, candidate_id: str):
        state = self.get_or_create_state(session_id, candidate_id)
        state.is_terminated = True
        state.is_locked = True
        state.lock_reason = "Terminated by proctor"

    def reset_candidate(self, session_id: str, candidate_id: str):
        key = f"{session_id}:{candidate_id}"
        if key in self._states:
            del self._states[key]

    def reset_session(self, session_id: str):
        prefix = f"{session_id}:"
        keys_to_delete = [k for k in self._states if k.startswith(prefix)]
        for k in keys_to_delete:
            del self._states[k]
