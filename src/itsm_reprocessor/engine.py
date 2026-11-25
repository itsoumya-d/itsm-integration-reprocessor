"""Idempotent ITSM workflow orchestration, auth verification, and DLQ reprocessing."""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, List, Tuple

from itsm_reprocessor.models import (
    AuditEvent,
    DeadLetterEntry,
    DispatchStatus,
    IntegrationEnvelope,
    Priority,
    RecordType,
)

RETRYABLE_STATUS_CODES = {401, 408, 429, 500, 502, 503, 504}
PRIORITY_MATRIX = {
    ("enterprise", "high"): (Priority.P1, 15),
    ("enterprise", "medium"): (Priority.P2, 60),
    ("enterprise", "low"): (Priority.P3, 240),
    ("department", "high"): (Priority.P2, 60),
    ("department", "medium"): (Priority.P3, 240),
    ("department", "low"): (Priority.P4, 480),
    ("user", "high"): (Priority.P3, 240),
    ("user", "medium"): (Priority.P4, 480),
    ("user", "low"): (Priority.P4, 1440),
}


@dataclass
class DispatchResult:
    correlation_id: str
    status: DispatchStatus
    priority: Priority
    assignment_group: str
    sla_minutes: int
    message: str


def verify_hmac_signature(secret: str, payload_bytes: bytes, signature_hex: str) -> bool:
    """Validate inbound webhook HMAC-SHA256 signatures in constant time."""
    expected = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_hex.strip().lower())


def triage_request(envelope: IntegrationEnvelope) -> Tuple[Priority, str, int]:
    """Assign ITSM priority, SLA target, and assignment group from operational context."""
    priority, sla_minutes = PRIORITY_MATRIX.get(
        (envelope.impact.lower(), envelope.urgency.lower()), (Priority.P3, 240)
    )
    text = f"{envelope.summary} {envelope.source_system}".lower()
    if any(k in text for k in ("sso", "mfa", "access", "password", "identity", "entra")):
        group = "IAM-Operations"
    elif any(k in text for k in ("api", "webhook", "sync", "erp", "workato", "connector")):
        group = "Platform-Integrations"
    elif any(k in text for k in ("firewall", "vpn", "dns", "network", "outage")):
        group = "Cloud-Infrastructure"
    else:
        group = "Service-Desk-Tier2"
    return priority, group, sla_minutes


class IntegrationOrchestrator:
    """Coordinates idempotent ITSM delivery, approval gates, and DLQ reprocessing."""

    def __init__(self, base_backoff_seconds: int = 30, max_attempts: int = 5) -> None:
        self.base_backoff_seconds = base_backoff_seconds
        self.max_attempts = max_attempts
        self.delivered: Dict[str, DispatchResult] = {}
        self.pending_approvals: Dict[str, IntegrationEnvelope] = {}
        self.dlq: Dict[str, DeadLetterEntry] = {}
        self.audit_log: List[AuditEvent] = []

    def _audit(self, correlation_id: str, action: str, status: str, detail: str) -> None:
        self.audit_log.append(AuditEvent(correlation_id, action, status, detail))

    def _backoff_delta(self, attempts: int) -> timedelta:
        seconds = min(3600, self.base_backoff_seconds * (2 ** max(0, attempts - 1)))
        return timedelta(seconds=seconds)

    def dispatch(
        self,
        envelope: IntegrationEnvelope,
        deliver_fn: Callable[[IntegrationEnvelope, Priority, str], Tuple[int, str]],
        now: datetime | None = None,
    ) -> DispatchResult:
        now = now or datetime.now(timezone.utc)
        cid = envelope.correlation_id

        if cid in self.delivered:
            prev = self.delivered[cid]
            self._audit(cid, "dispatch", "DEDUPLICATED", "Duplicate correlation_id suppressed")
            return DispatchResult(
                cid, DispatchStatus.DEDUPLICATED, prev.priority, prev.assignment_group, prev.sla_minutes, "Already delivered"
            )

        priority, group, sla = triage_request(envelope)

        if envelope.record_type == RecordType.CHANGE_REQUEST and priority in (Priority.P1, Priority.P2) and not envelope.approved_by:
            self.pending_approvals[cid] = envelope
            self._audit(cid, "approval_gate", "PENDING_APPROVAL", f"{priority.value} change requires human approver")
            return DispatchResult(cid, DispatchStatus.PENDING_APPROVAL, priority, group, sla, "Awaiting change approval")

        if envelope.auth_token_expires_at and envelope.auth_token_expires_at <= now:
            code, msg = 401, "Auth token expired prior to dispatch"
        else:
            code, msg = deliver_fn(envelope, priority, group)

        if 200 <= code < 300:
            res = DispatchResult(cid, DispatchStatus.DELIVERED, priority, group, sla, msg)
            self.delivered[cid] = res
            self.pending_approvals.pop(cid, None)
            self.dlq.pop(cid, None)
            self._audit(cid, "dispatch", "DELIVERED", f"Delivered to {group}: {msg}")
            return res

        retryable = code in RETRYABLE_STATUS_CODES
        entry = self.dlq.get(cid)
        attempts = (entry.attempts + 1) if entry else 1
        history = (entry.history if entry else []) + [f"attempt={attempts} code={code} msg={msg}"]

        if not retryable or attempts >= self.max_attempts:
            self.dlq[cid] = DeadLetterEntry(envelope, attempts, code, msg, now, retryable=False, history=history)
            self._audit(cid, "dlq_park", "DEAD_LETTER_PERMANENT", f"Code {code}: {msg}")
            return DispatchResult(cid, DispatchStatus.DEAD_LETTER_PERMANENT, priority, group, sla, msg)

        next_retry = now + self._backoff_delta(attempts)
        self.dlq[cid] = DeadLetterEntry(envelope, attempts, code, msg, next_retry, retryable=True, history=history)
        self._audit(cid, "dlq_queue", "QUEUED_DLQ", f"Attempt {attempts} failed ({code}); retry at {next_retry.isoformat()}")
        return DispatchResult(cid, DispatchStatus.QUEUED_DLQ, priority, group, sla, msg)

    def approve_and_dispatch(
        self,
        correlation_id: str,
        approver: str,
        deliver_fn: Callable[[IntegrationEnvelope, Priority, str], Tuple[int, str]],
        now: datetime | None = None,
    ) -> DispatchResult:
        env = self.pending_approvals.get(correlation_id)
        if not env:
            raise KeyError(f"No pending approval found for {correlation_id}")
        env.approved_by = approver
        self._audit(correlation_id, "approved", "APPROVED", f"Approved by {approver}")
        return self.dispatch(env, deliver_fn, now=now)

    def reprocess_dlq(
        self,
        deliver_fn: Callable[[IntegrationEnvelope, Priority, str], Tuple[int, str]],
        now: datetime | None = None,
        token_refresher: Callable[[IntegrationEnvelope, datetime], datetime] | None = None,
    ) -> Dict[str, int]:
        now = now or datetime.now(timezone.utc)
        stats = {"checked": 0, "recovered": 0, "requeued": 0, "permanent_failed": 0}
        for cid in list(self.dlq.keys()):
            entry = self.dlq[cid]
            if not entry.retryable or entry.next_retry_at > now:
                continue
            stats["checked"] += 1
            if entry.last_error_code == 401 and token_refresher is not None:
                entry.envelope.auth_token_expires_at = token_refresher(entry.envelope, now)
                self._audit(cid, "token_refresh", "REFRESHED", "Refreshed auth token before replay")
            res = self.dispatch(entry.envelope, deliver_fn, now=now)
            if res.status == DispatchStatus.DELIVERED:
                stats["recovered"] += 1
            elif res.status == DispatchStatus.QUEUED_DLQ:
                stats["requeued"] += 1
            else:
                stats["permanent_failed"] += 1
        return stats
