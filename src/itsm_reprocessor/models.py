"""Core domain models for ITSM integration routing and reprocessing."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List


class RecordType(str, Enum):
    INCIDENT = "INCIDENT"
    SERVICE_REQUEST = "SERVICE_REQUEST"
    CHANGE_REQUEST = "CHANGE_REQUEST"


class Priority(str, Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class DispatchStatus(str, Enum):
    DELIVERED = "DELIVERED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    QUEUED_DLQ = "QUEUED_DLQ"
    DEAD_LETTER_PERMANENT = "DEAD_LETTER_PERMANENT"
    DEDUPLICATED = "DEDUPLICATED"


@dataclass
class IntegrationEnvelope:
    correlation_id: str
    source_system: str
    target_system: str
    record_type: RecordType
    summary: str
    impact: str  # enterprise | department | user
    urgency: str  # high | medium | low
    payload: Dict[str, Any] = field(default_factory=dict)
    auth_token_expires_at: datetime | None = None
    approved_by: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class AuditEvent:
    correlation_id: str
    action: str
    status: str
    detail: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class DeadLetterEntry:
    envelope: IntegrationEnvelope
    attempts: int
    last_error_code: int
    last_error_message: str
    next_retry_at: datetime
    retryable: bool = True
    history: List[str] = field(default_factory=list)
