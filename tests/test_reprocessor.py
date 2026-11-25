from datetime import datetime, timedelta, timezone
import hashlib
import hmac

from itsm_reprocessor.engine import IntegrationOrchestrator, verify_hmac_signature
from itsm_reprocessor.models import DispatchStatus, IntegrationEnvelope, Priority, RecordType


def _make_env(cid: str = "corr-100", rtype: RecordType = RecordType.INCIDENT, **kw) -> IntegrationEnvelope:
    defaults = dict(
        correlation_id=cid,
        source_system="chat-assistant",
        target_system="itsm-core",
        record_type=rtype,
        summary="Enterprise SSO token failure",
        impact="enterprise",
        urgency="high",
    )
    defaults.update(kw)
    return IntegrationEnvelope(**defaults)


def test_hmac_verification_and_idempotent_delivery():
    secret = "whsec-test-key"
    body = b'{"correlation_id":"corr-100"}'
    sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert verify_hmac_signature(secret, body, sig) is True
    assert verify_hmac_signature(secret, body, "deadbeef") is False

    orch = IntegrationOrchestrator()
    calls = 0

    def ok_deliver(env, prio, group):
        nonlocal calls
        calls += 1
        assert prio == Priority.P1
        assert group == "IAM-Operations"
        return 201, "INC0042"

    env = _make_env()
    first = orch.dispatch(env, ok_deliver)
    second = orch.dispatch(env, ok_deliver)

    assert first.status == DispatchStatus.DELIVERED
    assert second.status == DispatchStatus.DEDUPLICATED
    assert calls == 1


def test_dlq_auth_expiry_recovery_and_backoff():
    now = datetime(2026, 11, 25, 1, 0, tzinfo=timezone.utc)
    orch = IntegrationOrchestrator(base_backoff_seconds=30, max_attempts=4)
    env = _make_env(
        cid="corr-auth-1",
        summary="Workato API sync rate limited",
        impact="department",
        urgency="high",
        auth_token_expires_at=now - timedelta(minutes=5),
    )

    res1 = orch.dispatch(env, lambda e, p, g: (200, "REQ1"), now=now)
    assert res1.status == DispatchStatus.QUEUED_DLQ
    assert "corr-auth-1" in orch.dlq
    assert orch.dlq["corr-auth-1"].last_error_code == 401

    # Too early: respects exponential backoff
    early = orch.reprocess_dlq(lambda e, p, g: (200, "REQ1"), now=now + timedelta(seconds=10))
    assert early["checked"] == 0

    # At +30s with token refresher: recovers cleanly
    recovered = orch.reprocess_dlq(
        lambda e, p, g: (200, "REQ1"),
        now=now + timedelta(seconds=30),
        token_refresher=lambda e, t: t + timedelta(hours=1),
    )
    assert recovered == {"checked": 1, "recovered": 1, "requeued": 0, "permanent_failed": 0}
    assert "corr-auth-1" in orch.delivered
    assert "corr-auth-1" not in orch.dlq


def test_change_request_human_approval_gate():
    orch = IntegrationOrchestrator()
    env = _make_env(
        cid="chg-99",
        rtype=RecordType.CHANGE_REQUEST,
        summary="Production firewall rule deployment",
        impact="enterprise",
        urgency="medium",
    )
    gated = orch.dispatch(env, lambda e, p, g: (200, "CHG0099"))
    assert gated.status == DispatchStatus.PENDING_APPROVAL

    approved = orch.approve_and_dispatch("chg-99", "release-lead@example.org", lambda e, p, g: (200, "CHG0099"))
    assert approved.status == DispatchStatus.DELIVERED
    assert approved.assignment_group == "Cloud-Infrastructure"


def test_permanent_validation_failure_parks_without_retry():
    orch = IntegrationOrchestrator()
    env = _make_env(cid="bad-422")
    res = orch.dispatch(env, lambda e, p, g: (422, "Invalid CMDB sys_id"))
    assert res.status == DispatchStatus.DEAD_LETTER_PERMANENT
    assert orch.dlq["bad-422"].retryable is False
