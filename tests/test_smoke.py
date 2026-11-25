from itsm_reprocessor.models import IntegrationEnvelope, Priority, RecordType


def test_envelope_construction():
    env = IntegrationEnvelope(
        correlation_id="corr-001",
        source_system="chat-portal",
        target_system="servicenow-itsm",
        record_type=RecordType.INCIDENT,
        summary="SSO login failure",
        impact="enterprise",
        urgency="high",
    )
    assert env.correlation_id == "corr-001"
    assert env.record_type == RecordType.INCIDENT
    assert Priority.P1.value == "P1"
