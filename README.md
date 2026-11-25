# ITSM Integration Reprocessor

Reliable enterprise ITSM/ITOM/ITAM integration engine providing idempotent API orchestration, authentication guardrails, dead-letter queue (DLQ) reprocessing, and auditable workflow routing.

## Problem

Enterprise service management workflows frequently connect multiple systems (ticketing, identity, CMDB, chat, and ERP). API rate limits (`429`), expired credentials (`401`), and transient upstream errors (`5xx`) often leave requests stranded or trigger duplicate ticket creation on naive retries.

## Solution

- **Idempotent Integration Dispatch**: Deduplicates external correlation IDs across retries to guarantee at-most-once downstream record creation.
- **Auth & HMAC Verification**: Enforces token expiry and request integrity prior to dispatch.
- **Dead-Letter Queue & Reprocessing**: Captures retryable failures with exponential backoff scheduling and deterministic replay once credentials or upstreams recover.
- **Governance & Audit Trail**: Emits structured audit records and human-in-the-loop approval gates for high-impact ITOM changes.

## Run Locally

```bash
python3 -m pip install -e ".[dev]"
pytest
```
