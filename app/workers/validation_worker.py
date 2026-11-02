"""Simple worker helper; Notify should call analyze_email before queue release."""
from app.pipeline.orchestrator import analyze_email
from app.schemas.email import EmailRequest


def validate_payload(payload: dict) -> dict:
    """Validate and inspect one payload; return a JSON-compatible verdict."""
    request = EmailRequest.model_validate(payload)
    return analyze_email(request).model_dump()
