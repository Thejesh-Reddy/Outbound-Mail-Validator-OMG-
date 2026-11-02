import pytest
from pydantic import ValidationError
from fastapi.testclient import TestClient

from app import app
from schemas.email import EmailRequest


def test_email_request_accepts_plain_text_body():
    request = EmailRequest(
        subject="Project update",
        body="Please review the attached project update.",
        recipients=["recipient@example.com"],
    )
    assert request.body == "Please review the attached project update."
    assert request.inspection_content == request.body


def test_email_request_keeps_legacy_html_support():
    request = EmailRequest(
        subject="Project update",
        html="<p>Please review the project update.</p>",
        recipients=["recipient@example.com"],
    )
    assert request.html.startswith("<p>")
    assert request.inspection_content == request.html


def test_email_request_combines_body_and_html_for_content_inspection():
    request = EmailRequest(
        subject="Project update",
        body="Plain text content",
        html="<p>HTML content</p>",
        recipients=["recipient@example.com"],
    )
    assert "Plain text content" in request.inspection_content
    assert "HTML content" in request.inspection_content


def test_email_request_rejects_missing_or_blank_body_and_html():
    with pytest.raises(ValidationError):
        EmailRequest(subject="No content", recipients=["recipient@example.com"])
    with pytest.raises(ValidationError):
        EmailRequest(subject="Blank content", body="  ", recipients=["recipient@example.com"])


def test_analyze_endpoint_accepts_body_field():
    client = TestClient(app)
    response = client.post(
        "/api/v1/analyze",
        json={
            "channel": "email",
            "subject": "Team meeting",
            "body": "The team meeting starts at 10 AM.",
            "recipients": ["recipient@example.com"],
            "attachments": [],
        },
    )
    # The request must reach analysis; the verdict may depend on local ML/scanner configuration.
    assert response.status_code == 200
    assert response.json()["status"] in {"SAFE", "WARNING", "RESTRICTED"}


def test_body_text_is_sent_through_text_inspection_pipeline():
    from decision_engine.orchestrator import analyze_email

    request = EmailRequest(
        subject="Congratulations",
        body="You have won a lottery prize. Claim your lottery prize now.",
        recipients=["recipient@example.com"],
    )
    result = analyze_email(request)
    assert "LOTTERY_SCAM" in result.patterns_detected
    assert result.status == "RESTRICTED"
