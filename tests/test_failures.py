from attachment_scanning.attachment_scanning import scan_attachments
from schemas.email import EmailRequest
from decision_engine.orchestrator import analyze_email


def test_attachments_fail_closed_when_scanner_missing():
    result = scan_attachments([{"filename": "report.pdf"}])
    assert result["completed"] is False
    assert result["safe"] is False
    assert result["findings"][0]["code"] == "ATTACHMENT_SCAN_UNAVAILABLE"


def test_attachments_no_files_need_no_scanner():
    result = scan_attachments([])
    assert result == {
        "completed": True,
        "safe": True,
        "findings": [],
        "status": "not_applicable_no_attachments",
    }


def test_normal_email_can_be_safe_when_required_baseline_checks_complete(monkeypatch):
    # The optional ML model may be absent; the baseline runtime checks still execute.
    monkeypatch.setattr("decision_engine.orchestrator.classify_email", lambda *_: {
        "available": False, "completed": False, "finding": None, "reason": "test"})
    request = EmailRequest(subject="Meeting", html="<p>See you at 10.</p>",
                           recipients=["user@example.com"], attachments=[])
    result = analyze_email(request)
    assert result.status == "SAFE"
    assert result.can_send is True


def test_suspicious_email_is_restricted(monkeypatch):
    monkeypatch.setattr("decision_engine.orchestrator.classify_email", lambda *_: {
        "available": False, "completed": False, "finding": None, "reason": "test"})
    request = EmailRequest(subject="Congratulations", html="<p>Claim your lottery prize</p>",
                           recipients=["user@example.com"], attachments=[])
    result = analyze_email(request)
    assert result.status == "RESTRICTED"
    assert result.can_send is False
    assert "LOTTERY_SCAM" in result.patterns_detected


def test_invalid_recipient_rejected():
    try:
        EmailRequest(subject="Hi", html="<p>Hi</p>", recipients=["not-an-email"])
    except Exception:
        return
    assert False, "Invalid recipient should be rejected"


def test_required_ml_unavailability_fails_closed(monkeypatch):
    from common.config import settings

    monkeypatch.setattr(settings, "REQUIRE_ML", True)
    monkeypatch.setattr("decision_engine.orchestrator.classify_email", lambda *_: {
        "available": False, "completed": False, "finding": None, "reason": "model missing"})
    request = EmailRequest(subject="Meeting", html="<p>See you at 10.</p>",
                           recipients=["user@example.com"], attachments=[])
    result = analyze_email(request)

    assert result.status == "RESTRICTED"
    assert result.can_send is False
    assert "ML_INSPECTION_INCOMPLETE" in result.patterns_detected
