from fastapi.testclient import TestClient

from app.main import app
from app.core.config import settings


client = TestClient(app)
API_PREFIX = settings.API_PREFIX.rstrip("/")


def test_root_endpoint_returns_success():
    response = client.get("/")

    assert response.status_code == 200
    assert response.json()["message"] == "OMG API is running."


def test_health_endpoint_returns_success():
    response = client.get(f"{API_PREFIX}/health")

    assert response.status_code == 200


def test_analyze_endpoint_detects_invalid_hostname():
    payload = {
        "channel": "email",
        "subject": "Account notification",
        "html": (
            '<html><body>'
            '<a href="https://-invalid.example/login">'
            "Open account"
            "</a>"
            "</body></html>"
        ),
        "recipients": ["user@example.com"],
        "attachments": [],
    }

    response = client.post(
        f"{API_PREFIX}/analyze",
        json=payload,
    )

    assert response.status_code == 200

    result = response.json()

    assert result["status"] == "RESTRICTED"
    assert result["can_send"] is False
    assert "INVALID_HOSTNAME" in result["patterns_detected"]


def test_analyze_endpoint_detects_embedded_url_credentials():
    payload = {
        "channel": "email",
        "subject": "Account notification",
        "html": (
            '<html><body>'
            '<a href="https://trusted.example@evil.example/login">'
            "Open account"
            "</a>"
            "</body></html>"
        ),
        "recipients": ["user@example.com"],
        "attachments": [],
    }

    response = client.post(
        f"{API_PREFIX}/analyze",
        json=payload,
    )

    assert response.status_code == 200

    result = response.json()

    assert result["status"] == "RESTRICTED"
    assert result["can_send"] is False
    assert (
        "URL_CREDENTIALS_PRESENT"
        in result["patterns_detected"]
    )


def test_analyze_endpoint_rejects_invalid_request():
    payload = {
        "channel": "invalid",
        "subject": "Test",
        "html": "<p>Hello</p>",
        "recipients": ["user@example.com"],
        "attachments": [],
    }

    response = client.post(
        f"{API_PREFIX}/analyze",
        json=payload,
    )

    assert response.status_code == 422


def test_clean_email_can_pass_baseline_inspections():
    payload = {
        "channel": "email",
        "subject": "Normal test message",
        "html": "<p>Hello, this is a test.</p>",
        "recipients": ["user@example.com"],
        "attachments": [],
    }

    response = client.post(
        f"{API_PREFIX}/analyze",
        json=payload,
    )

    assert response.status_code == 200

    result = response.json()

    assert result["status"] == "SAFE"
    assert result["can_send"] is True
    assert result["inspection_coverage"]["mandatory_inspections"] == "complete"

def test_readiness_endpoint_returns_component_status():
    response = client.get(f"{API_PREFIX}/ready")

    assert response.status_code == 200
    result = response.json()
    assert result["ready"] is True
    assert result["checks"]["runtime_rules"] == "ready"
    assert result["checks"]["attachment_scanner"] == (
        "unavailable_fail_closed_for_attachments" if not __import__("app.checks.attachment_scanning", fromlist=["configured_scanner"]).configured_scanner() else "clamav_configured"
    )


def test_response_includes_security_headers_and_request_id():
    response = client.get(f"{API_PREFIX}/health")

    assert response.headers.get("X-Request-ID")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Cache-Control"] == "no-store"


def test_request_body_size_limit_returns_413(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "MAX_REQUEST_BYTES", 100)
    response = client.post(
        f"{API_PREFIX}/analyze",
        content='{"subject":"' + ("x" * 150) + '"}',
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413
    assert "X-Request-ID" in response.headers


def test_analyze_restricts_messages_with_attachments_until_scanner_is_integrated():
    payload = {
        "channel": "email",
        "subject": "Please review the report",
        "html": "<p>Please review the report attached.</p>",
        "recipients": ["user@example.com"],
        "attachments": [{"filename": "report.pdf", "content_type": "application/pdf"}],
    }
    response = client.post(f"{API_PREFIX}/analyze", json=payload)

    assert response.status_code == 200
    result = response.json()
    assert result["status"] == "RESTRICTED"
    assert result["can_send"] is False
    assert "ATTACHMENT_SCAN_UNAVAILABLE" in result["patterns_detected"]


def test_readiness_returns_503_when_required_model_is_missing(monkeypatch, tmp_path):
    from app.core.config import settings

    monkeypatch.setattr(settings, "REQUIRE_ML", True)
    monkeypatch.setattr(settings, "MODEL_PATH", tmp_path / "missing-model.joblib")
    response = client.get(f"{API_PREFIX}/ready")

    assert response.status_code == 503
    assert response.json()["ready"] is False
    assert response.json()["checks"]["ml_classifier"] == "unavailable"


def test_analyze_allows_attachment_only_when_configured_scanner_confirms_clean(monkeypatch):
    from app.pipeline import orchestrator

    class CleanScanner:
        def scan(self, attachments):
            assert attachments[0]["content_base64"]
            return {
                "completed": True,
                "safe": True,
                "findings": [],
                "status": "clamav_scan_complete",
            }

    monkeypatch.setattr(orchestrator, "configured_scanner", lambda: CleanScanner())
    import base64
    payload = {
        "channel": "email",
        "subject": "Review the report",
        "html": "<p>Please review the report.</p>",
        "recipients": ["user@example.com"],
        "attachments": [{
            "filename": "report.txt",
            "content_type": "text/plain",
            "content_base64": base64.b64encode(b"sample clean document").decode("ascii"),
        }],
    }
    response = client.post(f"{API_PREFIX}/analyze", json=payload)
    assert response.status_code == 200
    assert response.json()["status"] == "SAFE"
    assert response.json()["inspection_coverage"]["attachment_scan"] == "clamav_scan_complete"


def test_analyze_restricts_attachment_when_configured_scanner_detects_malware(monkeypatch):
    from app.pipeline import orchestrator

    class MalwareScanner:
        def scan(self, attachments):
            return {
                "completed": True,
                "safe": False,
                "findings": [{
                    "code": "ATTACHMENT_MALWARE_DETECTED",
                    "category": "MALWARE",
                    "message": "ClamAV detected malware in attachment 1.",
                }],
                "status": "clamav_scan_complete",
            }

    monkeypatch.setattr(orchestrator, "configured_scanner", lambda: MalwareScanner())
    import base64
    payload = {
        "channel": "email",
        "subject": "Please see attached",
        "html": "<p>Attached.</p>",
        "recipients": ["user@example.com"],
        "attachments": [{
            "filename": "sample.bin",
            "content_type": "application/octet-stream",
            "content_base64": base64.b64encode(b"sample").decode("ascii"),
        }],
    }
    response = client.post(f"{API_PREFIX}/analyze", json=payload)
    assert response.status_code == 200
    result = response.json()
    assert result["status"] == "RESTRICTED"
    assert result["can_send"] is False
    assert "ATTACHMENT_MALWARE_DETECTED" in result["patterns_detected"]
