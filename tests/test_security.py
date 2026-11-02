import pytest
from fastapi.testclient import TestClient

from common.config import settings
from app import app

client = TestClient(app)
API_PREFIX = settings.API_PREFIX.rstrip("/")

PAYLOAD = {
    "channel": "email",
    "subject": "A normal meeting reminder",
    "html": "<p>The meeting starts at 10 AM.</p>",
    "recipients": ["user@example.com"],
    "attachments": [],
}


def test_analyze_requires_api_key_when_configured(monkeypatch):
    monkeypatch.setattr(settings, "API_KEY", "test-secret-key-that-is-long-enough")

    denied = client.post(f"{API_PREFIX}/analyze", json=PAYLOAD)
    assert denied.status_code == 401

    allowed = client.post(
        f"{API_PREFIX}/analyze",
        json=PAYLOAD,
        headers={"X-OMG-API-Key": settings.API_KEY},
    )
    assert allowed.status_code == 200


def test_production_configuration_rejects_missing_secrets_and_model(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(settings, "API_KEY", "")
    monkeypatch.setattr(settings, "REQUIRE_ML", False)
    monkeypatch.setattr(settings, "MODEL_PATH", tmp_path / "missing.joblib")
    monkeypatch.setattr(settings, "RULES_PATH", tmp_path / "missing-rules.json")

    with pytest.raises(RuntimeError, match="Invalid production configuration"):
        settings.validate_production_configuration()


def test_production_configuration_requires_strong_api_key_and_model(monkeypatch, tmp_path):
    model_path = tmp_path / "model.joblib"
    model_path.write_bytes(b"placeholder")
    rules_path = tmp_path / "rules.json"
    rules_path.write_text('{"rules": []}', encoding="utf-8")

    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(settings, "API_KEY", "x" * 40)
    monkeypatch.setattr(settings, "REQUIRE_ML", True)
    monkeypatch.setattr(settings, "MODEL_PATH", model_path)
    monkeypatch.setattr(settings, "RULES_PATH", rules_path)

    # Configuration validation checks presence; readiness loads and validates model contents.
    settings.validate_production_configuration()
