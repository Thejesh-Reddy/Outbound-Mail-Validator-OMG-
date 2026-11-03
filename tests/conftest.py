import pytest

from common.config import settings


@pytest.fixture(autouse=True)
def disable_configured_api_key_for_unrelated_tests(monkeypatch):
    """Keep developer .env credentials from breaking API tests.

    Individual authentication tests explicitly configure API_KEY and verify
    that the endpoint rejects missing/incorrect keys. All other tests run in
    the intended local-development mode without requiring a real secret.
    """
    monkeypatch.setattr(settings, "API_KEY", "")
