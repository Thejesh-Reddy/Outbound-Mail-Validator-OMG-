import base64
from types import SimpleNamespace

from app.checks.attachment_scanning import ClamAVScanner, scan_attachments


def encoded(data=b"hello"):
    return base64.b64encode(data).decode("ascii")


def test_attachment_without_scanner_fails_closed():
    result = scan_attachments([{"filename": "a.txt", "content_base64": encoded()}])
    assert result["completed"] is False
    assert result["safe"] is False
    assert result["findings"][0]["code"] == "ATTACHMENT_SCAN_UNAVAILABLE"


def test_attachment_metadata_without_bytes_fails_closed():
    scanner = ClamAVScanner()
    result = scanner.scan([{"filename": "a.txt"}])
    assert result["completed"] is False
    assert result["findings"][0]["code"] == "ATTACHMENT_CONTENT_MISSING"


def test_invalid_base64_fails_closed():
    result = ClamAVScanner().scan([{"content_base64": "not base64!"}])
    assert result["findings"][0]["code"] == "ATTACHMENT_ENCODING_INVALID"


def test_clamav_clean_result(monkeypatch):
    def fake_run(*args, **kwargs):
        assert kwargs["input"] == b"hello"
        return SimpleNamespace(returncode=0, stdout=b"stdin: OK", stderr=b"")
    monkeypatch.setattr("app.checks.attachment_scanning.subprocess.run", fake_run)
    result = ClamAVScanner().scan([{"content_base64": encoded()}])
    assert result["completed"] is True
    assert result["safe"] is True
    assert result["status"] == "clamav_scan_complete"


def test_clamav_malware_result(monkeypatch):
    def fake_run(*args, **kwargs):
        return SimpleNamespace(returncode=1, stdout=b"stdin: Eicar-Test-Signature FOUND", stderr=b"")
    monkeypatch.setattr("app.checks.attachment_scanning.subprocess.run", fake_run)
    result = ClamAVScanner().scan([{"content_base64": encoded()}])
    assert result["completed"] is True
    assert result["safe"] is False
    assert result["findings"][0]["code"] == "ATTACHMENT_MALWARE_DETECTED"


def test_clamav_nonzero_error_fails_closed(monkeypatch):
    def fake_run(*args, **kwargs):
        return SimpleNamespace(returncode=2, stdout=b"", stderr=b"scanner error")
    monkeypatch.setattr("app.checks.attachment_scanning.subprocess.run", fake_run)
    result = ClamAVScanner().scan([{"content_base64": encoded()}])
    assert result["completed"] is False
    assert result["findings"][0]["code"] == "ATTACHMENT_SCAN_INCOMPLETE"
