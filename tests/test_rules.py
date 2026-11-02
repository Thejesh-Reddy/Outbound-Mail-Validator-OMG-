from app.checks.url_inspection import inspect_urls
from app.checks.rule_checks import (
    inspect_patterns,
    extract_email_text,
    get_rule_catalog_status,
)
from app.checks.url_inspection import inspect_urls

def test_detects_lottery_prize_claim():
    findings = inspect_patterns(
        "Congratulations",
        "<html><body>Claim your lottery prize</body></html>",
    )

    assert any(
        finding["code"] == "LOTTERY_SCAM"
        for finding in findings
    )


def test_detects_credential_phishing():
    findings = inspect_patterns(
        "Important account notice",
        "<html><body>Verify your password immediately</body></html>",
    )

    assert any(
        finding["code"] == "CREDENTIAL_PHISHING"
        for finding in findings
    )


def test_detects_unsolicited_spam():
    findings = inspect_patterns(
        "Special offer",
        "<html><body>Earn money fast</body></html>",
    )

    assert any(
        finding["code"] == "UNSOLICITED_SPAM"
        for finding in findings
    )


def test_normal_email_does_not_match_current_rules():
    findings = inspect_patterns(
        "Meeting reminder",
        "<html><body>The team meeting starts at 10 AM.</body></html>",
    )

    assert findings == []


def test_extract_email_text_includes_subject_and_body():
    text = extract_email_text(
        "Project update",
        "<html><body>Deployment completed</body></html>",
    )

    assert "Project update" in text
    assert "Deployment completed" in text


def test_catalog_status_reports_156_entries():
    status = get_rule_catalog_status()

    assert status["total_patterns"] == 156
    assert (
        status["implemented_patterns"]
        + status["catalog_only_patterns"]
        == 156
    )
from app.checks.html_inspection import inspect_html_content


def test_detects_hidden_html_text():
    findings = inspect_html_content(
        "Account notice",
        '<html><body><div style="display:none">'
        "Claim your lottery prize</div></body></html>",
    )

    assert any(
        finding["code"] == "HIDDEN_HTML_TEXT"
        for finding in findings
    )


def test_detects_html_entity_encoded_suspicious_text():
    findings = inspect_html_content(
        "Account notice",
        "<html><body>claim your lottery &#112;ri&#122;e</body></html>",
    )

    assert any(
        finding["code"] == "ENCODED_SUSPICIOUS_TEXT"
        for finding in findings
    )


def test_normal_html_does_not_trigger_hidden_content_finding():
    findings = inspect_html_content(
        "Meeting reminder",
        "<html><body><p>The meeting starts at 10 AM.</p></body></html>",
    )

    assert not any(
        finding["code"] == "HIDDEN_HTML_TEXT"
        for finding in findings
    )

    from app.checks.url_inspection import inspect_urls


def test_detects_non_http_link():
    findings = inspect_urls(
        '<a href="javascript:alert(1)">Open account</a>'
    )
    assert any(f["code"] == "NON_HTTP_LINK" for f in findings)


def test_detects_ip_address_link():
    findings = inspect_urls(
        '<a href="http://192.0.2.10/login">Open account</a>'
    )
    assert any(f["code"] == "IP_ADDRESS_LINK" for f in findings)


def test_detects_displayed_url_mismatch():
    findings = inspect_urls(
        '<a href="https://example.com/login">'
        "https://different.example</a>"
    )
    assert any(f["code"] == "LINK_TEXT_MISMATCH" for f in findings)


def test_normal_https_link_does_not_trigger_basic_url_findings():
    findings = inspect_urls(
        '<a href="https://example.com/meeting">Meeting details</a>'
    )
    assert findings == []

def test_detects_malformed_http_url():
    findings = inspect_urls(
        '<a href="https://">Open account</a>'
    )
    assert any(
        finding["code"] == "MALFORMED_URL"
        for finding in findings
    )


def test_detects_url_with_credentials_in_authority():
    findings = inspect_urls(
        '<a href="https://trusted.example@evil.example/login">'
        "Open account</a>"
    )
    assert any(
        finding["code"] == "URL_CREDENTIALS_PRESENT"
        for finding in findings
    )


def test_detects_hostname_with_suspicious_ip_format():
    findings = inspect_urls(
        '<a href="http://192.0.2.10/login">Open account</a>'
    )
    assert any(
        finding["code"] == "IP_ADDRESS_LINK"
        for finding in findings
    )


def test_detects_http_url_with_missing_hostname():
    findings = inspect_urls(
        '<a href="http:///login">Open account</a>'
    )
    assert any(
        finding["code"] == "MALFORMED_URL"
        for finding in findings
    )

def test_detects_punycode_hostname():
    findings = inspect_urls(
        '<a href="https://xn--pple-43d.example/login">Open account</a>'
    )
    assert any(
        finding["code"] == "IDN_HOSTNAME"
        for finding in findings
    )


def test_detects_unicode_hostname():
    findings = inspect_urls(
        '<a href="https://аpple.example/login">Open account</a>'
    )
    assert any(
        finding["code"] == "IDN_HOSTNAME"
        for finding in findings
    )


def test_detects_hostname_with_invalid_label_format():
    findings = inspect_urls(
        '<a href="https://-invalid.example/login">Open account</a>'
    )
    assert any(
        finding["code"] == "INVALID_HOSTNAME"
        for finding in findings
    )


def test_accepts_ordinary_ascii_hostname():
    findings = inspect_urls(
        '<a href="https://example.com/meeting">Meeting details</a>'
    )
    assert not any(
        finding["code"] in {"IDN_HOSTNAME", "INVALID_HOSTNAME"}
        for finding in findings
    )

def test_detects_url_with_invalid_port():
    findings = inspect_urls(
        '<a href="https://example.com:99999/login">Open account</a>'
    )
    assert any(
        finding["code"] == "MALFORMED_URL"
        for finding in findings
    )


def test_detects_url_with_empty_hostname_and_port():
    findings = inspect_urls(
        '<a href="https://:443/login">Open account</a>'
    )
    assert any(
        finding["code"] == "MALFORMED_URL"
        for finding in findings
    )

def test_runtime_rules_can_be_updated_without_source_changes(tmp_path, monkeypatch):
    import json
    from app.core.config import settings
    rules_path = tmp_path / "rules.json"
    rules_path.write_text(json.dumps({"rules": [{
        "code": "CUSTOM_TEST_RULE", "category": "TEST",
        "patterns": [r"\bcustom-danger-phrase\b"]
    }]}), encoding="utf-8")
    monkeypatch.setattr(settings, "RULES_PATH", rules_path)
    findings = inspect_patterns("Notice", "<p>custom-danger-phrase</p>")
    assert any(item["code"] == "CUSTOM_TEST_RULE" for item in findings)
