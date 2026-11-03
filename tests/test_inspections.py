from URL.url_validator import inspect_urls
from Content.text_validator import inspect_patterns, extract_email_text, get_rule_catalog_status
from URL.url_validator import inspect_urls

def test_rules__test_detects_lottery_prize_claim():
    findings = inspect_patterns('Congratulations', '<html><body>Claim your lottery prize</body></html>')
    assert any((finding['code'] == 'LOTTERY_SCAM' for finding in findings))

def test_rules__test_detects_credential_phishing():
    findings = inspect_patterns('Important account notice', '<html><body>Verify your password immediately</body></html>')
    assert any((finding['code'] == 'CREDENTIAL_PHISHING' for finding in findings))

def test_rules__test_detects_unsolicited_spam():
    findings = inspect_patterns('Special offer', '<html><body>Earn money fast</body></html>')
    assert any((finding['code'] == 'UNSOLICITED_SPAM' for finding in findings))

def test_rules__test_normal_email_does_not_match_current_rules():
    findings = inspect_patterns('Meeting reminder', '<html><body>The team meeting starts at 10 AM.</body></html>')
    assert findings == []

def test_rules__test_extract_email_text_includes_subject_and_body():
    text = extract_email_text('Project update', '<html><body>Deployment completed</body></html>')
    assert 'Project update' in text
    assert 'Deployment completed' in text

def test_rules__test_catalog_status_reports_156_entries():
    status = get_rule_catalog_status()
    assert status['total_patterns'] == 156
    assert status['implemented_patterns'] + status['catalog_only_patterns'] == 156
from Content.html_validator import inspect_html_content

def test_rules__test_detects_hidden_html_text():
    findings = inspect_html_content('Account notice', '<html><body><div style="display:none">Claim your lottery prize</div></body></html>')
    assert any((finding['code'] == 'HIDDEN_HTML_TEXT' for finding in findings))

def test_rules__test_detects_html_entity_encoded_suspicious_text():
    findings = inspect_html_content('Account notice', '<html><body>claim your lottery &#112;ri&#122;e</body></html>')
    assert any((finding['code'] == 'ENCODED_SUSPICIOUS_TEXT' for finding in findings))

def test_rules__test_normal_html_does_not_trigger_hidden_content_finding():
    findings = inspect_html_content('Meeting reminder', '<html><body><p>The meeting starts at 10 AM.</p></body></html>')
    assert not any((finding['code'] == 'HIDDEN_HTML_TEXT' for finding in findings))
    from URL.url_validator import inspect_urls

def test_rules__test_detects_non_http_link():
    findings = inspect_urls('<a href="javascript:alert(1)">Open account</a>')
    assert any((f['code'] == 'NON_HTTP_LINK' for f in findings))

def test_rules__test_detects_ip_address_link():
    findings = inspect_urls('<a href="http://192.0.2.10/login">Open account</a>')
    assert any((f['code'] == 'IP_ADDRESS_LINK' for f in findings))

def test_rules__test_detects_displayed_url_mismatch():
    findings = inspect_urls('<a href="https://example.com/login">https://different.example</a>')
    assert any((f['code'] == 'LINK_TEXT_MISMATCH' for f in findings))

def test_rules__test_normal_https_link_does_not_trigger_basic_url_findings():
    findings = inspect_urls('<a href="https://example.com/meeting">Meeting details</a>')
    assert findings == []

def test_rules__test_detects_malformed_http_url():
    findings = inspect_urls('<a href="https://">Open account</a>')
    assert any((finding['code'] == 'MALFORMED_URL' for finding in findings))

def test_rules__test_detects_url_with_credentials_in_authority():
    findings = inspect_urls('<a href="https://trusted.example@evil.example/login">Open account</a>')
    assert any((finding['code'] == 'URL_CREDENTIALS_PRESENT' for finding in findings))

def test_rules__test_detects_hostname_with_suspicious_ip_format():
    findings = inspect_urls('<a href="http://192.0.2.10/login">Open account</a>')
    assert any((finding['code'] == 'IP_ADDRESS_LINK' for finding in findings))

def test_rules__test_detects_http_url_with_missing_hostname():
    findings = inspect_urls('<a href="http:///login">Open account</a>')
    assert any((finding['code'] == 'MALFORMED_URL' for finding in findings))

def test_rules__test_detects_punycode_hostname():
    findings = inspect_urls('<a href="https://xn--pple-43d.example/login">Open account</a>')
    assert any((finding['code'] == 'IDN_HOSTNAME' for finding in findings))

def test_rules__test_detects_unicode_hostname():
    findings = inspect_urls('<a href="https://аpple.example/login">Open account</a>')
    assert any((finding['code'] == 'IDN_HOSTNAME' for finding in findings))

def test_rules__test_detects_hostname_with_invalid_label_format():
    findings = inspect_urls('<a href="https://-invalid.example/login">Open account</a>')
    assert any((finding['code'] == 'INVALID_HOSTNAME' for finding in findings))

def test_rules__test_accepts_ordinary_ascii_hostname():
    findings = inspect_urls('<a href="https://example.com/meeting">Meeting details</a>')
    assert not any((finding['code'] in {'IDN_HOSTNAME', 'INVALID_HOSTNAME'} for finding in findings))

def test_rules__test_detects_url_with_invalid_port():
    findings = inspect_urls('<a href="https://example.com:99999/login">Open account</a>')
    assert any((finding['code'] == 'MALFORMED_URL' for finding in findings))

def test_rules__test_detects_url_with_empty_hostname_and_port():
    findings = inspect_urls('<a href="https://:443/login">Open account</a>')
    assert any((finding['code'] == 'MALFORMED_URL' for finding in findings))

def test_rules__test_runtime_rules_can_be_updated_without_source_changes(tmp_path, monkeypatch):
    import json
    from common.config import settings
    rules_path = tmp_path / 'rules.json'
    rules_path.write_text(json.dumps({'rules': [{'code': 'CUSTOM_TEST_RULE', 'category': 'TEST', 'patterns': ['\\bcustom-danger-phrase\\b']}]}), encoding='utf-8')
    monkeypatch.setattr(settings, 'RULES_PATH', rules_path)
    findings = inspect_patterns('Notice', '<p>custom-danger-phrase</p>')
    assert any((item['code'] == 'CUSTOM_TEST_RULE' for item in findings))
from Content.text_validator import inspect_patterns
from Content.html_validator import inspect_html_content
from URL.url_validator import inspect_urls
tests = [{'name': 'Lottery scam', 'subject': 'Congratulations! You Won a Lottery', 'body': 'You have won a lottery prize. Pay an advance fee to claim your winnings.', 'should_detect': True}, {'name': 'Credential phishing', 'subject': 'Urgent: Verify Your Account', 'body': 'Your account will be suspended. Verify your password immediately.', 'should_detect': True}, {'name': 'Urgent payment demand', 'subject': 'Urgent Payment Required', 'body': 'Transfer the payment immediately to avoid account suspension.', 'should_detect': True}, {'name': 'Fake prize offer', 'subject': 'Claim Your Free Prize', 'body': 'You have been selected to receive a free prize. Pay a processing fee to claim it.', 'should_detect': True}, {'name': 'Legitimate meeting invitation', 'subject': 'Team Meeting Tomorrow', 'body': 'Hello team, our weekly meeting is scheduled for tomorrow at 10 AM. Please review the agenda.', 'should_detect': False}, {'name': 'Legitimate invoice reminder', 'subject': 'Invoice Reminder', 'body': 'This is a reminder that invoice INV-1024 is due on November 5. Please contact our accounts team if you have any questions.', 'should_detect': False}]
for test in tests:
    subject = test['subject']
    body = test['body']
    findings = []
    try:
        findings.extend(inspect_patterns(subject, body))
        findings.extend(inspect_html_content(subject, body))
        findings.extend(inspect_urls(body))
        codes = sorted({item.get('code', 'UNKNOWN') for item in findings})
        detected = bool(findings)
        expected = test['should_detect']
        passed = detected == expected
        print(f"{('PASS' if passed else 'CHECK')} | {test['name']} | Findings: {codes}")
    except Exception as exc:
        print(f"ERROR | {test['name']} | {exc!r}")
from URL.url_validator import inspect_urls
tests = [('Plain-text IP URL', 'Verify your account at http://192.168.1.10/login immediately.', 'IP_ADDRESS_LINK'), ('HTML IP hyperlink', '<a href="http://192.168.1.10/login">Verify account</a>', 'IP_ADDRESS_LINK'), ('Mismatched displayed URL', '<a href="https://evil.example/login">https://trusted.example</a>', 'LINK_TEXT_MISMATCH'), ('Non-HTTP hyperlink', '<a href="javascript:alert(1)">Click</a>', 'NON_HTTP_LINK'), ('Legitimate email without links', '<p>The team meeting is scheduled for tomorrow at 10 AM.</p>', None)]
for name, body, expected_code in tests:
    findings = inspect_urls(body)
    detected_codes = {finding['code'] for finding in findings}
    if expected_code is None:
        passed = not findings
    else:
        passed = expected_code in detected_codes
    print(f"{('PASS' if passed else 'FAIL')} | {name} | Detected: {sorted(detected_codes)}")
import base64
from types import SimpleNamespace
from Attachments.attachment_validator import ClamAVScanner, scan_attachments

def encoded(data=b'hello'):
    return base64.b64encode(data).decode('ascii')

def test_attachment_scanning__test_attachment_without_scanner_fails_closed():
    result = scan_attachments([{'filename': 'a.txt', 'content_base64': encoded()}])
    assert result['completed'] is False
    assert result['safe'] is False
    assert result['findings'][0]['code'] == 'ATTACHMENT_SCAN_UNAVAILABLE'

def test_attachment_scanning__test_attachment_metadata_without_bytes_fails_closed():
    scanner = ClamAVScanner()
    result = scanner.scan([{'filename': 'a.txt'}])
    assert result['completed'] is False
    assert result['findings'][0]['code'] == 'ATTACHMENT_CONTENT_MISSING'

def test_attachment_scanning__test_invalid_base64_fails_closed():
    result = ClamAVScanner().scan([{'content_base64': 'not base64!'}])
    assert result['findings'][0]['code'] == 'ATTACHMENT_ENCODING_INVALID'

def test_attachment_scanning__test_clamav_clean_result(monkeypatch):

    def fake_run(*args, **kwargs):
        assert kwargs['input'] == b'hello'
        return SimpleNamespace(returncode=0, stdout=b'stdin: OK', stderr=b'')
    monkeypatch.setattr('Attachments.attachment_validator.subprocess.run', fake_run)
    result = ClamAVScanner().scan([{'content_base64': encoded()}])
    assert result['completed'] is True
    assert result['safe'] is True
    assert result['status'] == 'clamav_scan_complete'

def test_attachment_scanning__test_clamav_malware_result(monkeypatch):

    def fake_run(*args, **kwargs):
        return SimpleNamespace(returncode=1, stdout=b'stdin: Eicar-Test-Signature FOUND', stderr=b'')
    monkeypatch.setattr('Attachments.attachment_validator.subprocess.run', fake_run)
    result = ClamAVScanner().scan([{'content_base64': encoded()}])
    assert result['completed'] is True
    assert result['safe'] is False
    assert result['findings'][0]['code'] == 'ATTACHMENT_MALWARE_DETECTED'

def test_attachment_scanning__test_clamav_nonzero_error_fails_closed(monkeypatch):

    def fake_run(*args, **kwargs):
        return SimpleNamespace(returncode=2, stdout=b'', stderr=b'scanner error')
    monkeypatch.setattr('Attachments.attachment_validator.subprocess.run', fake_run)
    result = ClamAVScanner().scan([{'content_base64': encoded()}])
    assert result['completed'] is False
    assert result['findings'][0]['code'] == 'ATTACHMENT_SCAN_INCOMPLETE'
