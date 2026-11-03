from fastapi.testclient import TestClient
from app import app
from common.config import settings
client = TestClient(app)
API_PREFIX = settings.API_PREFIX.rstrip('/')

def test_api__test_root_endpoint_returns_success():
    response = client.get('/')
    assert response.status_code == 200
    assert response.json()['message'] == 'OMG API is running.'

def test_api__test_health_endpoint_returns_success():
    response = client.get(f'{API_PREFIX}/health')
    assert response.status_code == 200

def test_api__test_analyze_endpoint_detects_invalid_hostname():
    payload = {'channel': 'email', 'subject': 'Account notification', 'html': '<html><body><a href="https://-invalid.example/login">Open account</a></body></html>', 'recipients': ['user@example.com'], 'attachments': []}
    response = client.post(f'{API_PREFIX}/analyze', json=payload)
    assert response.status_code == 200
    result = response.json()
    assert result['status'] == 'RESTRICTED'
    assert result['can_send'] is False
    assert any((issue['code'] == 'INVALID_HOSTNAME' for issue in result['URL']))

def test_api__test_analyze_endpoint_detects_embedded_url_credentials():
    payload = {'channel': 'email', 'subject': 'Account notification', 'html': '<html><body><a href="https://trusted.example@evil.example/login">Open account</a></body></html>', 'recipients': ['user@example.com'], 'attachments': []}
    response = client.post(f'{API_PREFIX}/analyze', json=payload)
    assert response.status_code == 200
    result = response.json()
    assert result['status'] == 'RESTRICTED'
    assert result['can_send'] is False
    assert any((issue['code'] == 'URL_CREDENTIALS_PRESENT' for issue in result['URL']))

def test_api__test_analyze_endpoint_rejects_invalid_request():
    payload = {'channel': 'invalid', 'subject': 'Test', 'html': '<p>Hello</p>', 'recipients': ['user@example.com'], 'attachments': []}
    response = client.post(f'{API_PREFIX}/analyze', json=payload)
    assert response.status_code == 422

def test_api__test_clean_email_can_pass_baseline_inspections():
    payload = {'channel': 'email', 'subject': 'Normal test message', 'html': '<p>Hello, this is a test.</p>', 'recipients': ['user@example.com'], 'attachments': []}
    response = client.post(f'{API_PREFIX}/analyze', json=payload)
    assert response.status_code == 200
    result = response.json()
    assert result['status'] == 'SAFE'
    assert result['can_send'] is True
    assert set(result) == {'status', 'can_send', 'confidence_score', 'requires_acknowledgement', 'text', 'URL', 'attachments', 'warnings', 'popup'}

def test_api__test_readiness_endpoint_returns_component_status():
    response = client.get(f'{API_PREFIX}/ready')
    assert response.status_code == 200
    result = response.json()
    assert result['ready'] is True
    assert result['checks']['runtime_rules'] == 'ready'
    assert result['checks']['attachment_scanner'] == ('unavailable_fail_closed_for_attachments' if not __import__('Attachments.attachment_validator', fromlist=['configured_scanner']).configured_scanner() else 'clamav_configured')

def test_api__test_response_includes_security_headers_and_request_id():
    response = client.get(f'{API_PREFIX}/health')
    assert response.headers.get('X-Request-ID')
    assert response.headers['X-Content-Type-Options'] == 'nosniff'
    assert response.headers['Cache-Control'] == 'no-store'

def test_api__test_request_body_size_limit_returns_413(monkeypatch):
    from common.config import settings
    monkeypatch.setattr(settings, 'MAX_REQUEST_BYTES', 100)
    response = client.post(f'{API_PREFIX}/analyze', content='{"subject":"' + 'x' * 150 + '"}', headers={'Content-Type': 'application/json'})
    assert response.status_code == 413
    assert 'X-Request-ID' in response.headers

def test_api__test_analyze_restricts_messages_with_attachments_until_scanner_is_integrated():
    payload = {'channel': 'email', 'subject': 'Please review the report', 'html': '<p>Please review the report attached.</p>', 'recipients': ['user@example.com'], 'attachments': [{'filename': 'report.pdf', 'content_type': 'application/pdf'}]}
    response = client.post(f'{API_PREFIX}/analyze', json=payload)
    assert response.status_code == 200
    result = response.json()
    assert result['status'] == 'RESTRICTED'
    assert result['can_send'] is False
    assert any((issue['code'] == 'ATTACHMENT_SCAN_UNAVAILABLE' for issue in result['attachments'][0]['issues']))

def test_api__test_readiness_returns_503_when_required_model_is_missing(monkeypatch, tmp_path):
    from common.config import settings
    monkeypatch.setattr(settings, 'REQUIRE_ML', True)
    monkeypatch.setattr(settings, 'MODEL_PATH', tmp_path / 'missing-model.joblib')
    response = client.get(f'{API_PREFIX}/ready')
    assert response.status_code == 503
    assert response.json()['ready'] is False
    assert response.json()['checks']['ml_classifier'] == 'unavailable'

def test_api__test_analyze_allows_attachment_only_when_configured_scanner_confirms_clean(monkeypatch):
    from decision_engine import orchestrator

    class CleanScanner:

        def scan(self, attachments):
            assert attachments[0]['content_base64']
            return {'completed': True, 'safe': True, 'findings': [], 'status': 'clamav_scan_complete'}
    monkeypatch.setattr(orchestrator, 'configured_scanner', lambda: CleanScanner())
    import base64
    payload = {'channel': 'email', 'subject': 'Review the report', 'html': '<p>Please review the report.</p>', 'recipients': ['user@example.com'], 'attachments': [{'filename': 'report.txt', 'content_type': 'text/plain', 'content_base64': base64.b64encode(b'sample clean document').decode('ascii')}]}
    response = client.post(f'{API_PREFIX}/analyze', json=payload)
    assert response.status_code == 200
    assert response.json()['status'] == 'SAFE'
    assert response.json()['attachments'][0]['antivirus'] == 'CLAMAV_CLEAN'

def test_api__test_analyze_restricts_attachment_when_configured_scanner_detects_malware(monkeypatch):
    from decision_engine import orchestrator

    class MalwareScanner:

        def scan(self, attachments):
            return {'completed': True, 'safe': False, 'findings': [{'code': 'ATTACHMENT_MALWARE_DETECTED', 'category': 'MALWARE', 'message': 'ClamAV detected malware in attachment 1.'}], 'status': 'clamav_scan_complete'}
    monkeypatch.setattr(orchestrator, 'configured_scanner', lambda: MalwareScanner())
    import base64
    payload = {'channel': 'email', 'subject': 'Please see attached', 'html': '<p>Attached.</p>', 'recipients': ['user@example.com'], 'attachments': [{'filename': 'sample.bin', 'content_type': 'application/octet-stream', 'content_base64': base64.b64encode(b'sample').decode('ascii')}]}
    response = client.post(f'{API_PREFIX}/analyze', json=payload)
    assert response.status_code == 200
    result = response.json()
    assert result['status'] == 'RESTRICTED'
    assert result['can_send'] is False
    assert any((issue['code'] == 'ATTACHMENT_MALWARE_DETECTED' for issue in result['attachments'][0]['issues']))
from fastapi.testclient import TestClient
from app import app
client = TestClient(app)
EXPECTED_KEYS = {'status', 'can_send', 'confidence_score', 'requires_acknowledgement', 'text', 'URL', 'attachments', 'warnings', 'popup'}

def test_response_contract__test_safe_response_uses_only_teammate_contract_fields():
    response = client.post('/api/v1/analyze', json={'subject': 'Team update', 'body': 'Hello team, the meeting is at 10 AM.', 'recipients': ['user@example.com'], 'attachments': []})
    assert response.status_code == 200
    result = response.json()
    assert set(result) == EXPECTED_KEYS
    assert result['status'] == 'SAFE'
    assert result['can_send'] is True
    assert isinstance(result['confidence_score'], (int, float))
    assert result['text'] == []
    assert result['URL'] == []
    assert result['attachments'] == []
    assert result['popup'] is None

def test_response_contract__test_url_issue_uses_exact_code_severity_reason_shape():
    response = client.post('/api/v1/analyze', json={'subject': 'Account alert', 'html': '<a href="http://192.168.1.10/login">Open account</a>', 'recipients': ['user@example.com'], 'attachments': []})
    issue = response.json()['URL'][0]
    assert set(issue) == {'code', 'severity', 'reason'}
    assert issue['code'] == 'IP_ADDRESS_LINK'
    assert issue['severity'] == 'CRITICAL'
    assert issue['reason']

def test_response_contract__test_attachment_issue_uses_exact_reference_fields_when_scanner_unavailable():
    response = client.post('/api/v1/analyze', json={'subject': 'Report', 'body': 'Please review the attached report.', 'recipients': ['user@example.com'], 'attachments': [{'filename': 'report.docx'}]})
    result = response.json()
    attachment = result['attachments'][0]
    assert set(attachment) == {'filename', 'status', 'detected_type', 'antivirus', 'confidence_score', 'issues'}
    assert attachment['detected_type'] == 'DOCX'
    assert attachment['antivirus'] == 'NOT_CONFIGURED'
    assert set(attachment['issues'][0]) == {'code', 'severity', 'reason'}
    assert result['warnings'] == ['Malware scanning is disabled.']

def test_response_contract__test_warning_popup_uses_reference_shape_and_does_not_fabricate_challenge(monkeypatch):
    from decision_engine import orchestrator
    monkeypatch.setattr(orchestrator, 'calculate_safety_score', lambda **kwargs: (81.2, {'text': 100.0, 'html': None, 'urls': 100.0, 'attachments': None}))
    response = client.post('/api/v1/analyze', json={'subject': 'Team update', 'body': 'Hello team, the meeting is at 10 AM.', 'recipients': ['user@example.com'], 'attachments': []})
    result = response.json()
    assert result['status'] == 'WARNING'
    assert result['can_send'] is False
    assert result['requires_acknowledgement'] is True
    assert set(result['popup']) == {'show', 'type', 'title', 'message', 'actions'}
    assert result['popup']['actions'] == ['EDIT_MAIL', 'CLOSE']
    assert 'warning_challenge' in result
    assert result['warning_challenge'] is None
import pytest
from pydantic import ValidationError
from fastapi.testclient import TestClient
from app import app
from schemas.email import EmailRequest

def test_email_body_parsing__test_email_request_accepts_plain_text_body():
    request = EmailRequest(subject='Project update', body='Please review the attached project update.', recipients=['recipient@example.com'])
    assert request.body == 'Please review the attached project update.'
    assert request.inspection_content == request.body

def test_email_body_parsing__test_email_request_keeps_legacy_html_support():
    request = EmailRequest(subject='Project update', html='<p>Please review the project update.</p>', recipients=['recipient@example.com'])
    assert request.html.startswith('<p>')
    assert request.inspection_content == request.html

def test_email_body_parsing__test_email_request_combines_body_and_html_for_content_inspection():
    request = EmailRequest(subject='Project update', body='Plain text content', html='<p>HTML content</p>', recipients=['recipient@example.com'])
    assert 'Plain text content' in request.inspection_content
    assert 'HTML content' in request.inspection_content

def test_email_body_parsing__test_email_request_rejects_missing_or_blank_body_and_html():
    with pytest.raises(ValidationError):
        EmailRequest(subject='No content', recipients=['recipient@example.com'])
    with pytest.raises(ValidationError):
        EmailRequest(subject='Blank content', body='  ', recipients=['recipient@example.com'])

def test_email_body_parsing__test_analyze_endpoint_accepts_body_field():
    client = TestClient(app)
    response = client.post('/api/v1/analyze', json={'channel': 'email', 'subject': 'Team meeting', 'body': 'The team meeting starts at 10 AM.', 'recipients': ['recipient@example.com'], 'attachments': []})
    assert response.status_code == 200
    assert response.json()['status'] in {'SAFE', 'WARNING', 'RESTRICTED'}

def test_email_body_parsing__test_body_text_is_sent_through_text_inspection_pipeline():
    from decision_engine.orchestrator import analyze_email
    request = EmailRequest(subject='Congratulations', body='You have won a lottery prize. Claim your lottery prize now.', recipients=['recipient@example.com'])
    result = analyze_email(request)
    assert any((issue.code == 'LOTTERY_SCAM' for issue in result.text))
    assert result.status == 'RESTRICTED'
import pytest
from fastapi.testclient import TestClient
from common.config import settings
from app import app
client = TestClient(app)
API_PREFIX = settings.API_PREFIX.rstrip('/')
PAYLOAD = {'channel': 'email', 'subject': 'A normal meeting reminder', 'html': '<p>The meeting starts at 10 AM.</p>', 'recipients': ['user@example.com'], 'attachments': []}

def test_security__test_analyze_requires_api_key_when_configured(monkeypatch):
    monkeypatch.setattr(settings, 'API_KEY', 'test-secret-key-that-is-long-enough')
    denied = client.post(f'{API_PREFIX}/analyze', json=PAYLOAD)
    assert denied.status_code == 401
    allowed = client.post(f'{API_PREFIX}/analyze', json=PAYLOAD, headers={'X-OMG-API-Key': settings.API_KEY})
    assert allowed.status_code == 200

def test_security__test_production_configuration_rejects_missing_secrets_and_model(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, 'ENVIRONMENT', 'production')
    monkeypatch.setattr(settings, 'API_KEY', '')
    monkeypatch.setattr(settings, 'REQUIRE_ML', False)
    monkeypatch.setattr(settings, 'MODEL_PATH', tmp_path / 'missing.joblib')
    monkeypatch.setattr(settings, 'RULES_PATH', tmp_path / 'missing-rules.json')
    with pytest.raises(RuntimeError, match='Invalid production configuration'):
        settings.validate_production_configuration()

def test_security__test_production_configuration_requires_strong_api_key_and_model(monkeypatch, tmp_path):
    model_path = tmp_path / 'model.joblib'
    model_path.write_bytes(b'placeholder')
    rules_path = tmp_path / 'rules.json'
    rules_path.write_text('{"rules": []}', encoding='utf-8')
    monkeypatch.setattr(settings, 'ENVIRONMENT', 'production')
    monkeypatch.setattr(settings, 'API_KEY', 'x' * 40)
    monkeypatch.setattr(settings, 'REQUIRE_ML', True)
    monkeypatch.setattr(settings, 'MODEL_PATH', model_path)
    monkeypatch.setattr(settings, 'RULES_PATH', rules_path)
    settings.validate_production_configuration()
