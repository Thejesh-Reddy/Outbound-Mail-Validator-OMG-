from decision_engine.decision_aggregator import decide_verdict
SAFE_SCAN = {'completed': True, 'safe': True, 'findings': []}

def test_verdicts__test_safe_requires_complete_checks_and_no_findings():
    result = decide_verdict([], SAFE_SCAN, checks_complete=True)
    assert result.status == 'SAFE'
    assert result.can_send is True
    assert result.confidence_score == 100.0
    assert result.requires_acknowledgement is False

def test_verdicts__test_any_finding_restricts_until_finding_severity_policy_is_defined():
    finding = {'code': 'TEST_THREAT', 'category': 'SPAM', 'message': 'Test finding'}
    result = decide_verdict([finding], SAFE_SCAN, checks_complete=True, safety_score=82)
    assert result.status == 'RESTRICTED'
    assert result.can_send is False

def test_verdicts__test_incomplete_checks_restrict():
    result = decide_verdict([], SAFE_SCAN, checks_complete=False)
    assert result.status == 'RESTRICTED'
    assert result.can_send is False

def test_verdicts__test_incomplete_attachment_scan_restricts():
    result = decide_verdict([], {'completed': False, 'safe': False, 'findings': []}, checks_complete=True)
    assert result.status == 'RESTRICTED'
    assert result.can_send is False

def test_verdicts__test_score_below_75_is_restricted():
    result = decide_verdict([], SAFE_SCAN, safety_score=74.99)
    assert result.status == 'RESTRICTED'
    assert result.can_send is False

def test_verdicts__test_score_75_to_below_86_is_warning_and_requires_acknowledgement():
    result = decide_verdict([], SAFE_SCAN, safety_score=75)
    assert result.status == 'WARNING'
    assert result.can_send is False
    assert result.requires_acknowledgement is True
    assert result.requires_acknowledgement is True

def test_verdicts__test_score_85_99_is_warning():
    result = decide_verdict([], SAFE_SCAN, safety_score=85.99)
    assert result.status == 'WARNING'
    assert result.can_send is False

def test_verdicts__test_score_86_is_safe():
    result = decide_verdict([], SAFE_SCAN, safety_score=86)
    assert result.status == 'SAFE'
    assert result.can_send is True

def test_verdicts__test_score_above_100_is_rejected():
    import pytest
    with pytest.raises(ValueError):
        decide_verdict([], SAFE_SCAN, safety_score=100.01)

def test_verdicts__test_missing_score_does_not_fabricate_a_numeric_safety_score():
    result = decide_verdict([], SAFE_SCAN, checks_complete=True)
    assert result.status == 'SAFE'
    assert result.confidence_score == 100.0

def test_verdicts__test_hard_block_overrides_high_score():
    finding = {'code': 'LOTTERY_SCAM', 'category': 'FRAUD', 'message': 'confirmed'}
    result = decide_verdict([finding], SAFE_SCAN, safety_score=99)
    assert result.status == 'RESTRICTED'
    assert result.can_send is False
from fastapi.testclient import TestClient
from app import app
from decision_engine.scoring import calculate_safety_score, score_findings
client = TestClient(app)

def test_scoring__test_clean_api_analysis_returns_numeric_overall_and_component_scores():
    response = client.post('/api/v1/analyze', json={'subject': 'Weekly team meeting', 'body': 'Hello team, our meeting is scheduled for 10 AM.', 'recipients': ['recipient@example.com'], 'attachments': []})
    assert response.status_code == 200
    result = response.json()
    assert isinstance(result['confidence_score'], (int, float))
    assert result['confidence_score'] == 100.0
    assert result['text'] == []
    assert result['URL'] == []
    assert result['attachments'] == []
    assert set(result) == {'status', 'can_send', 'confidence_score', 'requires_acknowledgement', 'text', 'URL', 'attachments', 'warnings', 'popup'}

def test_scoring__test_text_finding_reduces_score_and_still_respects_fail_closed_policy():
    response = client.post('/api/v1/analyze', json={'subject': 'Congratulations', 'body': 'You have won a lottery prize. Claim your lottery prize now.', 'recipients': ['recipient@example.com'], 'attachments': []})
    assert response.status_code == 200
    result = response.json()
    assert result['confidence_score'] < 100
    assert result['status'] == 'RESTRICTED'
    assert result['can_send'] is False
    assert any((issue['code'] == 'LOTTERY_SCAM' for issue in result['text']))

def test_scoring__test_url_findings_are_included_in_url_component_score():
    response = client.post('/api/v1/analyze', json={'subject': 'Account notice', 'html': '<a href="http://192.168.1.10/login">Open account</a>', 'recipients': ['recipient@example.com'], 'attachments': []})
    assert response.status_code == 200
    result = response.json()
    assert result['URL']
    assert any((issue['code'] == 'IP_ADDRESS_LINK' for issue in result['URL']))
    assert result['status'] == 'RESTRICTED'

def test_scoring__test_missing_attachment_scanner_returns_zero_score_and_per_file_issue():
    response = client.post('/api/v1/analyze', json={'subject': 'Report', 'body': 'Please review the attached report.', 'recipients': ['recipient@example.com'], 'attachments': [{'filename': 'report.pdf'}]})
    assert response.status_code == 200
    result = response.json()
    assert result['confidence_score'] == 0.0
    assert result['attachments'][0]['confidence_score'] == 0.0
    assert result['attachments'][0]['antivirus'] == 'NOT_CONFIGURED'
    assert result['attachments'][0]['status'] == 'RESTRICTED'

def test_scoring__test_duplicate_findings_are_penalized_only_once_within_component():
    finding = {'code': 'LOTTERY_SCAM', 'category': 'FRAUD', 'message': 'same finding'}
    assert score_findings([finding, finding]) == score_findings([finding])

def test_scoring__test_incomplete_mandatory_inspection_forces_conservative_zero_score():
    score, breakdown = calculate_safety_score(text_findings=[], html_findings=[], url_findings=[], attachment_scan={'completed': True, 'safe': True, 'findings': []}, checks_complete=False, html_applicable=False, attachments_present=False)
    assert score == 0.0
    assert breakdown['text'] == 0.0
    assert breakdown['urls'] == 0.0
from decision_engine.finding_policy import FindingAction, action_for_finding, is_hard_block_finding

def test_finding_policy__test_catalog_implemented_patterns_remain_restricted():
    for code in ('LOTTERY_SCAM', 'CREDENTIAL_PHISHING', 'URL_CREDENTIALS_IN_AUTHORITY'):
        assert action_for_finding(code) == FindingAction.RESTRICTED
        assert is_hard_block_finding({'code': code, 'category': 'PHISHING'})

def test_finding_policy__test_unknown_finding_codes_fail_closed():
    assert action_for_finding('NEW_UNREVIEWED_PATTERN') == FindingAction.RESTRICTED
    assert is_hard_block_finding({'code': 'NEW_UNREVIEWED_PATTERN'})

def test_finding_policy__test_inspection_failures_always_block():
    assert is_hard_block_finding({'code': 'ANY_CODE', 'category': 'INSPECTION_FAILURE'})

def test_finding_policy__test_warning_codes_are_not_enabled_without_policy_approval():
    assert action_for_finding('IP_ADDRESS_LINK') == FindingAction.RESTRICTED
from Attachments.attachment_validator import scan_attachments
from schemas.email import EmailRequest
from decision_engine.orchestrator import analyze_email

def test_failures__test_attachments_fail_closed_when_scanner_missing():
    result = scan_attachments([{'filename': 'report.pdf'}])
    assert result['completed'] is False
    assert result['safe'] is False
    assert result['findings'][0]['code'] == 'ATTACHMENT_SCAN_UNAVAILABLE'

def test_failures__test_attachments_no_files_need_no_scanner():
    result = scan_attachments([])
    assert result == {'completed': True, 'safe': True, 'findings': [], 'status': 'not_applicable_no_attachments'}

def test_failures__test_normal_email_can_be_safe_when_required_baseline_checks_complete(monkeypatch):
    monkeypatch.setattr('decision_engine.orchestrator.classify_email', lambda *_: {'available': False, 'completed': False, 'finding': None, 'reason': 'test'})
    request = EmailRequest(subject='Meeting', html='<p>See you at 10.</p>', recipients=['user@example.com'], attachments=[])
    result = analyze_email(request)
    assert result.status == 'SAFE'
    assert result.can_send is True

def test_failures__test_suspicious_email_is_restricted(monkeypatch):
    monkeypatch.setattr('decision_engine.orchestrator.classify_email', lambda *_: {'available': False, 'completed': False, 'finding': None, 'reason': 'test'})
    request = EmailRequest(subject='Congratulations', html='<p>Claim your lottery prize</p>', recipients=['user@example.com'], attachments=[])
    result = analyze_email(request)
    assert result.status == 'RESTRICTED'
    assert result.can_send is False
    assert any((issue.code == 'LOTTERY_SCAM' for issue in result.text))

def test_failures__test_invalid_recipient_rejected():
    try:
        EmailRequest(subject='Hi', html='<p>Hi</p>', recipients=['not-an-email'])
    except Exception:
        return
    assert False, 'Invalid recipient should be rejected'

def test_failures__test_required_ml_unavailability_fails_closed(monkeypatch):
    from common.config import settings
    monkeypatch.setattr(settings, 'REQUIRE_ML', True)
    monkeypatch.setattr('decision_engine.orchestrator.classify_email', lambda *_: {'available': False, 'completed': False, 'finding': None, 'reason': 'model missing'})
    request = EmailRequest(subject='Meeting', html='<p>See you at 10.</p>', recipients=['user@example.com'], attachments=[])
    result = analyze_email(request)
    assert result.status == 'RESTRICTED'
    assert result.can_send is False
    assert any((issue.code == 'ML_INSPECTION_INCOMPLETE' for issue in result.text))
from schemas.email import EmailRequest
from decision_engine.orchestrator import analyze_email
test_cases = [{'name': 'Suspicious plain-text IP URL', 'subject': 'Urgent: Verify Your Account', 'html': 'Your mailbox will be disabled today. Verify your credentials at http://192.168.1.10/login immediately.', 'attachments': [], 'expected': 'RESTRICTED'}, {'name': 'Suspicious HTML IP hyperlink', 'subject': 'Account Verification Required', 'html': '<p>Verify your account immediately.</p><a href="http://192.168.1.10/login">Verify Account</a>', 'attachments': [], 'expected': 'RESTRICTED'}, {'name': 'Lottery scam', 'subject': 'Congratulations! You Won a Lottery', 'html': 'You have won a lottery prize. Pay an advance fee to claim your winnings.', 'attachments': [], 'expected': 'RESTRICTED'}, {'name': 'Credential phishing', 'subject': 'Urgent: Verify Your Account', 'html': 'Your account will be suspended. Verify your password immediately.', 'attachments': [], 'expected': 'RESTRICTED'}, {'name': 'Urgent payment demand', 'subject': 'Urgent Payment Required', 'html': 'Transfer the payment immediately to avoid account suspension.', 'attachments': [], 'expected': 'RESTRICTED'}, {'name': 'Legitimate meeting invitation', 'subject': 'Team Meeting Tomorrow', 'html': 'Hello team, our weekly meeting is scheduled for tomorrow at 10 AM. Please review the agenda.', 'attachments': [], 'expected': 'SAFE'}, {'name': 'Email containing attachment', 'subject': 'Project Report', 'html': 'Please find the requested project report attached.', 'attachments': [{'filename': 'report.pdf'}], 'expected': 'RESTRICTED'}]
for test in test_cases:
    print(f"\nTesting: {test['name']}")
    try:
        email = EmailRequest(channel='email', subject=test['subject'], html=test['html'], recipients=['test@example.com'], attachments=test['attachments'])
        result = analyze_email(email)
        if hasattr(result, 'model_dump'):
            result = result.model_dump()
        elif not isinstance(result, dict):
            result = vars(result)
        actual = result.get('status')
        can_send = result.get('can_send')
        passed = actual == test['expected'] and can_send is (test['expected'] == 'SAFE')
        print(f"Expected verdict: {test['expected']}")
        print(f'Actual verdict:   {actual}')
        print(f'Can send:         {can_send}')
        print(f"Result:           {('PASS' if passed else 'FAIL')}")
        if not passed:
            print('Response:', result)
    except Exception as exc:
        print('PIPELINE TEST ERROR:', repr(exc))
