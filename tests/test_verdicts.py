from app.pipeline.decision_aggregator import decide_verdict


SAFE_SCAN = {"completed": True, "safe": True, "findings": []}


def test_safe_requires_complete_checks_and_no_findings():
    result = decide_verdict([], SAFE_SCAN, checks_complete=True)
    assert result.status == "SAFE"
    assert result.can_send is True
    assert result.confidence_score is None
    assert result.warning_required is False


def test_any_finding_restricts_until_finding_severity_policy_is_defined():
    finding = {"code": "TEST_THREAT", "category": "SPAM", "message": "Test finding"}
    result = decide_verdict([finding], SAFE_SCAN, checks_complete=True, safety_score=82)
    assert result.status == "RESTRICTED"
    assert result.can_send is False


def test_incomplete_checks_restrict():
    result = decide_verdict([], SAFE_SCAN, checks_complete=False)
    assert result.status == "RESTRICTED"
    assert result.can_send is False


def test_incomplete_attachment_scan_restricts():
    result = decide_verdict(
        [], {"completed": False, "safe": False, "findings": []},
        checks_complete=True,
    )
    assert result.status == "RESTRICTED"
    assert result.can_send is False


def test_score_below_75_is_restricted():
    result = decide_verdict([], SAFE_SCAN, safety_score=74.99)
    assert result.status == "RESTRICTED"
    assert result.can_send is False


def test_score_75_to_below_86_is_warning_and_requires_acknowledgement():
    result = decide_verdict([], SAFE_SCAN, safety_score=75)
    assert result.status == "WARNING"
    assert result.can_send is False
    assert result.warning_required is True
    assert result.requires_acknowledgement is True


def test_score_85_99_is_warning():
    result = decide_verdict([], SAFE_SCAN, safety_score=85.99)
    assert result.status == "WARNING"
    assert result.can_send is False


def test_score_86_is_safe():
    result = decide_verdict([], SAFE_SCAN, safety_score=86)
    assert result.status == "SAFE"
    assert result.can_send is True


def test_score_above_100_is_rejected():
    import pytest
    with pytest.raises(ValueError):
        decide_verdict([], SAFE_SCAN, safety_score=100.01)


def test_missing_score_does_not_fabricate_a_numeric_safety_score():
    result = decide_verdict([], SAFE_SCAN, checks_complete=True)
    assert result.status == "SAFE"
    assert result.confidence_score is None


def test_hard_block_overrides_high_score():
    finding = {"code": "LOTTERY_SCAM", "category": "FRAUD", "message": "confirmed"}
    result = decide_verdict([finding], SAFE_SCAN, safety_score=99)
    assert result.status == "RESTRICTED"
    assert result.can_send is False
