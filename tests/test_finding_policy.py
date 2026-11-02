from app.pipeline.finding_policy import (
    FindingAction,
    action_for_finding,
    is_hard_block_finding,
)


def test_catalog_implemented_patterns_remain_restricted():
    for code in ("LOTTERY_SCAM", "CREDENTIAL_PHISHING", "URL_CREDENTIALS_IN_AUTHORITY"):
        assert action_for_finding(code) == FindingAction.RESTRICTED
        assert is_hard_block_finding({"code": code, "category": "PHISHING"})


def test_unknown_finding_codes_fail_closed():
    assert action_for_finding("NEW_UNREVIEWED_PATTERN") == FindingAction.RESTRICTED
    assert is_hard_block_finding({"code": "NEW_UNREVIEWED_PATTERN"})


def test_inspection_failures_always_block():
    assert is_hard_block_finding({"code": "ANY_CODE", "category": "INSPECTION_FAILURE"})


def test_warning_codes_are_not_enabled_without_policy_approval():
    assert action_for_finding("IP_ADDRESS_LINK") == FindingAction.RESTRICTED
