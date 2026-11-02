"""Central severity policy for findings produced by OMG inspections.

The initial Stage 2 policy deliberately preserves the existing fail-closed
behaviour: every known or unknown finding is blocking until its code has been
reviewed and explicitly assigned a less restrictive action.
"""
from enum import Enum


class FindingAction(str, Enum):
    INFORMATIONAL = "INFORMATIONAL"
    WARNING = "WARNING"
    RESTRICTED = "RESTRICTED"


# These are the three patterns explicitly marked implemented in the 156-entry
# catalog. Their catalog default action is RESTRICTED when confirmed.
CATALOG_CRITICAL_CODES = frozenset({
    "LOTTERY_SCAM",
    "CREDENTIAL_PHISHING",
    "URL_CREDENTIALS_IN_AUTHORITY",
})

# Runtime inspection codes not yet reviewed for warning eligibility remain
# restricted by default. Do not add codes here without policy approval and tests.
WARNING_ELIGIBLE_CODES: frozenset[str] = frozenset()
INFORMATIONAL_CODES: frozenset[str] = frozenset()


def action_for_finding(code: str | None) -> FindingAction:
    """Return the approved action for a finding code; unknown codes fail closed."""
    normalized = (code or "").strip().upper()
    if normalized in CATALOG_CRITICAL_CODES:
        return FindingAction.RESTRICTED
    if normalized in WARNING_ELIGIBLE_CODES:
        return FindingAction.WARNING
    if normalized in INFORMATIONAL_CODES:
        return FindingAction.INFORMATIONAL
    return FindingAction.RESTRICTED


def is_hard_block_finding(finding: dict) -> bool:
    """Whether a finding must force a RESTRICTED verdict."""
    if not isinstance(finding, dict):
        return True
    if finding.get("category") == "INSPECTION_FAILURE":
        return True
    return action_for_finding(finding.get("code")) == FindingAction.RESTRICTED
