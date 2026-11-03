"""Deterministic heuristic safety scoring for completed OMG inspections.

The score is a rule-based indicator, not a probability or measured accuracy.
Finding penalties and component weights are initial policy values and must be
validated against an independent, representative labelled holdout set.
"""
from __future__ import annotations

from collections.abc import Iterable

COMPONENT_WEIGHTS = {
    "text": 35.0,
    "html": 20.0,
    "urls": 25.0,
    "attachments": 20.0,
}

# Explicit code penalties take precedence over category fallback penalties.
# These values are policy tuning parameters, not empirically calibrated risks.
CODE_PENALTIES = {
    "LOTTERY_SCAM": 75.0,
    "CREDENTIAL_PHISHING": 80.0,
    "URL_CREDENTIALS_PRESENT": 90.0,
    "URL_CREDENTIALS_IN_AUTHORITY": 90.0,
    "ATTACHMENT_MALWARE_DETECTED": 100.0,
    "ATTACHMENT_SCAN_UNAVAILABLE": 100.0,
    "ATTACHMENT_SCAN_TIMEOUT": 100.0,
    "ATTACHMENT_SCANNER_ERROR": 100.0,
    "ATTACHMENT_SCAN_ERROR": 100.0,
    "ATTACHMENT_SCAN_INCOMPLETE": 100.0,
    "ATTACHMENT_CONTENT_MISSING": 100.0,
    "ATTACHMENT_ENCODING_INVALID": 100.0,
    "ATTACHMENT_EMPTY": 100.0,
    "ATTACHMENT_TOO_LARGE": 100.0,
    "ATTACHMENTS_TOTAL_TOO_LARGE": 100.0,
}

CATEGORY_PENALTIES = {
    "INSPECTION_FAILURE": 100.0,
    "MALWARE": 100.0,
    "FRAUD": 70.0,
    "PHISHING": 75.0,
    "CREDENTIAL_THEFT": 75.0,
    "SOCIAL_ENGINEERING": 60.0,
    "SUSPICIOUS_LINK": 55.0,
    "SUSPICIOUS_CONTENT": 35.0,
    "SPAM": 35.0,
    "ML_CLASSIFICATION": 50.0,
}

UNKNOWN_FINDING_PENALTY = 50.0


def _penalty_for(finding: dict) -> float:
    code = str(finding.get("code", "")).strip().upper()
    category = str(finding.get("category", "")).strip().upper()
    return CODE_PENALTIES.get(
        code,
        CATEGORY_PENALTIES.get(category, UNKNOWN_FINDING_PENALTY),
    )


def score_findings(findings: Iterable[dict]) -> float:
    """Return a 0-100 component score after applying unique finding penalties."""
    seen: set[tuple[str, str, str]] = set()
    total_penalty = 0.0
    for finding in findings:
        if not isinstance(finding, dict):
            total_penalty += UNKNOWN_FINDING_PENALTY
            continue
        key = (
            str(finding.get("code", "UNKNOWN_FINDING")),
            str(finding.get("category", "UNSPECIFIED")),
            str(finding.get("message", "")),
        )
        if key in seen:
            continue
        seen.add(key)
        total_penalty += _penalty_for(finding)
    return round(max(0.0, 100.0 - total_penalty), 2)


def calculate_safety_score(
    *,
    text_findings: list[dict],
    html_findings: list[dict],
    url_findings: list[dict],
    attachment_scan: dict,
    checks_complete: bool,
    html_applicable: bool,
    attachments_present: bool,
) -> tuple[float, dict[str, float | None]]:
    """Calculate weighted score; incomplete mandatory scans conservatively score 0."""
    attachment_complete = (
        isinstance(attachment_scan, dict)
        and attachment_scan.get("completed") is True
        and attachment_scan.get("safe") is True
    )

    breakdown: dict[str, float | None] = {
        "text": score_findings(text_findings),
        "html": score_findings(html_findings) if html_applicable else None,
        "urls": score_findings(url_findings),
        "attachments": (
            score_findings(attachment_scan.get("findings", []))
            if attachments_present and isinstance(attachment_scan, dict)
            else (100.0 if attachments_present else None)
        ),
    }

    if not checks_complete or (attachments_present and not attachment_complete):
        if not checks_complete:
            # Keep component-level evidence, but don't present an incomplete
            # mandatory pipeline as a high safety score.
            for key in ("text", "html", "urls"):
                if breakdown[key] is not None:
                    breakdown[key] = min(float(breakdown[key]), 0.0)
        if attachments_present and not attachment_complete:
            breakdown["attachments"] = 0.0
        return 0.0, breakdown

    applicable = [
        (name, score, COMPONENT_WEIGHTS[name])
        for name, score in breakdown.items()
        if score is not None
    ]
    if not applicable:
        return 0.0, breakdown

    total_weight = sum(weight for _, _, weight in applicable)
    weighted_score = sum(float(score) * weight for _, score, weight in applicable) / total_weight
    return round(weighted_score, 2), breakdown
