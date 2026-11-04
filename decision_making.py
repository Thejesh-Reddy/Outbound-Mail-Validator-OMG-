"""OMG inspection orchestration, scoring and three-verdict policy."""
from __future__ import annotations

import logging
import re
from enum import Enum
from typing import Iterable

from app import settings
from Content.text_validator import inspect_patterns
from Content.html_validator import inspect_html_content
from URL.url_validator import inspect_urls
from schemas.email import EmailRequest
from schemas.verdict import AnalysisResponse, InspectionIssue, PopupAction

logger = logging.getLogger(__name__)


class FindingAction(str, Enum):
    INFORMATIONAL = "INFORMATIONAL"
    WARNING = "WARNING"
    RESTRICTED = "RESTRICTED"


EXPLICIT_RESTRICTED_CODES = frozenset({
    "LEARNED_PATTERN_RESTRICTED",
    "HTML_PASSWORD_CAPTURE_FORM",
    "URL_CREDENTIALS_PRESENT",
    "URL_CREDENTIALS_IN_AUTHORITY",
    "NON_HTTP_LINK",
    "MALFORMED_URL",
    "INVALID_HOSTNAME",
})
WARNING_ELIGIBLE_CODES = frozenset({
    "LEARNED_PATTERN_WARNING",
    "HIDDEN_HTML_TEXT",
    "IP_ADDRESS_LINK",
    "IDN_HOSTNAME",
    "LINK_TEXT_MISMATCH",
})
INFORMATIONAL_CODES: frozenset[str] = frozenset()


def action_for_finding(code: str | None) -> FindingAction:
    normalized = (code or "").strip().upper()
    if normalized in EXPLICIT_RESTRICTED_CODES:
        return FindingAction.RESTRICTED
    if normalized in WARNING_ELIGIBLE_CODES:
        return FindingAction.WARNING
    if normalized in INFORMATIONAL_CODES:
        return FindingAction.INFORMATIONAL
    # Unknown findings fail closed.
    return FindingAction.RESTRICTED


def is_hard_block_finding(finding: dict) -> bool:
    if not isinstance(finding, dict) or finding.get("category") == "INSPECTION_FAILURE":
        return True
    return action_for_finding(finding.get("code")) == FindingAction.RESTRICTED


COMPONENT_WEIGHTS = {"text": 35.0, "html": 20.0, "urls": 25.0}
CODE_PENALTIES = {
    "LEARNED_PATTERN_WARNING": 15.0,
    "LEARNED_PATTERN_RESTRICTED": 75.0,
    "HIDDEN_HTML_TEXT": 15.0,
    "IP_ADDRESS_LINK": 20.0,
    "IDN_HOSTNAME": 15.0,
    "LINK_TEXT_MISMATCH": 20.0,
    "HTML_PASSWORD_CAPTURE_FORM": 90.0,
    "URL_CREDENTIALS_PRESENT": 90.0,
    "URL_CREDENTIALS_IN_AUTHORITY": 90.0,
    "NON_HTTP_LINK": 60.0,
    "MALFORMED_URL": 60.0,
    "INVALID_HOSTNAME": 60.0,
}
CATEGORY_PENALTIES = {
    "INSPECTION_FAILURE": 100.0,
    "MALWARE": 100.0,
    "FRAUD": 70.0,
    "PHISHING": 75.0,
    "CREDENTIAL_THEFT": 90.0,
    "SOCIAL_ENGINEERING": 60.0,
    "SUSPICIOUS_LINK": 55.0,
    "SUSPICIOUS_CONTENT": 20.0,
    "SPAM": 75.0,
}
UNKNOWN_FINDING_PENALTY = 50.0


def _penalty_for(finding: dict) -> float:
    code = str(finding.get("code", "")).strip().upper()
    category = str(finding.get("category", "")).strip().upper()
    return CODE_PENALTIES.get(code, CATEGORY_PENALTIES.get(category, UNKNOWN_FINDING_PENALTY))


def score_findings(findings: Iterable[dict]) -> float:
    seen = set()
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
    *, text_findings: list[dict], html_findings: list[dict],
    url_findings: list[dict], checks_complete: bool, html_applicable: bool,
) -> tuple[float, dict[str, float | None]]:
    breakdown = {
        "text": score_findings(text_findings),
        "html": score_findings(html_findings) if html_applicable else None,
        "urls": score_findings(url_findings),
    }
    applicable = [
        (name, score, COMPONENT_WEIGHTS[name])
        for name, score in breakdown.items() if score is not None
    ]
    if not checks_complete or not applicable:
        return 0.0, breakdown
    total_weight = sum(weight for _, _, weight in applicable)
    score = sum(float(value) * weight for _, value, weight in applicable) / total_weight
    return round(score, 2), breakdown


def _severity_for(finding: dict) -> str:
    if finding.get("category") == "INSPECTION_FAILURE":
        return "CRITICAL"
    action = action_for_finding(finding.get("code"))
    if action == FindingAction.RESTRICTED:
        return "CRITICAL"
    if action == FindingAction.WARNING:
        return "MEDIUM"
    return "LOW"


def _issues(findings: list[dict]) -> list[InspectionIssue]:
    result, seen = [], set()
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        code = str(finding.get("code") or "UNKNOWN_FINDING")
        reason = str(finding.get("message") or "No additional details available.")
        if (code, reason) in seen:
            continue
        seen.add((code, reason))
        result.append(InspectionIssue(code=code, severity=_severity_for(finding), reason=reason))
    return result


def _warning_message(text_findings: list[dict], url_findings: list[dict]) -> str:
    """Build a concise explanation from the actual warning findings."""
    warning_findings = [
        item for item in text_findings + url_findings
        if isinstance(item, dict)
        and action_for_finding(item.get("code")) == FindingAction.WARNING
    ]
    reasons = []
    for item in warning_findings:
        reason = str(item.get("message") or "").strip()
        if reason and reason not in reasons:
            reasons.append(reason)
    if reasons:
        return "Review this email before sending: " + " ".join(reasons)
    return "The email received a WARNING verdict. Review its content carefully before sending."


def _popup(
    status: str, text_findings: list[dict], url_findings: list[dict],
    warning_message: str,
) -> PopupAction | None:
    if status == "WARNING":
        return PopupAction(
            show=True, type="WARNING", title="Email Security Warning",
            message=warning_message,
            actions=["SEND_ANYWAY", "EDIT_MAIL"],
        )
    if status != "RESTRICTED":
        return None
    codes = {
        str(item.get("code", "")).upper()
        for item in text_findings + url_findings if isinstance(item, dict)
    }
    url_codes = {
        "NON_HTTP_LINK", "MALFORMED_URL", "URL_CREDENTIALS_PRESENT",
        "URL_CREDENTIALS_IN_AUTHORITY", "IP_ADDRESS_LINK", "INVALID_HOSTNAME",
        "IDN_HOSTNAME", "LINK_TEXT_MISMATCH",
    }
    if codes & url_codes:
        title, message = "URL Restricted", "Remove the suspicious link or discard the email."
    else:
        title, message = "Email Restricted", "This email contains restricted content and cannot be sent."
    return PopupAction(show=True, type="RESTRICTED", title=title, message=message, actions=["DISCARD_MAIL"])


def decide_verdict(
    findings: list[dict], checks_complete: bool = True,
    inspection_results: dict | None = None, safety_score: float | None = None,
) -> AnalysisResponse:
    all_findings = [item for item in findings if isinstance(item, dict)]
    if not checks_complete and not any(x.get("category") == "INSPECTION_FAILURE" for x in all_findings):
        all_findings.append({
            "code": "REQUIRED_INSPECTION_INCOMPLETE",
            "category": "INSPECTION_FAILURE",
            "message": "One or more required inspection components did not complete.",
        })

    hard_block = any(is_hard_block_finding(item) for item in all_findings) or not checks_complete
    if safety_score is None:
        safety_score = 0.0 if hard_block else 100.0
    if not 0 <= safety_score <= 100:
        raise ValueError("safety_score must be between 0 and 100")

    has_warning = any(action_for_finding(x.get("code")) == FindingAction.WARNING for x in all_findings)
    if hard_block or safety_score < 75:
        status = "RESTRICTED"
    elif has_warning or safety_score < 86:
        status = "WARNING"
    else:
        status = "SAFE"

    inspection_results = inspection_results or {}
    text_findings = list(inspection_results.get("text", []))
    text_findings.extend(inspection_results.get("html", []))
    url_findings = list(inspection_results.get("urls", []))

    warning_message = _warning_message(text_findings, url_findings) if status == "WARNING" else (
        "Email passed the configured security checks." if status == "SAFE" else
        "This email is restricted and cannot be sent."
    )
    return AnalysisResponse(
        status=status,
        # SAFE can proceed directly. WARNING requires Notify to obtain
        # explicit user acknowledgement before sending. RESTRICTED is blocked.
        can_send=(status in {"SAFE", "WARNING"}),
        confidence_score=round(float(safety_score), 2),
        requires_acknowledgement=(status == "WARNING"),
        text=_issues(text_findings),
        URL=_issues(url_findings),
        # The warning explanation is displayed only through popup.message.
        # Keep this list empty to prevent Notify from displaying it twice.
        warnings=[],
        popup=_popup(status, text_findings, url_findings, warning_message),
    )


def analyze_email(email: EmailRequest) -> AnalysisResponse:
    """Run deterministic text, HTML and URL checks; fail closed on errors."""
    findings: list[dict] = []
    checks_complete = True
    results = {"text": [], "html": [], "urls": []}
    checks = (
        ("text", lambda: inspect_patterns(email.subject, email.inspection_content)),
        ("urls", lambda: inspect_urls(email.inspection_content)),
        ("html", lambda: inspect_html_content(email.subject, email.html_content)),
    )
    for result_key, check in checks:
        try:
            output = check()
            if not isinstance(output, list):
                raise TypeError("Inspection returned an invalid result")
            results[result_key].extend(output)
            findings.extend(output)
        except Exception as exc:
            logger.exception("%s inspection failed", result_key)
            checks_complete = False
            failure = {
                "code": f"{result_key.upper()}_INSPECTION_FAILED",
                "category": "INSPECTION_FAILURE",
                "message": f"The {result_key} inspection failed ({type(exc).__name__}).",
            }
            results[result_key].append(failure)
            findings.append(failure)

    score, _ = calculate_safety_score(
        text_findings=results["text"],
        html_findings=results["html"],
        url_findings=results["urls"],
        checks_complete=checks_complete,
        html_applicable=bool(email.html_content),
    )
    if any(
        action_for_finding(item.get("code")) == FindingAction.WARNING
        for item in findings if isinstance(item, dict)
    ):
        score = min(score, 85.0)

    return decide_verdict(
        findings=findings, checks_complete=checks_complete,
        inspection_results=results, safety_score=score,
    )
