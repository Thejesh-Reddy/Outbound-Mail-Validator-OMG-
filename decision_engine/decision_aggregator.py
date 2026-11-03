from schemas.verdict import AnalysisResponse, InspectionIssue, AttachmentResult, PopupAction
from decision_engine.finding_policy import action_for_finding, FindingAction, is_hard_block_finding


def _severity_for(finding: dict) -> str:
    """Map the approved central finding action to the response severity."""
    if finding.get("category") == "INSPECTION_FAILURE":
        return "CRITICAL"
    action = action_for_finding(finding.get("code"))
    if action == FindingAction.RESTRICTED:
        return "CRITICAL"
    if action == FindingAction.WARNING:
        return "MINOR"
    return "LOW"


def _issues(findings: list[dict]) -> list[InspectionIssue]:
    result: list[InspectionIssue] = []
    seen: set[tuple[str, str]] = set()
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        code = str(finding.get("code") or "UNKNOWN_FINDING")
        reason = str(finding.get("message") or "No additional details available.")
        key = (code, reason)
        if key in seen:
            continue
        seen.add(key)
        result.append(InspectionIssue(
            code=code,
            severity=_severity_for(finding),
            reason=reason,
        ))
    return result


def _popup(
    status: str,
    text_findings: list[dict],
    url_findings: list[dict],
    attachment_findings: list[dict],
) -> PopupAction | None:

    if status == "WARNING":
        return PopupAction(
            show=True,
            type="WARNING",
            title="Email Warning",
            message="Review the email content before sending.",
            actions=["EDIT_MAIL", "CLOSE"],
        )

    if status != "RESTRICTED":
        return None

    all_findings = text_findings + url_findings + attachment_findings

    attachment_codes = {
        "ATTACHMENT_MALWARE_DETECTED",
        "PDF_ACTIVE_CONTENT",
        "ATTACHMENT_SCAN_UNAVAILABLE",
        "ATTACHMENT_SCAN_INCOMPLETE",
        "PROHIBITED_ATTACHMENT_TYPE",
        "DISGUISED_EXECUTABLE_FILENAME",
        "FILE_SIGNATURE_MISMATCH",
    }

    url_codes = {
        "NON_HTTP_LINK",
        "MALFORMED_URL",
        "URL_CREDENTIALS_PRESENT",
        "URL_CREDENTIALS_IN_AUTHORITY",
        "IP_ADDRESS_LINK",
        "INVALID_HOSTNAME",
        "IDN_HOSTNAME",
        "LINK_TEXT_MISMATCH",
    }

    detected_codes = {
        str(item.get("code", "")).upper()
        for item in all_findings
        if isinstance(item, dict)
    }

    if detected_codes & attachment_codes:
        return PopupAction(
            show=True,
            type="RESTRICTED",
            title="Attachment Restricted",
            message="Remove the restricted attachment or discard the email.",
            actions=["DISCARD_MAIL"],
        )

    if detected_codes & url_codes:
        return PopupAction(
            show=True,
            type="RESTRICTED",
            title="URL Restricted",
            message="Remove the suspicious link or discard the email.",
            actions=["DISCARD_MAIL"],
        )

    return PopupAction(
        show=True,
        type="RESTRICTED",
        title="Email Restricted",
        message="This email contains restricted content and cannot be sent.",
        actions=["DISCARD_MAIL"],
    )
def decide_verdict(
    findings: list[dict],
    attachment_scan: dict,
    checks_complete: bool = True,
    coverage: dict[str, str] | None = None,
    model_version: str = "rules-baseline-v1",
    safety_score: float | None = None,
    inspection_results: dict | None = None,
    score_breakdown: dict[str, float | None] | None = None,
) -> AnalysisResponse:
    """Build only the agreed Notify response fields; internal diagnostics stay internal."""
    all_findings = [item for item in findings if isinstance(item, dict)]
    inspection_results = inspection_results or {}

    attachment_findings = attachment_scan.get("findings", []) if isinstance(attachment_scan, dict) else []
    if isinstance(attachment_findings, list):
        all_findings.extend(item for item in attachment_findings if isinstance(item, dict))
    else:
        checks_complete = False
        all_findings.append({
            "code": "ATTACHMENT_SCAN_INCOMPLETE",
            "category": "INSPECTION_FAILURE",
            "message": "Attachment scanner returned an invalid response.",
        })

    attachment_complete = (
        isinstance(attachment_scan, dict)
        and attachment_scan.get("completed") is True
        and attachment_scan.get("safe") is True
    )
    if not attachment_complete and not any(x.get("category") == "INSPECTION_FAILURE" for x in all_findings):
        all_findings.append({
            "code": "ATTACHMENT_SCAN_INCOMPLETE",
            "category": "INSPECTION_FAILURE",
            "message": "Attachment inspection did not complete successfully.",
        })
    if not checks_complete and not any(x.get("category") == "INSPECTION_FAILURE" for x in all_findings):
        all_findings.append({
            "code": "REQUIRED_INSPECTION_INCOMPLETE",
            "category": "INSPECTION_FAILURE",
            "message": "One or more required inspection components did not complete.",
        })

    mandatory_complete = checks_complete and attachment_complete
    hard_block = any(is_hard_block_finding(item) for item in all_findings) or not mandatory_complete

    # A numeric score is always returned. Pipeline failures are conservatively zero.
    if safety_score is None:
        safety_score = 0.0 if hard_block else 100.0
    if not 0 <= safety_score <= 100:
        raise ValueError("safety_score must be between 0 and 100")

    if hard_block or safety_score < 75:
        status = "RESTRICTED"
    elif safety_score < 86:
        status = "WARNING"
    else:
        status = "SAFE"

    text_findings = list(inspection_results.get("text", []))
    # HTML-specific findings are represented in the agreed `text` issue array;
    # the reference response has no separate top-level `html` field.
    text_findings.extend(inspection_results.get("html", []))
    url_findings = list(inspection_results.get("urls", []))

    # Include any pipeline failures that were attached to the text inspection.
    text_issues = _issues(text_findings)
    url_issues = _issues(url_findings)

    attachment_items = attachment_scan.get("attachments", []) if isinstance(attachment_scan, dict) else []
    if not isinstance(attachment_items, list):
        attachment_items = []
    attachments = [AttachmentResult.model_validate(item) for item in attachment_items]

    warnings = attachment_scan.get("warnings", []) if isinstance(attachment_scan, dict) else []
    if not isinstance(warnings, list):
        warnings = []

    # A WARNING acknowledgement token is not generated here: the project does
    # not yet have a user-bound challenge/verification endpoint. Do not invent one.
    return AnalysisResponse(
        status=status,
        can_send=(status == "SAFE"),
        confidence_score=round(float(safety_score), 2),
        requires_acknowledgement=(status == "WARNING"),
        text=text_issues,
        URL=url_issues,
        attachments=attachments,
        warnings=warnings,
        popup=_popup(
        status,
        text_findings,
        url_findings,
        attachment_findings if isinstance(attachment_findings, list) else [],
        ),
        # Match the reference WARNING response shape without creating a token,
        # database, endpoint, or acknowledgement infrastructure.
        **({"warning_challenge": None} if status == "WARNING" else {}),
    )
