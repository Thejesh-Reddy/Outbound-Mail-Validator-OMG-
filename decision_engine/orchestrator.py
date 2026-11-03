import logging
import re
from pathlib import Path

from Content.text_validator import inspect_patterns
from URL.url_validator import inspect_urls
from Attachments.attachment_validator import (
    scan_attachments,
    configured_scanner,
)
from Content.html_validator import inspect_html_content
from decision_engine.decision_aggregator import decide_verdict
from schemas.email import EmailRequest
from schemas.verdict import AnalysisResponse
from ml_classifier.classifier import classify_email
from common.config import settings
from decision_engine.scoring import calculate_safety_score
from decision_engine.finding_policy import action_for_finding, FindingAction

logger = logging.getLogger(__name__)


def _extract_urls(content: str) -> list[str]:
    """Extract HTTP and HTTPS URLs for the API response."""

    if not content:
        return []

    matches = re.findall(
        r"""https?://[^\s<>"']+""",
        content,
        flags=re.IGNORECASE,
    )

    urls = []

    for url in matches:
        url = url.rstrip(".,;:!?)\"]}")

        if url and url not in urls:
            urls.append(url)

    return urls


def analyze_email(email: EmailRequest) -> AnalysisResponse:
    """Run configured inspections against the actual outgoing email."""

    findings: list[dict] = []
    checks_complete = True

    inspection_results = {
        "text": [],
        "html": [],
        "urls": [],
        "detected_urls": [],
        "text_applicable": bool(
            email.subject or email.inspection_content
        ),
        "html_applicable": bool(email.html_content),
    }

    coverage = {
        "runtime_text_rules": "complete",
        "html_inspection": "complete",
        "url_syntax_inspection": "complete",
        "ml_classifier": "unavailable_optional",
    }

    model_version = "rules-baseline-v1"

    # Run mandatory inspections independently.
    checks = (
        (
            "runtime_text_rules",
            "text",
            lambda: inspect_patterns(
                email.subject,
                email.inspection_content,
            ),
        ),
        (
            "url_syntax_inspection",
            "urls",
            lambda: inspect_urls(email.inspection_content),
        ),
        (
            "html_inspection",
            "html",
            lambda: inspect_html_content(
                email.subject,
                email.html_content,
            ),
        ),
    )

    for name, result_key, check in checks:
        try:
            result = check()

            if not isinstance(result, list):
                raise TypeError(
                    "Inspection returned an invalid result"
                )

            inspection_results[result_key].extend(result)
            findings.extend(result)

        except Exception as exc:
            logger.exception(
                "Inspection component failed: %s",
                name,
            )

            checks_complete = False
            coverage[name] = "failed"

            failure_finding = {
                "code": f"{name.upper()}_FAILED",
                "category": "INSPECTION_FAILURE",
                "message": (
                    f"The {name.replace('_', ' ')} inspection "
                    f"failed ({type(exc).__name__})."
                ),
            }

            findings.append(failure_finding)
            inspection_results[result_key].append(
                failure_finding
            )

    # Extract URLs from the available email content.
    url_content = "\n".join(
        filter(
            None,
            [
                email.inspection_content,
                email.html_content,
            ],
        )
    )

    inspection_results["detected_urls"] = _extract_urls(
        url_content
    )

    # Run ML classification.
    try:
        ml_result = classify_email(
            email.subject,
            email.inspection_content,
        )

        if not isinstance(ml_result, dict):
            raise TypeError(
                "Classifier returned an invalid result"
            )

    except Exception as exc:
        logger.exception("ML classifier failed")

        ml_result = {
            "available": False,
            "completed": False,
            "finding": None,
            "reason": type(exc).__name__,
        }

    if ml_result.get("completed") is True:
        coverage["ml_classifier"] = "complete"

        model_version = ml_result.get(
            "model_version",
            model_version,
        )

        if ml_result.get("finding"):
            ml_finding = ml_result["finding"]

            if isinstance(ml_finding, dict):
                findings.append(ml_finding)
                inspection_results["text"].append(
                    ml_finding
                )

    elif settings.REQUIRE_ML:
        checks_complete = False
        coverage["ml_classifier"] = (
            "required_but_unavailable"
        )

        ml_failure = {
            "code": "ML_INSPECTION_INCOMPLETE",
            "category": "INSPECTION_FAILURE",
            "message": (
                "ML inspection is required but the local trained "
                "model is unavailable or failed."
            ),
        }

        findings.append(ml_failure)
        inspection_results["text"].append(ml_failure)

    else:
        coverage["ml_classifier"] = "unavailable_optional"

    # Run attachment inspection.
    try:
        scanner = configured_scanner()

        attachment_result = scan_attachments(
            email.attachments,
            scanner=scanner,
        )

        if (
            not isinstance(attachment_result, dict)
            or not isinstance(
                attachment_result.get("findings"),
                list,
            )
        ):
            attachment_result = {
                "completed": False,
                "safe": False,
                "findings": [
                    {
                        "code": "ATTACHMENT_SCAN_INCOMPLETE",
                        "category": "INSPECTION_FAILURE",
                        "message": (
                            "Attachment inspection returned "
                            "an invalid response."
                        ),
                    }
                ],
            }

        elif (
            attachment_result.get("completed") is not True
            or attachment_result.get("safe") is not True
        ):
            attachment_findings = list(
                attachment_result["findings"]
            )

            if not any(
                isinstance(item, dict)
                and item.get("category") == "INSPECTION_FAILURE"
                for item in attachment_findings
            ):
                attachment_findings.append({
                    "code": "ATTACHMENT_SCAN_INCOMPLETE",
                    "category": "INSPECTION_FAILURE",
                    "message": (
                        "Attachment inspection did not complete "
                        "with a valid safe result."
                    ),
                })

            attachment_result = {
                **attachment_result,
                "completed": False,
                "safe": False,
                "findings": attachment_findings,
            }

        # Inform the API consumer when antivirus is not configured.
        if scanner is None and email.attachments:
            existing_warnings = attachment_result.get(
                "warnings", []
            )

            if not isinstance(existing_warnings, list):
                existing_warnings = []

            warning_message = "Malware scanning is disabled."

            if warning_message not in existing_warnings:
                existing_warnings.append(warning_message)

            attachment_result["warnings"] = existing_warnings

    except Exception as exc:
        logger.exception("Attachment inspection failed")

        attachment_result = {
            "completed": False,
            "safe": False,
            "findings": [
                {
                    "code": "ATTACHMENT_SCAN_ERROR",
                    "category": "INSPECTION_FAILURE",
                    "message": (
                        "Attachment inspection failed "
                        f"({type(exc).__name__})."
                    ),
                }
            ],
        }

    # Calculate a deterministic heuristic score from the inspection findings.
    # This is not a calibrated probability or a measured accuracy percentage.
    safety_score, score_breakdown = calculate_safety_score(
        text_findings=inspection_results["text"],
        html_findings=inspection_results["html"],
        url_findings=inspection_results["urls"],
        attachment_scan=attachment_result,
        checks_complete=checks_complete,
        html_applicable=inspection_results["html_applicable"],
        attachments_present=bool(email.attachments),
    )

    # The scanner currently returns an aggregate result. Build per-file response
    # summaries without claiming a MIME type that has not been independently
    # detected. A failed aggregate scan blocks every supplied attachment.
    attachment_items = []
    for item in email.attachments:
        if not isinstance(item, dict):
            continue
        scan_ok = (
            attachment_result.get("completed") is True
            and attachment_result.get("safe") is True
        )
        if scan_ok:
            scan_status = "SAFE"
            antivirus_status = "CLAMAV_CLEAN"
            issue_items = []
            attachment_score = 100.0
        else:
            scan_status = "RESTRICTED"
            unavailable = any(
                f.get("code") == "ATTACHMENT_SCAN_UNAVAILABLE"
                for f in attachment_result.get("findings", [])
                if isinstance(f, dict)
            )
            antivirus_status = "NOT_CONFIGURED" if unavailable else "SCAN_FAILED_OR_UNSAFE"
            issue_items = []
            for finding in attachment_result.get("findings", []):
                if not isinstance(finding, dict):
                    continue
                action = action_for_finding(finding.get("code"))
                severity = (
                    "CRITICAL" if finding.get("category") == "INSPECTION_FAILURE"
                    or action == FindingAction.RESTRICTED
                    else "MINOR" if action == FindingAction.WARNING
                    else "LOW"
                )
                issue_items.append({
                    "code": finding.get("code", "ATTACHMENT_SCAN_INCOMPLETE"),
                    "severity": severity,
                    "reason": finding.get("message", "Attachment scan did not confirm safety."),
                })
            attachment_score = 0.0

        filename = str(item.get("filename") or "unnamed_attachment")
        # Report the file extension as the detected type label when available.
        # This is a filename-derived label, not independent content/MIME validation.
        extension = Path(filename).suffix.lstrip(".").upper()
        declared_type = str(item.get("content_type") or "").strip()
        detected_type = extension or (declared_type.split("/")[-1].upper() if "/" in declared_type else None)
        attachment_items.append({
            "filename": filename,
            "status": scan_status,
            "detected_type": detected_type or None,
            "antivirus": antivirus_status,
            "confidence_score": attachment_score,
            "issues": issue_items,
        })

    attachment_result["attachments"] = attachment_items

    # Generate the combined API response.
    return decide_verdict(
        findings=findings,
        attachment_scan=attachment_result,
        checks_complete=checks_complete,
        coverage=coverage,
        model_version=model_version,
        inspection_results=inspection_results,
        safety_score=safety_score,
        score_breakdown=score_breakdown,
    )
