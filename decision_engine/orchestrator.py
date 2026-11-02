import logging

from text_validation.rule_checks import inspect_patterns
from url_inspection.url_inspection import inspect_urls
from attachment_scanning.attachment_scanning import scan_attachments, configured_scanner
from html_inspection.html_inspection import inspect_html_content
from decision_engine.decision_aggregator import decide_verdict
from schemas.email import EmailRequest
from schemas.verdict import AnalysisResponse
from ml_classifier.classifier import classify_email
from common.config import settings

logger = logging.getLogger(__name__)


def analyze_email(email: EmailRequest) -> AnalysisResponse:
    """Run configured inspections against the actual outgoing email."""

    findings: list[dict] = []
    checks_complete = True

    coverage = {
        "runtime_text_rules": "complete",
        "html_inspection": "complete",
        "url_syntax_inspection": "complete",
        "ml_classifier": "unavailable_optional",
    }

    model_version = "rules-baseline-v1"

    # Run mandatory content inspections independently.
    checks = (
        (
            "runtime_text_rules",
            lambda: inspect_patterns(email.subject, email.inspection_content),
        ),
        (
            "url_syntax_inspection",
            lambda: inspect_urls(email.inspection_content),
        ),
        (
            "html_inspection",
            lambda: inspect_html_content(email.subject, email.html_content),
        ),
    )

    for name, check in checks:
        try:
            result = check()

            if not isinstance(result, list):
                raise TypeError("Inspection returned an invalid result")

            findings.extend(result)

        except Exception as exc:
            logger.exception("Inspection component failed: %s", name)

            checks_complete = False
            coverage[name] = "failed"

            findings.append(
                {
                    "code": f"{name.upper()}_FAILED",
                    "category": "INSPECTION_FAILURE",
                    "message": (
                        f"The {name.replace('_', ' ')} inspection "
                        f"failed ({type(exc).__name__})."
                    ),
                }
            )

    # Run ML classification with explicit exception handling.
    try:
        ml_result = classify_email(email.subject, email.inspection_content)

        if not isinstance(ml_result, dict):
            raise TypeError("Classifier returned an invalid result")

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
            findings.append(ml_result["finding"])

    elif settings.REQUIRE_ML:
        checks_complete = False
        coverage["ml_classifier"] = "required_but_unavailable"

        findings.append(
            {
                "code": "ML_INSPECTION_INCOMPLETE",
                "category": "INSPECTION_FAILURE",
                "message": (
                    "ML inspection is required but the local trained "
                    "model is unavailable or failed."
                ),
            }
        )

    else:
        coverage["ml_classifier"] = "unavailable_optional"

    # Run attachment inspection with explicit exception handling.
    try:
        attachment_result = scan_attachments(email.attachments, scanner=configured_scanner())

        if (
            not isinstance(attachment_result, dict)
            or not isinstance(attachment_result.get("findings"), list)
        ):
            attachment_result = {
                "completed": False,
                "safe": False,
                "findings": [{
                    "code": "ATTACHMENT_SCAN_INCOMPLETE",
                    "category": "INSPECTION_FAILURE",
                    "message": "Attachment inspection returned an invalid response.",
                }],
            }
        elif (
            attachment_result.get("completed") is not True
            or attachment_result.get("safe") is not True
        ):
            # Preserve the scanner's concrete failure code (e.g. the integration
            # placeholder) instead of obscuring it with a generic finding.
            attachment_findings = list(attachment_result["findings"])
            if not any(
                isinstance(item, dict)
                and item.get("category") == "INSPECTION_FAILURE"
                for item in attachment_findings
            ):
                attachment_findings.append({
                    "code": "ATTACHMENT_SCAN_INCOMPLETE",
                    "category": "INSPECTION_FAILURE",
                    "message": "Attachment inspection did not complete with a valid safe result.",
                })
            attachment_result = {
                "completed": False,
                "safe": False,
                "findings": attachment_findings,
            }

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

    return decide_verdict(
        findings,
        attachment_result,
        checks_complete=checks_complete,
        coverage=coverage,
        model_version=model_version,
    )
