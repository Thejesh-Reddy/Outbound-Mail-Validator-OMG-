from app.schemas.verdict import AnalysisResponse, Finding
from app.checks.pattern_catalog import get_catalog_summary
from app.pipeline.finding_policy import is_hard_block_finding


def decide_verdict(
    findings: list[dict],
    attachment_scan: dict,
    checks_complete: bool = True,
    coverage: dict[str, str] | None = None,
    model_version: str = "rules-baseline-v1",
    safety_score: float | None = None,
) -> AnalysisResponse:
    """Apply the three-state safety policy.

    Scores are safety scores (higher means safer), not raw classifier confidence.
    If no validated score is supplied, a clean result may pass the currently
    implemented mandatory inspections, but no numeric score is fabricated.
    """
    all_findings = list(findings)
    attachment_findings = (
        attachment_scan.get("findings", [])
        if isinstance(attachment_scan, dict) else []
    )
    if isinstance(attachment_findings, list):
        all_findings.extend(x for x in attachment_findings if isinstance(x, dict))
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
    if not attachment_complete and not any(
        x.get("category") == "INSPECTION_FAILURE" for x in all_findings
    ):
        all_findings.append({
            "code": "ATTACHMENT_SCAN_INCOMPLETE",
            "category": "INSPECTION_FAILURE",
            "message": "Attachment inspection did not complete successfully.",
        })
    if not checks_complete and not any(
        x.get("category") == "INSPECTION_FAILURE" for x in all_findings
    ):
        all_findings.append({
            "code": "REQUIRED_INSPECTION_INCOMPLETE",
            "category": "INSPECTION_FAILURE",
            "message": "One or more required inspection components did not complete.",
        })

    # Unknown and unreviewed finding codes remain blocking. The central policy
    # registry is the only place where warning eligibility may be approved.
    mandatory_complete = checks_complete and attachment_complete
    hard_block = any(is_hard_block_finding(item) for item in all_findings) or not mandatory_complete

    if safety_score is not None and not 0 <= safety_score <= 100:
        raise ValueError("safety_score must be between 0 and 100")

    if hard_block or (safety_score is not None and safety_score < 75):
        status = "RESTRICTED"
    elif safety_score is not None and safety_score < 86:
        status = "WARNING"
    else:
        # A missing score is not converted into a fabricated 100. SAFE here
        # means only that currently implemented mandatory checks found no
        # blocking condition; inspection coverage and limitations are returned.
        status = "SAFE"

    catalog = get_catalog_summary()
    merged_coverage = {
        "registered_catalog_entries": str(catalog["total_patterns"]),
        "catalog_entries_marked_implemented": str(catalog["implemented_patterns"]),
        "catalog_only_entries": str(catalog["catalog_only_patterns"]),
        "runtime_text_rules": "complete",
        "html_inspection": "complete",
        "url_syntax_inspection": "complete",
        "url_reputation": "not_implemented",
        "attachment_scan": (
            attachment_scan.get("status", "complete")
            if attachment_complete and isinstance(attachment_scan, dict)
            else "incomplete"
        ),
        "mandatory_inspections": "complete" if mandatory_complete else "incomplete",
    }
    if coverage:
        merged_coverage.update(coverage)

    unique = []
    seen = set()
    for item in all_findings:
        key = (item.get("code"), item.get("category"), item.get("message"))
        if key not in seen:
            seen.add(key)
            unique.append(item)

    is_warning = status == "WARNING"
    return AnalysisResponse(
        status=status,
        can_send=(status == "SAFE"),
        confidence_score=round(float(safety_score), 2) if safety_score is not None else None,
        warning_required=is_warning,
        requires_acknowledgement=is_warning,
        patterns_detected=sorted({
            x.get("code", "UNKNOWN_FINDING") for x in unique
        }),
        findings=[Finding(**x) for x in unique],
        inspection_coverage=merged_coverage,
        model_version=model_version,
    )
