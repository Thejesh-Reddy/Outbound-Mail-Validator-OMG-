import logging

from fastapi import APIRouter, Depends, HTTPException

from app.api.auth import require_api_key
from app.checks.pattern_catalog import get_catalog_summary
from app.checks.rule_checks import _load_runtime_rules
from app.checks.attachment_scanning import configured_scanner
from app.core.config import settings
from app.ml.model_loader import ModelUnavailableError, load_model
from app.pipeline.orchestrator import analyze_email
from app.schemas.email import EmailRequest
from app.schemas.verdict import AnalysisResponse

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/health")
def health_check():
    """Liveness probe: the process can answer HTTP requests."""
    return {"service": "OMG", "status": "running"}


@router.get("/ready")
def readiness_check():
    """Readiness probe: report whether configured mandatory components are usable."""
    checks: dict[str, str] = {}
    ready = True

    try:
        _load_runtime_rules()
        checks["runtime_rules"] = "ready"
    except Exception as exc:
        logger.exception("Readiness check failed for runtime rules")
        checks["runtime_rules"] = f"failed:{type(exc).__name__}"
        ready = False

    try:
        get_catalog_summary()
        checks["pattern_catalog"] = "ready"
    except Exception as exc:
        logger.exception("Readiness check failed for pattern catalog")
        checks["pattern_catalog"] = f"failed:{type(exc).__name__}"
        ready = False

    if settings.REQUIRE_ML:
        try:
            load_model(str(settings.resolve_path(settings.MODEL_PATH)))
            checks["ml_classifier"] = "ready"
        except ModelUnavailableError as exc:
            checks["ml_classifier"] = "unavailable"
            logger.warning("Readiness check failed for ML model: %s", type(exc).__name__)
            ready = False
        except Exception as exc:
            checks["ml_classifier"] = f"failed:{type(exc).__name__}"
            ready = False
    else:
        model_path = settings.resolve_path(settings.MODEL_PATH)
        checks["ml_classifier"] = "configured_optional" if model_path.is_file() else "optional_model_missing"

    checks["attachment_scanner"] = (
        "clamav_configured" if configured_scanner() else "unavailable_fail_closed_for_attachments"
    )
    checks["url_reputation"] = "not_implemented"
    payload = {"service": "OMG", "ready": ready, "checks": checks}
    if not ready:
        # Return a machine-readable 503 so orchestrators do not route traffic here.
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=503, content=payload)
    return payload


@router.get("/status", dependencies=[Depends(require_api_key)])
def service_status():
    model_path = settings.resolve_path(settings.MODEL_PATH)
    return {
        "service": "OMG",
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "catalog": get_catalog_summary(),
        "verdicts": ["SAFE", "WARNING", "RESTRICTED"],
        "ml_required": settings.REQUIRE_ML,
        "ml_model_file_present": model_path.is_file(),
        "attachment_scanner": (
            "clamav_configured" if configured_scanner() else "unavailable_fail_closed_for_attachments"
        ),
        "url_reputation": "not_implemented",
    }


@router.post("/analyze", response_model=AnalysisResponse, dependencies=[Depends(require_api_key)])
def analyze(email: EmailRequest):
    try:
        return analyze_email(email)
    except Exception as exc:
        # Do not leak exception text or secrets to callers. Never permit a send on failure.
        logger.exception("Analysis pipeline failed")
        return AnalysisResponse(
            status="RESTRICTED",
            can_send=False,
            patterns_detected=["ANALYSIS_PIPELINE_ERROR"],
            findings=[{
                "code": "ANALYSIS_PIPELINE_ERROR",
                "category": "INSPECTION_FAILURE",
                "message": f"Analysis could not be completed ({type(exc).__name__}).",
            }],
            inspection_coverage={"mandatory_inspections": "incomplete"},
            model_version="fail-closed",
        )
