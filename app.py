
"""
Merged OMG application with MongoDB persistence.

Business endpoint:
    POST /api/v1/analyze

Authorization endpoint:
    POST /api/v1/authorization

Accepts:
    application/json
    multipart/form-data

Validates:
    Email content
    URLs
    Binary attachments

MongoDB:
    Saves completed analysis results against the logged-in account.

This backend validates emails but NEVER sends emails.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import Depends, HTTPException, Query
from bson import ObjectId
import csv
import io
import re
import json
import logging
import os

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from fastapi import (
    FastAPI,
    Request,
    HTTPException,
    Depends,
)

from fastapi.responses import JSONResponse, FileResponse, StreamingResponse
from pydantic import ValidationError

from starlette.concurrency import run_in_threadpool
from starlette.datastructures import UploadFile as StarletteUploadFile
from starlette.exceptions import HTTPException as StarletteHTTPException


# ---------------------------------------------------------
# ENVIRONMENT CONFIGURATION
# ---------------------------------------------------------

load_dotenv(Path(__file__).resolve().parent / ".env")

if (
    os.getenv("OMG_ENV", "").lower() in {"production", "prod"}
    or os.getenv("OMG_ENVIRONMENT", "").lower()
    in {"production", "prod"}
):
    os.environ["OMG_ENV"] = "production"
    os.environ["OMG_ENVIRONMENT"] = "production"


# ---------------------------------------------------------
# EXISTING OMG MODULES
# ---------------------------------------------------------

from decision_making import decide_email

from Attachments.api import format_public_response
from Attachments.attachment_gate import POLICY, read_uploads
from Attachments.attachment_validator import scan_bytes
from Attachments.warning_ack import issue_warning_challenge

from Content.config import settings
from Content.content_validator import validate_content
from Content.email_schema import EmailRequest
from Content.request_middleware import RequestLoggingMiddleware

from URL.url_validator import validate_urls


# ---------------------------------------------------------
# MONGODB MODULES
# ---------------------------------------------------------

from database import (
    users_collection,
    sessions_collection,
    analysis_collection,
    connect_to_mongodb,
    client,
)

from db_repository import save_analysis, get_account_history

from auth import (
    router as auth_router,
    get_current_user,
)


# ---------------------------------------------------------
# LOGGING
# ---------------------------------------------------------

logger = logging.getLogger("omg.email")
logging.basicConfig(level=settings.LOG_LEVEL)


# ---------------------------------------------------------
# RESPONSE HANDLING
# ---------------------------------------------------------

def omit_empty_arrays(value: Any) -> Any:
    """Keep Error arrays while omitting unnecessary empty lists."""

    if isinstance(value, dict):
        return {
            key: omit_empty_arrays(item)
            for key, item in value.items()
            if key == "Error"
            or not (isinstance(item, list) and not item)
        }

    if isinstance(value, list):
        return [omit_empty_arrays(item) for item in value]

    return value


class CompactJSONResponse(JSONResponse):

    def render(self, content: Any) -> bytes:
        return super().render(omit_empty_arrays(content))


# ---------------------------------------------------------
# APPLICATION LIFESPAN AND MONGODB
# ---------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):

    settings.validate_production_configuration()

    # Verify MongoDB connection when the application starts.
    await run_in_threadpool(connect_to_mongodb)

    logger.info("OMG MongoDB connection initialized")

    try:

        if settings.is_production:

            if not POLICY.require_clamav:
                raise RuntimeError(
                    "Production requires ClamAV attachment scanning"
                )

            from Content.rule_checks import _load_runtime_rules
            from Content.model_loader import load_model

            _load_runtime_rules()

            load_model(
                str(settings.resolve_path(settings.MODEL_PATH))
            )

        yield

    finally:

        # Close the MongoDB client when the application stops.
        await run_in_threadpool(client.close)

        logger.info("OMG MongoDB connection closed")


# ---------------------------------------------------------
# FASTAPI APPLICATION
# ---------------------------------------------------------

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    lifespan=lifespan,
    default_response_class=CompactJSONResponse,
    description=(
        "Single security endpoint for email subject, body, HTML, "
        "embedded URLs, and optional binary attachments. "
        "This service does not send emails."
    ),
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None if settings.is_production else "/redoc",
    openapi_url=None if settings.is_production else "/openapi.json",
)

app.add_middleware(RequestLoggingMiddleware)

# Register the consolidated Authorization router exactly once.
# auth.py defines the complete /api/v1/authorization path.
app.include_router(auth_router)

_PREFIX = settings.API_PREFIX


# ---------------------------------------------------------
# OPERATIONAL ENDPOINTS
# ---------------------------------------------------------

@app.get("/portal", include_in_schema=False)
def mail_portal():

    return FileResponse(
        Path(__file__).resolve().parent
        / "frontend/index.html"
    )


FRONTEND_DIR = Path(__file__).resolve().parent / "frontend"

@app.get("/", include_in_schema=False)
async def service_root():
    portal_file = FRONTEND_DIR / "index.html"

    if not portal_file.exists():
        raise HTTPException(
            status_code=404,
            detail="Portal frontend/index.html not found."
        )

    return FileResponse(portal_file)

@app.get("/health", include_in_schema=False)
@app.get(f"{_PREFIX}/health", include_in_schema=False)
def health_check() -> dict:

    return {
        "service": "OMG",
        "status": "running",
    }


def _readiness_checks() -> dict[str, str]:

    rules = settings.resolve_path(settings.RULES_PATH)
    model = settings.resolve_path(settings.MODEL_PATH)

    checks = {

        "content_rules": (
            "present" if rules.is_file() else "missing"
        ),

        "content_engine": "loaded",

        "url_engine": "loaded",

        "attachment_engine": "loaded",

        "required_ml_artifact": (
            "present" if model.is_file() else "missing"
        ) if settings.REQUIRE_ML else "not_required",

        "antivirus": (
            "required_runtime_check"
            if POLICY.require_clamav
            else "not_required_by_policy"
        ),
    }

    return checks


@app.get(
    "/ready",
    include_in_schema=False,
)
@app.get(
    f"{_PREFIX}/ready",
    include_in_schema=False,
)
def readiness_check():

    checks = _readiness_checks()

    ready = (
        checks["content_rules"] == "present"
        and checks["required_ml_artifact"] != "missing"
    )

    data = {
        "service": "OMG",
        "ready": ready,
        "checks": checks,
        "notice": (
            "Antivirus/OCR readiness requires separate runtime checks."
        ),
    }

    if not ready:
        return JSONResponse(
            status_code=503,
            content=data,
        )

    return data


@app.get(
    "/status",
    include_in_schema=False,
    dependencies=[Depends(get_current_user)],
)
@app.get(
    f"{_PREFIX}/status",
    include_in_schema=False,
    dependencies=[Depends(get_current_user)],
)
def service_status() -> dict:

    checks = _readiness_checks()

    return {
        "service": "OMG",
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "verdicts": [
            "SAFE",
            "WARNING",
            "RESTRICTED",
        ],
        "email_validation_endpoint": f"{_PREFIX}/analyze",
        "content_rules": checks["content_rules"],
        "ml_classification": (
            "enabled"
            if settings.ENABLE_ML or settings.REQUIRE_ML
            else "disabled"
        ),
        "experimental_tfidf": (
            "enabled_review_only"
            if settings.ENABLE_EXPERIMENTAL_TFIDF
            else "disabled"
        ),
        "url_reputation": "not_implemented",
        "mail_delivery": "not_implemented",
        "attachment_antivirus": checks["antivirus"],
    }


# ---------------------------------------------------------
# EMAIL REQUEST VALIDATION
# ---------------------------------------------------------

def _valid_email(data: dict[str, Any]) -> EmailRequest:

    try:

        return EmailRequest.model_validate(data)

    except ValidationError as exc:

        raise HTTPException(
            status_code=422,
            detail=[
                {
                    "loc": list(error["loc"]),
                    "msg": error["msg"],
                }
                for error in exc.errors()
            ],
        )


def _recipients_from_form(
    value: str | None,
) -> list[str]:

    if value is None:
        return []

    try:

        parsed = json.loads(value)

    except json.JSONDecodeError:

        parsed = [
            part.strip()
            for part in value.split(",")
            if part.strip()
        ]

    if not isinstance(parsed, list):

        raise HTTPException(
            status_code=422,
            detail=(
                "recipients must be a JSON array "
                "or comma-separated addresses"
            ),
        )

    return parsed


# ---------------------------------------------------------
# MULTIPART REQUEST PARSING
# ---------------------------------------------------------

async def _multipart_payload(
    request: Request,
) -> tuple[dict[str, Any], list[StarletteUploadFile]]:

    max_body_bytes = min(
        settings.MAX_REQUEST_BYTES,
        POLICY.max_total_bytes + 3 * 1024 * 1024,
    )

    length = request.headers.get("content-length")

    if length is not None:

        try:

            if int(length) > max_body_bytes:

                raise HTTPException(
                    413,
                    detail=(
                        "Multipart request exceeds "
                        "the configured size limit"
                    ),
                )

        except ValueError:

            raise HTTPException(
                400,
                detail="Invalid Content-Length header",
            )

    try:

        form = await request.form(
            max_files=POLICY.max_files + 1,
            max_fields=30,
        )

    except StarletteHTTPException as exc:

        detail = str(exc.detail).lower()

        if any(
            term in detail
            for term in (
                "too many",
                "maximum",
                "exceeded",
                "part exceeded",
            )
        ):

            raise HTTPException(
                413,
                detail="Multipart attachment or field limit exceeded",
            ) from exc

        raise HTTPException(
            400,
            detail="Malformed multipart body",
        ) from exc

    except TypeError as exc:

        logger.exception(
            "Multipart parser compatibility error"
        )

        raise HTTPException(
            500,
            detail=(
                "Multipart parser is incompatible; "
                "update FastAPI/Starlette/python-multipart"
            ),
        ) from exc

    except Exception as exc:

        logger.warning(
            "Malformed multipart data: %s",
            type(exc).__name__,
        )

        raise HTTPException(
            400,
            detail="Malformed multipart body",
        ) from exc

    uploaded = []

    allowed_fields = {
        "channel",
        "subject",
        "body",
        "html",
        "recipients",
        "files",
        "attachments",
    }

    for field, value in form.multi_items():

        if field not in allowed_fields:

            raise HTTPException(
                422,
                detail=(
                    f"Unexpected form field: {field}; "
                    "URLs must be included in body or HTML"
                ),
            )

        if isinstance(value, StarletteUploadFile):

            if field not in {"files", "attachments"}:

                raise HTTPException(
                    422,
                    detail=f"Unexpected file field: {field}",
                )

            if not value.filename:

                if value.size != 0 or await value.read(1):

                    raise HTTPException(
                        422,
                        detail="Uploaded file requires a filename",
                    )

                continue

            uploaded.append(value)

        elif field in {"files", "attachments"}:

            if value not in ("", "[]"):

                raise HTTPException(
                    422,
                    detail="files must be binary uploads, not text",
                )

        else:

            if len(str(value).encode("utf-8")) > 1024 * 1024:

                raise HTTPException(
                    413,
                    detail=f"Multipart field '{field}' exceeds 1 MB",
                )

    data = {
        "channel": form.get("channel", "email"),
        "subject": form.get("subject"),
        "body": form.get("body"),
        "html": form.get("html"),
        "recipients": _recipients_from_form(
            form.get("recipients")
        ),
        "attachments": [],
    }

    return data, uploaded


# ---------------------------------------------------------
# PUBLIC FINDING FORMATTING
# ---------------------------------------------------------

def _one_issue(
    findings: list[dict],
    *,
    module: str,
) -> list[dict]:

    if not findings:
        return []

    failures = [
        finding
        for finding in findings
        if (
            finding.get("category") == "INSPECTION_FAILURE"
            or str(finding.get("code", "")).endswith(
                (
                    "_FAILED",
                    "_UNAVAILABLE",
                    "_ERROR",
                    "_INCOMPLETE",
                    "_FAILURE",
                )
            )
        )
    ]

    if failures:

        winner = failures[0]

    else:

        preferred = (

            (
                "LOTTERY_IDENTITY_HARVEST",
                "ADVANCE_FEE_SCAM",
                "LOTTERY_SCAM",
            )
            if module == "text"

            else (
                "ACCOUNT_UPDATE_LINK_REVIEW",
                "URL_CREDENTIALS_PRESENT",
            )
            if module == "URL"

            else ()
        )

        winner = next(
            (
                finding
                for code in preferred
                for finding in findings
                if finding.get("code") == code
            ),
            None,
        )

        if winner is None:

            weight = {
                "CRITICAL": 0,
                "HIGH": 1,
                "MEDIUM": 2,
                "LOW": 3,
                "MINOR": 3,
                "INFO": 4,
            }

            winner = min(
                findings,
                key=lambda finding: weight.get(
                    str(
                        finding.get("severity") or "HIGH"
                    ).upper(),
                    1,
                ),
            )

    return [
        {
            "code": winner.get("code") or "SECURITY_FINDING",
            "severity": str(
                winner.get("severity") or "HIGH"
            ).upper(),
            "reason": (
                winner.get("message")
                or winner.get("reason")
                or "Security finding requires review."
            ),
        }
    ]


def _overall_reason(
    result: dict,
    report: dict | None,
) -> str:

    findings = result.get("findings", [])

    def by(source):
        return [
            finding
            for finding in findings
            if finding.get("source") == source
        ]

    content = by("content")
    urls = by("urls")
    files = by("attachments")

    codes = {
        str(finding.get("code", ""))
        for finding in content
    }

    parts = []

    if any(
        finding.get("category") == "INSPECTION_FAILURE"
        for finding in findings
    ):

        parts.append(
            "One or more required security inspections could not be completed"
        )

    if (
        "LOTTERY_SCAM" in codes
        or "LOTTERY_IDENTITY_HARVEST" in codes
    ):

        if (
            "ADVANCE_FEE_SCAM" in codes
            and "LOTTERY_IDENTITY_HARVEST" in codes
        ):

            parts.append(
                "The email resembles a lottery-prize scam requesting sensitive bank or identity details and an upfront fee"
            )

        elif "ADVANCE_FEE_SCAM" in codes:

            parts.append(
                "The email resembles a lottery-prize claim requesting an upfront fee"
            )

        elif "LOTTERY_IDENTITY_HARVEST" in codes:

            parts.append(
                "The email contains a lottery-prize claim requesting sensitive identity or bank details"
            )

        else:

            parts.append(
                "The email contains suspicious lottery-prize claims"
            )

        if {
            "LOTTERY_DEADLINE_PRESSURE",
            "LOTTERY_SECRECY_REQUEST",
        } & codes:

            parts.append(
                "It also uses urgency or secrecy tactics"
            )

    elif content:

        selected = _one_issue(
            content,
            module="text",
        )[0]

        parts.append(
            "Email content requires action: "
            + selected["reason"].rstrip(". ")
        )

    if urls:

        top = _one_issue(
            urls,
            module="URL",
        )[0]

        parts.append(
            "A URL in the message requires review: "
            + top["reason"].rstrip(". ")
        )

    if files:

        filenames = sorted({
            finding.get("filename")
            for finding in files
            if finding.get("filename")
        })

        if filenames and len(filenames) == 1:

            parts.append(
                "Attachment '"
                + str(filenames[0])
                + "' has a security finding"
            )

        else:

            parts.append(
                "One or more attachments have security findings"
            )

    elif report and report.get("status") in {
        "WARNING",
        "RESTRICTED",
    }:

        parts.append(
            "Attachment validation requires review or was blocked"
        )

    if not parts:

        parts.append(
            "Security validation requires review"
            if result["status"] == "WARNING"
            else "A security policy restriction was triggered"
        )

    summary = ". ".join(
        part.rstrip(". ")
        for part in parts
    ) + "."

    if result["status"] == "RESTRICTED":

        summary += (
            " Sending is blocked until the issues are corrected and revalidated."
        )

    else:

        summary += (
            " Review the issue and acknowledge the warning before sending."
        )

    return summary


# ---------------------------------------------------------
# PUBLIC RESPONSE FORMAT
# ---------------------------------------------------------

def _format_public(
    result: dict,
    content: dict,
    urls: dict,
    report: dict | None,
) -> dict:

    vr = result["validation_results"]

    text_section = {
        "status": vr["content"]["status"],
        "confidence_score": vr["content"]["confidence_score"],
        "issues": _one_issue(
            vr["content"].get("findings", []),
            module="text",
        ),
    }

    urls_section: dict | str = "empty"

    if vr["urls"] != "empty":

        urls_section = {
            "status": vr["urls"]["status"],
            "confidence_score": vr["urls"]["confidence_score"],
            "issues": _one_issue(
                vr["urls"].get("findings", []),
                module="URL",
            ),
        }

    attachments_section: list[dict] | str = "empty"

    warnings = []

    if report is not None:

        public_report = format_public_response(report)

        attachments_section = []

        warnings = list(
            public_report.get("warnings", [])
        )

        for file in public_report.get("attachments", []):

            issues = [
                {
                    "code": issue["code"],
                    "severity": issue["severity"],
                    "message": issue["reason"],
                    "category": "ATTACHMENT",
                }
                for issue in file.get("issues", [])
            ]

            attachments_section.append(
                {
                    **{
                        key: value
                        for key, value in file.items()
                        if key != "issues"
                    },
                    "issues": _one_issue(
                        issues,
                        module="attachments",
                    ),
                }
            )

        if (
            not attachments_section
            and report.get("status") in {
                "WARNING",
                "RESTRICTED",
            }
        ):

            reasons = (
                report.get("popup") or {}
            ).get("reasons", []) or report.get("findings", [])

            grouped = {}

            for reason in reasons:

                if not isinstance(reason, dict):
                    continue

                name = str(
                    reason.get("filename") or "(attachments)"
                )

                grouped.setdefault(name, []).append(
                    {
                        "code": str(
                            reason.get("code")
                            or "ATTACHMENT_INSPECTION_INCOMPLETE"
                        ),
                        "severity": str(
                            reason.get("severity") or "CRITICAL"
                        ).upper(),
                        "category": reason.get(
                            "category",
                            "INSPECTION_FAILURE",
                        ),
                        "message": str(
                            reason.get("reason")
                            or reason.get("message")
                            or "Attachment blocked by policy"
                        ),
                    }
                )

            if not grouped:

                grouped["(attachments)"] = [
                    {
                        "code": "ATTACHMENT_INSPECTION_INCOMPLETE",
                        "severity": "CRITICAL",
                        "category": "INSPECTION_FAILURE",
                        "message": (
                            "Attachment scanning was blocked or incomplete."
                        ),
                    }
                ]

            attachments_section = [
                {
                    "filename": name,
                    "status": report["status"],
                    "detected_type": None,
                    "antivirus": "NOT_RUN",
                    "confidence_score": report.get(
                        "confidence_score"
                    ),
                    "issues": _one_issue(
                        items,
                        module="attachments",
                    ),
                }
                for name, items in grouped.items()
            ]

    errors = []

    if vr["content"].get("findings"):
        errors.append("text")

    if (
        isinstance(vr["urls"], dict)
        and vr["urls"].get("findings")
    ):
        errors.append("URL")

    if report and (
        result["validation_results"]["attachments"].get(
            "status"
        ) in {"WARNING", "RESTRICTED"}
        or (
            result["validation_results"]["attachments"].get(
                "files"
            )
            and any(
                file.get("findings") or file.get("advisories")
                for file in report.get("attachments", [])
            )
        )
    ):

        errors.append("attachments")

    status = result["status"]

    popup = None

    if status in {"WARNING", "RESTRICTED"}:

        attachment_only = errors == ["attachments"]

        popup = {
            "show": True,
            "type": status,
            "title": (
                "Attachment" if attachment_only else "Email"
            ) + (
                " Warning"
                if status == "WARNING"
                else " Restricted"
            ),
            "message": (
                "Review the detected security issues before sending."
                if status == "WARNING"
                else (
                    "Sending is blocked. Correct the detected "
                    "issues before trying again."
                )
            ),
            "actions": (
                ["EDIT_MAIL", "CLOSE"]
                if status == "WARNING"
                else ["DISCARD_MAIL"]
            ),
            "reasons": [
                _overall_reason(result, report)
            ],
        }

    public = {
        "status": status,
        "can_send": result["can_send"],
        "confidence_score": result["confidence_score"],
        "requires_acknowledgement": result[
            "requires_acknowledgement"
        ],
        "confidence_source": result["confidence_source"],
        "text": text_section,
        "URL": urls_section,
        "attachments": attachments_section,
        "Error": errors,
        "warnings": warnings,
        "popup": popup,
    }

    if (
        result.get("warning_challenge")
        and status == "WARNING"
    ):

        public["warning_challenge"] = (
            result["warning_challenge"]
        )

    return public


# ---------------------------------------------------------
# ATTACHMENT FAILURE HANDLING
# ---------------------------------------------------------

def _attachment_failure(
    code: str,
    message: str,
) -> dict[str, Any]:

    return {
        "status": "RESTRICTED",
        "can_send": False,
        "confidence_score": None,
        "findings": [
            {
                "code": code,
                "category": "INSPECTION_FAILURE",
                "reason": message,
            }
        ],
        "attachments": [],
        "popup": {
            "reasons": [
                {
                    "code": code,
                    "reason": message,
                    "severity": "CRITICAL",
                }
            ]
        },
    }


# ---------------------------------------------------------
# VALIDATE MODULE REPORT
# ---------------------------------------------------------

def _validate_module_report(
    data: Any,
    name: str,
) -> dict:

    valid = (
        isinstance(data, dict)
        and isinstance(data.get("findings"), list)
        and isinstance(data.get("coverage"), dict)
    )

    if valid:

        mandatory_checks = (
            ("url_syntax_inspection",)
            if name == "URL"
            else (
                "runtime_text_rules",
                "html_inspection",
                "contextual_text_rules",
            )
        )

        findings = data["findings"]

        valid = all(
            isinstance(finding, dict)
            for finding in findings
        )

        if valid:

            incomplete_checks = [
                check
                for check in mandatory_checks
                if data["coverage"].get(check) != "complete"
            ]

            if (
                incomplete_checks
                and not any(
                    finding.get("category") == "INSPECTION_FAILURE"
                    for finding in findings
                )
            ):

                data = {
                    **data,
                    "findings": [
                        *findings,
                        {
                            "code": f"{name}_SCAN_INCOMPLETE",
                            "category": "INSPECTION_FAILURE",
                            "message": (
                                "Mandatory checks incomplete: "
                                + ", ".join(incomplete_checks)
                            ),
                        },
                    ],
                }

    if valid:
        return data

    return {
        "findings": [
            {
                "code": f"{name}_SCAN_INCOMPLETE",
                "category": "INSPECTION_FAILURE",
                "message": (
                    f"{name} scanner did not return a complete, "
                    "valid inspection report."
                ),
            }
        ],
        "coverage": {
            (
                "url_syntax_inspection"
                if name == "URL"
                else "runtime_text_rules"
            ): "failed"
        },
    }


# ---------------------------------------------------------
# MAIN VALIDATION ENGINE
# ---------------------------------------------------------

async def _analyze(
    data: dict[str, Any],
    uploaded: list[StarletteUploadFile] | None = None,
) -> dict:

    email = _valid_email(data)

    # ---------------- ATTACHMENTS ----------------

    if email.attachments and not uploaded:

        report = {
            "status": "RESTRICTED",
            "can_send": False,
            "confidence_score": None,
            "findings": [
                {
                    "code": "ATTACHMENT_BINARY_REQUIRED",
                    "category": "INSPECTION_FAILURE",
                    "reason": (
                        "Attachments require actual binary multipart uploads."
                    ),
                }
            ],
            "attachments": [],
        }

    elif uploaded:

        try:

            items, error = await read_uploads(uploaded)

            if error:

                report = error

            else:

                report = await run_in_threadpool(
                    scan_bytes,
                    items,
                )

                if (
                    not isinstance(report, dict)
                    or report.get("status")
                    not in {"SAFE", "WARNING", "RESTRICTED"}
                ):

                    report = _attachment_failure(
                        "ATTACHMENT_SCAN_INCOMPLETE",
                        "Attachment scanner returned an invalid result.",
                    )

                elif report["status"] == "WARNING":

                    report["warning_challenge"] = (
                        issue_warning_challenge(items)
                    )

        except Exception:

            logger.exception(
                "Attachment engine failed"
            )

            report = _attachment_failure(
                "ATTACHMENT_SCAN_FAILED",
                "Attachment security inspection could not be completed.",
            )

    else:

        report = None

    # ---------------- CONTENT ----------------

    try:

        content = await run_in_threadpool(
            validate_content,
            email.subject,
            email.body or "",
            email.html or "",
        )

    except Exception as exc:

        logger.exception(
            "Content engine failed"
        )

        content = {
            "findings": [
                {
                    "code": "CONTENT_SCAN_FAILED",
                    "category": "INSPECTION_FAILURE",
                    "message": (
                        f"Content engine failed ({type(exc).__name__})"
                    ),
                }
            ],
            "coverage": {
                "runtime_text_rules": "failed"
            },
        }

    # ---------------- URL ----------------

    try:

        urls = await run_in_threadpool(
            validate_urls,
            "\n\n".join(
                (
                    email.subject,
                    email.body or "",
                )
            ),
            email.html or "",
        )

    except Exception as exc:

        logger.exception(
            "URL engine failed"
        )

        urls = {
            "findings": [
                {
                    "code": "URL_SCAN_FAILED",
                    "category": "INSPECTION_FAILURE",
                    "message": (
                        f"URL engine failed ({type(exc).__name__})"
                    ),
                }
            ],
            "coverage": {
                "url_syntax_inspection": "failed"
            },
        }

    # ---------------- DECISION ----------------

    content = _validate_module_report(
        content,
        "CONTENT",
    )

    urls = _validate_module_report(
        urls,
        "URL",
    )

    decided = decide_email(
        content,
        urls,
        report,
    )

    return _format_public(
        decided,
        content,
        urls,
        report,
    )


# ---------------------------------------------------------
# SWAGGER REQUEST BODY SCHEMA
# ---------------------------------------------------------

_ANALYZE_REQUEST_BODY = {

    "required": True,

    "content": {

        "application/json": {

            "schema": {

                "type": "object",

                "required": [
                    "subject",
                    # "recipients",
                ],

                "properties": {

                    "subject": {
                        "type": "string",
                        "example": "October invoice",
                    },

                    "body": {
                        "type": "string",
                        "example": "Please review the invoice.",
                    },

                    "html": {
                        "type": "string",
                        "example": "",
                    },

                    "recipients": {
                        "type": "array",
                        "items": {
                            "type": "string"
                        },
                        "example": [
                            "user@example.com"
                        ],
                    },

                    "attachments": {
                        "type": "array",
                        "items": {
                            "type": "object"
                        },
                        "description": (
                            "Use multipart binary uploads for real attachments."
                        ),
                    },
                },
            },
        },

        "multipart/form-data": {

            "schema": {

                "type": "object",

                "required": [
                    "subject",
                    # "recipients",
                ],

                "properties": {

                    "subject": {
                        "type": "string"
                    },

                    "body": {
                        "type": "string"
                    },

                    "html": {
                        "type": "string"
                    },

                    "recipients": {
                        "type": "string",
                        "description": (
                            'JSON list or comma-separated addresses, '
                            'e.g. ["user@example.com"]'
                        ),
                    },

                    "files": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "format": "binary",
                        },
                        "description": (
                            "Optional attachments (0–5 files)"
                        ),
                    },
                },
            },

            "encoding": {
                "files": {
                    "style": "form",
                    "explode": True,
                }
            },
        },
    },
}


# ---------------------------------------------------------
# SINGLE BUSINESS ENDPOINT: ANALYZE EMAIL
# ---------------------------------------------------------


# ---------------------------------------------------------
# SINGLE BUSINESS ENDPOINT: ANALYZE EMAIL
# ---------------------------------------------------------

@app.post(
    f"{_PREFIX}/analyze",
    tags=["Email Validation"],
    summary=(
        "Email Validation — subject, body, URLs "
        "and optional attachments"
    ),
    openapi_extra={
        "requestBody": _ANALYZE_REQUEST_BODY
    },
)
async def analyze(
    request: Request,
    current_user: dict = Depends(get_current_user),
):

    content_type = (
        request.headers.get("content-type", "")
        .split(";", 1)[0]
        .strip()
        .lower()
    )

    uploaded_files = []
    email_data = {}

    # Get authenticated account information
    account_id = str(current_user["id"])
    user_email = current_user["email"]

    # ---------------- JSON REQUEST ----------------

    if content_type == "application/json":

        try:
            payload = await request.json()

        except (ValueError, UnicodeError):

            raise HTTPException(
                400,
                detail="Invalid JSON payload",
            )

        if not isinstance(payload, dict):

            raise HTTPException(
                422,
                detail="JSON root must be an object",
            )

        # Recipients are optional.
        payload["recipients"] = payload.get("recipients") or []
        email_data = {
            "from": payload.get("from"),
            "to": payload["recipients"],
            "subject": payload.get("subject"),
            "body": payload.get("body"),
        }

        final_result = await _analyze(payload)

    # ---------------- MULTIPART REQUEST ----------------

    elif content_type in {
        "multipart/form-data",
        "application/x-www-form-urlencoded",
    }:

        payload, uploaded_files = await _multipart_payload(
            request
        )

        email_data = {
            "from": payload.get("from"),
            "to": payload.get("recipients") or [],
            "subject": payload.get("subject"),
            "body": payload.get("body"),
        }

        final_result = await _analyze(
            payload,
            uploaded_files,
        )

    else:

        raise HTTPException(
            415,
            detail=(
                "Use application/json or multipart/form-data"
            ),
        )

    # ---------------- ADD ACCOUNT DETAILS ----------------

    # Add authenticated account information to API response.
    final_result["account_id"] = account_id
    final_result["user_email"] = user_email

    # ---------------- REQUEST ID ----------------

    request_id = request.headers.get("x-request-id")

    # ---------------- SAVE RESULT IN MONGODB ----------------

    try:

        save_result = await run_in_threadpool(
            save_analysis,
            account_id=account_id,
            analysis_result=final_result,
            email_data=email_data,
            request_id=request_id,
            user_email=user_email,
        )

        logger.info(
            "MongoDB save successful. Record ID: %s",
            save_result.get("record_id"),
        )

    except Exception:

        logger.exception(
            "Failed to save email analysis in MongoDB"
        )

        raise HTTPException(
            status_code=503,
            detail=(
                "Email validation completed, but "
                "saving the result failed."
            ),
        )

    # ---------------- RETURN RESPONSE ----------------

    return final_result

def make_json_safe(value):
    if isinstance(value, dict):
        return {
            key: make_json_safe(item)
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [make_json_safe(item) for item in value]

    if isinstance(value, ObjectId):
        return str(value)

    if isinstance(value, datetime):
        return value.isoformat()

    return value



# =========================================================
# JSON VIEW ENDPOINT
# =========================================================

@app.get(f"{_PREFIX}/json_view", tags=["Validation History"])
async def json_view(
    view: str = Query("records"),
    search: Optional[str] = Query(None),
    status: Optional[str] = Query("ALL"),
    start_date: Optional[str] = Query(None),
    end_date: Optional[str] = Query(None),
    sort_by: str = Query("created_at"),
    order: str = Query("desc"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    fields: Optional[str] = Query("all"),
    record_id: Optional[str] = Query(None),
    export: Optional[str] = Query(None),
    account_id: Optional[str] = Query(None)
):
    collection = analysis_collection

    # -----------------------------------------
    # VIEW VALIDATION
    # -----------------------------------------
    view = (view or "records").strip().lower()

    if view not in ["records", "users"]:
        raise HTTPException(
            status_code=400,
            detail="View must be records or users"
        )

    # -----------------------------------------
    # PUBLIC DATABASE QUERY
    # -----------------------------------------
    # No authentication or account restriction.
    # All records are included unless filtered.

    query = {}

    if account_id and account_id.strip():
        query["account_id"] = account_id.strip()

    # -----------------------------------------
    # RECORD ID FILTER
    # -----------------------------------------
    if record_id:
        if view == "users":
            raise HTTPException(
                status_code=400,
                detail="record_id filter is available only in records view"
            )

        if not ObjectId.is_valid(record_id):
            raise HTTPException(
                status_code=400,
                detail="Invalid MongoDB record ID"
            )

        query["_id"] = ObjectId(record_id)

    # -----------------------------------------
    # STATUS FILTER
    # -----------------------------------------
    status = (status or "ALL").strip().upper()

    if status != "ALL":
        if status not in ["SAFE", "WARNING", "RESTRICTED"]:
            raise HTTPException(
                status_code=400,
                detail="Status must be ALL, SAFE, WARNING or RESTRICTED"
            )

        query["status"] = status

    # -----------------------------------------
    # DATE FILTER - DD-MM-YYYY
    # -----------------------------------------
    if start_date or end_date:
        date_filter = {}

        try:
            if start_date:
                start = datetime.strptime(
                    start_date, "%d-%m-%Y"
                ).replace(tzinfo=timezone.utc)

                date_filter["$gte"] = start

            if end_date:
                end = datetime.strptime(
                    end_date, "%d-%m-%Y"
                ).replace(tzinfo=timezone.utc)

                date_filter["$lt"] = end + timedelta(days=1)

            if (
                start_date
                and end_date
                and date_filter["$gte"] >= date_filter["$lt"]
            ):
                raise HTTPException(
                    status_code=400,
                    detail="End date must not be before start date"
                )

            query["created_at"] = date_filter

        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Use date format DD-MM-YYYY"
            )

    # -----------------------------------------
    # SEARCH FILTER
    # -----------------------------------------
    if search and search.strip():
        search_pattern = re.escape(search.strip())

        search_conditions = [
            {
                "user_email": {
                    "$regex": search_pattern,
                    "$options": "i"
                }
            },
            {
                "email.subject": {
                    "$regex": search_pattern,
                    "$options": "i"
                }
            },
            {
                "status": {
                    "$regex": search_pattern,
                    "$options": "i"
                }
            }
        ]

        if view == "users":
            query["user_email"] = {
                "$regex": search_pattern,
                "$options": "i"
            }
        else:
            query["$or"] = search_conditions

    # -----------------------------------------
    # EXPORT VALIDATION
    # -----------------------------------------
    if export:
        export = export.strip().lower()

        if export != "csv":
            raise HTTPException(
                status_code=400,
                detail="Export format must be csv"
            )

        if view == "users":
            raise HTTPException(
                status_code=400,
                detail="CSV export is available only in records view"
            )

    # -----------------------------------------
    # FIELD SELECTION
    # -----------------------------------------
    allowed_fields = {
        "record_id",
        "account_id",
        "user_email",
        "request_id",
        "email.from",
        "email.to",
        "email.subject",
        "email.body",
        "status",
        "confidence_score",
        "can_send",
        "requires_acknowledgement",
        "score_contributions",
        "text",
        "url",
        "attachments",
        "errors",
        "created_at"
    }

    if view == "users":
        selected_fields = ["user_email"]

    elif fields is None or fields.strip().lower() == "all":
        selected_fields = None

    elif fields.strip().lower() in ["none", ""]:
        selected_fields = ["record_id"]

    else:
        selected_fields = list(dict.fromkeys(
            field.strip()
            for field in fields.split(",")
            if field.strip()
        ))

        invalid_fields = [
            field for field in selected_fields
            if field not in allowed_fields
        ]

        if invalid_fields:
            raise HTTPException(
                status_code=400,
                detail={
                    "message": "Invalid field selection",
                    "invalid_fields": invalid_fields,
                    "allowed_fields": sorted(allowed_fields)
                }
            )

        if "record_id" not in selected_fields:
            selected_fields.insert(0, "record_id")

    # -----------------------------------------
    # SORTING
    # -----------------------------------------
    allowed_sort_fields = [
        "created_at",
        "status",
        "confidence_score",
        "email.subject",
        "user_email"
    ]

    if sort_by not in allowed_sort_fields:
        raise HTTPException(
            status_code=400,
            detail="Invalid sort field"
        )

    order = order.strip().lower()

    if order not in ["asc", "desc"]:
        raise HTTPException(
            status_code=400,
            detail="Order must be asc or desc"
        )

    sort_direction = 1 if order == "asc" else -1

    # =====================================================
    # UNIQUE USERS VIEW
    # =====================================================
    if view == "users":

        def fetch_unique_users():
            pipeline = [
                {"$match": query},
                {
                    "$group": {
                        "_id": "$user_email"
                    }
                },
                {
                    "$match": {
                        "_id": {
                            "$type": "string",
                            "$ne": ""
                        }
                    }
                },
                {
                    "$sort": {
                        "_id": sort_direction
                    }
                }
            ]

            total_users = len(
                list(collection.aggregate(pipeline + [
                    {"$count": "total"}
                ]))
            )

            users = list(
                collection.aggregate(
                    pipeline + [
                        {"$skip": (page - 1) * page_size},
                        {"$limit": page_size},
                        {
                            "$project": {
                                "_id": 0,
                                "user_email": "$_id"
                            }
                        }
                    ]
                )
            )

            return total_users, users

        total_users, users = await run_in_threadpool(
            fetch_unique_users
        )

        total_pages = (
            (total_users + page_size - 1) // page_size
            if total_users else 0
        )

        return {
            "success": True,
            "view": "users",
            "total_users": total_users,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "records": users
        }

    # =====================================================
    # RECORDS VIEW
    # =====================================================

    # -----------------------------------------
    # MONGODB QUERY
    # -----------------------------------------
    def fetch_records():
        total = collection.count_documents(query)

        cursor = collection.find(query).sort(
            sort_by, sort_direction
        )

        # CSV exports all matching records.
        if export != "csv":
            if record_id:
                cursor = cursor.limit(1)
            else:
                cursor = cursor.skip(
                    (page - 1) * page_size
                ).limit(page_size)

        return total, list(cursor)

    total_records, records = await run_in_threadpool(
        fetch_records
    )

    # -----------------------------------------
    # FORMAT RECORDS
    # -----------------------------------------
    formatted_records = []

    for record in records:
        record["record_id"] = str(record.pop("_id"))
        formatted_records.append(make_json_safe(record))

    # -----------------------------------------
    # NESTED FIELD HELPERS
    # -----------------------------------------
    def get_nested_value(data, field_path):
        value = data

        for part in field_path.split("."):
            if not isinstance(value, dict) or part not in value:
                return None

            value = value[part]

        return value

    def set_nested_value(data, field_path, value):
        parts = field_path.split(".")
        current = data

        for part in parts[:-1]:
            current = current.setdefault(part, {})

        current[parts[-1]] = value

    def select_record_fields(record):
        if selected_fields is None:
            return record

        selected = {}

        for field in selected_fields:
            value = get_nested_value(record, field)

            if value is not None:
                set_nested_value(selected, field, value)

        return selected

    formatted_records = [
        select_record_fields(record)
        for record in formatted_records
    ]

    # -----------------------------------------
    # CSV EXPORT
    # -----------------------------------------
    if export == "csv":

        def flatten_record(data, prefix=""):
            flattened = {}

            for key, value in data.items():
                field_name = (
                    f"{prefix}.{key}" if prefix else key
                )

                if isinstance(value, dict):
                    flattened.update(
                        flatten_record(value, field_name)
                    )
                else:
                    flattened[field_name] = value

            return flattened

        if selected_fields is None:
            flattened_records = [
                flatten_record(record)
                for record in formatted_records
            ]

            csv_fields = ["record_id"]

            for record in flattened_records:
                for field in record:
                    if field not in csv_fields:
                        csv_fields.append(field)

        else:
            csv_fields = selected_fields

            flattened_records = []

            for record in formatted_records:
                flattened = {}

                for field in csv_fields:
                    flattened[field] = get_nested_value(
                        record, field
                    )

                flattened_records.append(flattened)

        output = io.StringIO(newline="")

        writer = csv.DictWriter(
            output,
            fieldnames=csv_fields,
            extrasaction="ignore"
        )

        writer.writeheader()

        for record in flattened_records:
            safe_row = {}

            for field in csv_fields:
                value = record.get(field)

                if isinstance(value, (dict, list)):
                    value = json.dumps(
                        value,
                        ensure_ascii=False,
                        default=str
                    )

                elif value is not None:
                    value = str(value)

                    # Protect against CSV formula injection.
                    if value.startswith(
                        ("=", "+", "-", "@", "\t", "\r")
                    ):
                        value = "'" + value

                safe_row[field] = value

            writer.writerow(safe_row)

        csv_content = output.getvalue()
        output.close()

        return StreamingResponse(
            iter([csv_content]),
            media_type="text/csv",
            headers={
                "Content-Disposition":
                    'attachment; filename="omg_validation_history.csv"'
            }
        )

    # -----------------------------------------
    # JSON RESPONSE
    # -----------------------------------------
    total_pages = (
        (total_records + page_size - 1) // page_size
        if total_records else 0
    )

    return {
        "success": True,
        "view": "records",
        "total_records": total_records,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "records": formatted_records
    }
