"""OMG FastAPI application, configuration, authentication and HTTP middleware."""
from __future__ import annotations

import hmac
import logging
import os
import re
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.responses import JSONResponse

from schemas.email import EmailRequest
from schemas.verdict import AnalysisResponse

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


class Settings:
    APP_NAME = "OMG - Outbound Mail Gatekeeper"
    APP_VERSION = "2.0.0"
    API_PREFIX = os.getenv("OMG_API_PREFIX", "/api/v1").rstrip("/") or "/api/v1"
    ENVIRONMENT = os.getenv("OMG_ENVIRONMENT", "development").strip().lower()
    PATTERN_CATALOG_PATH = Path(os.getenv("OMG_PATTERN_CATALOG_PATH", "patterns/pattern_catalog.json"))
    API_KEY = os.getenv("OMG_API_KEY", "").strip()
    LOG_LEVEL = os.getenv("OMG_LOG_LEVEL", "INFO").upper()
    MAX_REQUEST_BYTES = int(os.getenv("OMG_MAX_REQUEST_BYTES", "2100000"))

    @staticmethod
    def resolve_path(path: Path) -> Path:
        return path if path.is_absolute() else BASE_DIR / path

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT in {"production", "prod"}

    def validate_production_configuration(self) -> None:
        if not self.is_production:
            return
        errors = []
        if len(self.API_KEY) < 32:
            errors.append("OMG_API_KEY must contain at least 32 characters")
        if not self.resolve_path(self.PATTERN_CATALOG_PATH).is_file():
            errors.append(f"pattern catalogue not found: {self.resolve_path(self.PATTERN_CATALOG_PATH)}")
        if self.MAX_REQUEST_BYTES < 1024:
            errors.append("OMG_MAX_REQUEST_BYTES must be at least 1024")
        if errors:
            raise RuntimeError("Invalid production configuration: " + "; ".join(errors))


settings = Settings()
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)


def require_api_key(x_omg_api_key: str | None = Header(default=None)) -> None:
    """Require the shared API key when configured; production always requires it."""
    expected = settings.API_KEY
    if not expected:
        if settings.is_production:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="API authentication is not configured.",
            )
        return
    if not x_omg_api_key or not hmac.compare_digest(x_omg_api_key, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )


_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,100}$")


class RequestLoggingMiddleware:
    """Add request IDs/security headers, enforce request size, and log requests."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers_in = {key.lower(): value for key, value in scope.get("headers", [])}
        supplied_id = headers_in.get(b"x-request-id", b"").decode("ascii", errors="ignore")
        request_id = supplied_id if _REQUEST_ID_RE.fullmatch(supplied_id) else str(uuid.uuid4())
        scope.setdefault("state", {})["request_id"] = request_id
        started = time.perf_counter()
        response_status = 500
        response_started = False
        bytes_received = 0

        async def send_with_headers(message):
            nonlocal response_status, response_started
            if message["type"] == "http.response.start":
                response_started = True
                response_status = message["status"]
                response_headers = list(message.get("headers", []))
                existing = {key.lower() for key, _ in response_headers}
                additions = {
                    b"x-request-id": request_id.encode("ascii"),
                    b"x-content-type-options": b"nosniff",
                    b"cache-control": b"no-store",
                    b"x-frame-options": b"DENY",
                    b"referrer-policy": b"no-referrer",
                }
                for key, value in additions.items():
                    if key not in existing:
                        response_headers.append((key, value))
                message["headers"] = response_headers
            await send(message)

        content_length = headers_in.get(b"content-length")
        if content_length is not None:
            try:
                declared_size = int(content_length)
                if declared_size < 0:
                    raise ValueError
                if declared_size > settings.MAX_REQUEST_BYTES:
                    response = JSONResponse(
                        status_code=413,
                        content={"detail": "Request body exceeds the configured size limit."},
                    )
                    await response(scope, receive, send_with_headers)
                    self._log(request_id, scope, response_status, started)
                    return
            except ValueError:
                response = JSONResponse(
                    status_code=400,
                    content={"detail": "Invalid Content-Length header."},
                )
                await response(scope, receive, send_with_headers)
                self._log(request_id, scope, response_status, started)
                return

        async def limited_receive():
            nonlocal bytes_received
            message = await receive()
            if message["type"] == "http.request":
                bytes_received += len(message.get("body", b""))
                if bytes_received > settings.MAX_REQUEST_BYTES:
                    raise _RequestTooLarge
            return message

        try:
            await self.app(scope, limited_receive, send_with_headers)
        except _RequestTooLarge:
            if not response_started:
                response = JSONResponse(
                    status_code=413,
                    content={"detail": "Request body exceeds the configured size limit."},
                )
                await response(scope, receive, send_with_headers)
            else:
                logger.error("request_body_limit_exceeded_after_response_started request_id=%s", request_id)
        except Exception:
            logger.exception("request_failed request_id=%s path=%s", request_id, scope.get("path", ""))
            raise
        finally:
            self._log(request_id, scope, response_status, started)

    @staticmethod
    def _log(request_id, scope, response_status, started):
        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
        logger.info(
            "request_complete request_id=%s method=%s path=%s status=%s elapsed_ms=%s",
            request_id, scope.get("method", ""), scope.get("path", ""),
            response_status, elapsed_ms,
        )


class _RequestTooLarge(Exception):
    pass


@asynccontextmanager
async def lifespan(_app: FastAPI):
    settings.validate_production_configuration()
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Outgoing email inspection service. SAFE messages may be sent directly; "
        "WARNING messages require explicit user acknowledgement in Notify; "
        "RESTRICTED messages must be blocked."
    ),
    lifespan=lifespan,
    docs_url="/docs" if not settings.is_production else None,
    redoc_url="/redoc" if not settings.is_production else None,
    openapi_url="/openapi.json" if not settings.is_production else None,
)
app.add_middleware(RequestLoggingMiddleware)


@app.get("/")
def root():
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "message": "OMG API is running.",
        "docs": "/docs" if not settings.is_production else None,
    }


@app.get(f"{settings.API_PREFIX}/health")
def health_check():
    return {"service": "OMG", "status": "running"}


@app.get(f"{settings.API_PREFIX}/ready")
def readiness_check():
    catalog_path = settings.resolve_path(settings.PATTERN_CATALOG_PATH)
    checks = {
        "pattern_catalogue": "ready" if catalog_path.is_file() else "missing",
        "html_inspection": "ready",
        "url_inspection": "ready",
    }
    ready = catalog_path.is_file()
    payload = {"service": "OMG", "ready": ready, "checks": checks}
    if not ready:
        return JSONResponse(status_code=503, content=payload)
    return payload


@app.get(f"{settings.API_PREFIX}/status", dependencies=[Depends(require_api_key)])
def service_status():
    catalog_path = settings.resolve_path(settings.PATTERN_CATALOG_PATH)
    return {
        "service": "OMG",
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "verdicts": ["SAFE", "WARNING", "RESTRICTED"],
        "pattern_catalogue_present": catalog_path.is_file(),
        "detection_method": "TF-IDF pattern extraction with deterministic runtime matching",
        "url_reputation": "not_implemented",
    }


@app.post(
    f"{settings.API_PREFIX}/analyze",
    response_model=AnalysisResponse,
    response_model_exclude_unset=True,
    dependencies=[Depends(require_api_key)],
)
def analyze(email: EmailRequest):
    from decision_making import analyze_email
    try:
        return analyze_email(email)
    except Exception:
        logger.exception("Analysis pipeline failed")
        return AnalysisResponse(
            status="RESTRICTED",
            message="Email analysis could not be completed, so this message cannot be sent.",
            can_send=False,
            confidence_score=0.0,
            requires_acknowledgement=False,
            text=[{
                "code": "ANALYSIS_PIPELINE_ERROR",
                "severity": "CRITICAL",
                "reason": "Email analysis could not be completed.",
            }],
            URL=[],
            warnings=["Email analysis could not be completed."],
            popup={
                "show": True,
                "type": "RESTRICTED",
                "title": "Email Restricted",
                "message": "Email analysis could not be completed, so this message cannot be sent.",
                "actions": ["DISCARD_MAIL"],
            },
        )

