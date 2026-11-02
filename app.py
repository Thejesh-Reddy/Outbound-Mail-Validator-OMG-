from contextlib import asynccontextmanager

from fastapi import FastAPI

from api.middleware import RequestLoggingMiddleware
from api.routes import router
from common.config import settings
from common.logging import configure_logging

configure_logging()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Fail fast on insecure/incomplete production settings instead of starting
    # a service that might silently bypass mandatory ML inspection.
    settings.validate_production_configuration()
    if settings.is_production:
        from text_validation.rule_checks import _load_runtime_rules
        from ml_classifier.model_loader import load_model

        _load_runtime_rules()
        load_model(str(settings.resolve_path(settings.MODEL_PATH)))
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Outgoing email inspection service. A message may be released only when "
        "the verdict is SAFE and can_send is true."
    ),
    lifespan=lifespan,
    docs_url="/docs" if not settings.is_production else None,
    redoc_url="/redoc" if not settings.is_production else None,
    openapi_url="/openapi.json" if not settings.is_production else None,
)
app.add_middleware(RequestLoggingMiddleware)
app.include_router(router, prefix=settings.API_PREFIX, tags=["Email Analysis"])


@app.get("/")
def root():
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "message": "OMG API is running.",
        "docs": "/docs" if not settings.is_production else None,
    }
