import hmac

from fastapi import Header, HTTPException, status

from app.core.config import settings


def require_api_key(x_omg_api_key: str | None = Header(default=None)) -> None:
    """Require a shared secret when configured; production startup requires one."""
    expected = settings.API_KEY
    if not expected:
        if settings.is_production:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="API authentication is not configured.",
            )
        # Local development only: authentication is deliberately optional.
        return

    if not x_omg_api_key or not hmac.compare_digest(x_omg_api_key, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
