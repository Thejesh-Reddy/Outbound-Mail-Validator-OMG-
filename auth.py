
"""Single Authorization endpoint for registration, login, profile and logout."""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.exc import IntegrityError
from typing import Literal, Optional
import jwt

from database import AuthSession, SessionLocal, User, utc_now_naive
from security import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
    hash_session_id,
)

router = APIRouter(tags=["Authorization"])
bearer = HTTPBearer(auto_error=False)

class SessionExpiredError(Exception):
    """Raised whenever a bearer token is missing, malformed, expired, or
    belongs to a revoked/invalid session.
 
    Access tokens are only valid for one hour (see
    ``OMG_ACCESS_TOKEN_EXPIRE_MINUTES`` in security.py). Once that hour has
    passed, every request made with the old token must fail with the
    ``SESSION_EXPIRED`` status handled in app.py, regardless of which
    specific validation step detected the problem.
    """
 
    def __init__(self, message: str = "Your session has expired. Please log in again."):
        self.message = message
        super().__init__(message)

class AuthorizationRequest(BaseModel):
    action: Literal["register", "login", "profile", "logout"]

    # Required for registration
    name: Optional[str] = Field(default=None, min_length=2, max_length=100)

    # Required for registration and login
    email: Optional[EmailStr] = None
    password: Optional[str] = Field(default=None, min_length=1, max_length=128)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
):
    """Validate JWT and confirm that its MySQL session is active."""

    if credentials is None or credentials.scheme.lower() != "bearer":
        raise SessionExpiredError("Bearer access token required")

    try:
        payload = decode_access_token(credentials.credentials)

        account_id = payload["sub"]
        email = payload["email"]
        jti = payload["jti"]

        with SessionLocal() as db:
            session = db.query(AuthSession).filter(
                AuthSession.account_id == account_id,
                AuthSession.jti_hash == hash_session_id(jti),
                AuthSession.revoked_at.is_(None),
                AuthSession.expires_at > utc_now_naive(),
            ).first()

            if not session:
                raise SessionExpiredError("Session expired or revoked")

            user = db.query(User).filter(
                User.id == account_id,
                User.is_active.is_(True),
            ).first()

            if not user or user.email != email:
                raise SessionExpiredError("Invalid user session")

            user_data = {
                "id": user.id,
                "name": user.name,
                "email": user.email,
            }

        return user_data

    except HTTPException:
        raise
    except (jwt.InvalidTokenError, KeyError, ValueError, TypeError):
        raise SessionExpiredError("Invalid or expired access token")


def _register(data: AuthorizationRequest):
    if not data.name or not data.email or not data.password:
        raise HTTPException(
            status_code=422,
            detail="Registration requires name, email and password",
        )

    email = str(data.email).strip().lower()

    try:
        with SessionLocal() as db:
            user = User(
                name=data.name.strip(),
                email=email,
                password_hash=hash_password(data.password),
                created_at=utc_now_naive(),
                is_active=True,
            )
            db.add(user)
            db.commit()
            user_id = user.id
    except IntegrityError:
        raise HTTPException(
            status_code=409,
            detail="Email already registered",
        )

    return {
        "message": "Account created successfully",
        "user": {
            "id": user_id,
            "name": data.name.strip(),
            "email": email,
        },
    }


def _login(data: AuthorizationRequest):
    if not data.email or not data.password:
        raise HTTPException(
            status_code=422,
            detail="Login requires email and password",
        )

    email = str(data.email).strip().lower()
    with SessionLocal() as db:
        user = db.query(User).filter(User.email == email).first()
        user_data = None if user is None else {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "password_hash": user.password_hash,
            "is_active": user.is_active,
        }

    if (
        not user_data
        or not user_data["is_active"]
        or not verify_password(data.password, user_data["password_hash"])
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password",
        )

    account_id = user_data["id"]
    login_time = datetime.now(timezone.utc)

    token, jti, expires_at = create_access_token(
        account_id,
        email,
        issued_at=login_time,
    )

    with SessionLocal() as db:
        db.add(AuthSession(
            account_id=account_id,
            jti_hash=hash_session_id(jti),
            created_at=login_time.replace(tzinfo=None),
            expires_at=expires_at.astimezone(timezone.utc).replace(tzinfo=None),
        ))
        db.commit()

    return {
        "message": "Login successful",
        "access_token": token,
        "token_type": "bearer",
        "login_time": login_time.isoformat(),
        "expires_at": expires_at.isoformat(),
        "user": {
            "id": account_id,
            "name": user_data["name"],
            "email": email,
        },
    }


@router.post("/api/v1/authorization", summary="Authorization")
def authorization(
    data: AuthorizationRequest,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
):
    """
    One endpoint for all account operations.

    Actions:
      - register: create a new account
      - login: authenticate and issue a JWT
      - profile: return the authenticated user's profile
      - logout: revoke the authenticated user's session
    """

    if data.action == "register":
        return _register(data)

    if data.action == "login":
        return _login(data)

    # Profile and logout require an authenticated bearer token.
    current_user = get_current_user(credentials)

    if data.action == "profile":
        return {
            "message": "Profile retrieved successfully",
            "user": current_user,
        }

    if data.action == "logout":
        payload = decode_access_token(credentials.credentials)

        with SessionLocal() as db:
            session = db.query(AuthSession).filter(
                AuthSession.account_id == current_user["id"],
                AuthSession.jti_hash == hash_session_id(payload["jti"]),
                AuthSession.revoked_at.is_(None),
            ).first()
            if session:
                session.revoked_at = utc_now_naive()
                db.commit()

        return {"message": "Logged out successfully"}

    raise HTTPException(status_code=400, detail="Unsupported authorization action")
