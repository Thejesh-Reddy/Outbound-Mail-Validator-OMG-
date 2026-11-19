
"""Single Authorization endpoint for registration, login, profile and logout."""

from datetime import datetime, timezone
from bson import ObjectId
from bson.errors import InvalidId
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from pymongo.errors import DuplicateKeyError
from typing import Literal, Optional
import jwt

from database import users_collection, sessions_collection
from security import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
    hash_session_id,
)

router = APIRouter(tags=["Authorization"])
bearer = HTTPBearer(auto_error=False)


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
    """Validate JWT and confirm that its MongoDB session is active."""

    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=401,
            detail="Bearer access token required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_access_token(credentials.credentials)

        account_id = payload["sub"]
        email = payload["email"]
        jti = payload["jti"]

        session = sessions_collection.find_one({
            "account_id": account_id,
            "jwt_token": hash_session_id(jti),
            "revoked": False,
            "expires_at": {"$gt": datetime.now(timezone.utc)},
        })

        if not session:
            raise HTTPException(
                status_code=401,
                detail="Session expired or revoked",
            )

        user = users_collection.find_one({
            "_id": ObjectId(account_id),
            "is_active": True,
        })

        if not user or user["email"] != email:
            raise HTTPException(
                status_code=401,
                detail="Invalid user session",
            )

        return {
            "id": str(user["_id"]),
            "name": user.get("name"),
            "email": user["email"],
        }

    except HTTPException:
        raise
    except (jwt.InvalidTokenError, KeyError, ValueError, InvalidId, TypeError):
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def _register(data: AuthorizationRequest):
    if not data.name or not data.email or not data.password:
        raise HTTPException(
            status_code=422,
            detail="Registration requires name, email and password",
        )

    email = str(data.email).strip().lower()

    user = {
        "name": data.name.strip(),
        "email": email,
        "password_hash": hash_password(data.password),
        "created_at": datetime.now(timezone.utc),
        "is_active": True,
    }

    try:
        result = users_collection.insert_one(user)
    except DuplicateKeyError:
        raise HTTPException(
            status_code=409,
            detail="Email already registered",
        )

    return {
        "message": "Account created successfully",
        "user": {
            "id": str(result.inserted_id),
            "name": user["name"],
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
    user = users_collection.find_one({"email": email})

    if (
        not user
        or not user.get("is_active", False)
        or not verify_password(data.password, user.get("password_hash", ""))
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password",
        )

    account_id = str(user["_id"])

    token, jti, expires_at = create_access_token(
        account_id,
        email,
    )

    sessions_collection.insert_one({
        "account_id": account_id,
        "email": email,
        "jwt_token": hash_session_id(jti),
        "created_at": datetime.now(timezone.utc),
        "expires_at": expires_at,
        "revoked": False,
    })

    return {
        "message": "Login successful",
        "access_token": token,
        "token_type": "bearer",
        "expires_at": expires_at.isoformat(),
        "user": {
            "id": account_id,
            "name": user.get("name"),
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

        sessions_collection.update_one(
            {
                "account_id": current_user["id"],
                "jwt_token": hash_session_id(payload["jti"]),
                "revoked": False,
            },
            {
                "$set": {
                    "revoked": True,
                    "revoked_at": datetime.now(timezone.utc),
                }
            },
        )

        return {"message": "Logged out successfully"}

    raise HTTPException(status_code=400, detail="Unsupported authorization action")
