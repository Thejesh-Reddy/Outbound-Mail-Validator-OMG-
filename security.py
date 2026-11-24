# """JWT creation and password hashing for OMG accounts."""

import os
import hashlib
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from pwdlib import PasswordHash
from dotenv import load_dotenv

load_dotenv()

JWT_SECRET = os.getenv("OMG_JWT_SECRET")
JWT_ALGORITHM = os.getenv("OMG_JWT_ALGORITHM", "HS256")
TOKEN_EXPIRE_MINUTES = int(
    os.getenv("OMG_ACCESS_TOKEN_EXPIRE_MINUTES", "60")
)

if not JWT_SECRET or len(JWT_SECRET) < 32:
    raise RuntimeError("OMG_JWT_SECRET must contain at least 32 characters")

password_hash = PasswordHash.recommended()


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    return password_hash.verify(password, hashed_password)


def hash_session_id(jti: str) -> str:
    return hashlib.sha256(jti.encode()).hexdigest()


def create_access_token(account_id: str, email: str, issued_at=None):
    now = issued_at or datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=TOKEN_EXPIRE_MINUTES)

    jti = str(uuid.uuid4())

    payload = {
        "sub": account_id,
        "email": email,
        "jti": jti,
        "iat": now,
        "exp": expires_at,
    }

    token = jwt.encode(
        payload,
        JWT_SECRET,
        algorithm=JWT_ALGORITHM
    )

    return token, jti, expires_at


def decode_access_token(token: str):
    return jwt.decode(
        token,
        JWT_SECRET,
        algorithms=[JWT_ALGORITHM]
    )