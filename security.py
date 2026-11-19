# """JWT creation and password hashing for OMG accounts."""
# import hashlib, hmac, os, secrets
# from datetime import datetime, timedelta, timezone
# import jwt
# from fastapi import HTTPException

# JWT_SECRET = os.getenv("OMG_JWT_SECRET", "")
# JWT_ALGORITHM = "HS256"
# JWT_EXPIRE_MINUTES = int(os.getenv("OMG_JWT_EXPIRE_MINUTES", "60"))

# def _secret():
#     if len(JWT_SECRET.encode("utf-8")) < 32:
#         raise RuntimeError("OMG_JWT_SECRET must be set to at least 32 characters")
#     return JWT_SECRET

# def hash_password(password: str) -> str:
#     salt = secrets.token_bytes(16)
#     digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310000)
#     return "pbkdf2_sha256$310000$%s$%s" % (salt.hex(), digest.hex())

# def verify_password(password: str, encoded: str) -> bool:
#     try:
#         algorithm, rounds, salt_hex, digest_hex = encoded.split("$")
#         if algorithm != "pbkdf2_sha256": return False
#         candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(rounds)).hex()
#         return hmac.compare_digest(candidate, digest_hex)
#     except Exception:
#         return False

# def create_access_token(account_id: str, email: str, jti: str) -> tuple[str, datetime]:
#     now = datetime.now(timezone.utc)
#     expires = now + timedelta(minutes=JWT_EXPIRE_MINUTES)
#     payload = {"sub": account_id, "email": email, "jti": jti, "iat": now, "exp": expires, "type": "access"}
#     return jwt.encode(payload, _secret(), algorithm=JWT_ALGORITHM), expires

# def decode_access_token(token: str) -> dict:
#     try:
#         return jwt.decode(token, _secret(), algorithms=[JWT_ALGORITHM], options={"require": ["sub", "jti", "exp"]})
#     except jwt.InvalidTokenError:
#         raise HTTPException(status_code=401, detail="Invalid or expired access token", headers={"WWW-Authenticate": "Bearer"})




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


def create_access_token(account_id: str, email: str):
    now = datetime.now(timezone.utc)
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