"""
Password hashing and JWT helpers.

Uses the `bcrypt` library directly rather than passlib - passlib's bcrypt
backend has a known compatibility issue with bcrypt>=4.1 (it probes
`bcrypt.__about__.__version__`, which no longer exists), and a portfolio
project has no reason to carry that indirection for one hashing call.

JWTs are stateless (no server-side session/refresh-token store, per the
explicit "no refresh-token infrastructure" scope). A token's only claim
is `sub` (the username) and `exp`; there is nothing to revoke early -
tokens simply expire after `settings.jwt_expires_minutes`.
"""

from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

from app.config import settings


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def create_access_token(username: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_expires_minutes)
    payload = {"sub": username, "exp": expire}
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> str | None:
    """
    Return the username embedded in a valid, unexpired token, or None if
    the token is invalid/expired/malformed in any way.
    """
    try:
        payload = jwt.decode(
            token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm]
        )
    except jwt.PyJWTError:
        return None
    return payload.get("sub")
