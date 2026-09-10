"""
Auth API.

Single login endpoint - JSON body, not OAuth2PasswordBearer's form-flow,
since there's no need to pull in python-multipart for a form the app's
own frontend never renders. Issues a stateless JWT (see app.auth.security)
on success.

Also applies a lightweight in-process rate limiter (_LoginRateLimiter
below) to failed login attempts, keyed by client IP. This is an
in-memory, single-process safeguard only - it resets on restart and each
process/instance would track its own counts independently. That's an
acceptable tradeoff for this single-operator, single-uvicorn-worker
application; a distributed deployment would need a shared store (e.g.
Redis) instead, which is deliberately out of scope here.
"""

import threading
import time
from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.auth.schemas import LoginRequest, LoginResponse
from app.auth.security import create_access_token, verify_password
from app.config import settings
from app.database.postgres import get_db
from app.models.user import User

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class _LoginRateLimiter:
    """
    Fixed-window limiter over failed login attempts, keyed by an
    arbitrary string (here, the client's IP). Not distributed - state
    lives only in this process' memory - but that's sufficient to stop
    an unlimited rapid-fire password-guessing loop against a single
    running instance, which is the threat this is meant to address.
    """

    def __init__(self, max_attempts: int, window_seconds: int):
        self._max_attempts = max_attempts
        self._window_seconds = window_seconds
        self._lock = threading.Lock()
        self._failures: dict[str, list[float]] = defaultdict(list)

    def check(self, key: str) -> None:
        """Raise HTTPException(429) if `key` is currently rate-limited."""
        cutoff = time.monotonic() - self._window_seconds
        with self._lock:
            recent = [t for t in self._failures[key] if t > cutoff]
            self._failures[key] = recent
            if len(recent) >= self._max_attempts:
                raise HTTPException(
                    status_code=429,
                    detail="Too many login attempts. Please try again later.",
                )

    def record_failure(self, key: str) -> None:
        with self._lock:
            self._failures[key].append(time.monotonic())


_login_limiter = _LoginRateLimiter(
    max_attempts=settings.login_rate_limit_max_attempts,
    window_seconds=settings.login_rate_limit_window_seconds,
)


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    client_key = request.client.host if request.client else "unknown"

    _login_limiter.check(client_key)

    user = db.query(User).filter(User.username == payload.username).first()

    if user is None or not verify_password(payload.password, user.password_hash):
        _login_limiter.record_failure(client_key)
        # Deliberately generic - never reveal whether the username exists.
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = create_access_token(user.username)
    return LoginResponse(access_token=token, username=user.username)
