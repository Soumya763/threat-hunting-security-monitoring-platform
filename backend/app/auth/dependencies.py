"""
FastAPI dependency that resolves the current authenticated user from a
Bearer token, for use on any route that needs to require login.
"""

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.auth.security import decode_access_token
from app.database.postgres import get_db
from app.models.user import User

# auto_error=False so a missing header is handled here (as a 401 with a
# WWW-Authenticate header) rather than HTTPBearer's default 403, which is
# the wrong status code for "not authenticated".
_bearer_scheme = HTTPBearer(auto_error=False)

_UNAUTHORIZED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Not authenticated",
    headers={"WWW-Authenticate": "Bearer"},
)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None:
        raise _UNAUTHORIZED

    username = decode_access_token(credentials.credentials)
    if username is None:
        raise _UNAUTHORIZED

    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise _UNAUTHORIZED

    return user
