"""
One-off CLI for creating a login user.

There is no public self-registration endpoint by design - this is a
single-operator portfolio tool, so a signup form would only add attack
surface for no benefit. Creating a user is an operator action, run the
same way init_db.py/migrate.py already are:

    python -m app.auth.create_user <username> <password>
"""

import sys

from sqlalchemy.exc import IntegrityError

from app.auth.security import hash_password
from app.database.postgres import SessionLocal
from app.models.user import User


def create_user(username: str, password: str) -> None:
    db = SessionLocal()
    try:
        user = User(username=username, password_hash=hash_password(password))
        db.add(user)
        db.commit()
        db.refresh(user)
        print(f"Created user id={user.id} username={user.username!r}")
    except IntegrityError:
        db.rollback()
        print(f"A user named {username!r} already exists.")
        sys.exit(1)
    finally:
        db.close()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python -m app.auth.create_user <username> <password>")
        sys.exit(1)
    create_user(sys.argv[1], sys.argv[2])
