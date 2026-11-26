"""Storage and accounts: one SQLite file, password hashing, and the signed-in user."""
import base64
import hashlib
import hmac
import os
import secrets
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from fastapi import HTTPException, Request

from .i18n import T


# ============================================================================
# Database
# ============================================================================
# SQLite storage. One file, no server needed.

DB_PATH = Path(os.environ.get("STUDYPATH_DB", Path(__file__).resolve().parent.parent / "data" / "studypath.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    university TEXT NOT NULL DEFAULT 'openu',
    pw_hash TEXT NOT NULL,
    target_credits INTEGER NOT NULL DEFAULT 108,
    target_advanced INTEGER NOT NULL DEFAULT 36,
    plan_notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS courses (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    number TEXT NOT NULL,
    name TEXT NOT NULL,
    credits REAL NOT NULL DEFAULT 0,
    level TEXT NOT NULL DEFAULT '',
    field TEXT NOT NULL DEFAULT '',
    semester TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'planned',  -- planned | current | done
    grade INTEGER,
    result TEXT NOT NULL DEFAULT '',          -- '' | pass (עבר בינרי) | exempt (פטור)
    color TEXT NOT NULL DEFAULT '#6366f1',
    UNIQUE(user_id, number)
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    uid TEXT NOT NULL,
    course_number TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'other',      -- exam | meeting | assignment | other
    start TEXT NOT NULL,                      -- ISO datetime (local time)
    end TEXT,
    all_day INTEGER NOT NULL DEFAULT 0,
    location TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'manual',   -- ics | manual
    done INTEGER NOT NULL DEFAULT 0,
    UNIQUE(user_id, uid)
);
CREATE TABLE IF NOT EXISTS catalog (
    number TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    credits REAL NOT NULL DEFAULT 0,
    level TEXT NOT NULL DEFAULT '',
    field TEXT NOT NULL DEFAULT '',
    prior_knowledge TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    exams TEXT NOT NULL DEFAULT '[]',
    fetched_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS assistant_proposals (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    payload TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',  -- pending | applied | rejected
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS assistant_usage (
    user_id INTEGER NOT NULL,
    day TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, day)
);
CREATE INDEX IF NOT EXISTS idx_events_user_start ON events(user_id, start);
"""


MIGRATIONS = [
    ("users", "university", "ALTER TABLE users ADD COLUMN university TEXT NOT NULL DEFAULT 'openu'"),
    ("catalog", "exams", "ALTER TABLE catalog ADD COLUMN exams TEXT NOT NULL DEFAULT '[]'"),
    ("courses", "result", "ALTER TABLE courses ADD COLUMN result TEXT NOT NULL DEFAULT ''"),
]


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with connect() as con:
        con.executescript(SCHEMA)
        for table, column, sql in MIGRATIONS:
            cols = {r[1] for r in con.execute(f"PRAGMA table_info({table})")}
            if column not in cols:
                con.execute(sql)
        # catalog keys became "<university>:<code>"
        con.execute("DELETE FROM catalog WHERE number NOT LIKE '%:%'")


@contextmanager
def connect():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    try:
        yield con
        con.commit()
    finally:
        con.close()


def rows(cur) -> list[dict]:
    return [dict(r) for r in cur.fetchall()]


# ============================================================================
# Accounts
# ============================================================================
# Accounts: scrypt password hashes (stdlib), signed session cookie.

_N, _R, _P = 2**14, 8, 1


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(dk).decode()


def verify_password(password: str, stored: str) -> bool:
    try:
        _, salt_b64, dk_b64 = stored.split("$")
        salt, dk = base64.b64decode(salt_b64), base64.b64decode(dk_b64)
    except ValueError:
        return False
    test = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P)
    return hmac.compare_digest(test, dk)


def secret_key() -> str:
    key = os.environ.get("SECRET_KEY")
    if key:
        return key
    path = DB_PATH.parent / ".secret_key"
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(secrets.token_urlsafe(48))
    return path.read_text().strip()


def current_user(request: Request) -> dict | None:
    uid = request.session.get("uid")
    if not uid:
        return None
    with connect() as con:
        row = con.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    return dict(row) if row else None


def require_user(request: Request) -> dict:
    user = current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail=T("לא מחובר"))
    return user


def require_api_user(request: Request) -> dict:
    """JSON API guard: logged-in user + same-origin header (basic CSRF protection)."""
    if request.method not in ("GET", "HEAD") and request.headers.get("x-requested-with") != "studypath":
        raise HTTPException(status_code=403, detail=T("בקשה לא מורשית"))
    return require_user(request)
