"""
Authentication module for SentinelAI.
All state (users, OTP, rate limits, audit log) persists in the database.
"""
import os
import secrets
import hashlib
import time
import uuid
import json
import logging
from datetime import datetime, timezone, timedelta

import bcrypt
from jose import JWTError, jwt

from database import db
from services.email_service import send_otp_email

logger = logging.getLogger(__name__)

# JWT config
SECRET_KEY = os.environ.get("SECRET_KEY", "")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY environment variable is required")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7


# ── Ensure auth tables exist ──
def _ensure_auth_tables():
    """Create auth tables if they do not exist."""
    try:
        with db._cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS otp_store (
                    id TEXT PRIMARY KEY,
                    email TEXT NOT NULL,
                    hash TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    attempts INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL
                )
            """)
    except Exception as e:
        logger.error("Failed to create otp_store table: %s", e)

    try:
        with db._cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS rate_limits (
                    id TEXT PRIMARY KEY,
                    key TEXT NOT NULL,
                    timestamp REAL NOT NULL
                )
            """)
    except Exception as e:
        logger.error("Failed to create rate_limits table: %s", e)

    try:
        with db._cursor() as cur:
            if db.use_postgresql:
                cur.execute("CREATE INDEX IF NOT EXISTS idx_rate_limits_key ON rate_limits(key)")
            else:
                cur.execute("CREATE INDEX IF NOT EXISTS idx_rate_limits_key ON rate_limits(key)")
    except Exception:
        pass

_ensure_auth_tables()


# ── Password hashing ──
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


# ── JWT tokens ──
def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(token: str) -> dict | None:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


# ── OTP (database-backed) ──
def generate_otp(email: str) -> None:
    """Generate OTP, store hash in DB, and send email. OTP is never returned."""
    otp = f"{secrets.randbelow(1000000):06d}"
    hashed = hashlib.sha256(otp.encode()).hexdigest()
    now = datetime.now(timezone.utc).isoformat()
    otp_id = str(uuid.uuid4())
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()

    try:
        with db._cursor() as cur:
            # Clean expired OTPs for this email
            if db.use_postgresql:
                cur.execute("DELETE FROM otp_store WHERE email = %s", (email,))
            else:
                cur.execute("DELETE FROM otp_store WHERE email = ?", (email,))

            # Insert new OTP
            if db.use_postgresql:
                cur.execute(
                    "INSERT INTO otp_store (id, email, hash, expires_at, attempts, created_at) VALUES (%s,%s,%s,%s,0,%s)",
                    (otp_id, email, hashed, expires_at, now)
                )
            else:
                cur.execute(
                    "INSERT INTO otp_store (id, email, hash, expires_at, attempts, created_at) VALUES (?,?,?,?,0,?)",
                    (otp_id, email, hashed, expires_at, now)
                )
    except Exception as e:
        logger.error("Failed to store OTP for %s: %s", email, e)

    # Send OTP via email (best-effort, doesn't block registration)
    send_otp_email(email, otp)
    return None


def verify_otp(email: str, otp: str) -> bool:
    """Verify OTP from database. Returns True on match."""
    try:
        with db._cursor() as cur:
            if db.use_postgresql:
                cur.execute("SELECT * FROM otp_store WHERE email = %s ORDER BY created_at DESC LIMIT 1", (email,))
            else:
                cur.execute("SELECT * FROM otp_store WHERE email = ? ORDER BY created_at DESC LIMIT 1", (email,))
            row = cur.fetchone()

        if not row:
            return False

        record = dict(row)
        now = datetime.now(timezone.utc)

        # Check expiry
        expires_at = datetime.fromisoformat(record["expires_at"])
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if now > expires_at:
            _delete_otp(email)
            return False

        # Check max attempts
        if record["attempts"] >= 5:
            _delete_otp(email)
            return False

        # Increment attempts
        _increment_otp_attempts(record["id"])

        # Verify hash
        hashed = hashlib.sha256(otp.encode()).hexdigest()
        if hashed == record["hash"]:
            _delete_otp(email)
            return True

        return False
    except Exception as e:
        logger.error("Failed to verify OTP for %s: %s", email, e)
        return False


def _delete_otp(email: str):
    try:
        with db._cursor() as cur:
            if db.use_postgresql:
                cur.execute("DELETE FROM otp_store WHERE email = %s", (email,))
            else:
                cur.execute("DELETE FROM otp_store WHERE email = ?", (email,))
    except Exception:
        pass


def _increment_otp_attempts(otp_id: str):
    try:
        with db._cursor() as cur:
            if db.use_postgresql:
                cur.execute("UPDATE otp_store SET attempts = attempts + 1 WHERE id = %s", (otp_id,))
            else:
                cur.execute("UPDATE otp_store SET attempts = attempts + 1 WHERE id = ?", (otp_id,))
    except Exception:
        pass


# ── Rate limiting (database-backed) ──
def check_rate_limit(key: str, max_requests: int = 60, window_seconds: int = 60) -> bool:
    """Returns True if request is allowed, False if rate limited."""
    now = time.time()
    cutoff = now - window_seconds

    try:
        with db._cursor() as cur:
            # Clean old entries
            if db.use_postgresql:
                cur.execute("DELETE FROM rate_limits WHERE key = %s AND timestamp < %s", (key, cutoff))
            else:
                cur.execute("DELETE FROM rate_limits WHERE key = ? AND timestamp < ?", (key, cutoff))

            # Count current window
            if db.use_postgresql:
                cur.execute("SELECT COUNT(*) as cnt FROM rate_limits WHERE key = %s AND timestamp >= %s", (key, cutoff))
            else:
                cur.execute("SELECT COUNT(*) as cnt FROM rate_limits WHERE key = ? AND timestamp >= ?", (key, cutoff))
            row = cur.fetchone()
            count = row["cnt"] if db.use_postgresql else row[0]

            if count >= max_requests:
                return False

            # Record this request
            rl_id = str(uuid.uuid4())
            if db.use_postgresql:
                cur.execute("INSERT INTO rate_limits (id, key, timestamp) VALUES (%s,%s,%s)", (rl_id, key, now))
            else:
                cur.execute("INSERT INTO rate_limits (id, key, timestamp) VALUES (?,?,?)", (rl_id, key, now))

            return True
    except Exception as e:
        logger.error("Rate limit check failed: %s", e)
        return True  # Fail open


# ── Audit logging (database + memory for quick access) ──
_audit_buffer: list = []
AUDIT_BUFFER_MAX = 1000


def log_audit(user: str, action: str, details: str = ""):
    """Log audit event to database and in-memory buffer."""
    try:
        db.log_audit(user_id=user, action=action, details=details)
    except Exception:
        pass
    _audit_buffer.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user": user,
        "action": action,
        "details": details,
    })
    if len(_audit_buffer) > AUDIT_BUFFER_MAX:
        _audit_buffer.pop(0)


# ── User registration and authentication ──
def register_user(email: str, password: str, name: str, organization_id: str = '') -> dict | None:
    existing = db.get_user_by_email(email)
    if existing:
        return None
    hashed = hash_password(password)
    result = db.create_user(email, hashed, name, organization_id=organization_id)
    if not result:
        return None
    log_audit(email, "register", f"New user registered: {email}")
    return {
        "email": email,
        "name": name,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "role": "analyst",
        "organization_id": organization_id or result.get("organization_id", "")
    }


def authenticate_user(email: str, password: str) -> dict | None:
    row = db.get_user_by_email(email)
    if not row:
        log_audit(email, "login_failed", "Invalid credentials")
        return None
    user = dict(row)
    if not verify_password(password, user["password_hash"]):
        log_audit(email, "login_failed", "Invalid credentials")
        return None
    log_audit(email, "login_success", "User authenticated")
    return {
        "email": user["email"],
        "name": user["name"],
        "role": user["role"],
        "organization_id": user.get("organization_id", ""),
        "created_at": user["created_at"]
    }


# ── RBAC (Role-Based Access Control) ──
ROLES = {
    "admin": {"level": 4, "permissions": ["read", "write", "delete", "manage_users", "manage_rules", "manage_agents", "export", "configure"]},
    "soc_manager": {"level": 3, "permissions": ["read", "write", "delete", "manage_rules", "export", "configure"]},
    "analyst": {"level": 2, "permissions": ["read", "write", "export"]},
    "viewer": {"level": 1, "permissions": ["read"]},
}

def check_permission(role: str, permission: str) -> bool:
    role_config = ROLES.get(role.lower(), ROLES["viewer"])
    return permission in role_config.get("permissions", [])

def require_role(min_role: str):
    min_level = ROLES.get(min_role.lower(), ROLES["viewer"])["level"]
    def check(user_role: str) -> bool:
        user_level = ROLES.get(user_role.lower(), ROLES["viewer"])["level"]
        return user_level >= min_level
    return check

def get_user_role(payload: dict) -> str:
    return payload.get("role", "viewer")
