import os
import secrets
import hashlib
import time
import uuid
from collections import defaultdict
import bcrypt
from jose import JWTError, jwt
from datetime import datetime, timezone, timedelta

from database import db

# JWT config
SECRET_KEY = os.environ.get("SECRET_KEY", "")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY environment variable is required")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

# In-memory user store (replace with PostgreSQL in production)
users_db = {}
otp_store = {}
audit_log = []
rate_limit_store = defaultdict(list)

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))

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

def generate_otp(email: str) -> None:
    """Generate OTP and store hash. OTP must be sent via email, never returned."""
    otp = f"{secrets.randbelow(1000000):06d}"
    hashed = hashlib.sha256(otp.encode()).hexdigest()
    otp_store[email] = {
        "hash": hashed,
        "expires": datetime.now(timezone.utc) + timedelta(minutes=5),
        "attempts": 0,
    }
    # In production, send OTP via email here
    # email_service.send_otp(email, otp)
    return None

def verify_otp(email: str, otp: str) -> bool:
    if email not in otp_store:
        return False
    record = otp_store[email]
    if datetime.now(timezone.utc) > record["expires"]:
        del otp_store[email]
        return False
    if record["attempts"] >= 5:
        del otp_store[email]
        return False
    record["attempts"] += 1
    hashed = hashlib.sha256(otp.encode()).hexdigest()
    if hashed == record["hash"]:
        del otp_store[email]
        return True
    return False

def check_rate_limit(key: str, max_requests: int = 60, window_seconds: int = 60) -> bool:
    """Returns True if request is allowed, False if rate limited."""
    now = time.time()
    rate_limit_store[key] = [t for t in rate_limit_store[key] if now - t < window_seconds]
    if len(rate_limit_store[key]) >= max_requests:
        return False
    rate_limit_store[key].append(now)
    return True

def log_audit(user: str, action: str, details: str = ""):
    # Persist to database
    try:
        db.log_audit(user_id=user, action=action, details=details)
    except Exception:
        pass
    # Also keep in memory for quick access (capped)
    audit_log.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user": user,
        "action": action,
        "details": details,
    })
    if len(audit_log) > 1000:
        audit_log.pop(0)

def register_user(email: str, password: str, name: str) -> dict | None:
    existing = db.get_user_by_email(email)
    if existing:
        return None
    hashed = hash_password(password)
    result = db.create_user(email, hashed, name)
    if not result:
        return None
    log_audit(email, "register", f"New user registered: {email}")
    return {
        "email": email,
        "name": name,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "role": "analyst"
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
    """Check if a role has a specific permission."""
    role_config = ROLES.get(role.lower(), ROLES["viewer"])
    return permission in role_config.get("permissions", [])

def require_role(min_role: str):
    """Decorator/factory that checks minimum role level."""
    min_level = ROLES.get(min_role.lower(), ROLES["viewer"])["level"]
    def check(user_role: str) -> bool:
        user_level = ROLES.get(user_role.lower(), ROLES["viewer"])["level"]
        return user_level >= min_level
    return check

def get_user_role(payload: dict) -> str:
    """Extract role from JWT payload."""
    return payload.get("role", "viewer")
