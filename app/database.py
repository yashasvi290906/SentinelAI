"""
Database Manager for SentinelAI.
Supports SQLite (development) and PostgreSQL (production).
Handles: users, sessions, logs, threats, predictions, reports, notifications, audit_logs, organizations, devices, alerts, investigation_notes.
"""
import os
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any
from contextlib import contextmanager

try:
    import psycopg2
    import psycopg2.extras
    HAS_POSTGRESQL = True
except ImportError:
    HAS_POSTGRESQL = False

DB_URL = os.environ.get("DATABASE_URL", "")
DB_PATH = Path(os.environ.get("DATABASE_PATH", Path(__file__).parent / "sentinelai.db"))

USE_POSTGRESQL = HAS_POSTGRESQL and DB_URL and DB_URL.startswith("postgres")


class DatabaseManager:
    def __init__(self):
        if USE_POSTGRESQL:
            self._init_postgresql()
        else:
            self._init_sqlite()

    def _init_sqlite(self):
        self.conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.row_factory = sqlite3.Row
        self._create_tables_sqlite()

    def _init_postgresql(self):
        self.conn = psycopg2.connect(DB_URL, cursor_factory=psycopg2.extras.RealDictCursor)
        self.conn.autocommit = False
        self._create_tables_postgresql()

    @contextmanager
    def _cursor(self):
        if USE_POSTGRESQL:
            cursor = self.conn.cursor()
            try:
                yield cursor
                self.conn.commit()
            except Exception:
                self.conn.rollback()
                raise
            finally:
                cursor.close()
        else:
            cursor = self.conn.cursor()
            try:
                yield cursor
                self.conn.commit()
            except Exception:
                self.conn.rollback()
                raise

    def _create_tables_sqlite(self):
        with self._cursor() as cur:
            cur.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    name TEXT NOT NULL,
                    role TEXT DEFAULT 'analyst',
                    is_active INTEGER DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    refresh_token TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                );

                CREATE TABLE IF NOT EXISTS uploaded_logs (
                    id TEXT PRIMARY KEY,
                    user_id TEXT,
                    filename TEXT NOT NULL,
                    file_size INTEGER DEFAULT 0,
                    source_type TEXT NOT NULL,
                    event_count INTEGER DEFAULT 0,
                    upload_time TEXT NOT NULL,
                    status TEXT DEFAULT 'processing',
                    metadata TEXT DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS log_events (
                    id TEXT PRIMARY KEY,
                    log_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT DEFAULT '',
                    dest_ip TEXT DEFAULT '',
                    source_port INTEGER DEFAULT 0,
                    dest_port INTEGER DEFAULT 0,
                    protocol TEXT DEFAULT '',
                    event_type TEXT DEFAULT '',
                    severity TEXT DEFAULT 'INFO',
                    user_name TEXT DEFAULT '',
                    url TEXT DEFAULT '',
                    method TEXT DEFAULT '',
                    status_code INTEGER DEFAULT 0,
                    message TEXT DEFAULT '',
                    raw_line TEXT DEFAULT '',
                    source_format TEXT DEFAULT '',
                    metadata TEXT DEFAULT '{}',
                    FOREIGN KEY (log_id) REFERENCES uploaded_logs(id)
                );

                CREATE TABLE IF NOT EXISTS threat_detections (
                    id TEXT PRIMARY KEY,
                    log_id TEXT,
                    detection_time TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    source_ip TEXT DEFAULT '',
                    dest_ip TEXT DEFAULT '',
                    dest_port INTEGER DEFAULT 0,
                    description TEXT DEFAULT '',
                    evidence TEXT DEFAULT '[]',
                    mitre_technique TEXT DEFAULT '',
                    mitre_tactic TEXT DEFAULT '',
                    first_seen TEXT DEFAULT '',
                    last_seen TEXT DEFAULT '',
                    event_count INTEGER DEFAULT 0,
                    recommendations TEXT DEFAULT '[]',
                    status TEXT DEFAULT 'open',
                    FOREIGN KEY (log_id) REFERENCES uploaded_logs(id)
                );

                CREATE TABLE IF NOT EXISTS anomaly_scores (
                    id TEXT PRIMARY KEY,
                    log_id TEXT,
                    analysis_time TEXT NOT NULL,
                    anomaly_score REAL NOT NULL,
                    risk_level TEXT NOT NULL,
                    anomalies TEXT DEFAULT '[]',
                    feature_scores TEXT DEFAULT '{}',
                    explanation TEXT DEFAULT '',
                    FOREIGN KEY (log_id) REFERENCES uploaded_logs(id)
                );

                CREATE TABLE IF NOT EXISTS predictions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    sequence TEXT NOT NULL,
                    prediction TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    severity TEXT NOT NULL,
                    severity_score REAL NOT NULL,
                    latency_ms REAL NOT NULL,
                    model TEXT DEFAULT 'v2.1-deterministic'
                );

                CREATE TABLE IF NOT EXISTS comparisons (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    sequence TEXT NOT NULL,
                    ml_prediction TEXT NOT NULL,
                    markov_prediction TEXT NOT NULL,
                    agreement INTEGER NOT NULL,
                    agreement_score REAL DEFAULT 0.0,
                    latency_ms REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS reports (
                    id TEXT PRIMARY KEY,
                    user_id TEXT,
                    report_type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    generated_at TEXT NOT NULL,
                    data_json TEXT NOT NULL,
                    file_path TEXT,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                );

                CREATE TABLE IF NOT EXISTS notifications (
                    id TEXT PRIMARY KEY,
                    user_id TEXT,
                    title TEXT NOT NULL,
                    message TEXT NOT NULL,
                    type TEXT DEFAULT 'info',
                    read INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                );

                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT,
                    action TEXT NOT NULL,
                    details TEXT DEFAULT '',
                    ip_address TEXT DEFAULT '',
                    timestamp TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS organizations (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    slug TEXT UNIQUE NOT NULL,
                    created_at TEXT NOT NULL,
                    settings TEXT DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS devices (
                    id TEXT PRIMARY KEY,
                    organization_id TEXT,
                    hostname TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    os_type TEXT DEFAULT 'unknown',
                    status TEXT DEFAULT 'active',
                    risk_score REAL DEFAULT 0.0,
                    last_seen TEXT,
                    created_at TEXT NOT NULL,
                    metadata TEXT DEFAULT '{}',
                    FOREIGN KEY (organization_id) REFERENCES organizations(id)
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    organization_id TEXT,
                    log_id TEXT,
                    device_id TEXT,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    source_ip TEXT DEFAULT '',
                    destination_ip TEXT DEFAULT '',
                    source_port INTEGER DEFAULT 0,
                    destination_port INTEGER DEFAULT 0,
                    protocol TEXT DEFAULT '',
                    mitre_technique TEXT DEFAULT '',
                    mitre_tactic TEXT DEFAULT '',
                    evidence TEXT DEFAULT '[]',
                    recommendations TEXT DEFAULT '[]',
                    status TEXT DEFAULT 'open',
                    assigned_to TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT,
                    resolved_at TEXT,
                    FOREIGN KEY (organization_id) REFERENCES organizations(id),
                    FOREIGN KEY (log_id) REFERENCES uploaded_logs(id),
                    FOREIGN KEY (device_id) REFERENCES devices(id)
                );

                CREATE TABLE IF NOT EXISTS investigation_notes (
                    id TEXT PRIMARY KEY,
                    alert_id TEXT NOT NULL,
                    user_id TEXT,
                    note TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (alert_id) REFERENCES alerts(id),
                    FOREIGN KEY (user_id) REFERENCES users(id)
                );

                CREATE INDEX IF NOT EXISTS idx_log_events_log_id ON log_events(log_id);
                CREATE INDEX IF NOT EXISTS idx_log_events_timestamp ON log_events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_log_events_source_ip ON log_events(source_ip);
                CREATE INDEX IF NOT EXISTS idx_log_events_event_type ON log_events(event_type);
                CREATE INDEX IF NOT EXISTS idx_log_events_severity ON log_events(severity);
                CREATE INDEX IF NOT EXISTS idx_threat_detections_log_id ON threat_detections(log_id);
                CREATE INDEX IF NOT EXISTS idx_threat_detections_severity ON threat_detections(severity);
                CREATE INDEX IF NOT EXISTS idx_threat_detections_threat_type ON threat_detections(threat_type);
                CREATE INDEX IF NOT EXISTS idx_uploaded_logs_user_id ON uploaded_logs(user_id);
            """)

    def _create_tables_postgresql(self):
        with self._cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    name VARCHAR(255) NOT NULL,
                    role VARCHAR(50) DEFAULT 'analyst',
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    user_id UUID NOT NULL REFERENCES users(id),
                    refresh_token TEXT NOT NULL,
                    expires_at TIMESTAMPTZ NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS uploaded_logs (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    user_id UUID REFERENCES users(id),
                    filename VARCHAR(500) NOT NULL,
                    file_size BIGINT DEFAULT 0,
                    source_type VARCHAR(100) NOT NULL,
                    event_count INTEGER DEFAULT 0,
                    upload_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    status VARCHAR(50) DEFAULT 'processing',
                    metadata JSONB DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS log_events (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    log_id UUID NOT NULL REFERENCES uploaded_logs(id),
                    timestamp TIMESTAMPTZ NOT NULL,
                    source_ip INET,
                    dest_ip INET,
                    source_port SMALLINT,
                    dest_port SMALLINT,
                    protocol VARCHAR(20),
                    event_type VARCHAR(100),
                    severity VARCHAR(20) DEFAULT 'INFO',
                    user_name VARCHAR(255),
                    url TEXT,
                    method VARCHAR(10),
                    status_code SMALLINT,
                    message TEXT,
                    raw_line TEXT,
                    source_format VARCHAR(50),
                    metadata JSONB DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS threat_detections (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    log_id UUID REFERENCES uploaded_logs(id),
                    detection_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    threat_type VARCHAR(100) NOT NULL,
                    severity VARCHAR(20) NOT NULL,
                    confidence REAL NOT NULL,
                    source_ip INET,
                    dest_ip INET,
                    dest_port SMALLINT,
                    description TEXT,
                    evidence JSONB DEFAULT '[]',
                    mitre_technique VARCHAR(20),
                    mitre_tactic VARCHAR(100),
                    first_seen TIMESTAMPTZ,
                    last_seen TIMESTAMPTZ,
                    event_count INTEGER DEFAULT 0,
                    recommendations JSONB DEFAULT '[]',
                    status VARCHAR(50) DEFAULT 'open'
                );

                CREATE TABLE IF NOT EXISTS anomaly_scores (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    log_id UUID REFERENCES uploaded_logs(id),
                    analysis_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    anomaly_score REAL NOT NULL,
                    risk_level VARCHAR(20) NOT NULL,
                    anomalies JSONB DEFAULT '[]',
                    feature_scores JSONB DEFAULT '{}',
                    explanation TEXT
                );

                CREATE TABLE IF NOT EXISTS predictions (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    sequence JSONB NOT NULL,
                    prediction VARCHAR(100) NOT NULL,
                    confidence REAL NOT NULL,
                    severity VARCHAR(20) NOT NULL,
                    severity_score REAL NOT NULL,
                    latency_ms REAL NOT NULL,
                    model VARCHAR(100) DEFAULT 'v2.1-deterministic'
                );

                CREATE TABLE IF NOT EXISTS comparisons (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    sequence JSONB NOT NULL,
                    ml_prediction VARCHAR(100) NOT NULL,
                    markov_prediction VARCHAR(100) NOT NULL,
                    agreement BOOLEAN NOT NULL,
                    agreement_score REAL DEFAULT 0.0,
                    latency_ms REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS reports (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    user_id UUID REFERENCES users(id),
                    report_type VARCHAR(100) NOT NULL,
                    title VARCHAR(500) NOT NULL,
                    generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    data_json JSONB NOT NULL,
                    file_path TEXT
                );

                CREATE TABLE IF NOT EXISTS notifications (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    user_id UUID REFERENCES users(id),
                    title VARCHAR(500) NOT NULL,
                    message TEXT NOT NULL,
                    type VARCHAR(50) DEFAULT 'info',
                    read BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS audit_log (
                    id SERIAL PRIMARY KEY,
                    user_id UUID REFERENCES users(id),
                    action VARCHAR(100) NOT NULL,
                    details TEXT DEFAULT '',
                    ip_address INET,
                    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS organizations (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    name VARCHAR(255) NOT NULL,
                    slug VARCHAR(255) UNIQUE NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    settings JSONB DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS devices (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    organization_id UUID REFERENCES organizations(id),
                    hostname VARCHAR(255) NOT NULL,
                    ip_address INET NOT NULL,
                    os_type VARCHAR(50) DEFAULT 'unknown',
                    status VARCHAR(50) DEFAULT 'active',
                    risk_score REAL DEFAULT 0.0,
                    last_seen TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    metadata JSONB DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    organization_id UUID REFERENCES organizations(id),
                    log_id UUID REFERENCES uploaded_logs(id),
                    device_id UUID REFERENCES devices(id),
                    alert_type VARCHAR(100) NOT NULL,
                    severity VARCHAR(20) NOT NULL,
                    title VARCHAR(500) NOT NULL,
                    description TEXT DEFAULT '',
                    source_ip INET,
                    destination_ip INET,
                    source_port SMALLINT,
                    destination_port SMALLINT,
                    protocol VARCHAR(20),
                    mitre_technique VARCHAR(20),
                    mitre_tactic VARCHAR(100),
                    evidence JSONB DEFAULT '[]',
                    recommendations JSONB DEFAULT '[]',
                    status VARCHAR(50) DEFAULT 'open',
                    assigned_to UUID,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ,
                    resolved_at TIMESTAMPTZ
                );

                CREATE TABLE IF NOT EXISTS investigation_notes (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    alert_id UUID NOT NULL REFERENCES alerts(id),
                    user_id UUID REFERENCES users(id),
                    note TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
            """)

            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_log_events_log_id ON log_events(log_id);
                CREATE INDEX IF NOT EXISTS idx_log_events_timestamp ON log_events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_log_events_source_ip ON log_events(source_ip);
                CREATE INDEX IF NOT EXISTS idx_log_events_event_type ON log_events(event_type);
                CREATE INDEX IF NOT EXISTS idx_log_events_severity ON log_events(severity);
                CREATE INDEX IF NOT EXISTS idx_threat_detections_log_id ON threat_detections(log_id);
                CREATE INDEX IF NOT EXISTS idx_threat_detections_severity ON threat_detections(severity);
                CREATE INDEX IF NOT EXISTS idx_uploaded_logs_user_id ON uploaded_logs(user_id);
            """)

    def create_user(self, email: str, password_hash: str, name: str, role: str = 'analyst') -> Dict[str, Any]:
        user_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute(
                    "INSERT INTO users (id, email, password_hash, name, role, created_at) VALUES (%s,%s,%s,%s,%s,%s) RETURNING id, email, name, role, created_at",
                    (user_id, email, password_hash, name, role, now)
                )
                return dict(cur.fetchone())
            else:
                cur.execute(
                    "INSERT INTO users (id, email, password_hash, name, role, created_at) VALUES (?,?,?,?,?,?)",
                    (user_id, email, password_hash, name, role, now)
                )
                return {"id": user_id, "email": email, "name": name, "role": role, "created_at": now}

    def get_user_by_email(self, email: str) -> Optional[Dict]:
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("SELECT * FROM users WHERE email = %s", (email,))
            else:
                cur.execute("SELECT * FROM users WHERE email = ?", (email,))
            row = cur.fetchone()
            return dict(row) if row else None

    def get_user_by_id(self, user_id: str) -> Optional[Dict]:
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            else:
                cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def update_user_password(self, user_id: str, password_hash: str) -> bool:
        try:
            now = datetime.now(timezone.utc).isoformat()
            with self._cursor() as cur:
                if USE_POSTGRESQL:
                    cur.execute("UPDATE users SET password_hash = %s, updated_at = %s WHERE id = %s",
                                (password_hash, now, user_id))
                else:
                    cur.execute("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
                                (password_hash, now, user_id))
            return True
        except Exception:
            return False

    def create_session(self, user_id: str, refresh_token: str, expires_at: str) -> str:
        session_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute(
                    "INSERT INTO sessions (id, user_id, refresh_token, expires_at, created_at) VALUES (%s,%s,%s,%s,%s)",
                    (session_id, user_id, refresh_token, expires_at, now)
                )
            else:
                cur.execute(
                    "INSERT INTO sessions (id, user_id, refresh_token, expires_at, created_at) VALUES (?,?,?,?,?)",
                    (session_id, user_id, refresh_token, expires_at, now)
                )
        return session_id

    def get_session_by_token(self, refresh_token: str) -> Optional[Dict]:
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("SELECT * FROM sessions WHERE refresh_token = %s", (refresh_token,))
            else:
                cur.execute("SELECT * FROM sessions WHERE refresh_token = ?", (refresh_token,))
            row = cur.fetchone()
            return dict(row) if row else None

    def delete_session(self, session_id: str):
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("DELETE FROM sessions WHERE id = %s", (session_id,))
            else:
                cur.execute("DELETE FROM sessions WHERE id = ?", (session_id,))

    def create_uploaded_log(self, filename: str, source_type: str, user_id: str = None, file_size: int = 0) -> str:
        log_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute(
                    "INSERT INTO uploaded_logs (id, user_id, filename, file_size, source_type, upload_time) VALUES (%s,%s,%s,%s,%s,%s)",
                    (log_id, user_id, filename, file_size, source_type, now)
                )
            else:
                cur.execute(
                    "INSERT INTO uploaded_logs (id, user_id, filename, file_size, source_type, upload_time) VALUES (?,?,?,?,?,?)",
                    (log_id, user_id, filename, file_size, source_type, now)
                )
        return log_id

    def update_log_status(self, log_id: str, status: str, event_count: int = 0):
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("UPDATE uploaded_logs SET status = %s, event_count = %s WHERE id = %s", (status, event_count, log_id))
            else:
                cur.execute("UPDATE uploaded_logs SET status = ?, event_count = ? WHERE id = ?", (status, event_count, log_id))

    def insert_log_events(self, log_id: str, events: List[Dict]) -> int:
        if not events:
            return 0
        inserted = 0
        with self._cursor() as cur:
            for event in events:
                event_id = str(uuid.uuid4())
                try:
                    if USE_POSTGRESQL:
                        cur.execute("""
                            INSERT INTO log_events (id, log_id, timestamp, source_ip, dest_ip, source_port, dest_port,
                                protocol, event_type, severity, user_name, url, method, status_code, message, raw_line, source_format, metadata)
                            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        """, (
                            event_id, log_id,
                            event.get('timestamp', ''), event.get('source_ip', ''), event.get('dest_ip', ''),
                            event.get('source_port', 0), event.get('dest_port', 0),
                            event.get('protocol', ''), event.get('event_type', ''), event.get('severity', 'INFO'),
                            event.get('user', ''), event.get('url', ''), event.get('method', ''),
                            event.get('status_code', 0), event.get('message', ''), event.get('raw_line', ''),
                            event.get('source_type', ''), json.dumps(event.get('metadata', {}))
                        ))
                    else:
                        cur.execute("""
                            INSERT INTO log_events (id, log_id, timestamp, source_ip, dest_ip, source_port, dest_port,
                                protocol, event_type, severity, user_name, url, method, status_code, message, raw_line, source_format, metadata)
                            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                        """, (
                            event_id, log_id,
                            event.get('timestamp', ''), event.get('source_ip', ''), event.get('dest_ip', ''),
                            event.get('source_port', 0), event.get('dest_port', 0),
                            event.get('protocol', ''), event.get('event_type', ''), event.get('severity', 'INFO'),
                            event.get('user', ''), event.get('url', ''), event.get('method', ''),
                            event.get('status_code', 0), event.get('message', ''), event.get('raw_line', ''),
                            event.get('source_type', ''), json.dumps(event.get('metadata', {}))
                        ))
                    inserted += 1
                except Exception:
                    continue
        return inserted

    def get_log_events(self, log_id: str, limit: int = 1000) -> List[Dict]:
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("SELECT * FROM log_events WHERE log_id = %s ORDER BY timestamp LIMIT %s", (log_id, limit))
            else:
                cur.execute("SELECT * FROM log_events WHERE log_id = ? ORDER BY timestamp LIMIT ?", (log_id, limit))
            return [dict(row) for row in cur.fetchall()]

    def get_uploaded_logs(self, user_id: str = None, limit: int = 50) -> List[Dict]:
        with self._cursor() as cur:
            if user_id:
                if USE_POSTGRESQL:
                    cur.execute("SELECT * FROM uploaded_logs WHERE user_id = %s ORDER BY upload_time DESC LIMIT %s", (user_id, limit))
                else:
                    cur.execute("SELECT * FROM uploaded_logs WHERE user_id = ? ORDER BY upload_time DESC LIMIT ?", (user_id, limit))
            else:
                if USE_POSTGRESQL:
                    cur.execute("SELECT * FROM uploaded_logs ORDER BY upload_time DESC LIMIT %s", (limit,))
                else:
                    cur.execute("SELECT * FROM uploaded_logs ORDER BY upload_time DESC LIMIT ?", (limit,))
            return [dict(row) for row in cur.fetchall()]

    def insert_threat_detections(self, log_id: str, detections: List[Dict]) -> int:
        inserted = 0
        with self._cursor() as cur:
            for det in detections:
                det_id = str(uuid.uuid4())
                try:
                    if USE_POSTGRESQL:
                        cur.execute("""
                            INSERT INTO threat_detections (id, log_id, threat_type, severity, confidence, source_ip, dest_ip,
                                dest_port, description, evidence, mitre_technique, mitre_tactic, first_seen, last_seen, event_count, recommendations)
                            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        """, (
                            det_id, log_id, det.get('threat_type', ''), det.get('severity', 'INFO'),
                            det.get('confidence', 0.0), det.get('source_ip', ''), det.get('dest_ip', ''),
                            det.get('dest_port', 0), det.get('description', ''),
                            json.dumps(det.get('evidence', [])), det.get('mitre_technique', ''),
                            det.get('mitre_tactic', ''), det.get('first_seen', ''), det.get('last_seen', ''),
                            det.get('event_count', 0), json.dumps(det.get('recommendations', []))
                        ))
                    else:
                        cur.execute("""
                            INSERT INTO threat_detections (id, log_id, threat_type, severity, confidence, source_ip, dest_ip,
                                dest_port, description, evidence, mitre_technique, mitre_tactic, first_seen, last_seen, event_count, recommendations)
                            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                        """, (
                            det_id, log_id, det.get('threat_type', ''), det.get('severity', 'INFO'),
                            det.get('confidence', 0.0), det.get('source_ip', ''), det.get('dest_ip', ''),
                            det.get('dest_port', 0), det.get('description', ''),
                            json.dumps(det.get('evidence', [])), det.get('mitre_technique', ''),
                            det.get('mitre_tactic', ''), det.get('first_seen', ''), det.get('last_seen', ''),
                            det.get('event_count', 0), json.dumps(det.get('recommendations', []))
                        ))
                    inserted += 1
                except Exception:
                    continue
        return inserted

    def get_threat_detections(self, log_id: str = None, limit: int = 100) -> List[Dict]:
        with self._cursor() as cur:
            if log_id:
                if USE_POSTGRESQL:
                    cur.execute("SELECT * FROM threat_detections WHERE log_id = %s ORDER BY detection_time DESC LIMIT %s", (log_id, limit))
                else:
                    cur.execute("SELECT * FROM threat_detections WHERE log_id = ? ORDER BY detection_time DESC LIMIT ?", (log_id, limit))
            else:
                if USE_POSTGRESQL:
                    cur.execute("SELECT * FROM threat_detections ORDER BY detection_time DESC LIMIT %s", (limit,))
                else:
                    cur.execute("SELECT * FROM threat_detections ORDER BY detection_time DESC LIMIT ?", (limit,))
            return [dict(row) for row in cur.fetchall()]

    def get_threat_summary(self) -> Dict[str, Any]:
        with self._cursor() as cur:
            cur.execute("SELECT COUNT(*) as total FROM threat_detections")
            row = cur.fetchone()
            total = row['total'] if USE_POSTGRESQL else row[0]

            cur.execute("SELECT severity, COUNT(*) as count FROM threat_detections GROUP BY severity")
            severity_rows = cur.fetchall()
            severity = {row['severity']: row['count'] if USE_POSTGRESQL else row[1] for row in severity_rows}

            cur.execute("SELECT threat_type, COUNT(*) as count FROM threat_detections GROUP BY threat_type ORDER BY count DESC")
            type_rows = cur.fetchall()
            threat_types = {row['threat_type']: row['count'] if USE_POSTGRESQL else row[1] for row in type_rows}

            cur.execute("SELECT status, COUNT(*) as count FROM threat_detections GROUP BY status")
            status_rows = cur.fetchall()
            statuses = {row['status']: row['count'] if USE_POSTGRESQL else row[1] for row in status_rows}

            return {
                'total': total,
                'by_severity': severity,
                'by_type': threat_types,
                'by_status': statuses,
            }

    def insert_anomaly_score(self, log_id: str, score: float, risk_level: str, anomalies: List, feature_scores: Dict, explanation: str) -> str:
        score_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute(
                    "INSERT INTO anomaly_scores (id, log_id, analysis_time, anomaly_score, risk_level, anomalies, feature_scores, explanation) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                    (score_id, log_id, now, score, risk_level, json.dumps(anomalies), json.dumps(feature_scores), explanation)
                )
            else:
                cur.execute(
                    "INSERT INTO anomaly_scores (id, log_id, analysis_time, anomaly_score, risk_level, anomalies, feature_scores, explanation) VALUES (?,?,?,?,?,?,?,?)",
                    (score_id, log_id, now, score, risk_level, json.dumps(anomalies), json.dumps(feature_scores), explanation)
                )
        return score_id

    def record_prediction(self, timestamp, sequence, prediction, confidence,
                          severity, severity_score, latency_ms, model="v2.1-deterministic"):
        try:
            with self._cursor() as cur:
                if USE_POSTGRESQL:
                    cur.execute(
                        "INSERT INTO predictions (timestamp, sequence, prediction, confidence, severity, severity_score, latency_ms, model) "
                        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
                        (timestamp, json.dumps(sequence), prediction, confidence, severity, severity_score, latency_ms, model)
                    )
                    return cur.fetchone()['id']
                else:
                    cur.execute(
                        "INSERT INTO predictions (timestamp, sequence, prediction, confidence, severity, severity_score, latency_ms, model) "
                        "VALUES (?,?,?,?,?,?,?,?)",
                        (timestamp, json.dumps(sequence) if isinstance(sequence, (list, dict)) else sequence,
                         prediction, confidence, severity, severity_score, latency_ms, model)
                    )
                    return cur.lastrowid
        except Exception:
            return None

    def get_predictions(self, limit=100):
        try:
            with self._cursor() as cur:
                if USE_POSTGRESQL:
                    cur.execute("SELECT * FROM predictions ORDER BY id DESC LIMIT %s", (limit,))
                else:
                    cur.execute("SELECT * FROM predictions ORDER BY id DESC LIMIT ?", (limit,))
                return [dict(row) for row in cur.fetchall()]
        except Exception:
            return []

    def record_comparison(self, timestamp, sequence, ml_prediction, markov_prediction,
                          agreement, agreement_score=0.0, latency_ms=0.0):
        try:
            with self._cursor() as cur:
                if USE_POSTGRESQL:
                    cur.execute(
                        "INSERT INTO comparisons (timestamp, sequence, ml_prediction, markov_prediction, agreement, agreement_score, latency_ms) "
                        "VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id",
                        (timestamp, json.dumps(sequence), ml_prediction, markov_prediction, bool(agreement), agreement_score, latency_ms)
                    )
                    return cur.fetchone()['id']
                else:
                    cur.execute(
                        "INSERT INTO comparisons (timestamp, sequence, ml_prediction, markov_prediction, agreement, agreement_score, latency_ms) "
                        "VALUES (?,?,?,?,?,?,?)",
                        (timestamp, json.dumps(sequence) if isinstance(sequence, (list, dict)) else sequence,
                         ml_prediction, markov_prediction, int(agreement), agreement_score, latency_ms)
                    )
                    return cur.lastrowid
        except Exception:
            return None

    def get_comparisons(self, limit=100):
        try:
            with self._cursor() as cur:
                if USE_POSTGRESQL:
                    cur.execute("SELECT * FROM comparisons ORDER BY id DESC LIMIT %s", (limit,))
                else:
                    cur.execute("SELECT * FROM comparisons ORDER BY id DESC LIMIT ?", (limit,))
                return [dict(row) for row in cur.fetchall()]
        except Exception:
            return []

    def get_prediction_stats(self):
        try:
            with self._cursor() as cur:
                cur.execute("SELECT COUNT(*) as total FROM predictions")
                row = cur.fetchone()
                total = row['total'] if USE_POSTGRESQL else row[0]
                if total == 0:
                    return {
                        "total": 0,
                        "avg_confidence": 0.0,
                        "avg_latency_ms": 0.0,
                        "attack_distribution": {},
                        "severity_distribution": {},
                        "model_distribution": {},
                    }

                if USE_POSTGRESQL:
                    cur.execute("SELECT AVG(confidence) as avg_confidence, AVG(latency_ms) as avg_latency FROM predictions")
                else:
                    cur.execute("SELECT AVG(confidence) as avg_confidence, AVG(latency_ms) as avg_latency FROM predictions")
                row = cur.fetchone()
                avg_confidence = round(float(row['avg_confidence'] or 0.0), 4)
                avg_latency = round(float(row['avg_latency'] or 0.0), 4)

                if USE_POSTGRESQL:
                    cur.execute("SELECT prediction, COUNT(*) as count FROM predictions GROUP BY prediction")
                else:
                    cur.execute("SELECT prediction, COUNT(*) as count FROM predictions GROUP BY prediction")
                attack_distribution = {r['prediction']: r['count'] for r in cur.fetchall()}

                if USE_POSTGRESQL:
                    cur.execute("SELECT severity, COUNT(*) as count FROM predictions GROUP BY severity")
                else:
                    cur.execute("SELECT severity, COUNT(*) as count FROM predictions GROUP BY severity")
                severity_distribution = {r['severity']: r['count'] for r in cur.fetchall()}

                if USE_POSTGRESQL:
                    cur.execute("SELECT model, COUNT(*) as count FROM predictions GROUP BY model")
                else:
                    cur.execute("SELECT model, COUNT(*) as count FROM predictions GROUP BY model")
                model_distribution = {r['model']: r['count'] for r in cur.fetchall()}

                return {
                    "total": total,
                    "avg_confidence": avg_confidence,
                    "avg_latency_ms": avg_latency,
                    "attack_distribution": attack_distribution,
                    "severity_distribution": severity_distribution,
                    "model_distribution": model_distribution,
                }
        except Exception:
            return {
                "total": 0,
                "avg_confidence": 0.0,
                "avg_latency_ms": 0.0,
                "attack_distribution": {},
                "severity_distribution": {},
                "model_distribution": {},
            }

    def get_comparison_stats(self):
        try:
            with self._cursor() as cur:
                cur.execute("SELECT COUNT(*) as total FROM comparisons")
                row = cur.fetchone()
                total = row['total'] if USE_POSTGRESQL else row[0]
                if total == 0:
                    return {
                        "total": 0,
                        "agreement_rate": 0.0,
                        "avg_agreement_score": 0.0,
                        "avg_latency_ms": 0.0,
                    }

                if USE_POSTGRESQL:
                    cur.execute("SELECT AVG(CAST(agreement AS REAL)) as agreement_rate, "
                                "AVG(agreement_score) as avg_agreement_score, "
                                "AVG(latency_ms) as avg_latency FROM comparisons")
                else:
                    cur.execute("SELECT AVG(CAST(agreement AS REAL)) as agreement_rate, "
                                "AVG(agreement_score) as avg_agreement_score, "
                                "AVG(latency_ms) as avg_latency FROM comparisons")
                row = cur.fetchone()
                return {
                    "total": total,
                    "agreement_rate": round(float(row['agreement_rate'] or 0.0), 4),
                    "avg_agreement_score": round(float(row['avg_agreement_score'] or 0.0), 4),
                    "avg_latency_ms": round(float(row['avg_latency'] or 0.0), 4),
                }
        except Exception:
            return {
                "total": 0,
                "agreement_rate": 0.0,
                "avg_agreement_score": 0.0,
                "avg_latency_ms": 0.0,
            }

    def create_report(self, report_type: str, title: str, data: Dict, user_id: str = None) -> str:
        report_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute(
                    "INSERT INTO reports (id, user_id, report_type, title, generated_at, data_json) VALUES (%s,%s,%s,%s,%s,%s)",
                    (report_id, user_id, report_type, title, now, json.dumps(data))
                )
            else:
                cur.execute(
                    "INSERT INTO reports (id, user_id, report_type, title, generated_at, data_json) VALUES (?,?,?,?,?,?)",
                    (report_id, user_id, report_type, title, now, json.dumps(data))
                )
        return report_id

    def get_reports(self, user_id: str = None, limit: int = 50) -> List[Dict]:
        with self._cursor() as cur:
            if user_id:
                if USE_POSTGRESQL:
                    cur.execute("SELECT * FROM reports WHERE user_id = %s ORDER BY generated_at DESC LIMIT %s", (user_id, limit))
                else:
                    cur.execute("SELECT * FROM reports WHERE user_id = ? ORDER BY generated_at DESC LIMIT ?", (user_id, limit))
            else:
                if USE_POSTGRESQL:
                    cur.execute("SELECT * FROM reports ORDER BY generated_at DESC LIMIT %s", (limit,))
                else:
                    cur.execute("SELECT * FROM reports ORDER BY generated_at DESC LIMIT ?", (limit,))
            return [dict(row) for row in cur.fetchall()]

    def create_notification(self, user_id: str, title: str, message: str, notif_type: str = 'info') -> str:
        notif_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute(
                    "INSERT INTO notifications (id, user_id, title, message, type, created_at) VALUES (%s,%s,%s,%s,%s,%s)",
                    (notif_id, user_id, title, message, notif_type, now)
                )
            else:
                cur.execute(
                    "INSERT INTO notifications (id, user_id, title, message, type, created_at) VALUES (?,?,?,?,?,?)",
                    (notif_id, user_id, title, message, notif_type, now)
                )
        return notif_id

    def get_notifications(self, user_id: str, unread_only: bool = False, limit: int = 50) -> List[Dict]:
        with self._cursor() as cur:
            if unread_only:
                if USE_POSTGRESQL:
                    cur.execute("SELECT * FROM notifications WHERE user_id = %s AND read = FALSE ORDER BY created_at DESC LIMIT %s", (user_id, limit))
                else:
                    cur.execute("SELECT * FROM notifications WHERE user_id = ? AND read = 0 ORDER BY created_at DESC LIMIT ?", (user_id, limit))
            else:
                if USE_POSTGRESQL:
                    cur.execute("SELECT * FROM notifications WHERE user_id = %s ORDER BY created_at DESC LIMIT %s", (user_id, limit))
                else:
                    cur.execute("SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT ?", (user_id, limit))
            return [dict(row) for row in cur.fetchall()]

    def mark_notification_read(self, notification_id: str):
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("UPDATE notifications SET read = TRUE WHERE id = %s", (notification_id,))
            else:
                cur.execute("UPDATE notifications SET read = 1 WHERE id = ?", (notification_id,))

    def log_audit(self, user_id: str, action: str, details: str = '', ip_address: str = ''):
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute(
                    "INSERT INTO audit_log (user_id, action, details, ip_address, timestamp) VALUES (%s,%s,%s,%s,%s)",
                    (user_id, action, details, ip_address, now)
                )
            else:
                cur.execute(
                    "INSERT INTO audit_log (user_id, action, details, ip_address, timestamp) VALUES (?,?,?,?,?)",
                    (user_id, action, details, ip_address, now)
                )

    def get_audit_log(self, user_id: str = None, limit: int = 100) -> List[Dict]:
        with self._cursor() as cur:
            if user_id:
                if USE_POSTGRESQL:
                    cur.execute("SELECT * FROM audit_log WHERE user_id = %s ORDER BY timestamp DESC LIMIT %s", (user_id, limit))
                else:
                    cur.execute("SELECT * FROM audit_log WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?", (user_id, limit))
            else:
                if USE_POSTGRESQL:
                    cur.execute("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT %s", (limit,))
                else:
                    cur.execute("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?", (limit,))
            return [dict(row) for row in cur.fetchall()]

    def get_dashboard_stats(self) -> Dict[str, Any]:
        with self._cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM uploaded_logs")
            row = cur.fetchone()
            total_logs = row[0] if not USE_POSTGRESQL else row['count'] if 'count' in row else list(row.values())[0]

            cur.execute("SELECT COUNT(*) FROM log_events")
            row = cur.fetchone()
            total_events = row[0] if not USE_POSTGRESQL else list(row.values())[0]

            cur.execute("SELECT COUNT(*) FROM threat_detections")
            row = cur.fetchone()
            total_threats = row[0] if not USE_POSTGRESQL else list(row.values())[0]

            cur.execute("SELECT COUNT(*) FROM threat_detections WHERE severity IN ('CRITICAL', 'HIGH')")
            row = cur.fetchone()
            critical_threats = row[0] if not USE_POSTGRESQL else list(row.values())[0]

            cur.execute("SELECT COUNT(DISTINCT source_ip) FROM log_events WHERE source_ip != ''")
            row = cur.fetchone()
            unique_ips = row[0] if not USE_POSTGRESQL else list(row.values())[0]

            cur.execute("SELECT AVG(anomaly_score) FROM anomaly_scores")
            row = cur.fetchone()
            avg_anomaly = (row[0] if not USE_POSTGRESQL else list(row.values())[0]) or 0

            return {
                'total_logs': total_logs,
                'total_events': total_events,
                'total_threats': total_threats,
                'critical_threats': critical_threats,
                'unique_source_ips': unique_ips,
                'avg_anomaly_score': round(float(avg_anomaly), 3),
            }

    # ── Organization Operations ──

    def create_organization(self, name: str, slug: str) -> str:
        org_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("INSERT INTO organizations (id, name, slug, created_at) VALUES (%s,%s,%s,%s)",
                            (org_id, name, slug, now))
            else:
                cur.execute("INSERT INTO organizations (id, name, slug, created_at) VALUES (?,?,?,?)",
                            (org_id, name, slug, now))
        return org_id

    def get_organization(self, org_id: str) -> Optional[Dict]:
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("SELECT * FROM organizations WHERE id = %s", (org_id,))
            else:
                cur.execute("SELECT * FROM organizations WHERE id = ?", (org_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    # ── Device Operations ──

    def register_device(self, hostname: str, ip_address: str, os_type: str = "unknown", org_id: str = None) -> str:
        device_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute(
                    "INSERT INTO devices (id, organization_id, hostname, ip_address, os_type, last_seen, created_at) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                    (device_id, org_id, hostname, ip_address, os_type, now, now)
                )
            else:
                cur.execute(
                    "INSERT INTO devices (id, organization_id, hostname, ip_address, os_type, last_seen, created_at) VALUES (?,?,?,?,?,?,?)",
                    (device_id, org_id, hostname, ip_address, os_type, now, now)
                )
        return device_id

    def get_devices(self, org_id: str = None) -> List[Dict]:
        with self._cursor() as cur:
            if org_id:
                if USE_POSTGRESQL:
                    cur.execute("SELECT * FROM devices WHERE organization_id = %s ORDER BY last_seen DESC", (org_id,))
                else:
                    cur.execute("SELECT * FROM devices WHERE organization_id = ? ORDER BY last_seen DESC", (org_id,))
            else:
                cur.execute("SELECT * FROM devices ORDER BY last_seen DESC")
            return [dict(row) for row in cur.fetchall()]

    def update_device_last_seen(self, device_id: str):
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("UPDATE devices SET last_seen = %s WHERE id = %s", (now, device_id))
            else:
                cur.execute("UPDATE devices SET last_seen = ? WHERE id = ?", (now, device_id))

    def update_device_risk_score(self, device_id: str, risk_score: float):
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("UPDATE devices SET risk_score = %s WHERE id = %s", (risk_score, device_id))
            else:
                cur.execute("UPDATE devices SET risk_score = ? WHERE id = ?", (risk_score, device_id))

    # ── Alert Operations ──

    def create_alert(self, alert_type: str, severity: str, title: str, description: str = "",
                     source_ip: str = "", dest_ip: str = "", source_port: int = 0, dest_port: int = 0,
                     protocol: str = "", mitre_technique: str = "", mitre_tactic: str = "",
                     evidence: list = None, recommendations: list = None,
                     log_id: str = None, device_id: str = None, org_id: str = None) -> str:
        alert_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("""
                    INSERT INTO alerts (id, organization_id, log_id, device_id, alert_type, severity, title, description,
                        source_ip, destination_ip, source_port, destination_port, protocol, mitre_technique, mitre_tactic,
                        evidence, recommendations, status, created_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """, (alert_id, org_id, log_id, device_id, alert_type, severity, title, description,
                      source_ip, dest_ip, source_port, dest_port, protocol, mitre_technique, mitre_tactic,
                      json.dumps(evidence or []), json.dumps(recommendations or []), 'open', now))
            else:
                cur.execute("""
                    INSERT INTO alerts (id, organization_id, log_id, device_id, alert_type, severity, title, description,
                        source_ip, destination_ip, source_port, destination_port, protocol, mitre_technique, mitre_tactic,
                        evidence, recommendations, status, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (alert_id, org_id, log_id, device_id, alert_type, severity, title, description,
                      source_ip, dest_ip, source_port, dest_port, protocol, mitre_technique, mitre_tactic,
                      json.dumps(evidence or []), json.dumps(recommendations or []), 'open', now))
        return alert_id

    def get_alerts(self, org_id: str = None, status: str = None, severity: str = None, limit: int = 100) -> List[Dict]:
        with self._cursor() as cur:
            conditions = []
            params = []
            if org_id:
                conditions.append("organization_id = %s" if USE_POSTGRESQL else "organization_id = ?")
                params.append(org_id)
            if status:
                conditions.append("status = %s" if USE_POSTGRESQL else "status = ?")
                params.append(status)
            if severity:
                conditions.append("severity = %s" if USE_POSTGRESQL else "severity = ?")
                params.append(severity)

            where = " WHERE " + " AND ".join(conditions) if conditions else ""
            query = f"SELECT * FROM alerts{where} ORDER BY created_at DESC LIMIT {'%s' if USE_POSTGRESQL else '?'}"
            params.append(limit)

            cur.execute(query, tuple(params))
            return [dict(row) for row in cur.fetchall()]

    def get_alert(self, alert_id: str) -> Optional[Dict]:
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("SELECT * FROM alerts WHERE id = %s", (alert_id,))
            else:
                cur.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def update_alert_status(self, alert_id: str, status: str, assigned_to: str = None):
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                if assigned_to:
                    cur.execute("UPDATE alerts SET status = %s, assigned_to = %s, updated_at = %s, resolved_at = CASE WHEN %s = 'resolved' THEN %s ELSE resolved_at END WHERE id = %s",
                                (status, assigned_to, now, now, now, alert_id))
                else:
                    cur.execute("UPDATE alerts SET status = %s, updated_at = %s, resolved_at = CASE WHEN %s = 'resolved' THEN %s ELSE resolved_at END WHERE id = %s",
                                (status, now, now, now, alert_id))
            else:
                if assigned_to:
                    cur.execute("UPDATE alerts SET status = ?, assigned_to = ?, updated_at = ?, resolved_at = CASE WHEN ? = 'resolved' THEN ? ELSE resolved_at END WHERE id = ?",
                                (status, assigned_to, now, now, now, alert_id))
                else:
                    cur.execute("UPDATE alerts SET status = ?, updated_at = ?, resolved_at = CASE WHEN ? = 'resolved' THEN ? ELSE resolved_at END WHERE id = ?",
                                (status, now, now, now, alert_id))

    def get_alerts_by_device(self, device_id: str, limit: int = 50) -> List[Dict]:
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("SELECT * FROM alerts WHERE device_id = %s ORDER BY created_at DESC LIMIT %s", (device_id, limit))
            else:
                cur.execute("SELECT * FROM alerts WHERE device_id = ? ORDER BY created_at DESC LIMIT ?", (device_id, limit))
            return [dict(row) for row in cur.fetchall()]

    def get_alert_stats(self) -> Dict[str, Any]:
        with self._cursor() as cur:
            cur.execute("SELECT COUNT(*) as total FROM alerts")
            row = cur.fetchone()
            total = row['total'] if USE_POSTGRESQL else row[0]

            cur.execute("SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity")
            by_severity = {row['severity']: row['count'] if USE_POSTGRESQL else row[1] for row in cur.fetchall()}

            cur.execute("SELECT status, COUNT(*) as count FROM alerts GROUP BY status")
            by_status = {row['status']: row['count'] if USE_POSTGRESQL else row[1] for row in cur.fetchall()}

            cur.execute("SELECT alert_type, COUNT(*) as count FROM alerts GROUP BY alert_type ORDER BY count DESC")
            by_type = {row['alert_type']: row['count'] if USE_POSTGRESQL else row[1] for row in cur.fetchall()}

            return {'total': total, 'by_severity': by_severity, 'by_status': by_status, 'by_type': by_type}

    # ── Investigation Notes ──

    def add_investigation_note(self, alert_id: str, user_id: str, note: str) -> str:
        note_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("INSERT INTO investigation_notes (id, alert_id, user_id, note, created_at) VALUES (%s,%s,%s,%s,%s)",
                            (note_id, alert_id, user_id, note, now))
            else:
                cur.execute("INSERT INTO investigation_notes (id, alert_id, user_id, note, created_at) VALUES (?,?,?,?,?)",
                            (note_id, alert_id, user_id, note, now))
        return note_id

    def get_investigation_notes(self, alert_id: str) -> List[Dict]:
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("SELECT * FROM investigation_notes WHERE alert_id = %s ORDER BY created_at", (alert_id,))
            else:
                cur.execute("SELECT * FROM investigation_notes WHERE alert_id = ? ORDER BY created_at", (alert_id,))
            return [dict(row) for row in cur.fetchall()]

    def get_uploaded_log_by_id(self, log_id: str) -> Optional[Dict]:
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("SELECT * FROM uploaded_logs WHERE id = %s", (log_id,))
            else:
                cur.execute("SELECT * FROM uploaded_logs WHERE id = ?", (log_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def get_threat_detections_filtered(self, severity: str = None, threat_type: str = None,
                                       source_ip: str = None, limit: int = 100) -> List[Dict]:
        conditions = []
        params = []
        if severity:
            conditions.append("severity = %s" if USE_POSTGRESQL else "severity = ?")
            params.append(severity)
        if threat_type:
            conditions.append("threat_type = %s" if USE_POSTGRESQL else "threat_type = ?")
            params.append(threat_type)
        if source_ip:
            conditions.append("source_ip = %s" if USE_POSTGRESQL else "source_ip = ?")
            params.append(source_ip)

        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        limit_placeholder = "%s" if USE_POSTGRESQL else "?"
        query = f"SELECT * FROM threat_detections{where} ORDER BY detection_time DESC LIMIT {limit_placeholder}"
        params.append(limit)

        with self._cursor() as cur:
            cur.execute(query, tuple(params))
            return [dict(row) for row in cur.fetchall()]

    def get_threats_by_ip(self, ip: str, limit: int = 100) -> List[Dict]:
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("SELECT * FROM threat_detections WHERE source_ip = %s OR dest_ip = %s ORDER BY detection_time DESC LIMIT %s", (ip, ip, limit))
            else:
                cur.execute("SELECT * FROM threat_detections WHERE source_ip = ? OR dest_ip = ? ORDER BY detection_time DESC LIMIT ?", (ip, ip, limit))
            return [dict(row) for row in cur.fetchall()]

    def get_events_by_ip(self, ip: str, limit: int = 100) -> List[Dict]:
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("SELECT * FROM log_events WHERE source_ip = %s OR dest_ip = %s ORDER BY timestamp DESC LIMIT %s", (ip, ip, limit))
            else:
                cur.execute("SELECT * FROM log_events WHERE source_ip = ? OR dest_ip = ? ORDER BY timestamp DESC LIMIT ?", (ip, ip, limit))
            return [dict(row) for row in cur.fetchall()]

    def get_threat_summary_full(self) -> Dict[str, Any]:
        summary = self.get_threat_summary()
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("SELECT source_ip, COUNT(*) as count FROM threat_detections WHERE source_ip != '' GROUP BY source_ip ORDER BY count DESC LIMIT 10")
            else:
                cur.execute("SELECT source_ip, COUNT(*) as count FROM threat_detections WHERE source_ip != '' GROUP BY source_ip ORDER BY count DESC LIMIT 10")
            top_ips = [{"ip": row['source_ip'], "count": row['count']} for row in cur.fetchall()]

        by_severity = summary.get('by_severity', {})
        critical = by_severity.get('CRITICAL', 0)
        high = by_severity.get('HIGH', 0)
        total = summary.get('total', 0)
        if critical > 0:
            risk_level = "CRITICAL"
        elif high >= 3:
            risk_level = "HIGH"
        elif high > 0 or total > 5:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return {
            'total': total,
            'by_severity': by_severity,
            'by_type': summary.get('by_type', {}),
            'top_source_ips': top_ips,
            'risk_level': risk_level,
        }

    def get_latest_anomaly_score(self, log_id: str = None) -> Optional[Dict]:
        with self._cursor() as cur:
            if log_id:
                if USE_POSTGRESQL:
                    cur.execute("SELECT * FROM anomaly_scores WHERE log_id = %s ORDER BY analysis_time DESC LIMIT 1", (log_id,))
                else:
                    cur.execute("SELECT * FROM anomaly_scores WHERE log_id = ? ORDER BY analysis_time DESC LIMIT 1", (log_id,))
            else:
                cur.execute("SELECT * FROM anomaly_scores ORDER BY analysis_time DESC LIMIT 1")
            row = cur.fetchone()
            return dict(row) if row else None

    def get_total_reports(self) -> int:
        with self._cursor() as cur:
            cur.execute("SELECT COUNT(*) as cnt FROM reports")
            row = cur.fetchone()
            return row['cnt'] if USE_POSTGRESQL else row[0]

    def close(self):
        if self.conn:
            self.conn.close()


db = DatabaseManager()
