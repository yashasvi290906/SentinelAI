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


class _AutoAdaptingCursor:
    """Wraps a DB cursor to auto-convert SQLite '?' placeholders to PostgreSQL '%s'."""

    def __init__(self, cursor, is_postgresql: bool):
        self._cur = cursor
        self._pg = is_postgresql

    def _adapt(self, query: str) -> str:
        if not self._pg or '?' not in query:
            return query
        return query.replace('?', '%s')

    def execute(self, query, params=None):
        return self._cur.execute(self._adapt(query), params or ())

    def executemany(self, query, params_list):
        return self._cur.executemany(self._adapt(query), params_list)

    def fetchone(self):
        return self._cur.fetchone()

    def fetchall(self):
        return self._cur.fetchall()

    def fetchmany(self, size=None):
        return self._cur.fetchmany(size) if size else self._cur.fetchmany()

    @property
    def rowcount(self):
        return self._cur.rowcount

    @property
    def description(self):
        return self._cur.description

    def __getattr__(self, name):
        return getattr(self._cur, name)


class DatabaseManager:
    def __init__(self):
        global USE_POSTGRESQL
        self.use_postgresql = USE_POSTGRESQL
        if self.use_postgresql:
            try:
                self._init_postgresql()
            except Exception as e:
                print(f"PostgreSQL connection failed ({e}), falling back to SQLite")
                self.use_postgresql = False
                USE_POSTGRESQL = False
                self._init_sqlite()
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
        try:
            self._create_tables_postgresql()
        except Exception:
            self.conn.rollback()
            raise

    @contextmanager
    def _cursor(self):
        if self.use_postgresql:
            cursor = self.conn.cursor()
            try:
                yield _AutoAdaptingCursor(cursor, True)
                self.conn.commit()
            except Exception:
                self.conn.rollback()
                raise
            finally:
                cursor.close()
        else:
            cursor = self.conn.cursor()
            try:
                yield _AutoAdaptingCursor(cursor, False)
                self.conn.commit()
            except Exception:
                self.conn.rollback()
                raise

    def execute(self, query: str, params=None):
        with self._cursor() as cur:
            cur.execute(query, params or ())
            return cur.rowcount

    def fetch_one(self, query: str, params=None):
        with self._cursor() as cur:
            cur.execute(query, params or ())
            row = cur.fetchone()
            return dict(row) if row else None

    def fetch_all(self, query: str, params=None):
        with self._cursor() as cur:
            cur.execute(query, params or ())
            rows = cur.fetchall()
            return [dict(r) for r in rows] if rows else []

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

                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT DEFAULT 'open',
                    confidence REAL DEFAULT 0.0,
                    description TEXT DEFAULT '',
                    alert_ids TEXT DEFAULT '[]',
                    timeline TEXT DEFAULT '[]',
                    affected_ips TEXT DEFAULT '[]',
                    mitre_techniques TEXT DEFAULT '[]',
                    mitre_tactics TEXT DEFAULT '[]',
                    recommendations TEXT DEFAULT '[]',
                    assigned_to TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT
                );

                CREATE TABLE IF NOT EXISTS incident_notes (
                    id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    user_id TEXT,
                    note TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (incident_id) REFERENCES incidents(id)
                );

                CREATE TABLE IF NOT EXISTS assets (
                    id TEXT PRIMARY KEY,
                    organization_id TEXT,
                    hostname TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    os_type TEXT DEFAULT 'unknown',
                    os_version TEXT DEFAULT '',
                    asset_type TEXT DEFAULT 'endpoint',
                    criticality TEXT DEFAULT 'medium',
                    risk_score REAL DEFAULT 0.0,
                    owner TEXT DEFAULT '',
                    department TEXT DEFAULT '',
                    location TEXT DEFAULT '',
                    last_seen TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT,
                    metadata TEXT DEFAULT '{}',
                    FOREIGN KEY (organization_id) REFERENCES organizations(id)
                );

                CREATE TABLE IF NOT EXISTS ioc (
                    id TEXT PRIMARY KEY,
                    organization_id TEXT,
                    indicator_type TEXT NOT NULL,
                    indicator_value TEXT NOT NULL,
                    threat_type TEXT DEFAULT '',
                    severity TEXT DEFAULT 'MEDIUM',
                    confidence REAL DEFAULT 0.5,
                    source TEXT DEFAULT 'manual',
                    description TEXT DEFAULT '',
                    first_seen TEXT,
                    last_seen TEXT,
                    tags TEXT DEFAULT '[]',
                    created_at TEXT NOT NULL,
                    updated_at TEXT,
                    FOREIGN KEY (organization_id) REFERENCES organizations(id)
                );

                CREATE TABLE IF NOT EXISTS detection_rules (
                    id TEXT PRIMARY KEY,
                    organization_id TEXT,
                    title TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    condition TEXT NOT NULL,
                    window_seconds INTEGER DEFAULT 300,
                    threshold REAL DEFAULT 1.0,
                    severity TEXT DEFAULT 'MEDIUM',
                    mitre_technique TEXT DEFAULT '',
                    mitre_tactic TEXT DEFAULT '',
                    enabled INTEGER DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT,
                    FOREIGN KEY (organization_id) REFERENCES organizations(id)
                );

                CREATE TABLE IF NOT EXISTS agent_status (
                    id TEXT PRIMARY KEY,
                    organization_id TEXT,
                    hostname TEXT NOT NULL,
                    ip_address TEXT DEFAULT '',
                    os_type TEXT DEFAULT 'unknown',
                    agent_version TEXT DEFAULT '1.0.0',
                    status TEXT DEFAULT 'online',
                    last_seen TEXT,
                    logs_collected INTEGER DEFAULT 0,
                    events_processed INTEGER DEFAULT 0,
                    alerts_generated INTEGER DEFAULT 0,
                    uptime_seconds INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT,
                    metadata TEXT DEFAULT '{}',
                    FOREIGN KEY (organization_id) REFERENCES organizations(id)
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

                CREATE TABLE IF NOT EXISTS sigma_rules (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT,
                    author TEXT,
                    status TEXT DEFAULT 'experimental',
                    level TEXT DEFAULT 'medium',
                    logsource_category TEXT,
                    logsource_product TEXT,
                    logsource_service TEXT,
                    detection_yaml TEXT NOT NULL,
                    condition_text TEXT NOT NULL,
                    mitre_techniques TEXT DEFAULT '[]',
                    mitre_tactics TEXT DEFAULT '[]',
                    tags TEXT DEFAULT '[]',
                    falsepositives TEXT DEFAULT '[]',
                    enabled INTEGER DEFAULT 1,
                    created_at TEXT,
                    updated_at TEXT
                );

                CREATE TABLE IF NOT EXISTS sigma_matches (
                    id TEXT PRIMARY KEY,
                    rule_id TEXT NOT NULL,
                    event_id TEXT,
                    matched_at TEXT,
                    event_data TEXT,
                    FOREIGN KEY (rule_id) REFERENCES sigma_rules(id)
                );

                CREATE TABLE IF NOT EXISTS threat_feeds (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    feed_type TEXT NOT NULL DEFAULT 'taxii',
                    url TEXT,
                    taxii_version TEXT DEFAULT '2.1',
                    auth_type TEXT DEFAULT 'none',
                    auth_config TEXT DEFAULT '{}',
                    collection_id TEXT DEFAULT '',
                    description TEXT DEFAULT '',
                    poll_interval_seconds INTEGER DEFAULT 3600,
                    last_polled_at TEXT,
                    enabled INTEGER DEFAULT 1,
                    tlp TEXT DEFAULT 'white',
                    total_objects INTEGER DEFAULT 0,
                    total_indicators INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'idle',
                    error_message TEXT DEFAULT '',
                    organization_id TEXT,
                    created_at TEXT,
                    updated_at TEXT
                );

                CREATE TABLE IF NOT EXISTS stix_objects (
                    id TEXT PRIMARY KEY,
                    feed_id TEXT NOT NULL,
                    stix_id TEXT NOT NULL,
                    stix_type TEXT NOT NULL,
                    type TEXT NOT NULL,
                    spec_version TEXT DEFAULT '2.1',
                    name TEXT DEFAULT '',
                    description TEXT DEFAULT '',
                    labels TEXT DEFAULT '[]',
                    confidence INTEGER DEFAULT 0,
                    created TEXT DEFAULT '',
                    modified TEXT DEFAULT '',
                    revoked INTEGER DEFAULT 0,
                    raw_json TEXT NOT NULL,
                    created_at_stix TEXT,
                    modified_at_stix TEXT,
                    pattern TEXT,
                    valid_from TEXT,
                    valid_until TEXT,
                    object_marking_ref TEXT,
                    imported_at TEXT,
                    FOREIGN KEY (feed_id) REFERENCES threat_feeds(id)
                );

                CREATE TABLE IF NOT EXISTS stix_indicators (
                    id TEXT PRIMARY KEY,
                    feed_id TEXT NOT NULL,
                    stix_object_id TEXT,
                    stix_id TEXT DEFAULT '',
                    indicator_type TEXT NOT NULL,
                    indicator_value TEXT NOT NULL,
                    value TEXT NOT NULL,
                    pattern TEXT DEFAULT '',
                    confidence INTEGER DEFAULT 0,
                    severity TEXT,
                    labels TEXT DEFAULT '[]',
                    threat_types TEXT DEFAULT '[]',
                    kill_chain_phases TEXT DEFAULT '[]',
                    valid_from TEXT,
                    valid_until TEXT,
                    description TEXT DEFAULT '',
                    name TEXT DEFAULT '',
                    first_seen TEXT,
                    last_seen TEXT,
                    hit_count INTEGER DEFAULT 0,
                    created_at TEXT,
                    FOREIGN KEY (feed_id) REFERENCES threat_feeds(id),
                    FOREIGN KEY (stix_object_id) REFERENCES stix_objects(id)
                );

                CREATE TABLE IF NOT EXISTS network_flows (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol INTEGER,
                    bytes_sent INTEGER DEFAULT 0,
                    bytes_received INTEGER DEFAULT 0,
                    packets_sent INTEGER DEFAULT 0,
                    packets_received INTEGER DEFAULT 0,
                    flow_duration_ms INTEGER DEFAULT 0,
                    flags TEXT,
                    application TEXT,
                    source TEXT,
                    device_id TEXT,
                    created_at TEXT
                );

                CREATE TABLE IF NOT EXISTS dns_queries (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    src_ip TEXT,
                    query_name TEXT NOT NULL,
                    query_type TEXT,
                    response_code TEXT,
                    response_data TEXT,
                    resolved INTEGER DEFAULT 1,
                    ttl INTEGER,
                    source TEXT,
                    created_at TEXT
                );

                CREATE TABLE IF NOT EXISTS http_metadata (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    dst_port INTEGER DEFAULT 80,
                    method TEXT,
                    host TEXT,
                    uri TEXT,
                    user_agent TEXT,
                    status_code INTEGER,
                    response_size INTEGER DEFAULT 0,
                    content_type TEXT,
                    tls_version TEXT,
                    ja3_hash TEXT,
                    source TEXT,
                    created_at TEXT
                );

                CREATE TABLE IF NOT EXISTS network_anomalies (
                    id TEXT PRIMARY KEY,
                    anomaly_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    description TEXT,
                    evidence TEXT,
                    mitre_technique TEXT,
                    mitre_tactic TEXT,
                    detected_at TEXT,
                    resolved INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS playbooks (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    version TEXT DEFAULT '1.0.0',
                    author TEXT,
                    tags TEXT DEFAULT '[]',
                    severity_threshold TEXT DEFAULT 'MEDIUM',
                    mitre_tactics TEXT DEFAULT '[]',
                    trigger_type TEXT DEFAULT 'alert',
                    trigger_filter TEXT DEFAULT '{}',
                    steps_json TEXT NOT NULL,
                    enabled INTEGER DEFAULT 1,
                    execution_count INTEGER DEFAULT 0,
                    last_executed_at TEXT,
                    created_at TEXT,
                    updated_at TEXT
                );

                CREATE TABLE IF NOT EXISTS playbook_executions (
                    id TEXT PRIMARY KEY,
                    playbook_id TEXT NOT NULL,
                    trigger_event_id TEXT,
                    trigger_data TEXT,
                    status TEXT DEFAULT 'running',
                    step_results TEXT,
                    started_at TEXT,
                    completed_at TEXT,
                    duration_ms INTEGER,
                    actions_taken TEXT DEFAULT '[]',
                    FOREIGN KEY (playbook_id) REFERENCES playbooks(id)
                );

                CREATE TABLE IF NOT EXISTS playbook_action_log (
                    id TEXT PRIMARY KEY,
                    execution_id TEXT NOT NULL,
                    step_id TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    integration TEXT,
                    action_name TEXT,
                    input_params TEXT,
                    output_result TEXT,
                    status TEXT,
                    error_message TEXT,
                    executed_at TEXT,
                    FOREIGN KEY (execution_id) REFERENCES playbook_executions(id)
                );

                CREATE TABLE IF NOT EXISTS evidence (
                    id TEXT PRIMARY KEY,
                    incident_id TEXT,
                    alert_id TEXT,
                    evidence_type TEXT NOT NULL,
                    source_type TEXT DEFAULT '',
                    source_id TEXT DEFAULT '',
                    description TEXT DEFAULT '',
                    file_name TEXT,
                    file_path TEXT DEFAULT '',
                    file_size INTEGER DEFAULT 0,
                    sha256_hash TEXT NOT NULL,
                    md5_hash TEXT,
                    collected_by TEXT,
                    collected_at TEXT NOT NULL,
                    status TEXT DEFAULT 'collected',
                    chain_of_custody TEXT DEFAULT '[]',
                    metadata TEXT DEFAULT '{}',
                    created_at TEXT
                );

                CREATE TABLE IF NOT EXISTS evidence_chain (
                    id TEXT PRIMARY KEY,
                    evidence_id TEXT NOT NULL,
                    sequence_num INTEGER DEFAULT 0,
                    action TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    actor_name TEXT,
                    details TEXT DEFAULT '',
                    prev_hash TEXT DEFAULT '',
                    timestamp TEXT NOT NULL,
                    previous_hash TEXT,
                    entry_hash TEXT NOT NULL,
                    FOREIGN KEY (evidence_id) REFERENCES evidence(id)
                );

                CREATE TABLE IF NOT EXISTS forensic_timeline (
                    id TEXT PRIMARY KEY,
                    incident_id TEXT,
                    event_time TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    source TEXT DEFAULT '',
                    description TEXT DEFAULT '',
                    evidence_id TEXT DEFAULT '',
                    confidence REAL DEFAULT 1.0,
                    metadata TEXT DEFAULT '{}',
                    created_at TEXT
                );

                CREATE TABLE IF NOT EXISTS nist_controls (
                    id TEXT PRIMARY KEY,
                    control_id TEXT NOT NULL,
                    family TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    implementation_status TEXT DEFAULT 'not_assessed',
                    evidence_ids TEXT DEFAULT '[]',
                    responsible_party TEXT,
                    last_assessed_at TEXT,
                    next_assessment_at TEXT,
                    notes TEXT,
                    implementation_guidance TEXT,
                    automated_check TEXT,
                    created_at TEXT
                );

                CREATE TABLE IF NOT EXISTS compliance_assessments (
                    id TEXT PRIMARY KEY,
                    assessment_id TEXT NOT NULL,
                    score REAL,
                    total_controls INTEGER,
                    compliant_count INTEGER,
                    non_compliant_count INTEGER,
                    controls_status TEXT DEFAULT '[]',
                    gaps TEXT DEFAULT '[]',
                    system_state TEXT DEFAULT '{}',
                    created_at TEXT
                );

                CREATE TABLE IF NOT EXISTS user_behavior_baselines (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    metric_type TEXT NOT NULL,
                    baseline_value REAL NOT NULL,
                    standard_deviation REAL NOT NULL,
                    sample_count INTEGER DEFAULT 0,
                    last_updated TEXT,
                    UNIQUE(user_id, metric_type)
                );

                CREATE TABLE IF NOT EXISTS user_anomalies (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    anomaly_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    description TEXT,
                    baseline_value REAL,
                    observed_value REAL,
                    deviation_score REAL,
                    evidence TEXT,
                    mitre_technique TEXT,
                    mitre_tactic TEXT,
                    detected_at TEXT,
                    resolved INTEGER DEFAULT 0,
                    assigned_to TEXT
                );

                CREATE TABLE IF NOT EXISTS insider_threat_cases (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    case_status TEXT DEFAULT 'open',
                    risk_level TEXT,
                    anomaly_ids TEXT DEFAULT '[]',
                    assigned_to TEXT,
                    description TEXT,
                    findings TEXT,
                    resolution TEXT,
                    created_at TEXT,
                    updated_at TEXT
                );

                CREATE TABLE IF NOT EXISTS hunt_saved_searches (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    query_text TEXT DEFAULT '',
                    filters_json TEXT DEFAULT '[]',
                    created_at TEXT
                );

                CREATE TABLE IF NOT EXISTS event_bookmarks (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    note TEXT DEFAULT '',
                    created_at TEXT
                );

                CREATE TABLE IF NOT EXISTS rule_packs (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    version TEXT DEFAULT '1.0',
                    author TEXT DEFAULT '',
                    rules_json TEXT DEFAULT '[]',
                    enabled INTEGER DEFAULT 1,
                    created_at TEXT,
                    updated_at TEXT
                );

                CREATE TABLE IF NOT EXISTS playbook_runs (
                    id TEXT PRIMARY KEY,
                    playbook_id TEXT NOT NULL,
                    playbook_name TEXT DEFAULT '',
                    triggered_by TEXT DEFAULT '',
                    trigger_type TEXT DEFAULT 'manual',
                    status TEXT DEFAULT 'running',
                    input_data TEXT DEFAULT '{}',
                    output_data TEXT DEFAULT '{}',
                    actions_completed INTEGER DEFAULT 0,
                    actions_failed INTEGER DEFAULT 0,
                    started_at TEXT,
                    completed_at TEXT,
                    error_message TEXT DEFAULT ''
                );
            """)

            for alter_sql in [
                "ALTER TABLE threat_feeds ADD COLUMN collection_id TEXT DEFAULT ''",
                "ALTER TABLE threat_feeds ADD COLUMN description TEXT DEFAULT ''",
                "ALTER TABLE threat_feeds ADD COLUMN tlp TEXT DEFAULT 'white'",
                "ALTER TABLE threat_feeds ADD COLUMN total_objects INTEGER DEFAULT 0",
                "ALTER TABLE threat_feeds ADD COLUMN total_indicators INTEGER DEFAULT 0",
                "ALTER TABLE threat_feeds ADD COLUMN status TEXT DEFAULT 'idle'",
                "ALTER TABLE threat_feeds ADD COLUMN error_message TEXT DEFAULT ''",
                "ALTER TABLE threat_feeds ADD COLUMN updated_at TEXT",
                "ALTER TABLE stix_objects ADD COLUMN feed_id TEXT",
                "ALTER TABLE stix_objects ADD COLUMN stix_id TEXT DEFAULT ''",
                "ALTER TABLE stix_objects ADD COLUMN stix_type TEXT DEFAULT ''",
                "ALTER TABLE stix_objects ADD COLUMN created TEXT DEFAULT ''",
                "ALTER TABLE stix_objects ADD COLUMN modified TEXT DEFAULT ''",
                "ALTER TABLE stix_objects ADD COLUMN revoked INTEGER DEFAULT 0",
                "ALTER TABLE stix_indicators ADD COLUMN feed_id TEXT",
                "ALTER TABLE stix_indicators ADD COLUMN stix_id TEXT DEFAULT ''",
                "ALTER TABLE stix_indicators ADD COLUMN value TEXT NOT NULL DEFAULT ''",
                "ALTER TABLE stix_indicators ADD COLUMN pattern TEXT DEFAULT ''",
                "ALTER TABLE stix_indicators ADD COLUMN labels TEXT DEFAULT '[]'",
                "ALTER TABLE stix_indicators ADD COLUMN description TEXT DEFAULT ''",
                "ALTER TABLE stix_indicators ADD COLUMN name TEXT DEFAULT ''",
                "ALTER TABLE stix_indicators ADD COLUMN first_seen TEXT",
                "ALTER TABLE stix_indicators ADD COLUMN last_seen TEXT",
                "ALTER TABLE stix_indicators ADD COLUMN hit_count INTEGER DEFAULT 0",
                "ALTER TABLE stix_indicators ADD COLUMN created_at TEXT",
                "ALTER TABLE evidence ADD COLUMN source_type TEXT DEFAULT ''",
                "ALTER TABLE evidence ADD COLUMN source_id TEXT DEFAULT ''",
                "ALTER TABLE evidence ADD COLUMN status TEXT DEFAULT 'collected'",
                "ALTER TABLE evidence_chain ADD COLUMN sequence_num INTEGER DEFAULT 0",
                "ALTER TABLE evidence_chain ADD COLUMN prev_hash TEXT DEFAULT ''",
                "ALTER TABLE forensic_timeline ADD COLUMN metadata TEXT DEFAULT '{}'",
                "ALTER TABLE compliance_assessments ADD COLUMN assessment_id TEXT DEFAULT ''",
                "ALTER TABLE compliance_assessments ADD COLUMN score REAL",
                "ALTER TABLE compliance_assessments ADD COLUMN compliant_count INTEGER",
                "ALTER TABLE compliance_assessments ADD COLUMN non_compliant_count INTEGER",
                "ALTER TABLE compliance_assessments ADD COLUMN controls_status TEXT DEFAULT '[]'",
                "ALTER TABLE compliance_assessments ADD COLUMN gaps TEXT DEFAULT '[]'",
                "ALTER TABLE compliance_assessments ADD COLUMN system_state TEXT DEFAULT '{}'",
            ]:
                try:
                    cur.execute(alter_sql)
                except Exception:
                    pass

            for alter_sql in [
                "ALTER TABLE users ADD COLUMN organization_id TEXT DEFAULT ''",
                "ALTER TABLE uploaded_logs ADD COLUMN organization_id TEXT DEFAULT ''",
                "ALTER TABLE incidents ADD COLUMN organization_id TEXT DEFAULT ''",
                "ALTER TABLE incidents ADD COLUMN priority TEXT DEFAULT 'P4'",
                "ALTER TABLE incidents ADD COLUMN category TEXT DEFAULT 'general'",
                "ALTER TABLE incidents ADD COLUMN impact_summary TEXT DEFAULT ''",
                "ALTER TABLE incidents ADD COLUMN root_cause TEXT DEFAULT ''",
                "ALTER TABLE incidents ADD COLUMN lessons_learned TEXT DEFAULT ''",
                "ALTER TABLE incidents ADD COLUMN sla_deadline TEXT",
                "ALTER TABLE incidents ADD COLUMN resolved_at TEXT",
                "ALTER TABLE incidents ADD COLUMN closed_at TEXT",
                "ALTER TABLE notifications ADD COLUMN organization_id TEXT DEFAULT ''",
                "ALTER TABLE reports ADD COLUMN organization_id TEXT DEFAULT ''",
            ]:
                try:
                    cur.execute(alter_sql)
                except Exception:
                    pass

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

                CREATE TABLE IF NOT EXISTS incidents (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    title VARCHAR(500) NOT NULL,
                    severity VARCHAR(20) NOT NULL,
                    status VARCHAR(50) DEFAULT 'open',
                    confidence REAL DEFAULT 0.0,
                    description TEXT DEFAULT '',
                    alert_ids JSONB DEFAULT '[]',
                    timeline JSONB DEFAULT '[]',
                    affected_ips JSONB DEFAULT '[]',
                    mitre_techniques JSONB DEFAULT '[]',
                    mitre_tactics JSONB DEFAULT '[]',
                    recommendations JSONB DEFAULT '[]',
                    assigned_to UUID,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ
                );

                CREATE TABLE IF NOT EXISTS incident_notes (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    incident_id UUID NOT NULL REFERENCES incidents(id),
                    user_id UUID REFERENCES users(id),
                    note TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS assets (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    organization_id UUID REFERENCES organizations(id),
                    hostname VARCHAR(255) NOT NULL,
                    ip_address INET NOT NULL,
                    os_type VARCHAR(50) DEFAULT 'unknown',
                    os_version VARCHAR(100) DEFAULT '',
                    asset_type VARCHAR(50) DEFAULT 'endpoint',
                    criticality VARCHAR(20) DEFAULT 'medium',
                    risk_score REAL DEFAULT 0.0,
                    owner VARCHAR(255) DEFAULT '',
                    department VARCHAR(100) DEFAULT '',
                    location VARCHAR(255) DEFAULT '',
                    last_seen TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ,
                    metadata JSONB DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS ioc (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    organization_id UUID REFERENCES organizations(id),
                    indicator_type VARCHAR(50) NOT NULL,
                    indicator_value VARCHAR(500) NOT NULL,
                    threat_type VARCHAR(100) DEFAULT '',
                    severity VARCHAR(20) DEFAULT 'MEDIUM',
                    confidence REAL DEFAULT 0.5,
                    source VARCHAR(100) DEFAULT 'manual',
                    description TEXT DEFAULT '',
                    first_seen TIMESTAMPTZ,
                    last_seen TIMESTAMPTZ,
                    tags JSONB DEFAULT '[]',
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ
                );

                CREATE TABLE IF NOT EXISTS detection_rules (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    organization_id UUID REFERENCES organizations(id),
                    title VARCHAR(255) NOT NULL,
                    description TEXT DEFAULT '',
                    condition TEXT NOT NULL,
                    window_seconds INTEGER DEFAULT 300,
                    threshold REAL DEFAULT 1.0,
                    severity VARCHAR(20) DEFAULT 'MEDIUM',
                    mitre_technique VARCHAR(20) DEFAULT '',
                    mitre_tactic VARCHAR(100) DEFAULT '',
                    enabled BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ
                );

                CREATE TABLE IF NOT EXISTS agent_status (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    organization_id UUID REFERENCES organizations(id),
                    hostname VARCHAR(255) NOT NULL,
                    ip_address TEXT DEFAULT '',
                    os_type VARCHAR(50) DEFAULT 'unknown',
                    agent_version VARCHAR(50) DEFAULT '1.0.0',
                    status VARCHAR(20) DEFAULT 'online',
                    last_seen TIMESTAMPTZ,
                    logs_collected INTEGER DEFAULT 0,
                    events_processed INTEGER DEFAULT 0,
                    alerts_generated INTEGER DEFAULT 0,
                    uptime_seconds INTEGER DEFAULT 0,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ,
                    metadata JSONB DEFAULT '{}'
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

                CREATE TABLE IF NOT EXISTS sigma_rules (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT,
                    author TEXT,
                    status TEXT DEFAULT 'experimental',
                    level TEXT DEFAULT 'medium',
                    logsource_category TEXT,
                    logsource_product TEXT,
                    logsource_service TEXT,
                    detection_yaml TEXT NOT NULL,
                    condition_text TEXT NOT NULL,
                    mitre_techniques TEXT DEFAULT '[]',
                    mitre_tactics TEXT DEFAULT '[]',
                    tags TEXT DEFAULT '[]',
                    falsepositives TEXT DEFAULT '[]',
                    enabled INTEGER DEFAULT 1,
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    updated_at TIMESTAMPTZ
                );

                CREATE TABLE IF NOT EXISTS sigma_matches (
                    id TEXT PRIMARY KEY,
                    rule_id TEXT NOT NULL REFERENCES sigma_rules(id),
                    event_id TEXT,
                    matched_at TIMESTAMPTZ DEFAULT NOW(),
                    event_data TEXT
                );

                CREATE TABLE IF NOT EXISTS threat_feeds (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    feed_type TEXT NOT NULL DEFAULT 'taxii',
                    url TEXT,
                    taxii_version TEXT DEFAULT '2.1',
                    auth_type TEXT DEFAULT 'none',
                    auth_config TEXT DEFAULT '{}',
                    collection_id TEXT DEFAULT '',
                    description TEXT DEFAULT '',
                    poll_interval_seconds INTEGER DEFAULT 3600,
                    last_polled_at TIMESTAMPTZ,
                    enabled INTEGER DEFAULT 1,
                    tlp TEXT DEFAULT 'white',
                    total_objects INTEGER DEFAULT 0,
                    total_indicators INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'idle',
                    error_message TEXT DEFAULT '',
                    organization_id TEXT,
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    updated_at TIMESTAMPTZ
                );

                CREATE TABLE IF NOT EXISTS stix_objects (
                    id TEXT PRIMARY KEY,
                    feed_id TEXT NOT NULL,
                    stix_id TEXT NOT NULL,
                    stix_type TEXT NOT NULL,
                    type TEXT NOT NULL,
                    spec_version TEXT DEFAULT '2.1',
                    name TEXT DEFAULT '',
                    description TEXT DEFAULT '',
                    labels TEXT DEFAULT '[]',
                    confidence INTEGER DEFAULT 0,
                    created TEXT DEFAULT '',
                    modified TEXT DEFAULT '',
                    revoked INTEGER DEFAULT 0,
                    raw_json TEXT NOT NULL,
                    created_at_stix TIMESTAMPTZ,
                    modified_at_stix TIMESTAMPTZ,
                    pattern TEXT,
                    valid_from TIMESTAMPTZ,
                    valid_until TIMESTAMPTZ,
                    object_marking_ref TEXT,
                    imported_at TIMESTAMPTZ DEFAULT NOW(),
                    FOREIGN KEY (feed_id) REFERENCES threat_feeds(id)
                );

                CREATE TABLE IF NOT EXISTS stix_indicators (
                    id TEXT PRIMARY KEY,
                    feed_id TEXT NOT NULL,
                    stix_object_id TEXT,
                    stix_id TEXT DEFAULT '',
                    indicator_type TEXT NOT NULL,
                    indicator_value TEXT NOT NULL,
                    value TEXT NOT NULL,
                    pattern TEXT DEFAULT '',
                    confidence INTEGER DEFAULT 0,
                    severity TEXT,
                    labels TEXT DEFAULT '[]',
                    threat_types TEXT DEFAULT '[]',
                    kill_chain_phases TEXT DEFAULT '[]',
                    valid_from TIMESTAMPTZ,
                    valid_until TIMESTAMPTZ,
                    description TEXT DEFAULT '',
                    name TEXT DEFAULT '',
                    first_seen TIMESTAMPTZ,
                    last_seen TIMESTAMPTZ,
                    hit_count INTEGER DEFAULT 0,
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    FOREIGN KEY (feed_id) REFERENCES threat_feeds(id),
                    FOREIGN KEY (stix_object_id) REFERENCES stix_objects(id)
                );

                CREATE TABLE IF NOT EXISTS network_flows (
                    id TEXT PRIMARY KEY,
                    timestamp TIMESTAMPTZ NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol INTEGER,
                    bytes_sent INTEGER DEFAULT 0,
                    bytes_received INTEGER DEFAULT 0,
                    packets_sent INTEGER DEFAULT 0,
                    packets_received INTEGER DEFAULT 0,
                    flow_duration_ms INTEGER DEFAULT 0,
                    flags TEXT,
                    application TEXT,
                    source TEXT,
                    device_id TEXT,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS dns_queries (
                    id TEXT PRIMARY KEY,
                    timestamp TIMESTAMPTZ NOT NULL,
                    src_ip TEXT,
                    query_name TEXT NOT NULL,
                    query_type TEXT,
                    response_code TEXT,
                    response_data TEXT,
                    resolved INTEGER DEFAULT 1,
                    ttl INTEGER,
                    source TEXT,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS http_metadata (
                    id TEXT PRIMARY KEY,
                    timestamp TIMESTAMPTZ NOT NULL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    dst_port INTEGER DEFAULT 80,
                    method TEXT,
                    host TEXT,
                    uri TEXT,
                    user_agent TEXT,
                    status_code INTEGER,
                    response_size INTEGER DEFAULT 0,
                    content_type TEXT,
                    tls_version TEXT,
                    ja3_hash TEXT,
                    source TEXT,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS network_anomalies (
                    id TEXT PRIMARY KEY,
                    anomaly_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    description TEXT,
                    evidence TEXT,
                    mitre_technique TEXT,
                    mitre_tactic TEXT,
                    detected_at TIMESTAMPTZ DEFAULT NOW(),
                    resolved INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS playbooks (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    version TEXT DEFAULT '1.0.0',
                    author TEXT,
                    tags TEXT DEFAULT '[]',
                    severity_threshold TEXT DEFAULT 'MEDIUM',
                    mitre_tactics TEXT DEFAULT '[]',
                    trigger_type TEXT DEFAULT 'alert',
                    trigger_filter TEXT DEFAULT '{}',
                    steps_json TEXT NOT NULL,
                    enabled INTEGER DEFAULT 1,
                    execution_count INTEGER DEFAULT 0,
                    last_executed_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    updated_at TIMESTAMPTZ
                );

                CREATE TABLE IF NOT EXISTS playbook_executions (
                    id TEXT PRIMARY KEY,
                    playbook_id TEXT NOT NULL REFERENCES playbooks(id),
                    trigger_event_id TEXT,
                    trigger_data TEXT,
                    status TEXT DEFAULT 'running',
                    step_results TEXT,
                    started_at TIMESTAMPTZ DEFAULT NOW(),
                    completed_at TIMESTAMPTZ,
                    duration_ms INTEGER,
                    actions_taken TEXT DEFAULT '[]'
                );

                CREATE TABLE IF NOT EXISTS playbook_action_log (
                    id TEXT PRIMARY KEY,
                    execution_id TEXT NOT NULL REFERENCES playbook_executions(id),
                    step_id TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    integration TEXT,
                    action_name TEXT,
                    input_params TEXT,
                    output_result TEXT,
                    status TEXT,
                    error_message TEXT,
                    executed_at TIMESTAMPTZ DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS evidence (
                    id TEXT PRIMARY KEY,
                    incident_id TEXT,
                    alert_id TEXT,
                    evidence_type TEXT NOT NULL,
                    source_type TEXT DEFAULT '',
                    source_id TEXT DEFAULT '',
                    description TEXT DEFAULT '',
                    file_name TEXT,
                    file_path TEXT DEFAULT '',
                    file_size INTEGER DEFAULT 0,
                    sha256_hash TEXT NOT NULL,
                    md5_hash TEXT,
                    collected_by TEXT,
                    collected_at TIMESTAMPTZ NOT NULL,
                    status TEXT DEFAULT 'collected',
                    chain_of_custody TEXT DEFAULT '[]',
                    metadata TEXT DEFAULT '{}',
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS evidence_chain (
                    id TEXT PRIMARY KEY,
                    evidence_id TEXT NOT NULL REFERENCES evidence(id),
                    sequence_num INTEGER DEFAULT 0,
                    action TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    actor_name TEXT,
                    details TEXT DEFAULT '',
                    prev_hash TEXT DEFAULT '',
                    timestamp TIMESTAMPTZ NOT NULL,
                    previous_hash TEXT,
                    entry_hash TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS forensic_timeline (
                    id TEXT PRIMARY KEY,
                    incident_id TEXT,
                    event_time TIMESTAMPTZ NOT NULL,
                    event_type TEXT NOT NULL,
                    source TEXT DEFAULT '',
                    description TEXT DEFAULT '',
                    evidence_id TEXT DEFAULT '',
                    confidence REAL DEFAULT 1.0,
                    metadata TEXT DEFAULT '{}',
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS nist_controls (
                    id TEXT PRIMARY KEY,
                    control_id TEXT NOT NULL,
                    family TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    implementation_status TEXT DEFAULT 'not_assessed',
                    evidence_ids TEXT DEFAULT '[]',
                    responsible_party TEXT,
                    last_assessed_at TIMESTAMPTZ,
                    next_assessment_at TIMESTAMPTZ,
                    notes TEXT,
                    implementation_guidance TEXT,
                    automated_check TEXT,
                    created_at TIMESTAMPTZ
                );

                CREATE TABLE IF NOT EXISTS compliance_assessments (
                    id TEXT PRIMARY KEY,
                    assessment_id TEXT NOT NULL,
                    score REAL,
                    total_controls INTEGER,
                    compliant_count INTEGER,
                    non_compliant_count INTEGER,
                    controls_status TEXT DEFAULT '[]',
                    gaps TEXT DEFAULT '[]',
                    system_state TEXT DEFAULT '{}',
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS user_behavior_baselines (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    metric_type TEXT NOT NULL,
                    baseline_value REAL NOT NULL,
                    standard_deviation REAL NOT NULL,
                    sample_count INTEGER DEFAULT 0,
                    last_updated TIMESTAMPTZ DEFAULT NOW(),
                    UNIQUE(user_id, metric_type)
                );

                CREATE TABLE IF NOT EXISTS user_anomalies (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    anomaly_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    description TEXT,
                    baseline_value REAL,
                    observed_value REAL,
                    deviation_score REAL,
                    evidence TEXT,
                    mitre_technique TEXT,
                    mitre_tactic TEXT,
                    detected_at TIMESTAMPTZ DEFAULT NOW(),
                    resolved INTEGER DEFAULT 0,
                    assigned_to TEXT
                );

                CREATE TABLE IF NOT EXISTS insider_threat_cases (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    case_status TEXT DEFAULT 'open',
                    risk_level TEXT,
                    anomaly_ids TEXT DEFAULT '[]',
                    assigned_to TEXT,
                    description TEXT,
                    findings TEXT,
                    resolution TEXT,
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    updated_at TIMESTAMPTZ
                );

                CREATE TABLE IF NOT EXISTS hunt_saved_searches (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    query_text TEXT DEFAULT '',
                    filters_json TEXT DEFAULT '[]',
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS event_bookmarks (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    note TEXT DEFAULT '',
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS rule_packs (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    version TEXT DEFAULT '1.0',
                    author TEXT DEFAULT '',
                    rules_json TEXT DEFAULT '[]',
                    enabled INTEGER DEFAULT 1,
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    updated_at TIMESTAMPTZ
                );

                CREATE TABLE IF NOT EXISTS playbook_runs (
                    id TEXT PRIMARY KEY,
                    playbook_id TEXT NOT NULL,
                    playbook_name TEXT DEFAULT '',
                    triggered_by TEXT DEFAULT '',
                    trigger_type TEXT DEFAULT 'manual',
                    status TEXT DEFAULT 'running',
                    input_data TEXT DEFAULT '{}',
                    output_data TEXT DEFAULT '{}',
                    actions_completed INTEGER DEFAULT 0,
                    actions_failed INTEGER DEFAULT 0,
                    started_at TIMESTAMPTZ DEFAULT NOW(),
                    completed_at TIMESTAMPTZ,
                    error_message TEXT DEFAULT ''
                );
            """)

            for alter_sql in [
                "ALTER TABLE threat_feeds ADD COLUMN IF NOT EXISTS collection_id TEXT DEFAULT ''",
                "ALTER TABLE threat_feeds ADD COLUMN IF NOT EXISTS description TEXT DEFAULT ''",
                "ALTER TABLE threat_feeds ADD COLUMN IF NOT EXISTS tlp TEXT DEFAULT 'white'",
                "ALTER TABLE threat_feeds ADD COLUMN IF NOT EXISTS total_objects INTEGER DEFAULT 0",
                "ALTER TABLE threat_feeds ADD COLUMN IF NOT EXISTS total_indicators INTEGER DEFAULT 0",
                "ALTER TABLE threat_feeds ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'idle'",
                "ALTER TABLE threat_feeds ADD COLUMN IF NOT EXISTS error_message TEXT DEFAULT ''",
                "ALTER TABLE threat_feeds ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ",
                "ALTER TABLE stix_objects ADD COLUMN IF NOT EXISTS feed_id TEXT",
                "ALTER TABLE stix_objects ADD COLUMN IF NOT EXISTS stix_id TEXT DEFAULT ''",
                "ALTER TABLE stix_objects ADD COLUMN IF NOT EXISTS stix_type TEXT DEFAULT ''",
                "ALTER TABLE stix_objects ADD COLUMN IF NOT EXISTS created TEXT DEFAULT ''",
                "ALTER TABLE stix_objects ADD COLUMN IF NOT EXISTS modified TEXT DEFAULT ''",
                "ALTER TABLE stix_objects ADD COLUMN IF NOT EXISTS revoked INTEGER DEFAULT 0",
                "ALTER TABLE stix_indicators ADD COLUMN IF NOT EXISTS feed_id TEXT",
                "ALTER TABLE stix_indicators ADD COLUMN IF NOT EXISTS stix_id TEXT DEFAULT ''",
                "ALTER TABLE stix_indicators ADD COLUMN IF NOT EXISTS indicator_value TEXT NOT NULL DEFAULT ''",
                "ALTER TABLE stix_indicators ADD COLUMN IF NOT EXISTS value TEXT NOT NULL DEFAULT ''",
                "ALTER TABLE stix_indicators ADD COLUMN IF NOT EXISTS pattern TEXT DEFAULT ''",
                "ALTER TABLE stix_indicators ADD COLUMN IF NOT EXISTS labels TEXT DEFAULT '[]'",
                "ALTER TABLE stix_indicators ADD COLUMN IF NOT EXISTS description TEXT DEFAULT ''",
                "ALTER TABLE stix_indicators ADD COLUMN IF NOT EXISTS name TEXT DEFAULT ''",
                "ALTER TABLE stix_indicators ADD COLUMN IF NOT EXISTS first_seen TIMESTAMPTZ",
                "ALTER TABLE stix_indicators ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ",
                "ALTER TABLE stix_indicators ADD COLUMN IF NOT EXISTS hit_count INTEGER DEFAULT 0",
                "ALTER TABLE stix_indicators ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()",
                "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS source_type TEXT DEFAULT ''",
                "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS source_id TEXT DEFAULT ''",
                "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'collected'",
                "ALTER TABLE evidence_chain ADD COLUMN IF NOT EXISTS sequence_num INTEGER DEFAULT 0",
                "ALTER TABLE evidence_chain ADD COLUMN IF NOT EXISTS prev_hash TEXT DEFAULT ''",
                "ALTER TABLE forensic_timeline ADD COLUMN IF NOT EXISTS metadata TEXT DEFAULT '{}'",
                "ALTER TABLE compliance_assessments ADD COLUMN IF NOT EXISTS assessment_id TEXT DEFAULT ''",
                "ALTER TABLE compliance_assessments ADD COLUMN IF NOT EXISTS score REAL",
                "ALTER TABLE compliance_assessments ADD COLUMN IF NOT EXISTS compliant_count INTEGER",
                "ALTER TABLE compliance_assessments ADD COLUMN IF NOT EXISTS non_compliant_count INTEGER",
                "ALTER TABLE compliance_assessments ADD COLUMN IF NOT EXISTS controls_status TEXT DEFAULT '[]'",
                "ALTER TABLE compliance_assessments ADD COLUMN IF NOT EXISTS gaps TEXT DEFAULT '[]'",
                "ALTER TABLE compliance_assessments ADD COLUMN IF NOT EXISTS system_state TEXT DEFAULT '{}'",
            ]:
                try:
                    cur.execute(alter_sql)
                except Exception:
                    pass

            for alter_sql in [
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS organization_id TEXT DEFAULT ''",
                "ALTER TABLE uploaded_logs ADD COLUMN IF NOT EXISTS organization_id TEXT DEFAULT ''",
                "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS organization_id TEXT DEFAULT ''",
                "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS priority TEXT DEFAULT 'P4'",
                "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS category TEXT DEFAULT 'general'",
                "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS impact_summary TEXT DEFAULT ''",
                "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS root_cause TEXT DEFAULT ''",
                "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS lessons_learned TEXT DEFAULT ''",
                "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS sla_deadline TIMESTAMPTZ",
                "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ",
                "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS closed_at TIMESTAMPTZ",
                "ALTER TABLE notifications ADD COLUMN IF NOT EXISTS organization_id TEXT DEFAULT ''",
                "ALTER TABLE reports ADD COLUMN IF NOT EXISTS organization_id TEXT DEFAULT ''",
            ]:
                try:
                    cur.execute(alter_sql)
                except Exception:
                    pass

            # Fix existing NULL feed_type rows
            try:
                cur.execute("UPDATE threat_feeds SET feed_type = 'intel' WHERE feed_type IS NULL")
            except Exception:
                pass

            # Ensure unique constraint on threat_feeds.name for idempotent upserts
            try:
                cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_threat_feeds_name ON threat_feeds(name)")
            except Exception:
                pass

    # ── Organization Management ──

    def create_organization(self, name: str, slug: str, description: str = "") -> str:
        org_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("INSERT INTO organizations (id, name, slug, description, created_at) VALUES (%s,%s,%s,%s,%s)",
                    (org_id, name, slug, description, now))
            else:
                cur.execute("INSERT INTO organizations (id, name, slug, description, created_at) VALUES (?,?,?,?,?)",
                    (org_id, name, slug, description, now))
        return org_id

    def get_organization(self, org_id: str) -> Optional[Dict]:
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("SELECT * FROM organizations WHERE id = %s", (org_id,))
            else:
                cur.execute("SELECT * FROM organizations WHERE id = ?", (org_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def get_organization_by_slug(self, slug: str) -> Optional[Dict]:
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("SELECT * FROM organizations WHERE slug = %s", (slug,))
            else:
                cur.execute("SELECT * FROM organizations WHERE slug = ?", (slug,))
            row = cur.fetchone()
            return dict(row) if row else None

    def list_organizations(self) -> List[Dict]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM organizations ORDER BY name")
            return [dict(row) for row in cur.fetchall()]

    def add_org_member(self, org_id: str, user_id: str, role: str = 'analyst') -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            try:
                if USE_POSTGRESQL:
                    cur.execute("INSERT INTO org_members (organization_id, user_id, role, joined_at) VALUES (%s,%s,%s,%s)",
                        (org_id, user_id, role, now))
                else:
                    cur.execute("INSERT INTO org_members (organization_id, user_id, role, joined_at) VALUES (?,?,?,?)",
                        (org_id, user_id, role, now))
                return True
            except Exception:
                return False

    def get_user_org(self, user_id: str) -> Optional[Dict]:
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("""SELECT o.* FROM organizations o
                    JOIN org_members m ON o.id = m.organization_id
                    WHERE m.user_id = %s LIMIT 1""", (user_id,))
            else:
                cur.execute("""SELECT o.* FROM organizations o
                    JOIN org_members m ON o.id = m.organization_id
                    WHERE m.user_id = ? LIMIT 1""", (user_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def get_user_org_id(self, user_id: str) -> str:
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("SELECT organization_id FROM users WHERE id = %s", (user_id,))
            else:
                cur.execute("SELECT organization_id FROM users WHERE id = ?", (user_id,))
            row = cur.fetchone()
            if row:
                return row['organization_id'] if USE_POSTGRESQL else row[0]
            return ""

    def update_user_org(self, user_id: str, org_id: str):
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("UPDATE users SET organization_id = %s WHERE id = %s", (org_id, user_id))
            else:
                cur.execute("UPDATE users SET organization_id = ? WHERE id = ?", (org_id, user_id))

    def get_org_members(self, org_id: str) -> List[Dict]:
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("""SELECT u.id, u.email, u.name, u.role, m.role as org_role, m.joined_at
                    FROM users u JOIN org_members m ON u.id = m.user_id
                    WHERE m.organization_id = %s ORDER BY m.joined_at""", (org_id,))
            else:
                cur.execute("""SELECT u.id, u.email, u.name, u.role, m.role as org_role, m.joined_at
                    FROM users u JOIN org_members m ON u.id = m.user_id
                    WHERE m.organization_id = ? ORDER BY m.joined_at""", (org_id,))
            return [dict(row) for row in cur.fetchall()]

    def init_org_tables(self):
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("""CREATE TABLE IF NOT EXISTS org_members (
                    organization_id TEXT REFERENCES organizations(id),
                    user_id TEXT REFERENCES users(id),
                    role TEXT DEFAULT 'analyst',
                    joined_at TIMESTAMPTZ,
                    PRIMARY KEY (organization_id, user_id)
                )""")
            else:
                cur.execute("""CREATE TABLE IF NOT EXISTS org_members (
                    organization_id TEXT,
                    user_id TEXT,
                    role TEXT DEFAULT 'analyst',
                    joined_at TEXT,
                    PRIMARY KEY (organization_id, user_id)
                )""")

    def create_user(self, email: str, password_hash: str, name: str, role: str = 'analyst', organization_id: str = '') -> Dict[str, Any]:
        user_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute(
                    "INSERT INTO users (id, email, password_hash, name, role, organization_id, created_at) VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id, email, name, role, organization_id, created_at",
                    (user_id, email, password_hash, name, role, organization_id, now)
                )
                return dict(cur.fetchone())
            else:
                cur.execute(
                    "INSERT INTO users (id, email, password_hash, name, role, organization_id, created_at) VALUES (?,?,?,?,?,?,?)",
                    (user_id, email, password_hash, name, role, organization_id, now)
                )
                return {"id": user_id, "email": email, "name": name, "role": role, "organization_id": organization_id, "created_at": now}

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

    def create_uploaded_log(self, filename: str, source_type: str, user_id: str = None, file_size: int = 0, organization_id: str = None) -> str:
        log_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute(
                    "INSERT INTO uploaded_logs (id, user_id, filename, file_size, source_type, organization_id, upload_time) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                    (log_id, user_id, filename, file_size, source_type, organization_id, now)
                )
            else:
                cur.execute(
                    "INSERT INTO uploaded_logs (id, user_id, filename, file_size, source_type, organization_id, upload_time) VALUES (?,?,?,?,?,?,?)",
                    (log_id, user_id, filename, file_size, source_type, organization_id, now)
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
                    src_ip = event.get('source_ip', '') or None
                    dst_ip = event.get('dest_ip', '') or None
                    if USE_POSTGRESQL:
                        cur.execute("""
                            INSERT INTO log_events (id, log_id, timestamp, source_ip, dest_ip, source_port, dest_port,
                                protocol, event_type, severity, user_name, url, method, status_code, message, raw_line, source_format, metadata)
                            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        """, (
                            event_id, log_id,
                            event.get('timestamp', ''), src_ip, dst_ip,
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
                            event.get('timestamp', ''), src_ip or '', dst_ip or '',
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
                    src_ip = det.get('source_ip', '') or None
                    dst_ip = det.get('dest_ip', '') or None
                    if USE_POSTGRESQL:
                        cur.execute("""
                            INSERT INTO threat_detections (id, log_id, threat_type, severity, confidence, source_ip, dest_ip,
                                dest_port, description, evidence, mitre_technique, mitre_tactic, first_seen, last_seen, event_count, recommendations)
                            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        """, (
                            det_id, log_id, det.get('threat_type', ''), det.get('severity', 'INFO'),
                            det.get('confidence', 0.0), src_ip, dst_ip,
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
                            det.get('confidence', 0.0), src_ip or '', dst_ip or '',
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

            if USE_POSTGRESQL:
                cur.execute("SELECT COUNT(DISTINCT source_ip::text) FROM log_events WHERE source_ip IS NOT NULL AND source_ip::text != ''")
            else:
                cur.execute("SELECT COUNT(DISTINCT source_ip) FROM log_events WHERE source_ip IS NOT NULL AND source_ip != ''")
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
            pg_src = source_ip or None
            pg_dst = dest_ip or None
            if USE_POSTGRESQL:
                cur.execute("""
                    INSERT INTO alerts (id, organization_id, log_id, device_id, alert_type, severity, title, description,
                        source_ip, destination_ip, source_port, destination_port, protocol, mitre_technique, mitre_tactic,
                        evidence, recommendations, status, created_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """, (alert_id, org_id, log_id, device_id, alert_type, severity, title, description,
                      pg_src, pg_dst, source_port, dest_port, protocol, mitre_technique, mitre_tactic,
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

    def get_alert_stats(self, org_id: str = None) -> Dict[str, Any]:
        with self._cursor() as cur:
            org_filter = ""
            params = []
            if org_id:
                org_filter = " WHERE organization_id = %s" if USE_POSTGRESQL else " WHERE organization_id = ?"
                params = [org_id]

            cur.execute(f"SELECT COUNT(*) as total FROM alerts{org_filter}", tuple(params))
            row = cur.fetchone()
            total = row['total'] if USE_POSTGRESQL else row[0]

            cur.execute(f"SELECT severity, COUNT(*) as count FROM alerts{org_filter} GROUP BY severity", tuple(params))
            by_severity = {row['severity']: row['count'] if USE_POSTGRESQL else row[1] for row in cur.fetchall()}

            cur.execute(f"SELECT status, COUNT(*) as count FROM alerts{org_filter} GROUP BY status", tuple(params))
            by_status = {row['status']: row['count'] if USE_POSTGRESQL else row[1] for row in cur.fetchall()}

            cur.execute(f"SELECT alert_type, COUNT(*) as count FROM alerts{org_filter} GROUP BY alert_type ORDER BY count DESC", tuple(params))
            by_type = {row['alert_type']: row['count'] if USE_POSTGRESQL else row[1] for row in cur.fetchall()}

            return {'total': total, 'open': by_status.get('open', 0), 'critical': by_severity.get('CRITICAL', 0), 'high': by_severity.get('HIGH', 0), 'by_severity': by_severity, 'by_status': by_status, 'by_type': by_type}

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

    # ── Incident Operations ──

    def create_incident(self, title: str, severity: str, description: str = "",
                        alert_ids: list = None, timeline: list = None, affected_ips: list = None,
                        mitre_techniques: list = None, mitre_tactics: list = None,
                        recommendations: list = None, confidence: float = 0.0,
                        organization_id: str = None) -> str:
        incident_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("""
                    INSERT INTO incidents (id, title, severity, status, confidence, description,
                        alert_ids, timeline, affected_ips, mitre_techniques, mitre_tactics,
                        recommendations, organization_id, created_at, updated_at)
                    VALUES (%s,%s,%s,'open',%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """, (incident_id, title, severity, confidence, description,
                      json.dumps(alert_ids or []), json.dumps(timeline or []),
                      json.dumps(affected_ips or []), json.dumps(mitre_techniques or []),
                      json.dumps(mitre_tactics or []), json.dumps(recommendations or []),
                      organization_id, now, now))
            else:
                cur.execute("""
                    INSERT INTO incidents (id, title, severity, status, confidence, description,
                        alert_ids, timeline, affected_ips, mitre_techniques, mitre_tactics,
                        recommendations, organization_id, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (incident_id, title, severity, confidence, description,
                      json.dumps(alert_ids or []), json.dumps(timeline or []),
                      json.dumps(affected_ips or []), json.dumps(mitre_techniques or []),
                      json.dumps(mitre_tactics or []), json.dumps(recommendations or []),
                      organization_id, now, now))
        return incident_id

    def get_incidents(self, org_id: str = None, status: str = None, severity: str = None, limit: int = 100) -> List[Dict]:
        with self._cursor() as cur:
            conditions = []
            params = []
            if org_id:
                conditions.append(f"organization_id = {'%s' if USE_POSTGRESQL else '?'}")
                params.append(org_id)
            if status:
                conditions.append(f"status = {'%s' if USE_POSTGRESQL else '?'}")
                params.append(status)
            if severity:
                conditions.append(f"severity = {'%s' if USE_POSTGRESQL else '?'}")
                params.append(severity)

            where = " WHERE " + " AND ".join(conditions) if conditions else ""
            limit_q = '%s' if USE_POSTGRESQL else '?'
            query = f"SELECT * FROM incidents{where} ORDER BY created_at DESC LIMIT {limit_q}"
            params.append(limit)

            cur.execute(query, tuple(params))
            return [dict(row) for row in cur.fetchall()]

    def get_incident(self, incident_id: str) -> Optional[Dict]:
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("SELECT * FROM incidents WHERE id = %s", (incident_id,))
            else:
                cur.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def update_incident_status(self, incident_id: str, status: str, assigned_to: str = None):
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                if assigned_to:
                    cur.execute("UPDATE incidents SET status=%s, assigned_to=%s, updated_at=%s WHERE id=%s",
                                (status, assigned_to, now, incident_id))
                else:
                    cur.execute("UPDATE incidents SET status=%s, updated_at=%s WHERE id=%s",
                                (status, now, incident_id))
            else:
                if assigned_to:
                    cur.execute("UPDATE incidents SET status=?, assigned_to=?, updated_at=? WHERE id=?",
                                (status, assigned_to, now, incident_id))
                else:
                    cur.execute("UPDATE incidents SET status=?, updated_at=? WHERE id=?",
                                (status, now, incident_id))

    def get_incident_notes(self, incident_id: str) -> List[Dict]:
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("SELECT * FROM incident_notes WHERE incident_id = %s ORDER BY created_at", (incident_id,))
            else:
                cur.execute("SELECT * FROM incident_notes WHERE incident_id = ? ORDER BY created_at", (incident_id,))
            return [dict(row) for row in cur.fetchall()]

    def add_incident_note(self, incident_id: str, user_id: str, note: str) -> str:
        note_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("INSERT INTO incident_notes (id, incident_id, user_id, note, created_at) VALUES (%s,%s,%s,%s,%s)",
                            (note_id, incident_id, user_id, note, now))
            else:
                cur.execute("INSERT INTO incident_notes (id, incident_id, user_id, note, created_at) VALUES (?,?,?,?,?)",
                            (note_id, incident_id, user_id, note, now))
        return note_id

    def get_incident_stats(self, org_id: str = None) -> Dict[str, Any]:
        with self._cursor() as cur:
            org_filter = ""
            params = []
            if org_id:
                org_filter = " WHERE organization_id = %s" if USE_POSTGRESQL else " WHERE organization_id = ?"
                params = [org_id]

            cur.execute(f"SELECT COUNT(*) as total FROM incidents{org_filter}", tuple(params))
            row = cur.fetchone()
            total = row['total'] if USE_POSTGRESQL else row[0]

            cur.execute(f"SELECT severity, COUNT(*) as count FROM incidents{org_filter} GROUP BY severity", tuple(params))
            by_severity = {row['severity']: row['count'] if USE_POSTGRESQL else row[1] for row in cur.fetchall()}

            cur.execute(f"SELECT status, COUNT(*) as count FROM incidents{org_filter} GROUP BY status", tuple(params))
            by_status = {row['status']: row['count'] if USE_POSTGRESQL else row[1] for row in cur.fetchall()}

            open_count = by_status.get('open', 0) if isinstance(by_status, dict) else 0
            critical_count = by_severity.get('CRITICAL', 0) if isinstance(by_severity, dict) else 0

            return {'total': total, 'open': open_count, 'critical': critical_count, 'by_severity': by_severity, 'by_status': by_status}

    # ── Incident Lifecycle Operations ──

    def update_incident(self, incident_id: str, **fields) -> bool:
        allowed = {'title', 'severity', 'description', 'priority', 'category',
                    'assigned_to', 'impact_summary', 'root_cause', 'lessons_learned',
                    'sla_deadline', 'organization_id'}
        updates = {k: v for k, v in fields.items() if k in allowed and v is not None}
        if not updates:
            return False
        now = datetime.now(timezone.utc).isoformat()
        updates['updated_at'] = now
        set_parts = []
        params = []
        for k, v in updates.items():
            q = '%s' if USE_POSTGRESQL else '?'
            set_parts.append(f"{k} = {q}")
            params.append(v)
        params.append(incident_id)
        with self._cursor() as cur:
            cur.execute(f"UPDATE incidents SET {', '.join(set_parts)} WHERE id = {'%s' if USE_POSTGRESQL else '?'}", tuple(params))
            return cur.rowcount > 0

    def archive_incident(self, incident_id: str) -> bool:
        return self.update_incident(incident_id, status='archived')

    def merge_incidents(self, primary_id: str, secondary_ids: List[str]) -> str:
        primary = self.get_incident(primary_id)
        if not primary:
            return ""
        all_alert_ids = json.loads(primary.get('alert_ids', '[]'))
        all_ips = json.loads(primary.get('affected_ips', '[]'))
        all_techniques = json.loads(primary.get('mitre_techniques', '[]'))
        all_tactics = json.loads(primary.get('mitre_tactics', '[]'))
        all_recommendations = json.loads(primary.get('recommendations', '[]'))
        all_timeline = json.loads(primary.get('timeline', '[]'))
        for sid in secondary_ids:
            sec = self.get_incident(sid)
            if not sec:
                continue
            all_alert_ids.extend(json.loads(sec.get('alert_ids', '[]')))
            all_ips.extend(json.loads(sec.get('affected_ips', '[]')))
            all_techniques.extend(json.loads(sec.get('mitre_techniques', '[]')))
            all_tactics.extend(json.loads(sec.get('mitre_tactics', '[]')))
            all_recommendations.extend(json.loads(sec.get('recommendations', '[]')))
            all_timeline.extend(json.loads(sec.get('timeline', '[]')))
            all_timeline.append({'event': f'Merged from incident {sid}', 'timestamp': datetime.now(timezone.utc).isoformat()})
            self.archive_incident(sid)
        all_alert_ids = list(dict.fromkeys(all_alert_ids))
        all_ips = list(dict.fromkeys(all_ips))
        all_techniques = list(dict.fromkeys(all_techniques))
        all_tactics = list(dict.fromkeys(all_tactics))
        all_recommendations = list(dict.fromkeys(all_recommendations))
        self.update_incident(primary_id,
            description=primary.get('description', '') + f'\n[Merged {len(secondary_ids)} incidents]',
            alert_ids=json.dumps(all_alert_ids),
            affected_ips=json.dumps(all_ips),
            mitre_techniques=json.dumps(all_techniques),
            mitre_tactics=json.dumps(all_tactics),
            recommendations=json.dumps(all_recommendations),
            timeline=json.dumps(all_timeline))
        return primary_id

    def add_incident_evidence(self, incident_id: str, evidence_type: str, description: str = "",
                              file_name: str = "", source_type: str = "", source_id: str = "") -> str:
        evidence_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        import hashlib
        content_hash = hashlib.sha256(f"{incident_id}{evidence_type}{now}".encode()).hexdigest()
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("""INSERT INTO evidence (id, incident_id, evidence_type, source_type, source_id,
                    description, file_name, sha256_hash, collected_at, created_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (evidence_id, incident_id, evidence_type, source_type, source_id,
                     description, file_name, content_hash, now, now))
            else:
                cur.execute("""INSERT INTO evidence (id, incident_id, evidence_type, source_type, source_id,
                    description, file_name, sha256_hash, collected_at, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (evidence_id, incident_id, evidence_type, source_type, source_id,
                     description, file_name, content_hash, now, now))
        return evidence_id

    def get_incident_evidence(self, incident_id: str) -> List[Dict]:
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("SELECT * FROM evidence WHERE incident_id = %s ORDER BY collected_at", (incident_id,))
            else:
                cur.execute("SELECT * FROM evidence WHERE incident_id = ? ORDER BY collected_at", (incident_id,))
            return [dict(row) for row in cur.fetchall()]

    def add_incident_timeline(self, incident_id: str, event_type: str, description: str,
                              source: str = "", evidence_id: str = "", confidence: float = 1.0) -> str:
        entry_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("""INSERT INTO forensic_timeline (id, incident_id, event_time, event_type,
                    source, description, evidence_id, confidence, created_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (entry_id, incident_id, now, event_type, source, description, evidence_id, confidence, now))
            else:
                cur.execute("""INSERT INTO forensic_timeline (id, incident_id, event_time, event_type,
                    source, description, evidence_id, confidence, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?)""",
                    (entry_id, incident_id, now, event_type, source, description, evidence_id, confidence, now))
        return entry_id

    def get_incident_timeline(self, incident_id: str) -> List[Dict]:
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("SELECT * FROM forensic_timeline WHERE incident_id = %s ORDER BY event_time", (incident_id,))
            else:
                cur.execute("SELECT * FROM forensic_timeline WHERE incident_id = ? ORDER BY event_time", (incident_id,))
            return [dict(row) for row in cur.fetchall()]

    def create_incident_notification(self, user_id: str, incident_id: str, title: str, message: str, notif_type: str = "info") -> str:
        notif_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("INSERT INTO notifications (id, user_id, title, message, type, created_at) VALUES (%s,%s,%s,%s,%s,%s)",
                            (notif_id, user_id, title, message, notif_type, now))
            else:
                cur.execute("INSERT INTO notifications (id, user_id, title, message, type, created_at) VALUES (?,?,?,?,?,?)",
                            (notif_id, user_id, title, message, notif_type, now))
        return notif_id

    def get_incident_mttt(self) -> Dict[str, Any]:
        with self._cursor() as cur:
            cur.execute("SELECT created_at, updated_at, status FROM incidents WHERE status IN ('contained','resolved','closed')")
            rows = cur.fetchall()
            if not rows:
                return {'mttt_minutes': 0, 'mttr_minutes': 0, 'resolved_count': 0}
            contain_times = []
            resolve_times = []
            for row in rows:
                try:
                    created = datetime.fromisoformat(row['created_at'] if USE_POSTGRESQL else row[0])
                    updated = datetime.fromisoformat(row['updated_at'] if USE_POSTGRESQL else row[1])
                    status = row['status'] if USE_POSTGRESQL else row[2]
                    delta = (updated - created).total_seconds() / 60
                    if status in ('contained', 'resolved', 'closed'):
                        contain_times.append(delta)
                    if status in ('resolved', 'closed'):
                        resolve_times.append(delta)
                except Exception:
                    continue
            return {
                'mttt_minutes': round(sum(contain_times) / len(contain_times), 1) if contain_times else 0,
                'mttr_minutes': round(sum(resolve_times) / len(resolve_times), 1) if resolve_times else 0,
                'resolved_count': len(resolve_times),
            }

    def bulk_update_incidents(self, incident_ids: List[str], status: str = None, assigned_to: str = None) -> int:
        count = 0
        for iid in incident_ids:
            if status:
                self.update_incident_status(iid, status, assigned_to)
                count += 1
            elif assigned_to:
                self.update_incident(iid, assigned_to=assigned_to)
                count += 1
        return count

    # ── Pipeline Tracking Operations ──

    def init_pipeline_tracking(self):
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("""CREATE TABLE IF NOT EXISTS pipeline_stages (
                    id TEXT PRIMARY KEY,
                    event_id TEXT NOT NULL,
                    log_id TEXT,
                    stage TEXT NOT NULL,
                    status TEXT DEFAULT 'processing',
                    entered_at TEXT NOT NULL,
                    completed_at TEXT,
                    latency_ms REAL,
                    details TEXT DEFAULT '{}',
                    created_at TEXT NOT NULL
                )""")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_pipeline_stages_event ON pipeline_stages(event_id)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_pipeline_stages_log ON pipeline_stages(log_id)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_pipeline_stages_stage ON pipeline_stages(stage)")
                cur.execute("""CREATE TABLE IF NOT EXISTS pipeline_metrics (
                    id TEXT PRIMARY KEY,
                    stage TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    events_processed INTEGER DEFAULT 0,
                    events_succeeded INTEGER DEFAULT 0,
                    events_failed INTEGER DEFAULT 0,
                    avg_latency_ms REAL DEFAULT 0,
                    p95_latency_ms REAL DEFAULT 0,
                    metadata TEXT DEFAULT '{}'
                )""")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_pipeline_metrics_stage ON pipeline_metrics(stage)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_pipeline_metrics_ts ON pipeline_metrics(timestamp)")
            else:
                cur.execute("""CREATE TABLE IF NOT EXISTS pipeline_stages (
                    id TEXT PRIMARY KEY,
                    event_id TEXT NOT NULL,
                    log_id TEXT,
                    stage TEXT NOT NULL,
                    status TEXT DEFAULT 'processing',
                    entered_at TEXT NOT NULL,
                    completed_at TEXT,
                    latency_ms REAL,
                    details TEXT DEFAULT '{}',
                    created_at TEXT NOT NULL
                )""")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_pipeline_stages_event ON pipeline_stages(event_id)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_pipeline_stages_log ON pipeline_stages(log_id)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_pipeline_stages_stage ON pipeline_stages(stage)")
                cur.execute("""CREATE TABLE IF NOT EXISTS pipeline_metrics (
                    id TEXT PRIMARY KEY,
                    stage TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    events_processed INTEGER DEFAULT 0,
                    events_succeeded INTEGER DEFAULT 0,
                    events_failed INTEGER DEFAULT 0,
                    avg_latency_ms REAL DEFAULT 0,
                    p95_latency_ms REAL DEFAULT 0,
                    metadata TEXT DEFAULT '{}'
                )""")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_pipeline_metrics_stage ON pipeline_metrics(stage)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_pipeline_metrics_ts ON pipeline_metrics(timestamp)")

    def enter_pipeline_stage(self, event_id: str, stage: str, log_id: str = None) -> str:
        stage_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("""INSERT INTO pipeline_stages (id, event_id, log_id, stage, status, entered_at, created_at)
                    VALUES (%s,%s,%s,%s,'processing',%s,%s)""",
                    (stage_id, event_id, log_id, stage, now, now))
            else:
                cur.execute("""INSERT INTO pipeline_stages (id, event_id, log_id, stage, status, entered_at, created_at)
                    VALUES (?,?,?,?,?,?,?)""",
                    (stage_id, event_id, log_id, stage, 'processing', now, now))
        return stage_id

    def complete_pipeline_stage(self, stage_id: str, status: str = 'completed', details: str = '{}'):
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("""UPDATE pipeline_stages SET status=%s, completed_at=%s, details=%s,
                    latency_ms = EXTRACT(EPOCH FROM (CAST(%s AS TIMESTAMP) - CAST(entered_at AS TIMESTAMP))) * 1000
                    WHERE id=%s""",
                    (status, now, details, now, stage_id))
            else:
                cur.execute("UPDATE pipeline_stages SET status=?, completed_at=?, details=? WHERE id=?",
                    (status, now, details, stage_id))
                cur.execute("SELECT entered_at FROM pipeline_stages WHERE id=?", (stage_id,))
                row = cur.fetchone()
                if row:
                    try:
                        entered = datetime.fromisoformat(row[0] if USE_POSTGRESQL else row[0])
                        completed = datetime.fromisoformat(now)
                        latency = (completed - entered).total_seconds() * 1000
                        cur.execute("UPDATE pipeline_stages SET latency_ms=? WHERE id=?", (latency, stage_id))
                    except Exception:
                        pass

    def get_event_pipeline(self, event_id: str) -> List[Dict]:
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("SELECT * FROM pipeline_stages WHERE event_id = %s ORDER BY entered_at", (event_id,))
            else:
                cur.execute("SELECT * FROM pipeline_stages WHERE event_id = ? ORDER BY entered_at", (event_id,))
            return [dict(row) for row in cur.fetchall()]

    def get_log_pipeline(self, log_id: str) -> List[Dict]:
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("SELECT * FROM pipeline_stages WHERE log_id = %s ORDER BY entered_at", (log_id,))
            else:
                cur.execute("SELECT * FROM pipeline_stages WHERE log_id = ? ORDER BY entered_at", (log_id,))
            return [dict(row) for row in cur.fetchall()]

    def get_pipeline_metrics(self, stage: str = None, hours: int = 24) -> List[Dict]:
        cutoff = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            if stage:
                if USE_POSTGRESQL:
                    cur.execute("""SELECT stage, COUNT(*) as total,
                        COUNT(CASE WHEN status='completed' THEN 1 END) as succeeded,
                        COUNT(CASE WHEN status='failed' THEN 1 END) as failed,
                        AVG(latency_ms) as avg_latency,
                        MAX(latency_ms) as max_latency
                        FROM pipeline_stages WHERE stage=%s
                        GROUP BY stage""", (stage,))
                else:
                    cur.execute("""SELECT stage, COUNT(*) as total,
                        COUNT(CASE WHEN status='completed' THEN 1 END) as succeeded,
                        COUNT(CASE WHEN status='failed' THEN 1 END) as failed,
                        AVG(latency_ms) as avg_latency,
                        MAX(latency_ms) as max_latency
                        FROM pipeline_stages WHERE stage=? GROUP BY stage""", (stage,))
            else:
                cur.execute("""SELECT stage, COUNT(*) as total,
                    COUNT(CASE WHEN status='completed' THEN 1 END) as succeeded,
                    COUNT(CASE WHEN status='failed' THEN 1 END) as failed,
                    AVG(latency_ms) as avg_latency,
                    MAX(latency_ms) as max_latency
                    FROM pipeline_stages GROUP BY stage""")
            rows = cur.fetchall()
            return [dict(row) for row in rows]

    def get_pipeline_throughput(self, minutes: int = 60) -> List[Dict]:
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("""SELECT
                    DATE_TRUNC('hour', entered_at) as hour_bucket,
                    stage,
                    COUNT(*) as event_count
                    FROM pipeline_stages
                    WHERE entered_at >= NOW() - INTERVAL '%s minutes'
                    GROUP BY hour_bucket, stage
                    ORDER BY hour_bucket""", (minutes,))
            else:
                cur.execute("""SELECT
                    substr(entered_at, 1, 13) as hour_bucket,
                    stage,
                    COUNT(*) as event_count
                    FROM pipeline_stages
                    WHERE entered_at >= datetime('now', ?)
                    GROUP BY hour_bucket, stage
                    ORDER BY hour_bucket""", (f'-{minutes} minutes',))
            return [dict(row) for row in cur.fetchall()]

    def get_pipeline_summary(self) -> Dict[str, Any]:
        stages = ['ingested', 'parsed', 'normalized', 'ml_detected', 'rule_matched',
                   'sigma_matched', 'ioc_matched', 'alert_created', 'correlated',
                   'incident_created', 'notified']
        result = {}
        with self._cursor() as cur:
            for stage in stages:
                if USE_POSTGRESQL:
                    cur.execute("SELECT COUNT(*) as total, AVG(latency_ms) as avg_ms FROM pipeline_stages WHERE stage=%s", (stage,))
                else:
                    cur.execute("SELECT COUNT(*) as total, AVG(latency_ms) as avg_ms FROM pipeline_stages WHERE stage=?", (stage,))
                row = cur.fetchone()
                total = row['total'] if USE_POSTGRESQL else (row[0] if row else 0)
                avg_ms = row['avg_ms'] if USE_POSTGRESQL else (row[1] if row else 0)
                result[stage] = {'count': total or 0, 'avg_latency_ms': round(avg_ms or 0, 2)}
        return result

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
                cur.execute("SELECT source_ip::text as source_ip, COUNT(*) as count FROM threat_detections WHERE source_ip IS NOT NULL AND source_ip::text != '' GROUP BY source_ip ORDER BY count DESC LIMIT 10")
            else:
                cur.execute("SELECT source_ip, COUNT(*) as count FROM threat_detections WHERE source_ip IS NOT NULL AND source_ip != '' GROUP BY source_ip ORDER BY count DESC LIMIT 10")
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

    # ── Asset Inventory ──

    def create_asset(self, hostname: str, ip_address: str, os_type: str = "unknown",
                     os_version: str = "", asset_type: str = "endpoint", criticality: str = "medium",
                     owner: str = "", department: str = "", location: str = "", organization_id: str = None) -> str:
        asset_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("""INSERT INTO assets (id, organization_id, hostname, ip_address, os_type, os_version,
                    asset_type, criticality, owner, department, location, last_seen, created_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (asset_id, organization_id, hostname, ip_address, os_type, os_version,
                     asset_type, criticality, owner, department, location, now, now))
            else:
                cur.execute("""INSERT INTO assets (id, organization_id, hostname, ip_address, os_type, os_version,
                    asset_type, criticality, owner, department, location, last_seen, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (asset_id, organization_id, hostname, ip_address, os_type, os_version,
                     asset_type, criticality, owner, department, location, now, now))
        return asset_id

    def get_assets(self, org_id: str = None, limit: int = 200) -> List[Dict]:
        with self._cursor() as cur:
            if org_id:
                if USE_POSTGRESQL:
                    cur.execute("SELECT * FROM assets WHERE organization_id = %s ORDER BY last_seen DESC LIMIT %s", (org_id, limit))
                else:
                    cur.execute("SELECT * FROM assets WHERE organization_id = ? ORDER BY last_seen DESC LIMIT ?", (org_id, limit))
            else:
                cur.execute(f"SELECT * FROM assets ORDER BY last_seen DESC LIMIT {'%s' if USE_POSTGRESQL else '?'}", (limit,))
            return [dict(row) for row in cur.fetchall()]

    def get_asset(self, asset_id: str) -> Optional[Dict]:
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("SELECT * FROM assets WHERE id = %s", (asset_id,))
            else:
                cur.execute("SELECT * FROM assets WHERE id = ?", (asset_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def update_asset(self, asset_id: str, **kwargs):
        now = datetime.now(timezone.utc).isoformat()
        kwargs["updated_at"] = now
        set_clause = ", ".join(f"{k} = {'%s' if USE_POSTGRESQL else '?'}" for k in kwargs)
        values = list(kwargs.values()) + [asset_id]
        with self._cursor() as cur:
            cur.execute(f"UPDATE assets SET {set_clause} WHERE id = {'%s' if USE_POSTGRESQL else '?'}", tuple(values))

    def delete_asset(self, asset_id: str):
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("DELETE FROM assets WHERE id = %s", (asset_id,))
            else:
                cur.execute("DELETE FROM assets WHERE id = ?", (asset_id,))

    # ── IOC (Indicators of Compromise) ──

    def create_ioc(self, indicator_type: str, indicator_value: str, threat_type: str = "",
                   severity: str = "MEDIUM", confidence: float = 0.5, source: str = "manual",
                   description: str = "", tags: List[str] = None, organization_id: str = None) -> str:
        ioc_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        tags_json = _json.dumps(tags or [])
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("""INSERT INTO ioc (id, organization_id, indicator_type, indicator_value, threat_type,
                    severity, confidence, source, description, first_seen, last_seen, tags, created_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (ioc_id, organization_id, indicator_type, indicator_value, threat_type,
                     severity, confidence, source, description, now, now, tags_json, now))
            else:
                cur.execute("""INSERT INTO ioc (id, organization_id, indicator_type, indicator_value, threat_type,
                    severity, confidence, source, description, first_seen, last_seen, tags, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (ioc_id, organization_id, indicator_type, indicator_value, threat_type,
                     severity, confidence, source, description, now, now, tags_json, now))
        return ioc_id

    def get_iocs(self, org_id: str = None, indicator_type: str = None, limit: int = 200) -> List[Dict]:
        with self._cursor() as cur:
            conditions = []
            params = []
            if org_id:
                conditions.append(f"organization_id = {'%s' if USE_POSTGRESQL else '?'}")
                params.append(org_id)
            if indicator_type:
                conditions.append(f"indicator_type = {'%s' if USE_POSTGRESQL else '?'}")
                params.append(indicator_type)
            where = " WHERE " + " AND ".join(conditions) if conditions else ""
            cur.execute(f"SELECT * FROM ioc{where} ORDER BY created_at DESC LIMIT {'%s' if USE_POSTGRESQL else '?'}", tuple(params + [limit]))
            return [dict(row) for row in cur.fetchall()]

    def get_ioc(self, ioc_id: str) -> Optional[Dict]:
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("SELECT * FROM ioc WHERE id = %s", (ioc_id,))
            else:
                cur.execute("SELECT * FROM ioc WHERE id = ?", (ioc_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def check_ioc_match(self, indicator_value: str) -> Optional[Dict]:
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("SELECT * FROM ioc WHERE indicator_value = %s", (indicator_value,))
            else:
                cur.execute("SELECT * FROM ioc WHERE indicator_value = ?", (indicator_value,))
            row = cur.fetchone()
            return dict(row) if row else None

    def delete_ioc(self, ioc_id: str):
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("DELETE FROM ioc WHERE id = %s", (ioc_id,))
            else:
                cur.execute("DELETE FROM ioc WHERE id = ?", (ioc_id,))

    # ── Detection Rules ──

    def create_detection_rule(self, title: str, condition: str, description: str = "",
                              window_seconds: int = 300, threshold: float = 1.0, severity: str = "MEDIUM",
                              mitre_technique: str = "", mitre_tactic: str = "", organization_id: str = None) -> str:
        rule_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("""INSERT INTO detection_rules (id, organization_id, title, description, condition,
                    window_seconds, threshold, severity, mitre_technique, mitre_tactic, created_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (rule_id, organization_id, title, description, condition,
                     window_seconds, threshold, severity, mitre_technique, mitre_tactic, now))
            else:
                cur.execute("""INSERT INTO detection_rules (id, organization_id, title, description, condition,
                    window_seconds, threshold, severity, mitre_technique, mitre_tactic, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (rule_id, organization_id, title, description, condition,
                     window_seconds, threshold, severity, mitre_technique, mitre_tactic, now))
        return rule_id

    def get_detection_rules(self, org_id: str = None, enabled_only: bool = True, limit: int = 200) -> List[Dict]:
        with self._cursor() as cur:
            conditions = []
            params = []
            if org_id:
                conditions.append(f"organization_id = {'%s' if USE_POSTGRESQL else '?'}")
                params.append(org_id)
            if enabled_only:
                conditions.append(f"enabled = {'%s' if USE_POSTGRESQL else '?'}")
                params.append(1 if not USE_POSTGRESQL else True)
            where = " WHERE " + " AND ".join(conditions) if conditions else ""
            cur.execute(f"SELECT * FROM detection_rules{where} ORDER BY created_at DESC LIMIT {'%s' if USE_POSTGRESQL else '?'}", tuple(params + [limit]))
            return [dict(row) for row in cur.fetchall()]

    def update_detection_rule(self, rule_id: str, **kwargs):
        now = datetime.now(timezone.utc).isoformat()
        kwargs["updated_at"] = now
        set_clause = ", ".join(f"{k} = {'%s' if USE_POSTGRESQL else '?'}" for k in kwargs)
        values = list(kwargs.values()) + [rule_id]
        with self._cursor() as cur:
            cur.execute(f"UPDATE detection_rules SET {set_clause} WHERE id = {'%s' if USE_POSTGRESQL else '?'}", tuple(values))

    def delete_detection_rule(self, rule_id: str):
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("DELETE FROM detection_rules WHERE id = %s", (rule_id,))
            else:
                cur.execute("DELETE FROM detection_rules WHERE id = ?", (rule_id,))

    # ── Agent Status ──

    def register_agent(self, hostname: str, ip_address: str, os_type: str = "unknown",
                       agent_version: str = "1.0.0", organization_id: str = None) -> str:
        agent_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("""INSERT INTO agent_status (id, organization_id, hostname, ip_address, os_type,
                    agent_version, status, last_seen, created_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (agent_id, organization_id, hostname, ip_address, os_type,
                     agent_version, "online", now, now))
            else:
                cur.execute("""INSERT INTO agent_status (id, organization_id, hostname, ip_address, os_type,
                    agent_version, status, last_seen, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?)""",
                    (agent_id, organization_id, hostname, ip_address, os_type,
                     agent_version, "online", now, now))
        return agent_id

    def get_agents(self, org_id: str = None, limit: int = 100) -> List[Dict]:
        with self._cursor() as cur:
            if org_id:
                if USE_POSTGRESQL:
                    cur.execute("SELECT * FROM agent_status WHERE organization_id = %s ORDER BY last_seen DESC LIMIT %s", (org_id, limit))
                else:
                    cur.execute("SELECT * FROM agent_status WHERE organization_id = ? ORDER BY last_seen DESC LIMIT ?", (org_id, limit))
            else:
                cur.execute(f"SELECT * FROM agent_status ORDER BY last_seen DESC LIMIT {'%s' if USE_POSTGRESQL else '?'}", (limit,))
            return [dict(row) for row in cur.fetchall()]

    def update_agent_status(self, agent_id: str, status: str = None, logs_collected: int = None,
                           events_processed: int = None, alerts_generated: int = None):
        now = datetime.now(timezone.utc).isoformat()
        updates = {"updated_at": now, "last_seen": now}
        if status: updates["status"] = status
        if logs_collected is not None: updates["logs_collected"] = logs_collected
        if events_processed is not None: updates["events_processed"] = events_processed
        if alerts_generated is not None: updates["alerts_generated"] = alerts_generated
        set_clause = ", ".join(f"{k} = {'%s' if USE_POSTGRESQL else '?'}" for k in updates)
        values = list(updates.values()) + [agent_id]
        with self._cursor() as cur:
            cur.execute(f"UPDATE agent_status SET {set_clause} WHERE id = {'%s' if USE_POSTGRESQL else '?'}", tuple(values))

    def search_events_advanced(self, query: str = "", filters: List[Dict] = None,
                                date_from: str = "", date_to: str = "",
                                source: str = "", limit: int = 500, offset: int = 0,
                                sort_by: str = "timestamp", sort_order: str = "desc") -> Dict[str, Any]:
        """Advanced event search with AND/OR/NOT filtering across all event tables."""
        results = {"detections": [], "alerts": [], "events": [], "total": 0,
                   "field_stats": {}, "timeline": []}

        # Build filter conditions
        conditions = []
        params = []

        def _build_conditions(table_alias: str = ""):
            nonlocal conditions, params
            conditions = []
            params = []

            if date_from:
                conditions.append(f"timestamp >= {'%s' if USE_POSTGRESQL else '?'}")
                params.append(date_from)
            if date_to:
                conditions.append(f"timestamp <= {'%s' if USE_POSTGRESQL else '?'}")
                params.append(date_to)

            if filters:
                for f in filters:
                    field = f.get("field", "")
                    op = f.get("op", "contains")
                    value = f.get("value", "")
                    negate = f.get("negate", False)

                    if not field or not value:
                        continue

                    if op == "equals":
                        clause = f"{field} = {'%s' if USE_POSTGRESQL else '?'}"
                    elif op == "contains":
                        clause = f"{field} ILIKE {'%s' if USE_POSTGRESQL else '?'}" if USE_POSTGRESQL else f"{field} LIKE {'%s' if USE_POSTGRESQL else '?'}"
                        value = f"%{value}%" if USE_POSTGRESQL else f"%{value}%"
                    elif op == "starts_with":
                        clause = f"{field} ILIKE {'%s' if USE_POSTGRESQL else '?'}" if USE_POSTGRESQL else f"{field} LIKE {'%s' if USE_POSTGRESQL else '?'}"
                        value = f"{value}%" if USE_POSTGRESQL else f"{value}%"
                    elif op == "ends_with":
                        clause = f"{field} ILIKE {'%s' if USE_POSTGRESQL else '?'}" if USE_POSTGRESQL else f"{field} LIKE {'%s' if USE_POSTGRESQL else '?'}"
                        value = f"%{value}" if USE_POSTGRESQL else f"%{value}"
                    elif op == "gt":
                        clause = f"{field} > {'%s' if USE_POSTGRESQL else '?'}"
                    elif op == "lt":
                        clause = f"{field} < {'%s' if USE_POSTGRESQL else '?'}"
                    elif op == "in":
                        placeholders = ", ".join(["%s" if USE_POSTGRESQL else "?" for _ in value.split(",")])
                        clause = f"{field} IN ({placeholders})"
                        params.extend([v.strip() for v in value.split(",")])
                        if negate:
                            clause = f"NOT ({clause})"
                        conditions.append(clause)
                        continue
                    else:
                        continue

                    if negate:
                        clause = f"NOT ({clause})"
                    conditions.append(clause)
                    params.append(value)

        # Search detections
        try:
            _build_conditions()
            where = " WHERE " + " AND ".join(conditions) if conditions else ""
            limit_ph = "%s" if USE_POSTGRESQL else "?"
            offset_ph = "%s" if USE_POSTGRESQL else "?"
            sort_dir = "DESC" if sort_order == "desc" else "ASC"
            sort_col = sort_by if sort_by in ("timestamp", "severity", "threat_type", "source_ip", "created_at") else "timestamp"
            query_d = f"SELECT * FROM threat_detections{where} ORDER BY {sort_col} {sort_dir} LIMIT {limit_ph} OFFSET {limit_ph}"
            query_params = list(params) + [limit, offset]

            with self._cursor() as cur:
                cur.execute(query_d, tuple(query_params))
                results["detections"] = [dict(row) for row in cur.fetchall()]

                # Total count
                count_q = f"SELECT COUNT(*) as cnt FROM threat_detections{where}"
                cur.execute(count_q, tuple(params))
                row = cur.fetchone()
                results["total"] += row['cnt'] if USE_POSTGRESQL else row[0]
        except Exception:
            pass

        # Search alerts
        try:
            _build_conditions()
            where = " WHERE " + " AND ".join(conditions) if conditions else ""
            limit_ph = "%s" if USE_POSTGRESQL else "?"
            offset_ph = "%s" if USE_POSTGRESQL else "?"
            query_a = f"SELECT * FROM alerts{where} ORDER BY created_at DESC LIMIT {limit_ph} OFFSET {offset_ph}"
            query_params = list(params) + [limit, offset]

            with self._cursor() as cur:
                cur.execute(query_a, tuple(query_params))
                results["alerts"] = [dict(row) for row in cur.fetchall()]

                count_q = f"SELECT COUNT(*) as cnt FROM alerts{where}"
                cur.execute(count_q, tuple(params))
                row = cur.fetchone()
                results["total"] += row['cnt'] if USE_POSTGRESQL else row[0]
        except Exception:
            pass

        # Search log_events
        try:
            _build_conditions()
            where = " WHERE " + " AND ".join(conditions) if conditions else ""
            limit_ph = "%s" if USE_POSTGRESQL else "?"
            offset_ph = "%s" if USE_POSTGRESQL else "?"
            query_e = f"SELECT * FROM log_events{where} ORDER BY timestamp DESC LIMIT {limit_ph} OFFSET {offset_ph}"
            query_params = list(params) + [limit, offset]

            with self._cursor() as cur:
                cur.execute(query_e, tuple(query_params))
                results["events"] = [dict(row) for row in cur.fetchall()]

                count_q = f"SELECT COUNT(*) as cnt FROM log_events{where}"
                cur.execute(count_q, tuple(params))
                row = cur.fetchone()
                results["total"] += row['cnt'] if USE_POSTGRESQL else row[0]
        except Exception:
            pass

        # Full-text search across all tables
        if query:
            q_lower = query.lower()
            results["detections"] = [d for d in results["detections"] if any(
                q_lower in str(d.get(k, "")).lower()
                for k in ("threat_type", "source_ip", "dest_ip", "description", "severity", "mitre_technique", "mitre_tactic")
            )]
            results["alerts"] = [a for a in results["alerts"] if any(
                q_lower in str(a.get(k, "")).lower()
                for k in ("alert_type", "title", "description", "source_ip", "severity", "mitre_technique")
            )]
            results["events"] = [e for e in results["events"] if any(
                q_lower in str(e.get(k, "")).lower()
                for k in ("event_type", "source_ip", "dest_ip", "hostname", "message", "source")
            )]

        # Build timeline from all results
        timeline = []
        for d in results["detections"][:100]:
            timeline.append({
                "timestamp": d.get("timestamp", d.get("created_at", d.get("detection_time", ""))),
                "type": "detection",
                "title": d.get("threat_type", "Unknown"),
                "severity": d.get("severity", "LOW"),
                "source_ip": d.get("source_ip", ""),
                "description": d.get("description", ""),
            })
        for a in results["alerts"][:100]:
            timeline.append({
                "timestamp": a.get("created_at", ""),
                "type": "alert",
                "title": a.get("title", "Unknown"),
                "severity": a.get("severity", "LOW"),
                "source_ip": a.get("source_ip", ""),
                "description": a.get("description", ""),
            })
        for e in results["events"][:100]:
            timeline.append({
                "timestamp": e.get("timestamp", ""),
                "type": "event",
                "title": e.get("event_type", "Unknown"),
                "severity": e.get("severity", "INFO"),
                "source_ip": e.get("source_ip", ""),
                "description": e.get("message", ""),
            })
        timeline.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        results["timeline"] = timeline[:200]

        # Field stats
        sev_counts = {}
        type_counts = {}
        ip_counts = {}
        for d in results["detections"]:
            sev = d.get("severity", "UNKNOWN")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            tt = d.get("threat_type", "unknown")
            type_counts[tt] = type_counts.get(tt, 0) + 1
            sip = d.get("source_ip", "")
            if sip:
                ip_counts[sip] = ip_counts.get(sip, 0) + 1
        for a in results["alerts"]:
            sev = a.get("severity", "UNKNOWN")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            at = a.get("alert_type", "unknown")
            type_counts[at] = type_counts.get(at, 0) + 1
            sip = a.get("source_ip", "")
            if sip:
                ip_counts[sip] = ip_counts.get(sip, 0) + 1

        results["field_stats"] = {
            "by_severity": sev_counts,
            "by_type": type_counts,
            "top_source_ips": sorted([{"ip": k, "count": v} for k, v in ip_counts.items()],
                                     key=lambda x: x["count"], reverse=True)[:20],
        }

        return results

    def save_hunt_search(self, user_id: str, name: str, query: str, filters: List[Dict]) -> str:
        """Save a threat hunt search for reuse."""
        search_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute(
                    "INSERT INTO hunt_saved_searches (id, user_id, name, query_text, filters_json, created_at) VALUES (%s,%s,%s,%s,%s,%s)",
                    (search_id, user_id, name, query, json.dumps(filters), now)
                )
            else:
                cur.execute(
                    "INSERT INTO hunt_saved_searches (id, user_id, name, query_text, filters_json, created_at) VALUES (?,?,?,?,?,?)",
                    (search_id, user_id, name, query, json.dumps(filters), now)
                )
        return search_id

    def get_hunt_searches(self, user_id: str, limit: int = 50) -> List[Dict]:
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("SELECT * FROM hunt_saved_searches WHERE user_id = %s ORDER BY created_at DESC LIMIT %s", (user_id, limit))
            else:
                cur.execute("SELECT * FROM hunt_saved_searches WHERE user_id = ? ORDER BY created_at DESC LIMIT ?", (user_id, limit))
            return [dict(row) for row in cur.fetchall()]

    def delete_hunt_search(self, search_id: str, user_id: str):
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("DELETE FROM hunt_saved_searches WHERE id = %s AND user_id = %s", (search_id, user_id))
            else:
                cur.execute("DELETE FROM hunt_saved_searches WHERE id = ? AND user_id = ?", (search_id, user_id))

    def bookmark_event(self, user_id: str, event_type: str, event_id: str, note: str = "") -> str:
        """Bookmark an event for later review."""
        bookmark_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute(
                    "INSERT INTO event_bookmarks (id, user_id, event_type, event_id, note, created_at) VALUES (%s,%s,%s,%s,%s,%s)",
                    (bookmark_id, user_id, event_type, event_id, note, now)
                )
            else:
                cur.execute(
                    "INSERT INTO event_bookmarks (id, user_id, event_type, event_id, note, created_at) VALUES (?,?,?,?,?,?)",
                    (bookmark_id, user_id, event_type, event_id, note, now)
                )
        return bookmark_id

    def get_bookmarks(self, user_id: str, limit: int = 100) -> List[Dict]:
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("SELECT * FROM event_bookmarks WHERE user_id = %s ORDER BY created_at DESC LIMIT %s", (user_id, limit))
            else:
                cur.execute("SELECT * FROM event_bookmarks WHERE user_id = ? ORDER BY created_at DESC LIMIT ?", (user_id, limit))
            return [dict(row) for row in cur.fetchall()]

    def remove_bookmark(self, bookmark_id: str, user_id: str):
        with self._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("DELETE FROM event_bookmarks WHERE id = %s AND user_id = %s", (bookmark_id, user_id))
            else:
                cur.execute("DELETE FROM event_bookmarks WHERE id = ? AND user_id = ?", (bookmark_id, user_id))

    def close(self):
        if self.conn:
            self.conn.close()


db = DatabaseManager()
