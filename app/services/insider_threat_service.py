"""
Insider Threat Detection (UEBA) Service for SentinelAI.
User and Entity Behavior Analytics to detect anomalous user activity
that may indicate insider threats, compromised accounts, or data exfiltration.
"""
import math
import json
import uuid
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Tuple

from database import db, USE_POSTGRESQL

logger = logging.getLogger(__name__)

# ── Detection Pattern Constants ──

UNUSUAL_LOGIN_HOURS = {
    "description": "Login outside normal business hours (7am-7pm)",
    "window_start": 7,
    "window_end": 19,
    "severity": "MEDIUM",
}

EXCESSIVE_DATA_ACCESS = {
    "description": "Excessive file access in a short time window",
    "threshold": 100,
    "window_seconds": 3600,
    "severity": "HIGH",
}

ANOMALOUS_NETWORK_VOLUME = {
    "description": "Unusual outbound data transfer volume",
    "threshold_mb": 1024,
    "window_seconds": 3600,
    "severity": "HIGH",
}

PRIVILEGE_ABUSE = {
    "description": "Excessive privilege escalation actions",
    "threshold": 10,
    "window_seconds": 86400,
    "severity": "CRITICAL",
}

MASS_FILE_ACCESS = {
    "description": "Mass file access in a short time window",
    "threshold": 500,
    "window_seconds": 3600,
    "severity": "CRITICAL",
}


class BehaviorProfiler:
    """Build and maintain user behavior baselines using running statistics."""

    def __init__(self):
        self._in_memory_baselines: Dict[str, Dict[str, Dict[str, float]]] = {}

    def _ensure_tables(self):
        with db._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS user_behavior_baselines (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        user_id VARCHAR(255) NOT NULL,
                        metric_type VARCHAR(100) NOT NULL,
                        running_mean REAL DEFAULT 0.0,
                        running_m2 REAL DEFAULT 0.0,
                        sample_count INTEGER DEFAULT 0,
                        min_value REAL DEFAULT 0.0,
                        max_value REAL DEFAULT 0.0,
                        last_updated TIMESTAMPTZ DEFAULT NOW(),
                        created_at TIMESTAMPTZ DEFAULT NOW(),
                        UNIQUE(user_id, metric_type)
                    )
                """)
            else:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS user_behavior_baselines (
                        id TEXT PRIMARY KEY,
                        user_id TEXT NOT NULL,
                        metric_type TEXT NOT NULL,
                        running_mean REAL DEFAULT 0.0,
                        running_m2 REAL DEFAULT 0.0,
                        sample_count INTEGER DEFAULT 0,
                        min_value REAL DEFAULT 0.0,
                        max_value REAL DEFAULT 0.0,
                        last_updated TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        UNIQUE(user_id, metric_type)
                    )
                """)

    def update_baseline(self, user_id: str, metric_type: str, observed_value: float) -> Dict[str, Any]:
        self._ensure_tables()
        now = datetime.now(timezone.utc).isoformat()

        existing = self.get_baseline(user_id, metric_type)

        if existing and existing["sample_count"] > 0:
            count = existing["sample_count"]
            old_mean = existing["running_mean"]
            old_m2 = existing["running_m2"]
            old_min = existing["min_value"]
            old_max = existing["max_value"]

            count += 1
            delta = observed_value - old_mean
            new_mean = old_mean + delta / count
            delta2 = observed_value - new_mean
            new_m2 = old_m2 + delta * delta2
            new_min = min(old_min, observed_value)
            new_max = max(old_max, observed_value)

            if USE_POSTGRESQL:
                with db._cursor() as cur:
                    cur.execute("""
                        UPDATE user_behavior_baselines
                        SET running_mean = %s, running_m2 = %s, sample_count = %s,
                            min_value = %s, max_value = %s, last_updated = %s
                        WHERE user_id = %s AND metric_type = %s
                    """, (new_mean, new_m2, count, new_min, new_max, now, user_id, metric_type))
            else:
                with db._cursor() as cur:
                    cur.execute("""
                        UPDATE user_behavior_baselines
                        SET running_mean = ?, running_m2 = ?, sample_count = ?,
                            min_value = ?, max_value = ?, last_updated = ?
                        WHERE user_id = ? AND metric_type = ?
                    """, (new_mean, new_m2, count, new_min, new_max, now, user_id, metric_type))

            std_dev = math.sqrt(new_m2 / count) if count > 1 else 0.0
            self._set_memory(user_id, metric_type, new_mean, std_dev, count)
            return {"mean": new_mean, "std_dev": std_dev, "sample_count": count}
        else:
            baseline_id = str(uuid.uuid4())
            if USE_POSTGRESQL:
                with db._cursor() as cur:
                    cur.execute("""
                        INSERT INTO user_behavior_baselines
                            (id, user_id, metric_type, running_mean, running_m2, sample_count,
                             min_value, max_value, last_updated, created_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (baseline_id, user_id, metric_type, observed_value, 0.0,
                          1, observed_value, observed_value, now, now))
            else:
                with db._cursor() as cur:
                    cur.execute("""
                        INSERT INTO user_behavior_baselines
                            (id, user_id, metric_type, running_mean, running_m2, sample_count,
                             min_value, max_value, last_updated, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (baseline_id, user_id, metric_type, observed_value, 0.0,
                          1, observed_value, observed_value, now, now))

            self._set_memory(user_id, metric_type, observed_value, 0.0, 1)
            return {"mean": observed_value, "std_dev": 0.0, "sample_count": 1}

    def get_baseline(self, user_id: str, metric_type: str) -> Optional[Dict[str, Any]]:
        mem = self._get_memory(user_id, metric_type)
        if mem:
            return mem

        self._ensure_tables()
        with db._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("""
                    SELECT running_mean, running_m2, sample_count, min_value, max_value
                    FROM user_behavior_baselines
                    WHERE user_id = %s AND metric_type = %s
                """, (user_id, metric_type))
            else:
                cur.execute("""
                    SELECT running_mean, running_m2, sample_count, min_value, max_value
                    FROM user_behavior_baselines
                    WHERE user_id = ? AND metric_type = ?
                """, (user_id, metric_type))
            row = cur.fetchone()
            if not row:
                return None

            if USE_POSTGRESQL:
                mean = float(row["running_mean"])
                m2 = float(row["running_m2"])
                count = int(row["sample_count"])
                min_val = float(row["min_value"])
                max_val = float(row["max_value"])
            else:
                mean = float(row[0])
                m2 = float(row[1])
                count = int(row[2])
                min_val = float(row[3])
                max_val = float(row[4])

            std_dev = math.sqrt(m2 / count) if count > 1 else 0.0
            result = {
                "running_mean": mean,
                "running_m2": m2,
                "sample_count": count,
                "min_value": min_val,
                "max_value": max_val,
                "std_dev": std_dev,
            }
            self._set_memory(user_id, metric_type, mean, std_dev, count)
            return result

    def get_all_baselines(self, user_id: str) -> Dict[str, Dict[str, Any]]:
        self._ensure_tables()
        result = {}
        with db._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("""
                    SELECT metric_type, running_mean, running_m2, sample_count, min_value, max_value
                    FROM user_behavior_baselines WHERE user_id = %s
                """, (user_id,))
            else:
                cur.execute("""
                    SELECT metric_type, running_mean, running_m2, sample_count, min_value, max_value
                    FROM user_behavior_baselines WHERE user_id = ?
                """, (user_id,))
            for row in cur.fetchall():
                if USE_POSTGRESQL:
                    mt = row["metric_type"]
                    mean = float(row["running_mean"])
                    m2 = float(row["running_m2"])
                    count = int(row["sample_count"])
                    min_val = float(row["min_value"])
                    max_val = float(row["max_value"])
                else:
                    mt = row[0]
                    mean = float(row[1])
                    m2 = float(row[2])
                    count = int(row[3])
                    min_val = float(row[4])
                    max_val = float(row[5])

                std_dev = math.sqrt(m2 / count) if count > 1 else 0.0
                result[mt] = {
                    "running_mean": mean,
                    "running_m2": m2,
                    "sample_count": count,
                    "min_value": min_val,
                    "max_value": max_val,
                    "std_dev": std_dev,
                }
        return result

    def _set_memory(self, user_id: str, metric_type: str, mean: float, std_dev: float, count: int):
        if user_id not in self._in_memory_baselines:
            self._in_memory_baselines[user_id] = {}
        self._in_memory_baselines[user_id][metric_type] = {
            "running_mean": mean,
            "std_dev": std_dev,
            "sample_count": count,
        }

    def _get_memory(self, user_id: str, metric_type: str) -> Optional[Dict[str, Any]]:
        user_baselines = self._in_memory_baselines.get(user_id, {})
        return user_baselines.get(metric_type)


class AnomalyDetector:
    """Detect behavioral anomalies using Z-score analysis against user baselines."""

    Z_SCORE_THRESHOLD = 3.0

    def __init__(self, profiler: BehaviorProfiler):
        self.profiler = profiler

    def _calculate_z_score(self, observed: float, baseline: Optional[Dict[str, Any]]) -> float:
        if not baseline or baseline["sample_count"] < 2:
            return 0.0
        mean = baseline["running_mean"]
        std_dev = baseline["std_dev"]
        if std_dev == 0:
            return 0.0 if observed == mean else float("inf")
        return (observed - mean) / std_dev

    def _store_anomaly(self, user_id: str, anomaly_type: str, z_score: float,
                       observed_value: float, baseline_mean: float, details: Dict[str, Any]):
        anomaly_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with db._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS user_anomalies (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        user_id VARCHAR(255) NOT NULL,
                        anomaly_type VARCHAR(100) NOT NULL,
                        z_score REAL NOT NULL,
                        observed_value REAL NOT NULL,
                        baseline_mean REAL NOT NULL,
                        severity VARCHAR(20) NOT NULL,
                        details JSONB DEFAULT '{}',
                        detected_at TIMESTAMPTZ DEFAULT NOW(),
                        status VARCHAR(20) DEFAULT 'open'
                    )
                """)
                cur.execute("""
                    INSERT INTO user_anomalies
                        (id, user_id, anomaly_type, z_score, observed_value, baseline_mean, severity, details, detected_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (anomaly_id, user_id, anomaly_type, z_score, observed_value,
                      baseline_mean, self._severity_from_zscore(z_score),
                      json.dumps(details), now))
            else:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS user_anomalies (
                        id TEXT PRIMARY KEY,
                        user_id TEXT NOT NULL,
                        anomaly_type TEXT NOT NULL,
                        z_score REAL NOT NULL,
                        observed_value REAL NOT NULL,
                        baseline_mean REAL NOT NULL,
                        severity TEXT NOT NULL,
                        details TEXT DEFAULT '{}',
                        detected_at TEXT NOT NULL,
                        status TEXT DEFAULT 'open'
                    )
                """)
                cur.execute("""
                    INSERT INTO user_anomalies
                        (id, user_id, anomaly_type, z_score, observed_value, baseline_mean, severity, details, detected_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (anomaly_id, user_id, anomaly_type, z_score, observed_value,
                      baseline_mean, self._severity_from_zscore(z_score),
                      json.dumps(details), now))
        return anomaly_id

    def _severity_from_zscore(self, z_score: float) -> str:
        abs_z = abs(z_score)
        if abs_z >= 5.0:
            return "CRITICAL"
        elif abs_z >= 4.0:
            return "HIGH"
        elif abs_z >= 3.0:
            return "MEDIUM"
        return "LOW"

    def check_login_anomaly(self, user_id: str, login_hour: float, source_ip: str) -> Optional[Dict[str, Any]]:
        baseline = self.profiler.get_baseline(user_id, "login_hour")
        z_score = self._calculate_z_score(login_hour, baseline)

        outside_hours = login_hour < UNUSUAL_LOGIN_HOURS["window_start"] or login_hour > UNUSUAL_LOGIN_HOURS["window_end"]

        is_anomaly = abs(z_score) > self.Z_SCORE_THRESHOLD or outside_hours

        if not is_anomaly:
            return None

        baseline_mean = baseline["running_mean"] if baseline else login_hour
        details = {
            "login_hour": login_hour,
            "source_ip": source_ip,
            "outside_business_hours": outside_hours,
            "window_description": f"{UNUSUAL_LOGIN_HOURS['window_start']}:00 - {UNUSUAL_LOGIN_HOURS['window_end']}:00",
        }
        anomaly_id = self._store_anomaly(user_id, "unusual_login", z_score, login_hour, baseline_mean, details)
        return {
            "anomaly_id": anomaly_id,
            "type": "unusual_login",
            "z_score": round(z_score, 3),
            "severity": self._severity_from_zscore(z_score),
            "details": details,
            "description": UNUSUAL_LOGIN_HOURS["description"],
        }

    def check_data_access_anomaly(self, user_id: str, access_count: int,
                                  time_window: int = 3600) -> Optional[Dict[str, Any]]:
        threshold = EXCESSIVE_DATA_ACCESS["threshold"]
        if time_window != EXCESSIVE_DATA_ACCESS["window_seconds"]:
            scale = time_window / EXCESSIVE_DATA_ACCESS["window_seconds"]
            threshold = int(threshold * scale)

        baseline = self.profiler.get_baseline(user_id, "data_access_count")
        z_score = self._calculate_z_score(access_count, baseline)

        exceeds_threshold = access_count > threshold
        is_anomaly = abs(z_score) > self.Z_SCORE_THRESHOLD or exceeds_threshold

        if not is_anomaly:
            return None

        baseline_mean = baseline["running_mean"] if baseline else access_count
        details = {
            "access_count": access_count,
            "time_window_seconds": time_window,
            "threshold": threshold,
            "exceeds_threshold": exceeds_threshold,
        }
        severity = "CRITICAL" if access_count > threshold * 2 else "HIGH"
        anomaly_id = self._store_anomaly(user_id, "excessive_data_access", z_score, access_count, baseline_mean, details)
        return {
            "anomaly_id": anomaly_id,
            "type": "excessive_data_access",
            "z_score": round(z_score, 3),
            "severity": severity,
            "details": details,
            "description": EXCESSIVE_DATA_ACCESS["description"],
        }

    def check_network_anomaly(self, user_id: str, upload_mb: float,
                              time_window: int = 3600) -> Optional[Dict[str, Any]]:
        threshold = ANOMALOUS_NETWORK_VOLUME["threshold_mb"]
        if time_window != ANOMALOUS_NETWORK_VOLUME["window_seconds"]:
            scale = time_window / ANOMALOUS_NETWORK_VOLUME["window_seconds"]
            threshold = threshold * scale

        baseline = self.profiler.get_baseline(user_id, "network_upload_mb")
        z_score = self._calculate_z_score(upload_mb, baseline)

        exceeds_threshold = upload_mb > threshold
        is_anomaly = abs(z_score) > self.Z_SCORE_THRESHOLD or exceeds_threshold

        if not is_anomaly:
            return None

        baseline_mean = baseline["running_mean"] if baseline else upload_mb
        details = {
            "upload_mb": round(upload_mb, 2),
            "time_window_seconds": time_window,
            "threshold_mb": round(threshold, 2),
            "exceeds_threshold": exceeds_threshold,
        }
        severity = "CRITICAL" if upload_mb > threshold * 2 else "HIGH"
        anomaly_id = self._store_anomaly(user_id, "anomalous_network", z_score, upload_mb, baseline_mean, details)
        return {
            "anomaly_id": anomaly_id,
            "type": "anomalous_network",
            "z_score": round(z_score, 3),
            "severity": severity,
            "details": details,
            "description": ANOMALOUS_NETWORK_VOLUME["description"],
        }

    def check_privilege_anomaly(self, user_id: str, privilege_actions: int) -> Optional[Dict[str, Any]]:
        threshold = PRIVILEGE_ABUSE["threshold"]

        baseline = self.profiler.get_baseline(user_id, "privilege_usage_count")
        z_score = self._calculate_z_score(privilege_actions, baseline)

        exceeds_threshold = privilege_actions > threshold
        is_anomaly = abs(z_score) > self.Z_SCORE_THRESHOLD or exceeds_threshold

        if not is_anomaly:
            return None

        baseline_mean = baseline["running_mean"] if baseline else privilege_actions
        details = {
            "privilege_actions": privilege_actions,
            "threshold": threshold,
            "exceeds_threshold": exceeds_threshold,
            "window_seconds": PRIVILEGE_ABUSE["window_seconds"],
        }
        severity = "CRITICAL" if privilege_actions > threshold * 2 else "HIGH"
        anomaly_id = self._store_anomaly(user_id, "privilege_abuse", z_score, privilege_actions, baseline_mean, details)
        return {
            "anomaly_id": anomaly_id,
            "type": "privilege_abuse",
            "z_score": round(z_score, 3),
            "severity": severity,
            "details": details,
            "description": PRIVILEGE_ABUSE["description"],
        }

    def check_file_access_anomaly(self, user_id: str, file_count: int,
                                  time_window: int = 3600) -> Optional[Dict[str, Any]]:
        threshold = MASS_FILE_ACCESS["threshold"]
        if time_window != MASS_FILE_ACCESS["window_seconds"]:
            scale = time_window / MASS_FILE_ACCESS["window_seconds"]
            threshold = int(threshold * scale)

        baseline = self.profiler.get_baseline(user_id, "file_access_count")
        z_score = self._calculate_z_score(file_count, baseline)

        exceeds_threshold = file_count > threshold
        is_anomaly = abs(z_score) > self.Z_SCORE_THRESHOLD or exceeds_threshold

        if not is_anomaly:
            return None

        baseline_mean = baseline["running_mean"] if baseline else file_count
        details = {
            "file_count": file_count,
            "time_window_seconds": time_window,
            "threshold": threshold,
            "exceeds_threshold": exceeds_threshold,
        }
        severity = "CRITICAL" if file_count > threshold * 2 else "HIGH"
        anomaly_id = self._store_anomaly(user_id, "mass_file_access", z_score, file_count, baseline_mean, details)
        return {
            "anomaly_id": anomaly_id,
            "type": "mass_file_access",
            "z_score": round(z_score, 3),
            "severity": severity,
            "details": details,
            "description": MASS_FILE_ACCESS["description"],
        }


class RiskScorer:
    """Calculate and aggregate user risk scores from detected anomalies."""

    METRIC_WEIGHTS = {
        "unusual_login": 15,
        "excessive_data_access": 25,
        "anomalous_network": 25,
        "privilege_abuse": 30,
        "mass_file_access": 20,
    }

    SEVERITY_MULTIPLIERS = {
        "CRITICAL": 1.5,
        "HIGH": 1.2,
        "MEDIUM": 1.0,
        "LOW": 0.5,
    }

    def calculate_user_risk(self, user_id: str) -> Dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        with db._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("""
                    SELECT anomaly_type, z_score, severity, detected_at
                    FROM user_anomalies
                    WHERE user_id = %s AND status = 'open'
                    ORDER BY detected_at DESC
                """, (user_id,))
            else:
                cur.execute("""
                    SELECT anomaly_type, z_score, severity, detected_at
                    FROM user_anomalies
                    WHERE user_id = ? AND status = 'open'
                    ORDER BY detected_at DESC
                """, (user_id,))
            rows = cur.fetchall()

        if not rows:
            return {
                "user_id": user_id,
                "risk_score": 0,
                "risk_level": "NONE",
                "anomaly_count": 0,
                "breakdown": {},
                "calculated_at": now,
            }

        breakdown = {}
        raw_score = 0.0

        for row in rows:
            if USE_POSTGRESQL:
                anomaly_type = row["anomaly_type"]
                z_score = float(row["z_score"])
                severity = row["severity"]
                detected_at = row["detected_at"]
            else:
                anomaly_type = row[0]
                z_score = float(row[1])
                severity = row[2]
                detected_at = row[3]

            base_weight = self.METRIC_WEIGHTS.get(anomaly_type, 10)
            severity_mult = self.SEVERITY_MULTIPLIERS.get(severity, 1.0)
            z_factor = min(abs(z_score) / 3.0, 2.0)
            contribution = base_weight * severity_mult * z_factor

            if anomaly_type not in breakdown:
                breakdown[anomaly_type] = {
                    "count": 0,
                    "max_z_score": 0.0,
                    "contribution": 0.0,
                    "severities": [],
                }

            breakdown[anomaly_type]["count"] += 1
            breakdown[anomaly_type]["max_z_score"] = max(
                breakdown[anomaly_type]["max_z_score"], abs(z_score)
            )
            breakdown[anomaly_type]["contribution"] += contribution
            if severity not in breakdown[anomaly_type]["severities"]:
                breakdown[anomaly_type]["severities"].append(severity)

            raw_score += contribution

        capped_score = min(raw_score, 100.0)
        risk_level = self.get_risk_level(capped_score)

        for key in breakdown:
            breakdown[key]["contribution"] = round(breakdown[key]["contribution"], 2)

        return {
            "user_id": user_id,
            "risk_score": round(capped_score, 2),
            "risk_level": risk_level,
            "anomaly_count": len(rows),
            "breakdown": breakdown,
            "calculated_at": now,
        }

    def get_risk_level(self, score: float) -> str:
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score > 0:
            return "LOW"
        return "NONE"

    def get_all_risk_scores(self) -> List[Dict[str, Any]]:
        with db._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("SELECT DISTINCT user_id FROM user_anomalies WHERE status = 'open'")
            else:
                cur.execute("SELECT DISTINCT user_id FROM user_anomalies WHERE status = 'open'")
            user_rows = cur.fetchall()

        results = []
        for row in user_rows:
            uid = row["user_id"] if USE_POSTGRESQL else row[0]
            risk = self.calculate_user_risk(uid)
            results.append(risk)

        results.sort(key=lambda x: x["risk_score"], reverse=True)
        return results


class InsiderThreatEngine:
    """Orchestrate insider threat detection across all users."""

    def __init__(self):
        self.profiler = BehaviorProfiler()
        self.anomaly_detector = AnomalyDetector(self.profiler)
        self.risk_scorer = RiskScorer()
        self._ensure_case_table()

    def _ensure_case_table(self):
        with db._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS insider_threat_cases (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        user_id VARCHAR(255) NOT NULL,
                        title VARCHAR(500) NOT NULL,
                        risk_level VARCHAR(20) NOT NULL,
                        status VARCHAR(20) DEFAULT 'open',
                        anomaly_ids JSONB DEFAULT '[]',
                        description TEXT DEFAULT '',
                        assigned_to VARCHAR(255),
                        created_at TIMESTAMPTZ DEFAULT NOW(),
                        updated_at TIMESTAMPTZ DEFAULT NOW(),
                        closed_at TIMESTAMPTZ
                    )
                """)
            else:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS insider_threat_cases (
                        id TEXT PRIMARY KEY,
                        user_id TEXT NOT NULL,
                        title TEXT NOT NULL,
                        risk_level TEXT NOT NULL,
                        status TEXT DEFAULT 'open',
                        anomaly_ids TEXT DEFAULT '[]',
                        description TEXT DEFAULT '',
                        assigned_to TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        closed_at TEXT
                    )
                """)

    def process_event(self, user_id: str, event_type: str, event_data: Dict[str, Any]) -> Dict[str, Any]:
        result = {
            "user_id": user_id,
            "event_type": event_type,
            "anomalies_detected": [],
            "baseline_updated": False,
            "risk_score": None,
        }

        try:
            if event_type == "login":
                login_hour = event_data.get("login_hour")
                source_ip = event_data.get("source_ip", "")
                if login_hour is not None:
                    self.profiler.update_baseline(user_id, "login_hour", float(login_hour))
                    result["baseline_updated"] = True
                    anomaly = self.anomaly_detector.check_login_anomaly(user_id, float(login_hour), source_ip)
                    if anomaly:
                        result["anomalies_detected"].append(anomaly)

            elif event_type == "data_access":
                access_count = event_data.get("access_count", 0)
                time_window = event_data.get("time_window", 3600)
                self.profiler.update_baseline(user_id, "data_access_count", float(access_count))
                result["baseline_updated"] = True
                anomaly = self.anomaly_detector.check_data_access_anomaly(user_id, access_count, time_window)
                if anomaly:
                    result["anomalies_detected"].append(anomaly)

            elif event_type == "network":
                upload_mb = event_data.get("upload_mb", 0.0)
                time_window = event_data.get("time_window", 3600)
                self.profiler.update_baseline(user_id, "network_upload_mb", float(upload_mb))
                result["baseline_updated"] = True
                anomaly = self.anomaly_detector.check_network_anomaly(user_id, float(upload_mb), time_window)
                if anomaly:
                    result["anomalies_detected"].append(anomaly)

            elif event_type == "privilege":
                privilege_actions = event_data.get("privilege_actions", 0)
                self.profiler.update_baseline(user_id, "privilege_usage_count", float(privilege_actions))
                result["baseline_updated"] = True
                anomaly = self.anomaly_detector.check_privilege_anomaly(user_id, privilege_actions)
                if anomaly:
                    result["anomalies_detected"].append(anomaly)

            elif event_type == "file_access":
                file_count = event_data.get("file_count", 0)
                time_window = event_data.get("time_window", 3600)
                self.profiler.update_baseline(user_id, "file_access_count", float(file_count))
                result["baseline_updated"] = True
                anomaly = self.anomaly_detector.check_file_access_anomaly(user_id, file_count, time_window)
                if anomaly:
                    result["anomalies_detected"].append(anomaly)

            elif event_type == "login_count":
                login_count = event_data.get("login_count", 0)
                self.profiler.update_baseline(user_id, "login_count_daily", float(login_count))
                result["baseline_updated"] = True

            else:
                logger.warning("Unknown event_type '%s' for user %s", event_type, user_id)
                return result

            if result["anomalies_detected"]:
                risk_info = self.risk_scorer.calculate_user_risk(user_id)
                result["risk_score"] = risk_info

                if risk_info["risk_level"] in ("CRITICAL", "HIGH"):
                    anomaly_ids = [a["anomaly_id"] for a in result["anomalies_detected"]]
                    existing_case = self._get_open_case(user_id)
                    if existing_case:
                        self._update_case_anomalies(existing_case["id"], anomaly_ids, risk_info["risk_level"])
                    else:
                        self.create_case(user_id, anomaly_ids, risk_info["risk_level"])

        except Exception as e:
            logger.error("Error processing event for user %s: %s", user_id, str(e), exc_info=True)

        return result

    def _get_open_case(self, user_id: str) -> Optional[Dict[str, Any]]:
        with db._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("""
                    SELECT id, user_id, title, risk_level, status, anomaly_ids, created_at
                    FROM insider_threat_cases
                    WHERE user_id = %s AND status = 'open'
                    ORDER BY created_at DESC LIMIT 1
                """, (user_id,))
            else:
                cur.execute("""
                    SELECT id, user_id, title, risk_level, status, anomaly_ids, created_at
                    FROM insider_threat_cases
                    WHERE user_id = ? AND status = 'open'
                    ORDER BY created_at DESC LIMIT 1
                """, (user_id,))
            row = cur.fetchone()
            if not row:
                return None
            if USE_POSTGRESQL:
                return dict(row)
            return {
                "id": row[0], "user_id": row[1], "title": row[2],
                "risk_level": row[3], "status": row[4],
                "anomaly_ids": row[5], "created_at": row[6],
            }

    def _update_case_anomalies(self, case_id: str, new_anomaly_ids: List[str], risk_level: str):
        now = datetime.now(timezone.utc).isoformat()
        with db._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("SELECT anomaly_ids FROM insider_threat_cases WHERE id = %s", (case_id,))
            else:
                cur.execute("SELECT anomaly_ids FROM insider_threat_cases WHERE id = ?", (case_id,))
            row = cur.fetchone()
            if not row:
                return
            existing = row["anomaly_ids"] if USE_POSTGRESQL else row[0]
            if isinstance(existing, str):
                try:
                    existing = json.loads(existing)
                except (json.JSONDecodeError, TypeError):
                    existing = []
            merged = list(set(existing + new_anomaly_ids))
            if USE_POSTGRESQL:
                cur.execute("""
                    UPDATE insider_threat_cases
                    SET anomaly_ids = %s, risk_level = %s, updated_at = %s
                    WHERE id = %s
                """, (json.dumps(merged), risk_level, now, case_id))
            else:
                cur.execute("""
                    UPDATE insider_threat_cases
                    SET anomaly_ids = ?, risk_level = ?, updated_at = ?
                    WHERE id = ?
                """, (json.dumps(merged), risk_level, now, case_id))

    def detect_all(self) -> Dict[str, Any]:
        results = {"users_analyzed": 0, "anomalies_found": 0, "cases_created": 0, "risk_scores": []}

        with db._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("""
                    SELECT DISTINCT user_id FROM user_behavior_baselines
                    UNION
                    SELECT DISTINCT user_id FROM user_anomalies
                """)
            else:
                cur.execute("""
                    SELECT DISTINCT user_id FROM user_behavior_baselines
                    UNION
                    SELECT DISTINCT user_id FROM user_anomalies
                """)
            user_rows = cur.fetchall()

        user_ids = set()
        for row in user_rows:
            uid = row["user_id"] if USE_POSTGRESQL else row[0]
            if uid:
                user_ids.add(uid)

        for user_id in user_ids:
            results["users_analyzed"] += 1

            recent_anomalies = self._get_recent_anomalies(user_id, hours=24)
            for anomaly in recent_anomalies:
                if anomaly["type"] == "unusual_login":
                    details = anomaly.get("details", {})
                    self.profiler.update_baseline(user_id, "login_hour", float(details.get("login_hour", 12)))
                elif anomaly["type"] == "excessive_data_access":
                    details = anomaly.get("details", {})
                    self.profiler.update_baseline(user_id, "data_access_count", float(details.get("access_count", 0)))
                elif anomaly["type"] == "anomalous_network":
                    details = anomaly.get("details", {})
                    self.profiler.update_baseline(user_id, "network_upload_mb", float(details.get("upload_mb", 0)))
                elif anomaly["type"] == "privilege_abuse":
                    details = anomaly.get("details", {})
                    self.profiler.update_baseline(user_id, "privilege_usage_count", float(details.get("privilege_actions", 0)))
                elif anomaly["type"] == "mass_file_access":
                    details = anomaly.get("details", {})
                    self.profiler.update_baseline(user_id, "file_access_count", float(details.get("file_count", 0)))

            risk_info = self.risk_scorer.calculate_user_risk(user_id)
            results["risk_scores"].append(risk_info)
            results["anomalies_found"] += risk_info["anomaly_count"]

            if risk_info["risk_level"] in ("CRITICAL", "HIGH") and risk_info["anomaly_count"] > 0:
                existing = self._get_open_case(user_id)
                if not existing:
                    with db._cursor() as cur:
                        if USE_POSTGRESQL:
                            cur.execute("""
                                SELECT id FROM user_anomalies
                                WHERE user_id = %s AND status = 'open'
                                ORDER BY detected_at DESC LIMIT 5
                            """, (user_id,))
                        else:
                            cur.execute("""
                                SELECT id FROM user_anomalies
                                WHERE user_id = ? AND status = 'open'
                                ORDER BY detected_at DESC LIMIT 5
                            """, (user_id,))
                        anomaly_rows = cur.fetchall()

                    anomaly_ids = [r["id"] if USE_POSTGRESQL else r[0] for r in anomaly_rows]
                    if anomaly_ids:
                        self.create_case(user_id, anomaly_ids, risk_info["risk_level"])
                        results["cases_created"] += 1

        results["risk_scores"].sort(key=lambda x: x["risk_score"], reverse=True)
        return results

    def _get_recent_anomalies(self, user_id: str, hours: int = 24) -> List[Dict[str, Any]]:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        with db._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("""
                    SELECT anomaly_type, z_score, severity, details
                    FROM user_anomalies
                    WHERE user_id = %s AND detected_at >= %s
                    ORDER BY detected_at DESC
                """, (user_id, cutoff))
            else:
                cur.execute("""
                    SELECT anomaly_type, z_score, severity, details
                    FROM user_anomalies
                    WHERE user_id = ? AND detected_at >= ?
                    ORDER BY detected_at DESC
                """, (user_id, cutoff))
            rows = cur.fetchall()

        results = []
        for row in rows:
            if USE_POSTGRESQL:
                at = row["anomaly_type"]
                zs = float(row["z_score"])
                sev = row["severity"]
                det = row["details"]
            else:
                at = row[0]
                zs = float(row[1])
                sev = row[2]
                det = row[3]

            if isinstance(det, str):
                try:
                    det = json.loads(det)
                except (json.JSONDecodeError, TypeError):
                    det = {}

            results.append({
                "type": at,
                "z_score": zs,
                "severity": sev,
                "details": det,
            })
        return results

    def create_case(self, user_id: str, anomaly_ids: List[str], risk_level: str) -> Dict[str, Any]:
        case_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        title = f"Insider Threat Investigation - {risk_level} Risk User {user_id[:8]}..."
        description = (
            f"Automated insider threat case created for user {user_id}. "
            f"Risk level: {risk_level}. "
            f"Associated anomalies: {len(anomaly_ids)}. "
            f"Requires investigation and review of user behavioral patterns."
        )

        with db._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("""
                    INSERT INTO insider_threat_cases
                        (id, user_id, title, risk_level, status, anomaly_ids, description, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (case_id, user_id, title, risk_level, "open",
                      json.dumps(anomaly_ids), description, now, now))
            else:
                cur.execute("""
                    INSERT INTO insider_threat_cases
                        (id, user_id, title, risk_level, status, anomaly_ids, description, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (case_id, user_id, title, risk_level, "open",
                      json.dumps(anomaly_ids), description, now, now))

        logger.info("Created insider threat case %s for user %s (risk: %s)", case_id, user_id, risk_level)
        return {
            "case_id": case_id,
            "user_id": user_id,
            "title": title,
            "risk_level": risk_level,
            "anomaly_ids": anomaly_ids,
            "description": description,
            "created_at": now,
        }

    def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        with db._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("SELECT * FROM insider_threat_cases WHERE id = %s", (case_id,))
            else:
                cur.execute("SELECT * FROM insider_threat_cases WHERE id = ?", (case_id,))
            row = cur.fetchone()
            if not row:
                return None
            return dict(row) if USE_POSTGRESQL else {
                "id": row[0], "user_id": row[1], "title": row[2],
                "risk_level": row[3], "status": row[4], "anomaly_ids": row[5],
                "description": row[6], "assigned_to": row[7],
                "created_at": row[8], "updated_at": row[9], "closed_at": row[10],
            }

    def get_cases(self, status: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        with db._cursor() as cur:
            if status:
                if USE_POSTGRESQL:
                    cur.execute("""
                        SELECT * FROM insider_threat_cases WHERE status = %s
                        ORDER BY created_at DESC LIMIT %s
                    """, (status, limit))
                else:
                    cur.execute("""
                        SELECT * FROM insider_threat_cases WHERE status = ?
                        ORDER BY created_at DESC LIMIT ?
                    """, (status, limit))
            else:
                if USE_POSTGRESQL:
                    cur.execute("""
                        SELECT * FROM insider_threat_cases
                        ORDER BY created_at DESC LIMIT %s
                    """, (limit,))
                else:
                    cur.execute("""
                        SELECT * FROM insider_threat_cases
                        ORDER BY created_at DESC LIMIT ?
                    """, (limit,))
            rows = cur.fetchall()
            if USE_POSTGRESQL:
                return [dict(row) for row in rows]
            results = []
            for row in rows:
                results.append({
                    "id": row[0], "user_id": row[1], "title": row[2],
                    "risk_level": row[3], "status": row[4], "anomaly_ids": row[5],
                    "description": row[6], "assigned_to": row[7],
                    "created_at": row[8], "updated_at": row[9], "closed_at": row[10],
                })
            return results

    def close_case(self, case_id: str, resolution_notes: str = ""):
        now = datetime.now(timezone.utc).isoformat()
        with db._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("""
                    UPDATE insider_threat_cases
                    SET status = 'closed', closed_at = %s, updated_at = %s
                    WHERE id = %s
                """, (now, now, case_id))
            else:
                cur.execute("""
                    UPDATE insider_threat_cases
                    SET status = 'closed', closed_at = ?, updated_at = ?
                    WHERE id = ?
                """, (now, now, case_id))
        logger.info("Closed insider threat case %s", case_id)

    def get_user_anomalies(self, user_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        with db._cursor() as cur:
            if USE_POSTGRESQL:
                cur.execute("""
                    SELECT * FROM user_anomalies
                    WHERE user_id = %s
                    ORDER BY detected_at DESC LIMIT %s
                """, (user_id, limit))
            else:
                cur.execute("""
                    SELECT * FROM user_anomalies
                    WHERE user_id = ?
                    ORDER BY detected_at DESC LIMIT ?
                """, (user_id, limit))
            rows = cur.fetchall()
            if USE_POSTGRESQL:
                return [dict(row) for row in rows]
            results = []
            for row in rows:
                results.append({
                    "id": row[0], "user_id": row[1], "anomaly_type": row[2],
                    "z_score": row[3], "observed_value": row[4],
                    "baseline_mean": row[5], "severity": row[6],
                    "details": row[7], "detected_at": row[8], "status": row[9],
                })
            return results


insider_threat_engine = InsiderThreatEngine()
