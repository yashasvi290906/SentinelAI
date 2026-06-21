import sqlite3
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).parent / "sentinelai.db"
logger = logging.getLogger("sentinelai.db")


class DatabaseManager:
    def __init__(self):
        try:
            self.conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.row_factory = sqlite3.Row
            self._create_tables()
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            raise

    def _create_tables(self):
        try:
            cur = self.conn.cursor()
            cur.executescript("""
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
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    report_id TEXT NOT NULL UNIQUE,
                    report_type TEXT NOT NULL,
                    generated_at TEXT NOT NULL,
                    metrics_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    name TEXT NOT NULL,
                    role TEXT DEFAULT 'analyst',
                    is_active BOOLEAN DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT
                );
            """)
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to create tables: {e}")

    def record_prediction(self, timestamp, sequence, prediction, confidence,
                          severity, severity_score, latency_ms, model="v2.1-deterministic"):
        try:
            cur = self.conn.cursor()
            cur.execute(
                "INSERT INTO predictions (timestamp, sequence, prediction, confidence, severity, severity_score, latency_ms, model) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (timestamp, sequence, prediction, confidence, severity, severity_score, latency_ms, model)
            )
            self.conn.commit()
            return cur.lastrowid
        except Exception as e:
            logger.error(f"Failed to record prediction: {e}")
            return None

    def record_comparison(self, timestamp, sequence, ml_prediction, markov_prediction,
                          agreement, agreement_score=0.0, latency_ms=0.0):
        try:
            cur = self.conn.cursor()
            cur.execute(
                "INSERT INTO comparisons (timestamp, sequence, ml_prediction, markov_prediction, agreement, agreement_score, latency_ms) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (timestamp, sequence, ml_prediction, markov_prediction, int(agreement), agreement_score, latency_ms)
            )
            self.conn.commit()
            return cur.lastrowid
        except Exception as e:
            logger.error(f"Failed to record comparison: {e}")
            return None

    def record_report(self, report_id, report_type, generated_at, metrics_json):
        try:
            if isinstance(metrics_json, (dict, list)):
                metrics_json = json.dumps(metrics_json)
            cur = self.conn.cursor()
            cur.execute(
                "INSERT INTO reports (report_id, report_type, generated_at, metrics_json) "
                "VALUES (?, ?, ?, ?)",
                (report_id, report_type, generated_at, metrics_json)
            )
            self.conn.commit()
            return cur.lastrowid
        except Exception as e:
            logger.error(f"Failed to record report: {e}")
            return None

    def get_predictions(self, limit=100):
        try:
            cur = self.conn.cursor()
            cur.execute("SELECT * FROM predictions ORDER BY id DESC LIMIT ?", (limit,))
            return [dict(row) for row in cur.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get predictions: {e}")
            return []

    def get_comparisons(self, limit=100):
        try:
            cur = self.conn.cursor()
            cur.execute("SELECT * FROM comparisons ORDER BY id DESC LIMIT ?", (limit,))
            return [dict(row) for row in cur.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get comparisons: {e}")
            return []

    def get_reports(self, limit=50):
        try:
            cur = self.conn.cursor()
            cur.execute("SELECT * FROM reports ORDER BY id DESC LIMIT ?", (limit,))
            return [dict(row) for row in cur.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get reports: {e}")
            return []

    def get_prediction_stats(self):
        try:
            cur = self.conn.cursor()
            cur.execute("SELECT COUNT(*) as total FROM predictions")
            total = cur.fetchone()["total"]
            if total == 0:
                return {
                    "total": 0,
                    "avg_confidence": 0.0,
                    "avg_latency_ms": 0.0,
                    "attack_distribution": {},
                    "severity_distribution": {},
                    "model_distribution": {},
                }
            cur.execute("SELECT AVG(confidence) as avg_confidence, AVG(latency_ms) as avg_latency FROM predictions")
            row = cur.fetchone()
            avg_confidence = round(row["avg_confidence"] or 0.0, 4)
            avg_latency = round(row["avg_latency"] or 0.0, 4)

            cur.execute("SELECT prediction, COUNT(*) as count FROM predictions GROUP BY prediction")
            attack_distribution = {r["prediction"]: r["count"] for r in cur.fetchall()}

            cur.execute("SELECT severity, COUNT(*) as count FROM predictions GROUP BY severity")
            severity_distribution = {r["severity"]: r["count"] for r in cur.fetchall()}

            cur.execute("SELECT model, COUNT(*) as count FROM predictions GROUP BY model")
            model_distribution = {r["model"]: r["count"] for r in cur.fetchall()}

            return {
                "total": total,
                "avg_confidence": avg_confidence,
                "avg_latency_ms": avg_latency,
                "attack_distribution": attack_distribution,
                "severity_distribution": severity_distribution,
                "model_distribution": model_distribution,
            }
        except Exception as e:
            logger.error(f"Failed to get prediction stats: {e}")
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
            cur = self.conn.cursor()
            cur.execute("SELECT COUNT(*) as total FROM comparisons")
            total = cur.fetchone()["total"]
            if total == 0:
                return {
                    "total": 0,
                    "agreement_rate": 0.0,
                    "avg_agreement_score": 0.0,
                    "avg_latency_ms": 0.0,
                }
            cur.execute("SELECT AVG(CAST(agreement AS REAL)) as agreement_rate, "
                         "AVG(agreement_score) as avg_agreement_score, "
                         "AVG(latency_ms) as avg_latency FROM comparisons")
            row = cur.fetchone()
            return {
                "total": total,
                "agreement_rate": round(row["agreement_rate"] or 0.0, 4),
                "avg_agreement_score": round(row["avg_agreement_score"] or 0.0, 4),
                "avg_latency_ms": round(row["avg_latency"] or 0.0, 4),
            }
        except Exception as e:
            logger.error(f"Failed to get comparison stats: {e}")
            return {
                "total": 0,
                "agreement_rate": 0.0,
                "avg_agreement_score": 0.0,
                "avg_latency_ms": 0.0,
            }

    def create_user(self, user_id: str, email: str, password_hash: str, name: str, role: str = "analyst", is_active: bool = True):
        """Create a new user."""
        try:
            cur = self.conn.cursor()
            cur.execute(
                "INSERT OR IGNORE INTO users (id, email, password_hash, name, role, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (user_id, email, password_hash, name, role, is_active, datetime.now().isoformat())
            )
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Error creating user: {e}", extra={"module": "database", "action": "error"})
            return False

    def get_user_by_email(self, email: str):
        """Get user by email."""
        try:
            cur = self.conn.cursor()
            cur.execute("SELECT * FROM users WHERE email = ?", (email,))
            return cur.fetchone()
        except Exception as e:
            logger.error(f"Error getting user: {e}", extra={"module": "database", "action": "error"})
            return None

    def update_user_password(self, user_id: str, password_hash: str):
        """Update user password."""
        try:
            cur = self.conn.cursor()
            cur.execute("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
                        (password_hash, datetime.now().isoformat(), user_id))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Error updating password: {e}", extra={"module": "database", "action": "error"})
            return False

    def close(self):
        try:
            self.conn.close()
        except Exception as e:
            logger.error(f"Failed to close database: {e}")


db = DatabaseManager()
