"""
Incident Management Service for SentinelAI.
Manages incident lifecycle: creation, assignment, investigation, resolution.
"""
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import uuid


class IncidentService:
    """Manage incidents in the database."""

    def create_incident_from_correlation(self, db, incident_data: Dict) -> str:
        """Create an incident from correlation engine output."""
        incident_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        with db._cursor() as cur:
            if hasattr(db, '_init_postgresql'):
                cur.execute("""
                    INSERT INTO incidents (id, title, severity, status, confidence, description,
                        alert_ids, timeline, affected_ips, mitre_techniques, mitre_tactics,
                        recommendations, created_at, updated_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """, (
                    incident_id, incident_data.get('title', ''),
                    incident_data.get('severity', 'LOW'), 'open',
                    incident_data.get('confidence', 0.0),
                    incident_data.get('description', ''),
                    str(incident_data.get('alert_ids', [])),
                    str(incident_data.get('timeline', [])),
                    str(incident_data.get('affected_ips', [])),
                    str(incident_data.get('mitre_techniques', [])),
                    str(incident_data.get('mitre_tactics', [])),
                    str(incident_data.get('recommendations', [])),
                    now, now,
                ))
            else:
                cur.execute("""
                    INSERT INTO incidents (id, title, severity, status, confidence, description,
                        alert_ids, timeline, affected_ips, mitre_techniques, mitre_tactics,
                        recommendations, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    incident_id, incident_data.get('title', ''),
                    incident_data.get('severity', 'LOW'), 'open',
                    incident_data.get('confidence', 0.0),
                    incident_data.get('description', ''),
                    str(incident_data.get('alert_ids', [])),
                    str(incident_data.get('timeline', [])),
                    str(incident_data.get('affected_ips', [])),
                    str(incident_data.get('mitre_techniques', [])),
                    str(incident_data.get('mitre_tactics', [])),
                    str(incident_data.get('recommendations', [])),
                    now, now,
                ))

        return incident_id

    def get_incidents(self, db, status: str = None, severity: str = None, limit: int = 100) -> List[Dict]:
        with db._cursor() as cur:
            conditions = []
            params = []
            if status:
                conditions.append("status = ?" if not hasattr(db, '_init_postgresql') else "status = %s")
                params.append(status)
            if severity:
                conditions.append("severity = ?" if not hasattr(db, '_init_postgresql') else "severity = %s")
                params.append(severity)

            where = " WHERE " + " AND ".join(conditions) if conditions else ""
            limit_q = "?" if not hasattr(db, '_init_postgresql') else "%s"
            query = f"SELECT * FROM incidents{where} ORDER BY created_at DESC LIMIT {limit_q}"
            params.append(limit)

            cur.execute(query, tuple(params))
            return [dict(row) for row in cur.fetchall()]

    def get_incident(self, db, incident_id: str) -> Optional[Dict]:
        with db._cursor() as cur:
            if hasattr(db, '_init_postgresql'):
                cur.execute("SELECT * FROM incidents WHERE id = %s", (incident_id,))
            else:
                cur.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def update_incident_status(self, db, incident_id: str, status: str, assigned_to: str = None):
        now = datetime.now(timezone.utc).isoformat()
        with db._cursor() as cur:
            if hasattr(db, '_init_postgresql'):
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

    def add_incident_note(self, db, incident_id: str, user_id: str, note: str) -> str:
        note_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with db._cursor() as cur:
            if hasattr(db, '_init_postgresql'):
                cur.execute("INSERT INTO incident_notes (id, incident_id, user_id, note, created_at) VALUES (%s,%s,%s,%s,%s)",
                            (note_id, incident_id, user_id, note, now))
            else:
                cur.execute("INSERT INTO incident_notes (id, incident_id, user_id, note, created_at) VALUES (?,?,?,?,?)",
                            (note_id, incident_id, user_id, note, now))
        return note_id

    def get_incident_notes(self, db, incident_id: str) -> List[Dict]:
        with db._cursor() as cur:
            if hasattr(db, '_init_postgresql'):
                cur.execute("SELECT * FROM incident_notes WHERE incident_id = %s ORDER BY created_at", (incident_id,))
            else:
                cur.execute("SELECT * FROM incident_notes WHERE incident_id = ? ORDER BY created_at", (incident_id,))
            return [dict(row) for row in cur.fetchall()]

    def get_incident_stats(self, db) -> Dict[str, Any]:
        with db._cursor() as cur:
            cur.execute("SELECT COUNT(*) as total FROM incidents")
            row = cur.fetchone()
            total = row['total'] if hasattr(db, '_init_postgresql') else row[0]

            cur.execute("SELECT severity, COUNT(*) as count FROM incidents GROUP BY severity")
            by_severity = {row['severity']: row['count'] if hasattr(db, '_init_postgresql') else row[1] for row in cur.fetchall()}

            cur.execute("SELECT status, COUNT(*) as count FROM incidents GROUP BY status")
            by_status = {row['status']: row['count'] if hasattr(db, '_init_postgresql') else row[1] for row in cur.fetchall()}

            return {'total': total, 'by_severity': by_severity, 'by_status': by_status}


# Singleton
incident_service = IncidentService()
