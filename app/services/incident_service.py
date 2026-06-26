"""
Incident Management Service for SentinelAI.
Full lifecycle: Open → Investigating → Contained → Resolved → Closed
With state machine validation, timeline tracking, notifications, and SLA management.
"""
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import json
import uuid

INCIDENT_STATES = ["open", "investigating", "contained", "resolved", "closed", "archived"]
VALID_TRANSITIONS = {
    "open": ["investigating", "closed", "archived"],
    "investigating": ["contained", "resolved", "closed", "archived"],
    "contained": ["investigating", "resolved", "closed", "archived"],
    "resolved": ["closed", "open", "archived"],
    "closed": ["open", "archived"],
    "archived": ["open"],
}
SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
SEVERITY_ESCALATION = {
    "LOW": "MEDIUM",
    "MEDIUM": "HIGH",
    "HIGH": "CRITICAL",
    "CRITICAL": "CRITICAL",
}
PRIORITY_FROM_SEVERITY = {
    "CRITICAL": "P1",
    "HIGH": "P2",
    "MEDIUM": "P3",
    "LOW": "P4",
}
CATEGORY_KEYWORDS = {
    "data_breach": ["exfiltration", "data_leak", "unauthorized_access", "credential_theft"],
    "malware": ["malware", "ransomware", "trojan", "virus", "backdoor"],
    "denial_of_service": ["dos", "ddos", "service_disruption"],
    "insider_threat": ["insider", "privilege_abuse", "data_theft"],
    "web_attack": ["xss", "sqli", "command_injection", "path_traversal"],
    "reconnaissance": ["port_scan", "recon", "enumeration"],
    "lateral_movement": ["lateral_movement", "pivot", "credential_spray"],
    "phishing": ["phishing", "spear_phishing", "social_engineering"],
}


class IncidentService:
    """Manage incident lifecycle with state machine, notifications, and SLA."""

    def __init__(self):
        self._db = None

    def _get_db(self):
        if self._db is None:
            from database import db
            self._db = db
        return self._db

    def can_transition(self, current_status: str, new_status: str) -> bool:
        return new_status in VALID_TRANSITIONS.get(current_status, [])

    def create_incident(self, title: str, severity: str, description: str = "",
                        alert_ids: list = None, affected_ips: list = None,
                        mitre_techniques: list = None, mitre_tactics: list = None,
                        recommendations: list = None, confidence: float = 0.0,
                        organization_id: str = None, assigned_to: str = None,
                        category: str = None, priority: str = None) -> str:
        db = self._get_db()
        severity = severity.upper() if severity else "LOW"
        if severity not in SEVERITY_ORDER:
            severity = "LOW"
        if not priority:
            priority = PRIORITY_FROM_SEVERITY.get(severity, "P4")
        if not category:
            category = self._guess_category(alert_ids or [], description)
        incident_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        timeline_entry = [{'event': 'Incident created', 'timestamp': now, 'severity': severity}]
        db.create_incident(
            title=title, severity=severity, description=description,
            alert_ids=alert_ids or [], timeline=timeline_entry,
            affected_ips=affected_ips or [], mitre_techniques=mitre_techniques or [],
            mitre_tactics=mitre_tactics or [], recommendations=recommendations or [],
            confidence=confidence)
        db.update_incident(incident_id,
            priority=priority, category=category,
            assigned_to=assigned_to, organization_id=organization_id)
        db.add_incident_timeline(incident_id, 'created', f'Incident created: {title}',
                                 source='incident_engine', confidence=confidence)
        self._notify(incident_id, 'Incident Created',
                     f'New {severity} incident: {title}', 'warning')
        return incident_id

    def transition(self, incident_id: str, new_status: str, user_id: str = None,
                   note: str = None, assigned_to: str = None) -> Dict[str, Any]:
        db = self._get_db()
        incident = db.get_incident(incident_id)
        if not incident:
            return {'success': False, 'error': 'Incident not found'}
        current = incident.get('status', 'open').lower()
        new_status = new_status.lower()
        if not self.can_transition(current, new_status):
            return {
                'success': False,
                'error': f"Cannot transition from '{current}' to '{new_status}'",
                'valid_transitions': VALID_TRANSITIONS.get(current, []),
            }
        db.update_incident_status(incident_id, new_status, assigned_to)
        change_note = note or f'Status changed: {current} → {new_status}'
        db.add_incident_note(incident_id, user_id=user_id, note=change_note)
        db.add_incident_timeline(incident_id, 'status_change', change_note,
                                 source=user_id or 'system')
        if new_status in ('resolved', 'closed'):
            now = datetime.now(timezone.utc).isoformat()
            ts_field = 'resolved_at' if new_status == 'resolved' else 'closed_at'
            db.update_incident(incident_id, **{ts_field: now})
        self._notify(incident_id, f'Incident {new_status.title()}',
                     f'Incident "{incident.get("title", "")}" → {new_status}', 'info')
        return {'success': True, 'previous': current, 'current': new_status}

    def update_fields(self, incident_id: str, **fields) -> Dict[str, Any]:
        db = self._get_db()
        incident = db.get_incident(incident_id)
        if not incident:
            return {'success': False, 'error': 'Incident not found'}
        changed = []
        for k, v in fields.items():
            if v is not None and k in ('title', 'severity', 'description', 'priority',
                                       'category', 'assigned_to', 'impact_summary',
                                       'root_cause', 'lessons_learned', 'sla_deadline'):
                old = incident.get(k)
                if old != v:
                    changed.append(f'{k}: "{old}" → "{v}"')
        if changed:
            db.update_incident(incident_id, **fields)
            db.add_incident_note(incident_id, user_id=fields.get('_user_id'),
                                 note=f'Fields updated: {"; ".join(changed)}')
            db.add_incident_timeline(incident_id, 'fields_updated',
                                     '; '.join(changed), source=fields.get('_user_id', 'system'))
        return {'success': True, 'changed': changed}

    def merge(self, primary_id: str, secondary_ids: List[str]) -> Dict[str, Any]:
        db = self._get_db()
        primary = db.get_incident(primary_id)
        if not primary:
            return {'success': False, 'error': 'Primary incident not found'}
        valid_secondary = [sid for sid in secondary_ids if db.get_incident(sid)]
        if not valid_secondary:
            return {'success': False, 'error': 'No valid secondary incidents found'}
        db.merge_incidents(primary_id, valid_secondary)
        db.add_incident_timeline(primary_id, 'merged',
                                 f'Merged {len(valid_secondary)} incidents: {", ".join(valid_secondary)}',
                                 source='system')
        return {'success': True, 'merged_count': len(valid_secondary), 'primary_id': primary_id}

    def add_evidence(self, incident_id: str, evidence_type: str, description: str = "",
                     file_name: str = "", source_type: str = "", source_id: str = "") -> Dict[str, Any]:
        db = self._get_db()
        incident = db.get_incident(incident_id)
        if not incident:
            return {'success': False, 'error': 'Incident not found'}
        evidence_id = db.add_incident_evidence(incident_id, evidence_type, description,
                                                file_name, source_type, source_id)
        db.add_incident_timeline(incident_id, 'evidence_added',
                                 f'Evidence added: {evidence_type} - {description}',
                                 evidence_id=evidence_id, source='analyst')
        return {'success': True, 'evidence_id': evidence_id}

    def add_timeline_entry(self, incident_id: str, event_type: str, description: str,
                           source: str = "", evidence_id: str = "", confidence: float = 1.0) -> Dict[str, Any]:
        db = self._get_db()
        incident = db.get_incident(incident_id)
        if not incident:
            return {'success': False, 'error': 'Incident not found'}
        entry_id = db.add_incident_timeline(incident_id, event_type, description,
                                             source, evidence_id, confidence)
        return {'success': True, 'entry_id': entry_id}

    def get_full_incident(self, incident_id: str) -> Optional[Dict]:
        db = self._get_db()
        incident = db.get_incident(incident_id)
        if not incident:
            return None
        incident['notes'] = db.get_incident_notes(incident_id)
        incident['evidence'] = db.get_incident_evidence(incident_id)
        incident['forensic_timeline'] = db.get_incident_timeline(incident_id)
        for key in ('alert_ids', 'timeline', 'affected_ips', 'mitre_techniques',
                     'mitre_tactics', 'recommendations'):
            val = incident.get(key, '[]')
            if isinstance(val, str):
                try:
                    incident[key] = json.loads(val)
                except Exception:
                    incident[key] = []
        incident['valid_transitions'] = VALID_TRANSITIONS.get(incident.get('status', 'open'), [])
        return incident

    def escalate(self, incident_id: str) -> Dict[str, Any]:
        db = self._get_db()
        incident = db.get_incident(incident_id)
        if not incident:
            return {'success': False, 'error': 'Incident not found'}
        current_severity = incident.get('severity', 'LOW').upper()
        new_severity = SEVERITY_ESCALATION.get(current_severity, current_severity)
        if new_severity == current_severity:
            return {'success': False, 'error': f'Already at maximum severity ({current_severity})'}
        db.update_incident(incident_id, severity=new_severity)
        db.add_incident_note(incident_id, user_id='system',
                             note=f'Severity escalated: {current_severity} → {new_severity}')
        db.add_incident_timeline(incident_id, 'escalated',
                                 f'Severity escalated from {current_severity} to {new_severity}',
                                 source='auto_engine')
        self._notify(incident_id, 'Incident Escalated',
                     f'Incident "{incident.get("title", "")}" escalated to {new_severity}', 'error')
        return {'success': True, 'previous_severity': current_severity, 'new_severity': new_severity}

    def get_stats(self, org_id: str = None) -> Dict[str, Any]:
        db = self._get_db()
        stats = db.get_incident_stats(org_id)
        mttt = db.get_incident_mttt()
        stats['mttt_minutes'] = mttt['mttt_minutes']
        stats['mttr_minutes'] = mttt['mttr_minutes']
        stats['resolved_count'] = mttt['resolved_count']
        return stats

    def _guess_category(self, alert_ids: list, description: str) -> str:
        text = ' '.join(str(a) for a in alert_ids) + ' ' + description
        text = text.lower()
        for cat, keywords in CATEGORY_KEYWORDS.items():
            if any(kw in text for kw in keywords):
                return cat
        return 'general'

    def _notify(self, incident_id: str, title: str, message: str, notif_type: str = "info"):
        try:
            db = self._get_db()
            db.create_incident_notification(user_id=None, incident_id=incident_id,
                                            title=title, message=message, notif_type=notif_type)
        except Exception:
            pass


incident_service = IncidentService()
