"""
Forensic Chain of Custody Service for SentinelAI.
Manages evidence collection, chain of custody logging, timeline reconstruction,
and evidence integrity verification for incident investigations.
"""
import hashlib
import json
import uuid
import logging
import os
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

from database import db

logger = logging.getLogger(__name__)


class EvidenceCollector:
    """Collect and register forensic evidence with SHA-256 hashing."""

    def __init__(self):
        self._ensure_tables()

    def _ensure_tables(self):
        """Create forensic tables if they do not exist."""
        with db._cursor() as cur:
            if db.use_postgresql:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS evidence (
                        id TEXT PRIMARY KEY,
                        evidence_type TEXT NOT NULL,
                        source_type TEXT NOT NULL,
                        source_id TEXT DEFAULT '',
                        description TEXT DEFAULT '',
                        sha256_hash TEXT NOT NULL,
                        file_path TEXT DEFAULT '',
                        file_size INTEGER DEFAULT 0,
                        metadata TEXT DEFAULT '{}',
                        collected_at TEXT NOT NULL,
                        status TEXT DEFAULT 'collected'
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS evidence_chain (
                        id TEXT PRIMARY KEY,
                        evidence_id TEXT NOT NULL,
                        sequence_num INTEGER NOT NULL,
                        action TEXT NOT NULL,
                        actor TEXT NOT NULL,
                        details TEXT DEFAULT '',
                        prev_hash TEXT DEFAULT '',
                        entry_hash TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        FOREIGN KEY (evidence_id) REFERENCES evidence(id)
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS forensic_timeline (
                        id TEXT PRIMARY KEY,
                        incident_id TEXT NOT NULL,
                        event_time TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        source TEXT DEFAULT '',
                        description TEXT DEFAULT '',
                        evidence_id TEXT DEFAULT '',
                        metadata TEXT DEFAULT '{}',
                        created_at TEXT NOT NULL
                    )
                """)
                cur.execute("""
                    CREATE INDEX IF NOT EXISTS idx_evidence_chain_evidence
                    ON evidence_chain(evidence_id)
                """)
                cur.execute("""
                    CREATE INDEX IF NOT EXISTS idx_forensic_timeline_incident
                    ON forensic_timeline(incident_id)
                """)
            else:
                cur.executescript("""
                    CREATE TABLE IF NOT EXISTS evidence (
                        id TEXT PRIMARY KEY,
                        evidence_type TEXT NOT NULL,
                        source_type TEXT NOT NULL,
                        source_id TEXT DEFAULT '',
                        description TEXT DEFAULT '',
                        sha256_hash TEXT NOT NULL,
                        file_path TEXT DEFAULT '',
                        file_size INTEGER DEFAULT 0,
                        metadata TEXT DEFAULT '{}',
                        collected_at TEXT NOT NULL,
                        status TEXT DEFAULT 'collected'
                    );

                    CREATE TABLE IF NOT EXISTS evidence_chain (
                        id TEXT PRIMARY KEY,
                        evidence_id TEXT NOT NULL,
                        sequence_num INTEGER NOT NULL,
                        action TEXT NOT NULL,
                        actor TEXT NOT NULL,
                        details TEXT DEFAULT '',
                        prev_hash TEXT DEFAULT '',
                        entry_hash TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        FOREIGN KEY (evidence_id) REFERENCES evidence(id)
                    );

                    CREATE TABLE IF NOT EXISTS forensic_timeline (
                        id TEXT PRIMARY KEY,
                        incident_id TEXT NOT NULL,
                        event_time TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        source TEXT DEFAULT '',
                        description TEXT DEFAULT '',
                        evidence_id TEXT DEFAULT '',
                        metadata TEXT DEFAULT '{}',
                        created_at TEXT NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS idx_evidence_chain_evidence ON evidence_chain(evidence_id);
                    CREATE INDEX IF NOT EXISTS idx_forensic_timeline_incident ON forensic_timeline(incident_id);
                """)

    @staticmethod
    def _compute_hash(data: str) -> str:
        """Compute SHA-256 hash of string data."""
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    @staticmethod
    def _compute_file_hash(file_path: str) -> str:
        """Compute SHA-256 hash of a file's contents."""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _store_evidence(self, evidence_id: str, evidence_type: str, source_type: str,
                        source_id: str, description: str, sha256_hash: str,
                        file_path: str = '', file_size: int = 0,
                        metadata: Optional[Dict] = None) -> str:
        """Internal method to persist evidence record."""
        now = datetime.now(timezone.utc).isoformat()
        with db._cursor() as cur:
            if db.use_postgresql:
                cur.execute("""
                    INSERT INTO evidence (id, evidence_type, source_type, source_id, description,
                        sha256_hash, file_path, file_size, metadata, collected_at, status)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """, (evidence_id, evidence_type, source_type, source_id, description,
                      sha256_hash, file_path, file_size, json.dumps(metadata or {}), now, 'collected'))
            else:
                cur.execute("""
                    INSERT INTO evidence (id, evidence_type, source_type, source_id, description,
                        sha256_hash, file_path, file_size, metadata, collected_at, status)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                """, (evidence_id, evidence_type, source_type, source_id, description,
                      sha256_hash, file_path, file_size, json.dumps(metadata or {}), now, 'collected'))
        return evidence_id

    def _get_evidence(self, evidence_id: str) -> Optional[Dict]:
        """Retrieve an evidence record by ID."""
        with db._cursor() as cur:
            if db.use_postgresql:
                cur.execute("SELECT * FROM evidence WHERE id = %s", (evidence_id,))
            else:
                cur.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def collect_from_alert(self, alert_data: Dict[str, Any]) -> str:
        """
        Snapshot alert context as forensic evidence.

        Args:
            alert_data: Dictionary containing alert information (id, type, severity,
                       title, description, source_ip, dest_ip, etc.)

        Returns:
            Evidence ID string.
        """
        alert_id = alert_data.get('id', '')
        evidence_id = str(uuid.uuid4())

        snapshot = {
            'alert_id': alert_id,
            'alert_type': alert_data.get('alert_type', ''),
            'severity': alert_data.get('severity', ''),
            'title': alert_data.get('title', ''),
            'description': alert_data.get('description', ''),
            'source_ip': alert_data.get('source_ip', ''),
            'destination_ip': alert_data.get('destination_ip', ''),
            'source_port': alert_data.get('source_port', 0),
            'destination_port': alert_data.get('destination_port', 0),
            'protocol': alert_data.get('protocol', ''),
            'mitre_technique': alert_data.get('mitre_technique', ''),
            'mitre_tactic': alert_data.get('mitre_tactic', ''),
            'evidence_raw': alert_data.get('evidence', []),
            'recommendations': alert_data.get('recommendations', []),
            'status': alert_data.get('status', ''),
            'created_at': alert_data.get('created_at', ''),
            'snapshot_time': datetime.now(timezone.utc).isoformat(),
        }

        data_str = json.dumps(snapshot, sort_keys=True, default=str)
        sha256_hash = self._compute_hash(data_str)

        self._store_evidence(
            evidence_id=evidence_id,
            evidence_type='alert_snapshot',
            source_type='alert',
            source_id=alert_id,
            description=f"Alert snapshot for: {alert_data.get('title', alert_id)}",
            sha256_hash=sha256_hash,
            metadata=snapshot,
        )

        logger.info("Collected alert evidence %s for alert %s", evidence_id, alert_id)
        return evidence_id

    def collect_from_incident(self, incident_data: Dict[str, Any]) -> str:
        """
        Collect incident-related evidence by snapshotting the full incident state.

        Args:
            incident_data: Dictionary containing incident information.

        Returns:
            Evidence ID string.
        """
        incident_id = incident_data.get('id', '')
        evidence_id = str(uuid.uuid4())

        snapshot = {
            'incident_id': incident_id,
            'title': incident_data.get('title', ''),
            'severity': incident_data.get('severity', ''),
            'status': incident_data.get('status', ''),
            'confidence': incident_data.get('confidence', 0.0),
            'description': incident_data.get('description', ''),
            'alert_ids': incident_data.get('alert_ids', []),
            'timeline': incident_data.get('timeline', []),
            'affected_ips': incident_data.get('affected_ips', []),
            'mitre_techniques': incident_data.get('mitre_techniques', []),
            'mitre_tactics': incident_data.get('mitre_tactics', []),
            'recommendations': incident_data.get('recommendations', []),
            'assigned_to': incident_data.get('assigned_to', ''),
            'created_at': incident_data.get('created_at', ''),
            'updated_at': incident_data.get('updated_at', ''),
            'snapshot_time': datetime.now(timezone.utc).isoformat(),
        }

        data_str = json.dumps(snapshot, sort_keys=True, default=str)
        sha256_hash = self._compute_hash(data_str)

        self._store_evidence(
            evidence_id=evidence_id,
            evidence_type='incident_snapshot',
            source_type='incident',
            source_id=incident_id,
            description=f"Incident state snapshot for: {incident_data.get('title', incident_id)}",
            sha256_hash=sha256_hash,
            metadata=snapshot,
        )

        logger.info("Collected incident evidence %s for incident %s", evidence_id, incident_id)
        return evidence_id

    def collect_file(self, file_path: str, description: str) -> str:
        """
        Hash and register a file as forensic evidence.

        Args:
            file_path: Absolute path to the file.
            description: Human-readable description of the file's relevance.

        Returns:
            Evidence ID string.

        Raises:
            FileNotFoundError: If the file does not exist.
        """
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Evidence file not found: {file_path}")

        evidence_id = str(uuid.uuid4())
        file_size = os.path.getsize(file_path)
        sha256_hash = self._compute_file_hash(file_path)

        metadata = {
            'original_path': file_path,
            'file_name': os.path.basename(file_path),
            'file_size': file_size,
            'hash_algorithm': 'SHA-256',
        }

        self._store_evidence(
            evidence_id=evidence_id,
            evidence_type='file',
            source_type='file_system',
            source_id=file_path,
            description=description,
            sha256_hash=sha256_hash,
            file_path=file_path,
            file_size=file_size,
            metadata=metadata,
        )

        logger.info("Collected file evidence %s: %s (hash: %s)", evidence_id, file_path, sha256_hash[:16])
        return evidence_id

    def collect_memory_dump(self, host_id: str, description: str) -> str:
        """
        Register a memory dump as forensic evidence.

        Args:
            host_id: Identifier of the host from which the memory was dumped.
            description: Description of the memory dump context.

        Returns:
            Evidence ID string.
        """
        evidence_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        metadata = {
            'host_id': host_id,
            'dump_type': 'memory',
            'collection_time': now,
        }

        data_str = json.dumps({'evidence_id': evidence_id, 'host_id': host_id,
                                'description': description, 'time': now}, sort_keys=True)
        sha256_hash = self._compute_hash(data_str)

        self._store_evidence(
            evidence_id=evidence_id,
            evidence_type='memory_dump',
            source_type='host',
            source_id=host_id,
            description=description,
            sha256_hash=sha256_hash,
            metadata=metadata,
        )

        logger.info("Registered memory dump evidence %s for host %s", evidence_id, host_id)
        return evidence_id

    def collect_network_capture(self, description: str) -> str:
        """
        Register PCAP / network capture as forensic evidence.

        Args:
            description: Description of the capture context and time window.

        Returns:
            Evidence ID string.
        """
        evidence_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        metadata = {
            'capture_type': 'pcap',
            'collection_time': now,
        }

        data_str = json.dumps({'evidence_id': evidence_id, 'description': description,
                                'time': now}, sort_keys=True)
        sha256_hash = self._compute_hash(data_str)

        self._store_evidence(
            evidence_id=evidence_id,
            evidence_type='network_capture',
            source_type='network',
            source_id='pcap',
            description=description,
            sha256_hash=sha256_hash,
            metadata=metadata,
        )

        logger.info("Registered network capture evidence %s", evidence_id)
        return evidence_id


class ChainOfCustody:
    """Tamper-evident chain of custody log with hash chaining."""

    GENESIS_HASH = "0" * 64

    def __init__(self):
        pass

    def _get_last_entry(self, evidence_id: str) -> Optional[Dict]:
        """Get the most recent chain entry for an evidence item."""
        with db._cursor() as cur:
            if db.use_postgresql:
                cur.execute("""
                    SELECT * FROM evidence_chain WHERE evidence_id = %s
                    ORDER BY sequence_num DESC LIMIT 1
                """, (evidence_id,))
            else:
                cur.execute("""
                    SELECT * FROM evidence_chain WHERE evidence_id = ?
                    ORDER BY sequence_num DESC LIMIT 1
                """, (evidence_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def _get_sequence_num(self, evidence_id: str) -> int:
        """Get the next sequence number for an evidence item."""
        with db._cursor() as cur:
            if db.use_postgresql:
                cur.execute("SELECT MAX(sequence_num) as max_seq FROM evidence_chain WHERE evidence_id = %s",
                            (evidence_id,))
            else:
                cur.execute("SELECT MAX(sequence_num) as max_seq FROM evidence_chain WHERE evidence_id = ?",
                            (evidence_id,))
            row = cur.fetchone()
            if row:
                max_seq = row['max_seq'] if db.use_postgresql else row[0]
                return (max_seq or 0) + 1
            return 1

    def _compute_entry_hash(self, evidence_id: str, sequence_num: int, action: str,
                            actor: str, details: str, prev_hash: str, timestamp: str) -> str:
        """Compute SHA-256 hash for a chain entry."""
        payload = f"{evidence_id}:{sequence_num}:{action}:{actor}:{details}:{prev_hash}:{timestamp}"
        return hashlib.sha256(payload.encode('utf-8')).hexdigest()

    def add_entry(self, evidence_id: str, action: str, actor: str, details: str = '') -> Dict[str, Any]:
        """
        Append a custody entry with hash chaining.

        Args:
            evidence_id: The evidence item this entry belongs to.
            action: Action performed (e.g. 'collected', 'analyzed', 'transferred').
            actor: Person or system performing the action.
            details: Additional details about the action.

        Returns:
            Dictionary with the created entry data.
        """
        now = datetime.now(timezone.utc).isoformat()
        sequence_num = self._get_sequence_num(evidence_id)
        last_entry = self._get_last_entry(evidence_id)
        prev_hash = last_entry['entry_hash'] if last_entry else self.GENESIS_HASH

        entry_hash = self._compute_entry_hash(evidence_id, sequence_num, action, actor, details, prev_hash, now)
        entry_id = str(uuid.uuid4())

        with db._cursor() as cur:
            if db.use_postgresql:
                cur.execute("""
                    INSERT INTO evidence_chain (id, evidence_id, sequence_num, action, actor,
                        details, prev_hash, entry_hash, timestamp)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """, (entry_id, evidence_id, sequence_num, action, actor, details, prev_hash, entry_hash, now))
            else:
                cur.execute("""
                    INSERT INTO evidence_chain (id, evidence_id, sequence_num, action, actor,
                        details, prev_hash, entry_hash, timestamp)
                    VALUES (?,?,?,?,?,?,?,?,?)
                """, (entry_id, evidence_id, sequence_num, action, actor, details, prev_hash, entry_hash, now))

        logger.info("Chain entry added: evidence=%s seq=%d action=%s actor=%s",
                     evidence_id, sequence_num, action, actor)
        return {
            'id': entry_id,
            'evidence_id': evidence_id,
            'sequence_num': sequence_num,
            'action': action,
            'actor': actor,
            'details': details,
            'prev_hash': prev_hash,
            'entry_hash': entry_hash,
            'timestamp': now,
        }

    def get_chain(self, evidence_id: str) -> List[Dict[str, Any]]:
        """
        Get the full custody chain for an evidence item.

        Args:
            evidence_id: The evidence item to retrieve the chain for.

        Returns:
            List of chain entries ordered by sequence number.
        """
        with db._cursor() as cur:
            if db.use_postgresql:
                cur.execute("""
                    SELECT * FROM evidence_chain WHERE evidence_id = %s
                    ORDER BY sequence_num ASC
                """, (evidence_id,))
            else:
                cur.execute("""
                    SELECT * FROM evidence_chain WHERE evidence_id = ?
                    ORDER BY sequence_num ASC
                """, (evidence_id,))
            return [dict(row) for row in cur.fetchall()]

    def verify_chain(self, evidence_id: str) -> Tuple[bool, str]:
        """
        Validate the hash chain integrity for an evidence item.

        Args:
            evidence_id: The evidence item to verify.

        Returns:
            Tuple of (is_valid: bool, message: str).
        """
        chain = self.get_chain(evidence_id)
        if not chain:
            return False, f"No chain entries found for evidence {evidence_id}"

        prev_expected = self.GENESIS_HASH
        for entry in chain:
            if entry['prev_hash'] != prev_expected:
                return False, (
                    f"Chain broken at sequence {entry['sequence_num']}: "
                    f"expected prev_hash {prev_expected[:16]}..., "
                    f"got {entry['prev_hash'][:16]}..."
                )

            recomputed = self._compute_entry_hash(
                entry['evidence_id'], entry['sequence_num'], entry['action'],
                entry['actor'], entry['details'], entry['prev_hash'], entry['timestamp']
            )
            if recomputed != entry['entry_hash']:
                return False, (
                    f"Hash mismatch at sequence {entry['sequence_num']}: "
                    f"expected {entry['entry_hash'][:16]}..., "
                    f"got {recomputed[:16]}..."
                )

            prev_expected = entry['entry_hash']

        return True, f"Chain valid: {len(chain)} entries verified"

    def transfer(self, evidence_id: str, from_actor: str, to_actor: str, reason: str = '') -> Dict[str, Any]:
        """
        Transfer custody of evidence from one actor to another.

        Args:
            evidence_id: The evidence item to transfer.
            from_actor: Current custodian.
            to_actor: New custodian.
            reason: Reason for the transfer.

        Returns:
            Dictionary with the transfer entry data.
        """
        details = json.dumps({
            'from_actor': from_actor,
            'to_actor': to_actor,
            'reason': reason,
            'transfer_time': datetime.now(timezone.utc).isoformat(),
        })

        logger.info("Custody transfer: evidence=%s from=%s to=%s", evidence_id, from_actor, to_actor)
        return self.add_entry(
            evidence_id=evidence_id,
            action='transferred',
            actor=from_actor,
            details=details,
        )


class ForensicTimeline:
    """Reconstruct attack timelines for incidents."""

    def __init__(self):
        pass

    def add_event(self, incident_id: str, event_time: str, event_type: str,
                  source: str, description: str, evidence_id: str = '',
                  metadata: Optional[Dict] = None) -> str:
        """
        Add an event to an incident's forensic timeline.

        Args:
            incident_id: The incident this event belongs to.
            event_time: ISO timestamp of when the event occurred.
            event_type: Category (e.g. 'alert', 'detection', 'network_anomaly',
                       'user_anomaly', 'system_event').
            source: Source system or component that generated the event.
            description: Human-readable description.
            evidence_id: Optional linked evidence item ID.
            metadata: Optional additional structured data.

        Returns:
            Timeline event ID.
        """
        event_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        with db._cursor() as cur:
            if db.use_postgresql:
                cur.execute("""
                    INSERT INTO forensic_timeline (id, incident_id, event_time, event_type,
                        source, description, evidence_id, metadata, created_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """, (event_id, incident_id, event_time, event_type, source, description,
                      evidence_id, json.dumps(metadata or {}), now))
            else:
                cur.execute("""
                    INSERT INTO forensic_timeline (id, incident_id, event_time, event_type,
                        source, description, evidence_id, metadata, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                """, (event_id, incident_id, event_time, event_type, source, description,
                      evidence_id, json.dumps(metadata or {}), now))

        logger.info("Timeline event added: incident=%s type=%s source=%s", incident_id, event_type, source)
        return event_id

    def get_timeline(self, incident_id: str) -> List[Dict[str, Any]]:
        """
        Get the sorted forensic timeline for an incident.

        Args:
            incident_id: The incident to retrieve the timeline for.

        Returns:
            List of timeline events sorted by event_time ascending.
        """
        with db._cursor() as cur:
            if db.use_postgresql:
                cur.execute("""
                    SELECT * FROM forensic_timeline WHERE incident_id = %s
                    ORDER BY event_time ASC
                """, (incident_id,))
            else:
                cur.execute("""
                    SELECT * FROM forensic_timeline WHERE incident_id = ?
                    ORDER BY event_time ASC
                """, (incident_id,))
            return [dict(row) for row in cur.fetchall()]

    def build_timeline(self, incident_id: str) -> List[Dict[str, Any]]:
        """
        Aggregate events from alerts, detections, network anomalies,
        and user anomalies into a unified timeline for an incident.

        Args:
            incident_id: The incident to build the timeline for.

        Returns:
            Sorted list of all timeline events.
        """
        existing_events = self.get_timeline(incident_id)
        existing_ids = {e.get('id') for e in existing_events}
        added_count = 0

        incident = db.get_incident(incident_id)
        if not incident:
            logger.warning("Incident %s not found, returning existing events", incident_id)
            return existing_events

        alert_ids = json.loads(incident.get('alert_ids', '[]')) if isinstance(incident.get('alert_ids'), str) else incident.get('alert_ids', [])
        for alert_id in alert_ids:
            alert = db.get_alert(alert_id)
            if not alert:
                continue
            event_time = alert.get('created_at', '')
            if not event_time:
                continue

            self.add_event(
                incident_id=incident_id,
                event_time=event_time,
                event_type='alert',
                source=f"alert:{alert.get('alert_type', '')}",
                description=alert.get('title', alert.get('description', '')),
                metadata={
                    'alert_id': alert_id,
                    'severity': alert.get('severity', ''),
                    'source_ip': alert.get('source_ip', ''),
                    'destination_ip': alert.get('destination_ip', ''),
                    'mitre_technique': alert.get('mitre_technique', ''),
                    'mitre_tactic': alert.get('mitre_tactic', ''),
                },
            )
            added_count += 1

        affected_ips = json.loads(incident.get('affected_ips', '[]')) if isinstance(incident.get('affected_ips'), str) else incident.get('affected_ips', [])
        for ip in affected_ips:
            detections = db.get_threat_detections_filtered(source_ip=ip, limit=50)
            for det in detections:
                det_time = det.get('detection_time', '')
                if not det_time:
                    continue
                self.add_event(
                    incident_id=incident_id,
                    event_time=det_time,
                    event_type='detection',
                    source=f"threat_detection:{det.get('threat_type', '')}",
                    description=det.get('description', ''),
                    metadata={
                        'detection_id': det.get('id', ''),
                        'threat_type': det.get('threat_type', ''),
                        'severity': det.get('severity', ''),
                        'confidence': det.get('confidence', 0),
                        'source_ip': det.get('source_ip', ''),
                        'dest_ip': det.get('dest_ip', ''),
                        'mitre_technique': det.get('mitre_technique', ''),
                    },
                )
                added_count += 1

            events = db.get_events_by_ip(ip, limit=100)
            for evt in events:
                evt_time = evt.get('timestamp', '')
                if not evt_time:
                    continue
                self.add_event(
                    incident_id=incident_id,
                    event_time=evt_time,
                    event_type='network_anomaly',
                    source=f"network:{evt.get('event_type', '')}",
                    description=f"{evt.get('method', '')} {evt.get('url', '')} -> {evt.get('status_code', '')}" if evt.get('url') else evt.get('message', ''),
                    metadata={
                        'event_id': evt.get('id', ''),
                        'source_ip': evt.get('source_ip', ''),
                        'dest_ip': evt.get('dest_ip', ''),
                        'source_port': evt.get('source_port', 0),
                        'dest_port': evt.get('dest_port', 0),
                        'protocol': evt.get('protocol', ''),
                        'severity': evt.get('severity', ''),
                    },
                )
                added_count += 1

        if added_count > 0:
            logger.info("Built timeline for incident %s: added %d events", incident_id, added_count)

        return self.get_timeline(incident_id)


class EvidenceVerifier:
    """Verify evidence integrity and chain consistency."""

    def __init__(self):
        self.collector = EvidenceCollector()
        self.chain = ChainOfCustody()

    def verify_hash(self, evidence_id: str) -> Dict[str, Any]:
        """
        Re-hash stored evidence and compare against the recorded SHA-256 hash.

        For file evidence, the file is re-read and re-hashed.
        For snapshot evidence, the metadata is re-serialized and re-hashed.

        Returns:
            Dictionary with verification result.
        """
        evidence = self.collector._get_evidence(evidence_id)
        if not evidence:
            return {
                'evidence_id': evidence_id,
                'valid': False,
                'message': f'Evidence {evidence_id} not found',
                'expected_hash': '',
                'actual_hash': '',
            }

        expected_hash = evidence.get('sha256_hash', '')
        evidence_type = evidence.get('evidence_type', '')
        file_path = evidence.get('file_path', '')

        if evidence_type == 'file' and file_path and os.path.isfile(file_path):
            actual_hash = EvidenceCollector._compute_file_hash(file_path)
        else:
            metadata = evidence.get('metadata', '{}')
            if isinstance(metadata, str):
                try:
                    metadata = json.loads(metadata)
                except json.JSONDecodeError:
                    metadata = {'raw': metadata}
            data_str = json.dumps(metadata, sort_keys=True, default=str)
            actual_hash = hashlib.sha256(data_str.encode('utf-8')).hexdigest()

        is_valid = actual_hash == expected_hash
        return {
            'evidence_id': evidence_id,
            'valid': is_valid,
            'message': 'Hash verified' if is_valid else 'Hash MISMATCH - evidence may have been tampered with',
            'expected_hash': expected_hash,
            'actual_hash': actual_hash,
            'evidence_type': evidence_type,
        }

    def verify_chain_integrity(self, evidence_id: str) -> Dict[str, Any]:
        """
        Validate the entire chain of custody for an evidence item.

        Returns:
            Dictionary with chain verification result.
        """
        is_valid, message = self.chain.verify_chain(evidence_id)
        chain_entries = self.chain.get_chain(evidence_id)

        return {
            'evidence_id': evidence_id,
            'valid': is_valid,
            'message': message,
            'chain_length': len(chain_entries),
            'first_actor': chain_entries[0]['actor'] if chain_entries else None,
            'last_actor': chain_entries[-1]['actor'] if chain_entries else None,
            'first_timestamp': chain_entries[0]['timestamp'] if chain_entries else None,
            'last_timestamp': chain_entries[-1]['timestamp'] if chain_entries else None,
        }


class ForensicService:
    """
    Facade combining all forensic components: evidence collection,
    chain of custody, timeline reconstruction, and integrity verification.
    """

    def __init__(self):
        self.evidence_collector = EvidenceCollector()
        self.chain_of_custody = ChainOfCustody()
        self.timeline = ForensicTimeline()
        self.verifier = EvidenceVerifier()

    def collect_alert_evidence(self, alert_data: Dict[str, Any], actor: str = 'system') -> Dict[str, Any]:
        """
        Collect evidence from an alert and create the initial custody entry.

        Args:
            alert_data: Alert data dictionary.
            actor: Actor performing the collection.

        Returns:
            Dictionary with evidence_id and chain entry.
        """
        evidence_id = self.evidence_collector.collect_from_alert(alert_data)
        entry = self.chain_of_custody.add_entry(
            evidence_id=evidence_id,
            action='collected',
            actor=actor,
            details=f"Alert snapshot collected: {alert_data.get('title', '')}",
        )
        return {'evidence_id': evidence_id, 'chain_entry': entry}

    def collect_incident_evidence(self, incident_data: Dict[str, Any], actor: str = 'system') -> Dict[str, Any]:
        """
        Collect evidence from an incident and create the initial custody entry.

        Args:
            incident_data: Incident data dictionary.
            actor: Actor performing the collection.

        Returns:
            Dictionary with evidence_id and chain entry.
        """
        evidence_id = self.evidence_collector.collect_from_incident(incident_data)
        entry = self.chain_of_custody.add_entry(
            evidence_id=evidence_id,
            action='collected',
            actor=actor,
            details=f"Incident snapshot collected: {incident_data.get('title', '')}",
        )
        return {'evidence_id': evidence_id, 'chain_entry': entry}

    def collect_file_evidence(self, file_path: str, description: str, actor: str = 'system') -> Dict[str, Any]:
        """
        Collect file evidence and create the initial custody entry.

        Args:
            file_path: Path to the file.
            description: Description of the file's relevance.
            actor: Actor performing the collection.

        Returns:
            Dictionary with evidence_id, chain entry, and file hash.
        """
        evidence_id = self.evidence_collector.collect_file(file_path, description)
        evidence = self.evidence_collector._get_evidence(evidence_id)
        entry = self.chain_of_custody.add_entry(
            evidence_id=evidence_id,
            action='collected',
            actor=actor,
            details=f"File evidence collected: {file_path}",
        )
        return {
            'evidence_id': evidence_id,
            'chain_entry': entry,
            'sha256_hash': evidence.get('sha256_hash', '') if evidence else '',
        }

    def collect_memory_dump_evidence(self, host_id: str, description: str, actor: str = 'system') -> Dict[str, Any]:
        """
        Register a memory dump and create the initial custody entry.

        Args:
            host_id: Host identifier.
            description: Description of the memory dump.
            actor: Actor performing the collection.

        Returns:
            Dictionary with evidence_id and chain entry.
        """
        evidence_id = self.evidence_collector.collect_memory_dump(host_id, description)
        entry = self.chain_of_custody.add_entry(
            evidence_id=evidence_id,
            action='collected',
            actor=actor,
            details=f"Memory dump registered: host={host_id}",
        )
        return {'evidence_id': evidence_id, 'chain_entry': entry}

    def collect_network_capture_evidence(self, description: str, actor: str = 'system') -> Dict[str, Any]:
        """
        Register a network capture and create the initial custody entry.

        Args:
            description: Description of the capture.
            actor: Actor performing the collection.

        Returns:
            Dictionary with evidence_id and chain entry.
        """
        evidence_id = self.evidence_collector.collect_network_capture(description)
        entry = self.chain_of_custody.add_entry(
            evidence_id=evidence_id,
            action='collected',
            actor=actor,
            details=f"Network capture registered: {description}",
        )
        return {'evidence_id': evidence_id, 'chain_entry': entry}

    def transfer_custody(self, evidence_id: str, from_actor: str, to_actor: str,
                         reason: str = '') -> Dict[str, Any]:
        """
        Transfer custody of evidence between actors.

        Args:
            evidence_id: Evidence item to transfer.
            from_actor: Current custodian.
            to_actor: New custodian.
            reason: Reason for the transfer.

        Returns:
            Dictionary with the transfer chain entry.
        """
        return self.chain_of_custody.transfer(evidence_id, from_actor, to_actor, reason)

    def add_custody_entry(self, evidence_id: str, action: str, actor: str,
                          details: str = '') -> Dict[str, Any]:
        """
        Add a generic chain of custody entry.

        Args:
            evidence_id: Evidence item to log against.
            action: Action performed.
            actor: Person or system.
            details: Additional details.

        Returns:
            Dictionary with the created entry.
        """
        return self.chain_of_custody.add_entry(evidence_id, action, actor, details)

    def get_custody_chain(self, evidence_id: str) -> List[Dict[str, Any]]:
        """Get the full chain of custody for an evidence item."""
        return self.chain_of_custody.get_chain(evidence_id)

    def verify_evidence(self, evidence_id: str) -> Dict[str, Any]:
        """
        Perform full verification of evidence: hash check + chain integrity.

        Returns:
            Dictionary with combined verification results.
        """
        hash_result = self.verifier.verify_hash(evidence_id)
        chain_result = self.verifier.verify_chain_integrity(evidence_id)

        return {
            'evidence_id': evidence_id,
            'hash_valid': hash_result.get('valid', False),
            'hash_message': hash_result.get('message', ''),
            'chain_valid': chain_result.get('valid', False),
            'chain_message': chain_result.get('message', ''),
            'chain_length': chain_result.get('chain_length', 0),
            'fully_verified': hash_result.get('valid', False) and chain_result.get('valid', False),
        }

    def get_evidence(self, evidence_id: str) -> Optional[Dict[str, Any]]:
        """Get an evidence record by ID."""
        return self.evidence_collector._get_evidence(evidence_id)

    def build_incident_timeline(self, incident_id: str) -> List[Dict[str, Any]]:
        """Build the unified forensic timeline for an incident."""
        return self.timeline.build_timeline(incident_id)

    def add_timeline_event(self, incident_id: str, event_time: str, event_type: str,
                           source: str, description: str, evidence_id: str = '',
                           metadata: Optional[Dict] = None) -> str:
        """Add a manual event to an incident's forensic timeline."""
        return self.timeline.add_event(incident_id, event_time, event_type,
                                       source, description, evidence_id, metadata)

    def get_incident_timeline(self, incident_id: str) -> List[Dict[str, Any]]:
        """Get the sorted forensic timeline for an incident."""
        return self.timeline.get_timeline(incident_id)


forensic_service = ForensicService()
