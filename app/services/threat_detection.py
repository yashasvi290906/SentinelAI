"""
Real Threat Detection Engine for SentinelAI.
Detects: Brute Force, Port Scan, DoS, DDoS, Credential Stuffing,
Suspicious Auth, Web Attack, Data Exfiltration, Beaconing, Lateral Movement.
Uses pattern matching, frequency analysis, and statistical detection.
"""
from collections import defaultdict, Counter
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Tuple, Optional, Set
from dataclasses import dataclass, field, asdict
import math
import re


@dataclass
class ThreatDetection:
    """A detected threat/insecurity."""
    id: str
    threat_type: str           # brute_force, port_scan, dos, etc.
    severity: str              # LOW, MEDIUM, HIGH, CRITICAL
    confidence: float          # 0.0 to 1.0
    source_ip: str
    dest_ip: str = ""
    dest_port: int = 0
    description: str = ""
    evidence: List[str] = field(default_factory=list)
    mitre_technique: str = ""
    mitre_tactic: str = ""
    first_seen: str = ""
    last_seen: str = ""
    event_count: int = 0
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ThreatDetector:
    """Real-time threat detection from parsed log events."""

    def __init__(self):
        # Sliding window buffers
        self._ip_events: Dict[str, List[datetime]] = defaultdict(list)
        self._ip_connections: Dict[str, Set[str]] = defaultdict(set)
        self._port_access: Dict[str, List[Tuple[str, int]]] = defaultdict(list)
        self._auth_failures: Dict[str, List[datetime]] = defaultdict(list)
        self._url_access: Dict[str, List[Tuple[str, datetime]]] = defaultdict(list)

        # Detection thresholds
        self.BRUTE_FORCE_THRESHOLD = 5          # failed logins in window
        self.PORT_SCAN_THRESHOLD = 15           # unique ports in window
        self.DOS_THRESHOLD = 50                 # requests in window
        self.BEACONING_INTERVAL_THRESHOLD = 0.1  # coefficient of variation
        self.AUTH_FAILURE_WINDOW = timedelta(minutes=5)
        self.PORT_SCAN_WINDOW = timedelta(minutes=2)
        self.DOS_WINDOW = timedelta(seconds=30)

    def analyze_events(self, events: List[Dict[str, Any]]) -> List[ThreatDetection]:
        """Analyze a batch of events and return detections."""
        detections = []

        for event in events:
            # Track per-IP activity
            src_ip = event.get('source_ip', '')
            if src_ip:
                ts = self._parse_timestamp(event.get('timestamp', ''))
                if ts:
                    self._ip_events[src_ip].append(ts)

            # Run detection rules
            detections.extend(self._detect_brute_force(event))
            detections.extend(self._detect_port_scan(event))
            detections.extend(self._detect_dos(event))
            detections.extend(self._detect_web_attack(event))
            detections.extend(self._detect_suspicious_auth(event))
            detections.extend(self._detect_data_exfil(event))

        # Run cross-event detections
        detections.extend(self._detect_beaconing())
        detections.extend(self._detect_lateral_movement(events))

        # Deduplicate
        detections = self._deduplicate(detections)

        return detections

    def _detect_brute_force(self, event: Dict) -> List[ThreatDetection]:
        """Detect brute force attacks from failed authentication events."""
        detections = []
        event_type = event.get('event_type', '')
        src_ip = event.get('source_ip', '')

        if event_type in ('brute_force', 'suspicious_auth') or \
           (event.get('status_code', 0) in (401, 403) and event.get('method', '') in ('POST', '')):

            ts = self._parse_timestamp(event.get('timestamp', ''))
            if ts and src_ip:
                self._auth_failures[src_ip].append(ts)

                # Check window
                cutoff = ts - self.AUTH_FAILURE_WINDOW
                recent = [t for t in self._auth_failures[src_ip] if t >= cutoff]
                self._auth_failures[src_ip] = recent

                if len(recent) >= self.BRUTE_FORCE_THRESHOLD:
                    confidence = min(0.95, 0.5 + (len(recent) - self.BRUTE_FORCE_THRESHOLD) * 0.05)
                    severity = 'CRITICAL' if len(recent) >= 10 else 'HIGH'

                    detections.append(ThreatDetection(
                        id=f"bf_{src_ip}_{int(ts.timestamp())}",
                        threat_type='brute_force',
                        severity=severity,
                        confidence=confidence,
                        source_ip=src_ip,
                        dest_ip=event.get('dest_ip', ''),
                        dest_port=event.get('dest_port', 0),
                        description=f"Brute force attack detected from {src_ip}: {len(recent)} failed attempts in 5 minutes",
                        evidence=[
                            f"{len(recent)} failed authentication attempts",
                            f"Window: {self.AUTH_FAILURE_WINDOW.total_seconds()}s",
                            f"User targeted: {event.get('user', 'unknown')}",
                        ],
                        mitre_technique='T1110',
                        mitre_tactic='Credential Access',
                        first_seen=min(recent).isoformat(),
                        last_seen=max(recent).isoformat(),
                        event_count=len(recent),
                        recommendations=[
                            "Block source IP at firewall",
                            "Check for compromised credentials",
                            "Enable account lockout policy",
                            "Review authentication logs",
                        ],
                    ))

        return detections

    def _detect_port_scan(self, event: Dict) -> List[ThreatDetection]:
        """Detect port scanning from sequential port access."""
        detections = []
        src_ip = event.get('source_ip', '')
        dest_port = event.get('dest_port', 0)

        if src_ip and dest_port and (event.get('status_code', 0) in (0, None) or \
           event.get('event_type') == 'port_scan'):

            ts = self._parse_timestamp(event.get('timestamp', ''))
            if ts:
                key = f"{src_ip}:{event.get('dest_ip', '')}"
                self._port_access[key].append((src_ip, dest_port))

                # Check unique ports in window
                recent_ports = set()
                for ip, port in self._port_access[key][-50:]:
                    recent_ports.add(port)

                if len(recent_ports) >= self.PORT_SCAN_THRESHOLD:
                    confidence = min(0.95, 0.5 + (len(recent_ports) - self.PORT_SCAN_THRESHOLD) * 0.02)

                    detections.append(ThreatDetection(
                        id=f"ps_{src_ip}_{ts.timestamp()[:10]}",
                        threat_type='port_scan',
                        severity='MEDIUM',
                        confidence=confidence,
                        source_ip=src_ip,
                        dest_ip=event.get('dest_ip', ''),
                        description=f"Port scan detected from {src_ip}: {len(recent_ports)} unique ports accessed",
                        evidence=[
                            f"{len(recent_ports)} unique ports scanned",
                            f"Ports: {', '.join(str(p) for p in sorted(recent_ports)[:20])}",
                        ],
                        mitre_technique='T1595',
                        mitre_tactic='Reconnaissance',
                        event_count=len(recent_ports),
                        recommendations=[
                            "Monitor source IP for further scanning",
                            "Check firewall rules for exposed ports",
                            "Consider blocking source IP",
                        ],
                    ))

        return detections

    def _detect_dos(self, event: Dict) -> List[ThreatDetection]:
        """Detect DoS attacks from high request frequency."""
        detections = []
        src_ip = event.get('source_ip', '')

        if src_ip:
            ts = self._parse_timestamp(event.get('timestamp', ''))
            if ts:
                self._ip_events[src_ip].append(ts)

                cutoff = ts - self.DOS_WINDOW
                recent = [t for t in self._ip_events[src_ip] if t >= cutoff]

                if len(recent) >= self.DOS_THRESHOLD:
                    confidence = min(0.95, 0.6 + (len(recent) - self.DOS_THRESHOLD) * 0.005)

                    detections.append(ThreatDetection(
                        id=f"dos_{src_ip}_{ts.timestamp()[:10]}",
                        threat_type='dos',
                        severity='CRITICAL',
                        confidence=confidence,
                        source_ip=src_ip,
                        dest_ip=event.get('dest_ip', ''),
                        dest_port=event.get('dest_port', 0),
                        description=f"DoS attack detected from {src_ip}: {len(recent)} requests in {self.DOS_WINDOW.total_seconds()}s",
                        evidence=[
                            f"{len(recent)} requests in {self.DOS_WINDOW.total_seconds()}s",
                            f"Rate: {len(recent) / self.DOS_WINDOW.total_seconds():.1f} req/s",
                        ],
                        mitre_technique='T1499',
                        mitre_tactic='Impact',
                        event_count=len(recent),
                        recommendations=[
                            "Activate rate limiting",
                            "Block source IP",
                            "Enable DDoS protection",
                            "Scale infrastructure if under attack",
                        ],
                    ))

        return detections

    def _detect_web_attack(self, event: Dict) -> List[ThreatDetection]:
        """Detect web attacks from URL patterns."""
        detections = []
        event_type = event.get('event_type', '')

        if event_type == 'web_attack':
            src_ip = event.get('source_ip', '')
            url = event.get('url', '')
            msg = event.get('message', '')

            # Identify specific web attack type
            attack_subtypes = []
            if re.search(r'<script|javascript:', msg + url, re.I):
                attack_subtypes.append('XSS')
            if re.search(r'union.*select|select.*from|or\s+1=1', msg + url, re.I):
                attack_subtypes.append('SQL Injection')
            if re.search(r'\.\./|\.\.\\|/etc/passwd|/etc/shadow', msg + url, re.I):
                attack_subtypes.append('Path Traversal')
            if re.search(r'cmd=|exec=|system\(|/bin/', msg + url, re.I):
                attack_subtypes.append('Command Injection')

            attack_desc = ', '.join(attack_subtypes) if attack_subtypes else 'Web Attack'

            detections.append(ThreatDetection(
                id=f"web_{src_ip}_{event.get('timestamp', '')[:10]}",
                threat_type='web_attack',
                severity='HIGH',
                confidence=0.90,
                source_ip=src_ip,
                dest_ip=event.get('dest_ip', ''),
                dest_port=event.get('dest_port', 80),
                description=f"{attack_desc} detected from {src_ip}: {url[:100]}",
                evidence=[
                    f"URL: {url}",
                    f"Attack type: {attack_desc}",
                    f"Method: {event.get('method', 'unknown')}",
                ],
                mitre_technique='T1190',
                mitre_tactic='Initial Access',
                recommendations=[
                    "Block source IP immediately",
                    "Review web application firewall rules",
                    "Check for successful exploitation",
                    "Patch vulnerable endpoints",
                ],
            ))

        return detections

    def _detect_suspicious_auth(self, event: Dict) -> List[ThreatDetection]:
        """Detect suspicious authentication patterns."""
        detections = []
        event_type = event.get('event_type', '')

        if event_type == 'suspicious_auth' or \
           (event.get('status_code') in (401, 403) and event.get('user', '') and event.get('user') != '-'):

            detections.append(ThreatDetection(
                id=f"sa_{event.get('source_ip', '')}_{event.get('timestamp', '')[:10]}",
                threat_type='suspicious_auth',
                severity='HIGH',
                confidence=0.75,
                source_ip=event.get('source_ip', ''),
                dest_ip=event.get('dest_ip', ''),
                dest_port=event.get('dest_port', 0),
                description=f"Suspicious authentication attempt for user '{event.get('user', 'unknown')}'",
                evidence=[
                    f"User: {event.get('user', 'unknown')}",
                    f"Status: {event.get('status_code', 'unknown')}",
                ],
                mitre_technique='T1078',
                mitre_tactic='Initial Access',
                recommendations=[
                    "Verify user identity",
                    "Check for credential compromise",
                    "Review access logs",
                ],
            ))

        return detections

    def _detect_data_exfil(self, event: Dict) -> List[ThreatDetection]:
        """Detect data exfiltration indicators."""
        detections = []
        event_type = event.get('event_type', '')
        bytes_transferred = event.get('bytes_transferred', 0)

        if event_type == 'data_exfil' or (bytes_transferred > 10_000_000):  # > 10MB
            detections.append(ThreatDetection(
                id=f"de_{event.get('source_ip', '')}_{event.get('timestamp', '')[:10]}",
                threat_type='data_exfil',
                severity='CRITICAL',
                confidence=0.80,
                source_ip=event.get('source_ip', ''),
                dest_ip=event.get('dest_ip', ''),
                description=f"Potential data exfiltration: {bytes_transferred:,} bytes transferred",
                evidence=[
                    f"Bytes transferred: {bytes_transferred:,}",
                    f"Destination: {event.get('dest_ip', 'unknown')}",
                ],
                mitre_technique='T1041',
                mitre_tactic='Exfiltration',
                recommendations=[
                    "Investigate outbound connection",
                    "Check data sensitivity",
                    "Block destination IP if unauthorized",
                    "Review DLP policies",
                ],
            ))

        return detections

    def _detect_beaconing(self) -> List[ThreatDetection]:
        """Detect beaconing (regular periodic connections to C2)."""
        detections = []

        for src_ip, timestamps in self._ip_events.items():
            if len(timestamps) < 10:
                continue

            sorted_ts = sorted(timestamps)
            intervals = [(sorted_ts[i+1] - sorted_ts[i]).total_seconds()
                        for i in range(len(sorted_ts)-1)]

            if len(intervals) < 5:
                continue

            mean_interval = sum(intervals) / len(intervals)
            if mean_interval == 0:
                continue

            variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
            std_dev = math.sqrt(variance)
            cv = std_dev / mean_interval if mean_interval > 0 else float('inf')

            if cv < self.BEACONING_INTERVAL_THRESHOLD and mean_interval > 10:
                confidence = min(0.90, 0.5 + (self.BEACONING_INTERVAL_THRESHOLD - cv) * 2)

                detections.append(ThreatDetection(
                    id=f"bc_{src_ip}",
                    threat_type='beaconing',
                    severity='HIGH',
                    confidence=confidence,
                    source_ip=src_ip,
                    description=f"Beaconing detected: regular connections every {mean_interval:.1f}s (CV={cv:.3f})",
                    evidence=[
                        f"Mean interval: {mean_interval:.1f}s",
                        f"Standard deviation: {std_dev:.1f}s",
                        f"Coefficient of variation: {cv:.3f}",
                        f"Total connections: {len(timestamps)}",
                    ],
                    mitre_technique='T1573',
                    mitre_tactic='Command and Control',
                    recommendations=[
                        "Investigate destination IP",
                        "Check for malware/C2 communication",
                        "Block suspected C2 server",
                        "Run endpoint detection scan",
                    ],
                ))

        return detections

    def _detect_lateral_movement(self, events: List[Dict]) -> List[ThreatDetection]:
        """Detect lateral movement patterns."""
        detections = []

        # Track which hosts each source IP connects to
        ip_to_hosts: Dict[str, Set[str]] = defaultdict(set)
        for event in events:
            src = event.get('source_ip', '')
            dst = event.get('dest_ip', '')
            if src and dst:
                ip_to_hosts[src].add(dst)

        for src_ip, hosts in ip_to_hosts.items():
            if len(hosts) >= 3:
                detections.append(ThreatDetection(
                    id=f"lm_{src_ip}",
                    threat_type='lateral_movement',
                    severity='CRITICAL',
                    confidence=min(0.90, 0.5 + len(hosts) * 0.1),
                    source_ip=src_ip,
                    description=f"Lateral movement detected: {src_ip} connected to {len(hosts)} unique hosts",
                    evidence=[
                        f"Unique hosts contacted: {len(hosts)}",
                        f"Hosts: {', '.join(list(hosts)[:10])}",
                    ],
                    mitre_technique='T1021',
                    mitre_tactic='Lateral Movement',
                    recommendations=[
                        "Isolate compromised host",
                        "Check for stolen credentials",
                        "Review network segmentation",
                        "Run full endpoint scan",
                    ],
                ))

        return detections

    def _deduplicate(self, detections: List[ThreatDetection]) -> List[ThreatDetection]:
        """Remove duplicate detections."""
        seen = set()
        unique = []
        for d in detections:
            key = f"{d.threat_type}:{d.source_ip}:{d.severity}"
            if key not in seen:
                seen.add(key)
                unique.append(d)
        return unique

    def _parse_timestamp(self, ts: str) -> Optional[datetime]:
        """Parse ISO timestamp string."""
        if not ts:
            return None
        try:
            return datetime.fromisoformat(ts.replace('Z', '+00:00'))
        except (ValueError, TypeError):
            return None
