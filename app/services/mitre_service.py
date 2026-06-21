"""
MITRE ATT&CK Mapping Service for SentinelAI.
Maps detected threats to real MITRE techniques and tactics.
"""
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict


@dataclass
class MitreMapping:
    technique_id: str
    technique_name: str
    tactic: str
    tactic_id: str
    description: str
    detection: str
    mitigation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# Real MITRE ATT&CK mappings for common attack techniques
MITRE_DATABASE: Dict[str, MitreMapping] = {
    'brute_force': MitreMapping(
        technique_id='T1110',
        technique_name='Brute Force',
        tactic='Credential Access',
        tactic_id='TA0006',
        description='Adversaries may use brute force techniques to gain access to accounts.',
        detection='Monitor authentication events for multiple failed attempts from same source.',
        mitigation='Implement account lockout policies, use MFA, monitor auth logs.',
    ),
    'port_scan': MitreMapping(
        technique_id='T1595',
        technique_name='Active Scanning',
        tactic='Reconnaissance',
        tactic_id='TA0043',
        description='Adversaries may scan victim infrastructure to identify reachable services.',
        detection='Monitor network traffic for sequential port access patterns.',
        mitigation='Deploy IDS/IPS, limit exposed services, use network segmentation.',
    ),
    'dos': MitreMapping(
        technique_id='T1499',
        technique_name='Endpoint Denial of Service',
        tactic='Impact',
        tactic_id='TA0040',
        description='Adversaries may perform Denial of Service attacks against available resources.',
        detection='Monitor for abnormal traffic volumes and request rates.',
        mitigation='Implement rate limiting, use DDoS protection services, scale infrastructure.',
    ),
    'web_attack': MitreMapping(
        technique_id='T1190',
        technique_name='Exploit Public-Facing Application',
        tactic='Initial Access',
        tactic_id='TA0001',
        description='Adversaries may attempt to exploit public-facing applications.',
        detection='Monitor web application logs for suspicious input patterns.',
        mitigation='Patch applications, deploy WAF, input validation, security headers.',
    ),
    'suspicious_auth': MitreMapping(
        technique_id='T1078',
        technique_name='Valid Accounts',
        tactic='Initial Access',
        tactic_id='TA0001',
        description='Adversaries may obtain and abuse credentials of existing accounts.',
        detection='Monitor for unusual login patterns and credential usage.',
        mitigation='Enforce MFA, monitor access patterns, implement RBAC.',
    ),
    'data_exfil': MitreMapping(
        technique_id='T1041',
        technique_name='Exfiltration Over C2 Channel',
        tactic='Exfiltration',
        tactic_id='TA0010',
        description='Adversaries may steal data by exfiltrating it over an existing C2 channel.',
        detection='Monitor outbound data transfers and unusual network traffic.',
        mitigation='Implement DLP, monitor egress traffic, encrypt sensitive data.',
    ),
    'beaconing': MitreMapping(
        technique_id='T1573',
        technique_name='Encrypted Channel',
        tactic='Command and Control',
        tactic_id='TA0011',
        description='Adversaries may use encrypted channels for C2 communication.',
        detection='Analyze connection timing patterns for regular intervals.',
        mitigation='Deploy network monitoring, block known C2 servers, endpoint detection.',
    ),
    'lateral_movement': MitreMapping(
        technique_id='T1021',
        technique_name='Remote Services',
        tactic='Lateral Movement',
        tactic_id='TA0008',
        description='Adversaries may use valid accounts to log into remote services.',
        detection='Monitor for unusual internal connection patterns.',
        mitigation='Implement network segmentation, use PAM, monitor lateral movement.',
    ),
    'credential_stuffing': MitreMapping(
        technique_id='T1110.004',
        technique_name='Credential Stuffing',
        tactic='Credential Access',
        tactic_id='TA0006',
        description='Adversaries may use previously leaked credential pairs.',
        detection='Monitor for login attempts using known breached credentials.',
        mitigation='Implement credential screening, rate limiting, CAPTCHA.',
    ),
}


class MitreMapper:
    """Map threat detections to MITRE ATT&CK framework."""

    def get_mapping(self, threat_type: str) -> Optional[MitreMapping]:
        """Get MITRE mapping for a threat type."""
        return MITRE_DATABASE.get(threat_type)

    def map_detection(self, threat_type: str) -> Dict[str, Any]:
        """Map a detection to MITRE technique."""
        mapping = self.get_mapping(threat_type)
        if mapping:
            return mapping.to_dict()
        return {
            'technique_id': 'Unknown',
            'technique_name': 'Unknown',
            'tactic': 'Unknown',
            'tactic_id': 'Unknown',
            'description': 'No MITRE mapping available for this threat type.',
            'detection': 'N/A',
            'mitigation': 'N/A',
        }

    def get_tactic_summary(self, detections: List[Dict]) -> Dict[str, List[Dict]]:
        """Group detections by MITRE tactic."""
        by_tactic = {}
        for det in detections:
            mapping = self.get_mapping(det.get('threat_type', ''))
            if mapping:
                tactic = mapping.tactic
                if tactic not in by_tactic:
                    by_tactic[tactic] = []
                by_tactic[tactic].append({
                    'technique_id': mapping.technique_id,
                    'technique_name': mapping.technique_name,
                    'detection_count': 1,
                })
        return by_tactic

    def get_kill_chain_stage(self, threat_type: str) -> int:
        """Map threat to cyber kill chain stage (1-7)."""
        kill_chain_map = {
            'port_scan': 1,           # Reconnaissance
            'web_attack': 2,          # Weaponization/Delivery
            'brute_force': 3,         # Exploitation
            'credential_stuffing': 3, # Exploitation
            'suspicious_auth': 3,     # Exploitation
            'lateral_movement': 5,    # Installation
            'beaconing': 5,           # Command & Control
            'data_exfil': 7,          # Actions on Objectives
            'dos': 4,                 # Delivery (denial)
        }
        return kill_chain_map.get(threat_type, 0)


# Singleton
mitre_mapper = MitreMapper()
