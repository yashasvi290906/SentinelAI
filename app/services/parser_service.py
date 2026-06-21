"""
Real Log Parser Service for SentinelAI.
Parses Apache, Nginx, Syslog, Windows Event Logs, Firewall logs, CSV, JSON.
Extracts: timestamps, IPs, ports, protocols, URLs, users, event types, severity.
"""
import re
import json
import csv
import io
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field, asdict
import hashlib


@dataclass
class ParsedEvent:
    """Standardized event extracted from any log source."""
    timestamp: str
    source_ip: str = ""
    dest_ip: str = ""
    source_port: int = 0
    dest_port: int = 0
    protocol: str = ""
    event_type: str = ""       # brute_force, port_scan, dos, web_attack, etc.
    severity: str = "INFO"     # INFO, LOW, MEDIUM, HIGH, CRITICAL
    user: str = ""
    url: str = ""
    method: str = ""
    status_code: int = 0
    bytes_transferred: int = 0
    user_agent: str = ""
    message: str = ""
    raw_line: str = ""
    source_type: str = ""      # apache, nginx, syslog, windows, firewall, csv, json
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    def fingerprint(self) -> str:
        """Unique hash for deduplication."""
        key = f"{self.timestamp}:{self.source_ip}:{self.event_type}:{self.dest_port}"
        return hashlib.md5(key.encode()).hexdigest()


class LogParser:
    """Unified log parser supporting multiple formats."""
    
    # Apache/Nginx combined log format
    WEB_LOG_PATTERN = re.compile(
        r'(?P<ip>[\d\.]+)\s+-\s+(?P<user>\S+)\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\w+)\s+(?P<url>\S+)\s+(?P<protocol>[^"]+)"\s+'
        r'(?P<status>\d{3})\s+(?P<bytes>\d+|-)'
        r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
    )
    
    # Syslog pattern (RFC 3164)
    SYSLOG_PATTERN = re.compile(
        r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<hostname>\S+)\s+(?P<program>\S+?)(?:\[(?P<pid>\d+)\])?:\s+'
        r'(?P<message>.+)'
    )
    
    # Windows Event Log CSV pattern
    WINDOWS_CSV_FIELDS = [
        'Date', 'Time', 'Event ID', 'Level', 'Source', 'Task Category',
        'Keywords', 'User', 'Computer', 'Description'
    ]
    
    # Common firewall patterns
    FIREWALL_PATTERNS = {
        'iptables': re.compile(
            r'(?P<timestamp>\S+\s+\S+)\s+(?P<hostname>\S+)\s+'
            r'kernel:\s+\[(?P<rule>[\d\.]+)\]\s+'
            r'(?P<action>DROP|ACCEPT|REJECT)\s+'
            r'(?P<protocol>\w+)\s+'
            r'SRC=(?P<src_ip>[\d\.]+)\s+DST=(?P<dst_ip>[\d\.]+)\s+'
            r'(?:SPT=(?P<src_port>\d+))?\s+(?:DPT=(?P<dst_port>\d+))?'
        ),
        'pfsense': re.compile(
            r'(?P<timestamp>\S+\s+\S+)\s+'
            r'(?P<action>block|pass)\s+'
            r'(?P<protocol>\w+)\s+'
            r'(?P<src_ip>[\d\.]+)\s*:\s*(?P<src_port>\d+)?\s*->\s*'
            r'(?P<dst_ip>[\d\.]+)\s*:\s*(?P<dst_port>\d+)?'
        ),
        'cisco': re.compile(
            r'(?P<timestamp>\S+\s+\S+\s+\d+)\s+'
            r'(?P<hostname>\S+):?\s+'
            r'%(?P<facility>\w+)-(?P<severity>\d+)-(?P<mnemonic>\w+):\s+'
            r'(?P<message>.+)'
        ),
    }
    
    # Attack pattern signatures
    ATTACK_PATTERNS = {
        'brute_force': [
            r'failed password',
            r'authentication failure',
            r'invalid user',
            r'login failed',
            r'incorrect password',
            r'access denied.*auth',
        ],
        'port_scan': [
            r'connection refused',
            r'port \d+ (?:open|closed|filtered)',
            r'NMAP|nmap',
            r'scan detected',
            r'sequential connection',
        ],
        'dos': [
            r'syn flood',
            r'too many connections',
            r'connection limit exceeded',
            r'request timeout',
            r'service unavailable',
        ],
        'web_attack': [
            r'(\.\./)+',                              # path traversal
            r'<script',                               # XSS attempt
            r'union\s+select',                        # SQL injection
            r'cmd=|exec=|system\(',                   # command injection
            r'/etc/passwd',                           # file inclusion
            r'UNION.*SELECT',                         # SQLi
            r'SELECT.*FROM',                          # SQLi
            r'0x[0-9a-fA-F]+',                        # hex encoding
        ],
        'suspicious_auth': [
            r'brute\s+force',
            r'multiple failed',
            r'account lockout',
            r'password spray',
            r'credential stuffing',
        ],
        'data_exfil': [
            r'large.*transfer',
            r'outbound.*connection.*\d{4,}',
            r'upload.*\d{5,} bytes',
            r'unusual.*data.*volume',
        ],
        'lateral_movement': [
            r'psexec',
            r'wmi.*remote',
            r'ssh.*tunnel',
            r'rdp.*connection',
            r'lateral',
        ],
    }
    
    def parse(self, content: str, filename: str = "") -> List[ParsedEvent]:
        """Auto-detect format and parse log content."""
        ext = filename.lower().rsplit('.', 1)[-1] if '.' in filename else ''
        
        if ext == 'csv':
            return self.parse_csv(content)
        elif ext == 'json':
            return self.parse_json(content)
        elif ext == 'evtx':
            return []  # Binary format - need python-evtx library
        else:
            # Auto-detect text format
            return self._auto_parse_text(content, filename)
    
    def _auto_parse_text(self, content: str, filename: str) -> List[ParsedEvent]:
        """Auto-detect text log format and parse."""
        lines = content.strip().split('\n')
        if not lines:
            return []
        
        sample = '\n'.join(lines[:20])
        
        # Check for web server logs
        web_matches = sum(1 for line in lines[:50] if self.WEB_LOG_PATTERN.match(line))
        if web_matches > len(lines[:50]) * 0.5:
            return self.parse_apache('\n'.join(lines))
        
        # Check for syslog
        syslog_matches = sum(1 for line in lines[:50] if self.SYSLOG_PATTERN.match(line))
        if syslog_matches > len(lines[:50]) * 0.3:
            return self.parse_syslog('\n'.join(lines))
        
        # Check for firewall logs
        for fmt_name, pattern in self.FIREWALL_PATTERNS.items():
            fw_matches = sum(1 for line in lines[:50] if pattern.match(line))
            if fw_matches > len(lines[:50]) * 0.3:
                return self.parse_firewall('\n'.join(lines), fmt_name)
        
        # Fallback: generic line-by-line parsing
        return self.parse_generic('\n'.join(lines))
    
    def parse_apache(self, content: str) -> List[ParsedEvent]:
        """Parse Apache/Nginx combined log format."""
        events = []
        for line in content.strip().split('\n'):
            if not line.strip():
                continue
            match = self.WEB_LOG_PATTERN.match(line)
            if match:
                d = match.groupdict()
                status = int(d.get('status', 0))
                url = d.get('url', '')
                method = d.get('method', '')
                user_agent = d.get('user_agent', '')
                
                # Determine event type from request
                event_type = 'web_request'
                severity = 'INFO'
                
                combined = f"{url} {method} {user_agent}"
                for attack_type, patterns in self.ATTACK_PATTERNS.items():
                    for pat in patterns:
                        if re.search(pat, combined, re.IGNORECASE):
                            event_type = attack_type
                            severity = self._severity_for_attack(attack_type)
                            break
                
                # Status code based severity
                if status >= 500:
                    severity = 'HIGH'
                elif status == 403:
                    severity = 'MEDIUM'
                elif status == 404 and 'scan' in combined.lower():
                    severity = 'MEDIUM'
                
                events.append(ParsedEvent(
                    timestamp=self._parse_web_timestamp(d.get('timestamp', '')),
                    source_ip=d.get('ip', ''),
                    event_type=event_type,
                    severity=severity,
                    user=d.get('user', '-') or '',
                    url=url,
                    method=method,
                    status_code=status,
                    bytes_transferred=int(d.get('bytes', 0) or 0),
                    user_agent=user_agent,
                    message=line.strip(),
                    raw_line=line.strip(),
                    source_type='apache',
                ))
        return events
    
    def parse_syslog(self, content: str) -> List[ParsedEvent]:
        """Parse syslog format."""
        events = []
        for line in content.strip().split('\n'):
            match = self.SYSLOG_PATTERN.match(line)
            if match:
                d = match.groupdict()
                message = d.get('message', '')
                
                event_type = 'system_event'
                severity = 'INFO'
                
                for attack_type, patterns in self.ATTACK_PATTERNS.items():
                    for pat in patterns:
                        if re.search(pat, message, re.IGNORECASE):
                            event_type = attack_type
                            severity = self._severity_for_attack(attack_type)
                            break
                
                # Extract IPs from message
                ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', message)
                source_ip = ips[0] if ips else ''
                dest_ip = ips[1] if len(ips) > 1 else ''
                
                # Extract ports
                ports = re.findall(r'(?:port|dpt|spt)[=:\s]+(\d+)', message)
                
                events.append(ParsedEvent(
                    timestamp=self._parse_syslog_timestamp(d.get('timestamp', '')),
                    source_ip=source_ip,
                    dest_ip=dest_ip,
                    dest_port=int(ports[0]) if ports else 0,
                    event_type=event_type,
                    severity=severity,
                    message=message,
                    raw_line=line.strip(),
                    source_type='syslog',
                    metadata={'hostname': d.get('hostname', ''), 'program': d.get('program', '')},
                ))
        return events
    
    def parse_firewall(self, content: str, fmt: str = 'iptables') -> List[ParsedEvent]:
        """Parse firewall logs (iptables, pfSense, Cisco)."""
        events = []
        pattern = self.FIREWALL_PATTERNS.get(fmt)
        if not pattern:
            return events
        
        for line in content.strip().split('\n'):
            match = pattern.match(line)
            if match:
                d = match.groupdict()
                action = d.get('action', '').lower()
                
                event_type = 'firewall_event'
                severity = 'INFO'
                
                if action in ('drop', 'reject', 'block'):
                    severity = 'MEDIUM'
                    # Check if it's a known attack pattern
                    msg = line.lower()
                    for attack_type, patterns in self.ATTACK_PATTERNS.items():
                        for pat in patterns:
                            if re.search(pat, msg, re.IGNORECASE):
                                event_type = attack_type
                                severity = self._severity_for_attack(attack_type)
                                break
                
                events.append(ParsedEvent(
                    timestamp=d.get('timestamp', ''),
                    source_ip=d.get('src_ip', '') or d.get('ip', ''),
                    dest_ip=d.get('dst_ip', ''),
                    source_port=int(d.get('src_port', 0) or 0),
                    dest_port=int(d.get('dst_port', 0) or 0),
                    protocol=d.get('protocol', ''),
                    event_type=event_type,
                    severity=severity,
                    message=line.strip(),
                    raw_line=line.strip(),
                    source_type=f'firewall_{fmt}',
                    metadata={'action': action, 'rule': d.get('rule', '')},
                ))
        return events
    
    def parse_csv(self, content: str) -> List[ParsedEvent]:
        """Parse CSV log files."""
        events = []
        reader = csv.DictReader(io.StringIO(content))
        
        for row in reader:
            # Map common column names
            ts = row.get('timestamp', row.get('date', row.get('time', row.get('@timestamp', ''))))
            src_ip = row.get('source_ip', row.get('src_ip', row.get('source', row.get('ip', ''))))
            dst_ip = row.get('dest_ip', row.get('dst_ip', row.get('destination', '')))
            src_port = row.get('source_port', row.get('src_port', row.get('spt', '')))
            dst_port = row.get('dest_port', row.get('dst_port', row.get('dpt', row.get('port', ''))))
            proto = row.get('protocol', row.get('proto', ''))
            msg = row.get('message', row.get('description', row.get('log', '')))
            user = row.get('user', row.get('username', ''))
            event_type_raw = row.get('event_type', row.get('type', row.get('action', '')))
            severity_raw = row.get('severity', row.get('level', row.get('priority', '')))
            
            # Detect event type from all fields
            event_type = self._detect_event_type(str(row))
            severity = severity_raw.upper() if severity_raw else self._severity_for_attack(event_type)
            
            events.append(ParsedEvent(
                timestamp=ts,
                source_ip=str(src_ip),
                dest_ip=str(dst_ip),
                source_port=int(src_port) if src_port else 0,
                dest_port=int(dst_port) if dst_port else 0,
                protocol=str(proto),
                event_type=event_type,
                severity=severity,
                user=str(user),
                message=str(msg) or json.dumps(row, default=str),
                raw_line=json.dumps(row, default=str),
                source_type='csv',
                metadata={k: v for k, v in row.items() if v and k not in ['timestamp', 'date', 'time', 'source_ip', 'src_ip', 'dest_ip', 'dst_ip']},
            ))
        return events
    
    def parse_json(self, content: str) -> List[ParsedEvent]:
        """Parse JSON log files (single object or array)."""
        events = []
        try:
            data = json.loads(content)
            if isinstance(data, dict):
                data = [data]
            
            for item in data:
                ts = item.get('timestamp', item.get('@timestamp', item.get('time', item.get('date', ''))))
                src_ip = item.get('source_ip', item.get('src_ip', item.get('source', item.get('client_ip', item.get('remote_addr', '')))))
                dst_ip = item.get('dest_ip', item.get('dst_ip', item.get('destination', '')))
                src_port = item.get('source_port', item.get('src_port', item.get('spt', 0)))
                dst_port = item.get('dest_port', item.get('dst_port', item.get('dpt', item.get('port', 0))))
                proto = item.get('protocol', item.get('proto', ''))
                msg = item.get('message', item.get('description', item.get('log', item.get('msg', ''))))
                user = item.get('user', item.get('username', ''))
                url = item.get('url', item.get('path', item.get('request_uri', '')))
                method = item.get('method', item.get('http_method', ''))
                status = item.get('status', item.get('status_code', 0))
                ua = item.get('user_agent', item.get('useragent', item.get('http_user_agent', '')))
                
                event_type = self._detect_event_type(json.dumps(item, default=str))
                severity = item.get('severity', item.get('level', '')).upper() or self._severity_for_attack(event_type)
                
                events.append(ParsedEvent(
                    timestamp=str(ts),
                    source_ip=str(src_ip),
                    dest_ip=str(dst_ip),
                    source_port=int(src_port) if src_port else 0,
                    dest_port=int(dst_port) if dst_port else 0,
                    protocol=str(proto),
                    event_type=event_type,
                    severity=severity,
                    user=str(user),
                    url=str(url),
                    method=str(method),
                    status_code=int(status) if status else 0,
                    user_agent=str(ua),
                    message=str(msg) or json.dumps(item, default=str),
                    raw_line=json.dumps(item, default=str),
                    source_type='json',
                    metadata={k: v for k, v in item.items() if v},
                ))
        except json.JSONDecodeError:
            pass
        return events
    
    def parse_generic(self, content: str) -> List[ParsedEvent]:
        """Fallback parser for unrecognized formats."""
        events = []
        for line in content.strip().split('\n'):
            if not line.strip():
                continue
            
            event_type = self._detect_event_type(line)
            severity = self._severity_for_attack(event_type)
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
            ports = re.findall(r'(?:port|dpt|spt)[=:\s]+(\d+)', line)
            
            events.append(ParsedEvent(
                timestamp=datetime.now(timezone.utc).isoformat(),
                source_ip=ips[0] if ips else '',
                dest_ip=ips[1] if len(ips) > 1 else '',
                dest_port=int(ports[0]) if ports else 0,
                event_type=event_type,
                severity=severity,
                message=line.strip(),
                raw_line=line.strip(),
                source_type='generic',
            ))
        return events
    
    def _detect_event_type(self, text: str) -> str:
        """Detect attack/event type from text."""
        text_lower = text.lower()
        for attack_type, patterns in self.ATTACK_PATTERNS.items():
            for pat in patterns:
                if re.search(pat, text_lower):
                    return attack_type
        return 'info'
    
    def _severity_for_attack(self, attack_type: str) -> str:
        """Map attack type to severity."""
        severity_map = {
            'brute_force': 'HIGH',
            'port_scan': 'MEDIUM',
            'dos': 'CRITICAL',
            'ddos': 'CRITICAL',
            'web_attack': 'HIGH',
            'suspicious_auth': 'HIGH',
            'data_exfil': 'CRITICAL',
            'lateral_movement': 'CRITICAL',
            'credential_stuffing': 'HIGH',
            'beaconing': 'HIGH',
        }
        return severity_map.get(attack_type, 'INFO')
    
    def _parse_web_timestamp(self, ts: str) -> str:
        """Parse Apache timestamp format."""
        try:
            dt = datetime.strptime(ts, '%d/%b/%Y:%H:%M:%S %z')
            return dt.isoformat()
        except (ValueError, TypeError):
            return ts
    
    def _parse_syslog_timestamp(self, ts: str) -> str:
        """Parse syslog timestamp (no year)."""
        try:
            year = datetime.now().year
            dt = datetime.strptime(f"{year} {ts}", "%Y %b %d %H:%M:%S")
            return dt.isoformat()
        except (ValueError, TypeError):
            return ts


# Singleton
parser = LogParser()
