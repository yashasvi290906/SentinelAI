#!/usr/bin/env python3
"""
SentinelAI Agent - Log Collection Agent for Windows and Linux
Collects security events and sends them to SentinelAI server.
"""
import os
import sys
import json
import time
import uuid
import platform
import socket
import threading
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional
from collections import deque

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger('sentinel-agent')


class EventCollector:
    """Base class for event collection."""
    
    def __init__(self, config: Dict):
        self.config = config
    
    def collect(self) -> List[Dict[str, Any]]:
        raise NotImplementedError


class WindowsEventCollector(EventCollector):
    """Collect Windows Event Logs using wevtutil."""
    
    CHANNELS = {
        'Security': 'Security',
        'System': 'System',
        'Application': 'Application',
    }
    
    EVENT_IDS_DESCRIPTIONS = {
        4625: ('failed_login', 'HIGH'),
        4624: ('login', 'INFO'),
        4648: ('explicit_credentials', 'MEDIUM'),
        4720: ('account_created', 'MEDIUM'),
        4726: ('account_deleted', 'MEDIUM'),
        4732: ('group_membership_changed', 'MEDIUM'),
        7045: ('service_installed', 'HIGH'),
        4688: ('process_created', 'INFO'),
        4104: ('powershell_script', 'HIGH'),
        4103: ('powershell_module', 'MEDIUM'),
        5140: ('network_share_access', 'MEDIUM'),
        5156: ('network_connection', 'INFO'),
    }
    
    def collect(self) -> List[Dict[str, Any]]:
        events = []
        for channel_name in self.config.get('channels', ['Security']):
            try:
                channel_events = self._collect_channel(channel_name)
                events.extend(channel_events)
            except Exception as e:
                logger.warning(f"Failed to collect from {channel_name}: {e}")
        return events
    
    def _collect_channel(self, channel: str) -> List[Dict[str, Any]]:
        """Collect events from a Windows Event Log channel."""
        events = []
        event_ids = self.config.get('event_ids', [4625, 4624, 4648, 4720, 7045, 4688, 4104])
        
        # Build wevtutil query
        id_filter = " or ".join(f"EventID={eid}" for eid in event_ids)
        query = f'wevtutil qe {channel} /q:"*[System[{id_filter}]]" /c:50 /f:xml /rd:true'
        
        try:
            import subprocess
            result = subprocess.run(query, shell=True, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                return events
            
            # Parse XML output (simplified - in production use xml.etree)
            for line in result.stdout.split('<Event '):
                if '<EventID>' not in line:
                    continue
                event = self._parse_xml_event(line, channel)
                if event:
                    events.append(event)
        except Exception as e:
            logger.warning(f"wevtutil query failed for {channel}: {e}")
        
        return events
    
    def _parse_xml_event(self, xml: str, channel: str) -> Optional[Dict[str, Any]]:
        """Parse a single Windows event from XML."""
        import re
        
        event_id_match = re.search(r'<EventID>(\d+)</EventID>', xml)
        if not event_id_match:
            return None
        
        event_id = int(event_id_match.group(1))
        event_type, severity = self.EVENT_IDS_DESCRIPTIONS.get(event_id, ('unknown', 'INFO'))
        
        # Extract time
        time_match = re.search(r'<TimeCreated SystemTime="([^"]+)"', xml)
        timestamp = time_match.group(1) if time_match else datetime.now(timezone.utc).isoformat()
        
        # Extract data fields
        data = {}
        for match in re.finditer(r'<Data Name="([^"]+)">([^<]*)</Data>', xml):
            data[match.group(1)] = match.group(2)
        
        # Extract IP addresses
        source_ip = data.get('IpAddress', data.get('TargetUserName', ''))
        if source_ip and not self._is_valid_ip(source_ip):
            source_ip = ''
        
        message = self._build_message(event_id, data)
        
        return {
            'timestamp': timestamp,
            'source': 'windows',
            'hostname': socket.gethostname(),
            'source_ip': source_ip,
            'destination_ip': data.get('TargetDomainName', ''),
            'source_port': 0,
            'destination_port': 0,
            'protocol': '',
            'event_type': event_type,
            'severity': severity,
            'message': message,
            'raw_log': xml[:2000],
            'metadata': {
                'channel': channel,
                'event_id': event_id,
                'computer': data.get('Computer', ''),
                'user': data.get('TargetUserName', data.get('SubjectUserName', '')),
                'logon_id': data.get('LogonId', ''),
                'process_name': data.get('NewProcessName', data.get('ProcessName', '')),
                'service_name': data.get('ServiceName', ''),
            }
        }
    
    def _build_message(self, event_id: int, data: Dict) -> str:
        if event_id == 4625:
            return f"Failed login for {data.get('TargetUserName', '?')} from {data.get('IpAddress', '?')} (Logon Type: {data.get('LogonType', '?')})"
        elif event_id == 4624:
            return f"Successful login for {data.get('TargetUserName', '?')} from {data.get('IpAddress', '?')} (Logon Type: {data.get('LogonType', '?')})"
        elif event_id == 4648:
            return f"Explicit credential logon for {data.get('TargetUserName', '?')} by {data.get('SubjectUserName', '?')}"
        elif event_id == 4720:
            return f"User account created: {data.get('TargetUserName', '?')}"
        elif event_id == 4726:
            return f"User account deleted: {data.get('TargetUserName', '?')}"
        elif event_id == 7045:
            return f"Service installed: {data.get('ServiceName', '?')} ({data.get('ImagePath', '?')})"
        elif event_id == 4688:
            return f"Process created: {data.get('NewProcessName', '?')}"
        elif event_id == 4104:
            return f"PowerShell script block: {data.get('ScriptBlockText', '?')[:200]}"
        return f"Event {event_id}: {json.dumps(data)[:200]}"
    
    def _is_valid_ip(self, ip: str) -> bool:
        import re
        return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip))


class LinuxEventCollector(EventCollector):
    """Collect Linux syslog and auth events."""
    
    LOG_PATTERNS = {
        'auth': {
            'failed_password': ('failed_login', 'HIGH'),
            'authentication failure': ('auth_failure', 'HIGH'),
            'invalid user': ('invalid_user', 'HIGH'),
            'Accepted password': ('login_success', 'INFO'),
            'Accepted publickey': ('login_success', 'INFO'),
            'sudo': ('sudo_usage', 'MEDIUM'),
            'session opened': ('session_opened', 'INFO'),
            'session closed': ('session_closed', 'INFO'),
        },
        'syslog': {
            'kernel:': ('kernel_event', 'LOW'),
            'sshd': ('ssh_event', 'MEDIUM'),
            'firewall': ('firewall_event', 'MEDIUM'),
        },
        'kern': {
            'DROP': ('packet_dropped', 'MEDIUM'),
            'REJECT': ('packet_rejected', 'MEDIUM'),
            'ACCEPT': ('packet_accepted', 'LOW'),
        }
    }
    
    def __init__(self, config: Dict):
        super().__init__(config)
        self._file_offsets: Dict[str, int] = {}
    
    def collect(self) -> List[Dict[str, Any]]:
        events = []
        log_files = self.config.get('log_files', ['/var/log/auth.log', '/var/log/syslog'])
        
        for log_file in log_files:
            try:
                file_events = self._collect_log_file(log_file)
                events.extend(file_events)
            except FileNotFoundError:
                pass
            except Exception as e:
                logger.warning(f"Failed to collect {log_file}: {e}")
        
        return events
    
    def _collect_log_file(self, filepath: str) -> List[Dict[str, Any]]:
        events = []
        path = Path(filepath)
        
        if not path.exists():
            return events
        
        # Track file position for incremental reading
        last_offset = self._file_offsets.get(filepath, 0)
        
        try:
            with open(path, 'r', errors='ignore') as f:
                f.seek(last_offset)
                
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    event = self._parse_log_line(line, filepath)
                    if event:
                        events.append(event)
                
                self._file_offsets[filepath] = f.tell()
        except PermissionError:
            logger.warning(f"Permission denied: {filepath}")
        
        return events
    
    def _parse_log_line(self, line: str, filepath: str) -> Optional[Dict[str, Any]]:
        import re
        
        # Extract timestamp (simplified syslog format)
        ts_match = re.match(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', line)
        timestamp = ''
        if ts_match:
            try:
                year = datetime.now().year
                dt = datetime.strptime(f"{year} {ts_match.group(1)}", "%Y %b %d %H:%M:%S")
                timestamp = dt.isoformat()
            except ValueError:
                timestamp = datetime.now(timezone.utc).isoformat()
        else:
            timestamp = datetime.now(timezone.utc).isoformat()
        
        # Extract hostname and process
        parts = line.split(None, 5)
        hostname = parts[2] if len(parts) > 2 else socket.gethostname()
        process = parts[4].rstrip(':') if len(parts) > 4 else ''
        
        # Determine event type and severity
        event_type = 'system_event'
        severity = 'INFO'
        
        line_lower = line.lower()
        for category, patterns in self.LOG_PATTERNS.items():
            for pattern, (etype, sev) in patterns.items():
                if pattern.lower() in line_lower:
                    event_type = etype
                    severity = sev
                    break
        
        # Extract IPs
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
        source_ip = ips[0] if ips else ''
        
        # Extract user
        user_match = re.search(r'for\s+(?:invalid\s+user\s+)?(\S+)\s+from', line)
        user = user_match.group(1) if user_match else ''
        
        return {
            'timestamp': timestamp,
            'source': 'linux',
            'hostname': hostname,
            'source_ip': source_ip,
            'destination_ip': '',
            'source_port': 0,
            'destination_port': 0,
            'protocol': '',
            'event_type': event_type,
            'severity': severity,
            'message': line[:500],
            'raw_log': line[:2000],
            'metadata': {
                'log_file': filepath,
                'process': process,
                'user': user,
            }
        }


class SentinelAgent:
    """Main agent that collects events and sends to server."""
    
    def __init__(self, config_path: str = None):
        self.config = self._load_config(config_path)
        self.agent_config = self.config.get('agent', {})
        self.server_config = self.config.get('server', {})
        
        # Generate or load device ID
        self.device_id = self.agent_config.get('device_id', '') or self._get_or_create_device_id()
        self.hostname = self.agent_config.get('hostname', '') or socket.gethostname()
        self.org_id = self.agent_config.get('organization_id', '')
        
        # Event buffer
        self._buffer: deque = deque(maxlen=10000)
        self._running = False
        
        # Initialize collectors
        self._collectors = []
        self._init_collectors()
        
        logger.info(f"SentinelAI Agent initialized: device={self.device_id}, host={self.hostname}")
    
    def _load_config(self, config_path: str = None) -> Dict:
        if config_path and Path(config_path).exists():
            import yaml
            with open(config_path) as f:
                return yaml.safe_load(f)
        
        # Try default locations
        for path in ['config.yaml', 'sentinel-agent.yaml', os.path.expanduser('~/.sentinel-agent/config.yaml')]:
            if Path(path).exists():
                import yaml
                with open(path) as f:
                    return yaml.safe_load(f)
        
        return {'server': {'url': 'http://localhost:8000'}, 'agent': {}, 'collection': {}}
    
    def _get_or_create_device_id(self) -> str:
        id_file = Path.home() / '.sentinel-agent' / 'device_id'
        id_file.parent.mkdir(parents=True, exist_ok=True)
        
        if id_file.exists():
            return id_file.read_text().strip()
        
        device_id = str(uuid.uuid4())
        id_file.write_text(device_id)
        return device_id
    
    def _init_collectors(self):
        collection = self.config.get('collection', {})
        system = platform.system().lower()
        
        if system == 'windows' and collection.get('windows', {}).get('enabled', True):
            self._collectors.append(WindowsEventCollector(collection.get('windows', {})))
            logger.info("Windows event collector enabled")
        
        elif system == 'linux' and collection.get('linux', {}).get('enabled', True):
            self._collectors.append(LinuxEventCollector(collection.get('linux', {})))
            logger.info("Linux event collector enabled")
        
        if not self._collectors:
            logger.warning(f"No collectors enabled for platform: {system}")
    
    def collect_once(self) -> List[Dict]:
        """Collect events once."""
        all_events = []
        for collector in self._collectors:
            try:
                events = collector.collect()
                all_events.extend(events)
            except Exception as e:
                logger.error(f"Collection error: {e}")
        return all_events
    
    def send_events(self, events: List[Dict]) -> bool:
        """Send events to SentinelAI server."""
        if not events:
            return True
        
        url = f"{self.server_config.get('url', 'http://localhost:8000')}/ingest/batch"
        payload = {
            "events": [{
                **e,
                "device_id": self.device_id,
                "hostname": self.hostname,
                "organization_id": self.org_id,
            } for e in events],
            "device_id": self.device_id,
            "organization_id": self.org_id,
        }
        
        headers = {"Content-Type": "application/json"}
        api_key = self.server_config.get('api_key', '')
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        
        for attempt in range(self.server_config.get('retry_count', 3)):
            try:
                resp = requests.post(url, json=payload, headers=headers, 
                                   timeout=self.server_config.get('timeout', 30))
                if resp.status_code == 200:
                    logger.info(f"Sent {len(events)} events successfully")
                    return True
                else:
                    logger.warning(f"Server returned {resp.status_code}: {resp.text[:200]}")
            except requests.exceptions.ConnectionError:
                logger.warning(f"Connection failed (attempt {attempt + 1})")
            except Exception as e:
                logger.error(f"Send error: {e}")
            
            time.sleep(self.server_config.get('retry_delay', 5))
        
        return False
    
    def run(self):
        """Run the agent in continuous collection mode."""
        self._running = True
        batch_size = self.agent_config.get('batch_size', 50)
        flush_interval = self.agent_config.get('flush_interval', 10)
        
        logger.info(f"Starting collection loop (batch={batch_size}, interval={flush_interval}s)")
        
        last_flush = time.time()
        
        while self._running:
            try:
                events = self.collect_once()
                self._buffer.extend(events)
                
                # Flush if batch is full or interval elapsed
                now = time.time()
                if len(self._buffer) >= batch_size or (now - last_flush) >= flush_interval:
                    batch = []
                    while self._buffer and len(batch) < batch_size:
                        batch.append(self._buffer.popleft())
                    
                    if batch:
                        self.send_events(batch)
                    
                    last_flush = now
                
                time.sleep(1)
            
            except KeyboardInterrupt:
                logger.info("Agent stopped by user")
                self._running = False
            except Exception as e:
                logger.error(f"Collection loop error: {e}")
                time.sleep(5)
    
    def stop(self):
        self._running = False


def main():
    import argparse
    parser = argparse.ArgumentParser(description='SentinelAI Log Collection Agent')
    parser.add_argument('--config', '-c', help='Path to config.yaml')
    parser.add_argument('--once', action='store_true', help='Collect once and exit')
    parser.add_argument('--test', action='store_true', help='Test connection to server')
    args = parser.parse_args()
    
    agent = SentinelAgent(args.config)
    
    if args.test:
        url = f"{agent.server_config.get('url', 'http://localhost:8000')}/health"
        try:
            resp = requests.get(url, timeout=5)
            print(f"Server connection: OK ({resp.status_code})")
            print(f"Device ID: {agent.device_id}")
            print(f"Hostname: {agent.hostname}")
        except Exception as e:
            print(f"Server connection: FAILED ({e})")
        return
    
    if args.once:
        events = agent.collect_once()
        print(f"Collected {len(events)} events")
        for e in events[:10]:
            print(f"  [{e['severity']}] {e['event_type']}: {e['message'][:80]}")
        if events:
            agent.send_events(events)
        return
    
    agent.run()


if __name__ == '__main__':
    main()