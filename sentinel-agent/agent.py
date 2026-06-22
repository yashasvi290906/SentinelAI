"""
SentinelAI Agent — Real endpoint telemetry collector.
Runs as a Windows service or systemd unit.
Collects OS-native logs, detects threats locally, and ships events to the SentinelAI backend.
"""

import sys
import os
import time
import json
import uuid
import logging
import hashlib
import platform
import threading
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List, Any

import requests
import yaml

# ─── Configuration ────────────────────────────────────────────────────────────

CONFIG_FILE = Path(__file__).parent / "config.yaml"
STATE_FILE = Path(__file__).parent / "agent_state.json"

DEFAULT_CONFIG = {
    "server_url": "http://127.0.0.1:8000",
    "agent_token": "",
    "batch_size": 20,
    "flush_interval_seconds": 15,
    "collectors": {
        "windows": {
            "enabled": True,
            "channels": ["Security", "System", "Application"],
            "event_ids": [
                4625,  # Failed logon
                4624,  # Successful logon
                4648,  # Logon with explicit credentials
                4720,  # User account created
                4726,  # User account deleted
                4728,  # Member added to security group
                4732,  # Member added to local group
                7045,  # Service installed
                4688,  # New process created
                4104,  # PowerShell script block
                4697,  # Service installed
                1102,  # Audit log cleared
            ],
            "poll_interval_seconds": 30,
        },
        "linux": {
            "enabled": True,
            "files": [
                "/var/log/auth.log",
                "/var/log/syslog",
                "/var/log/kern.log",
                "/var/log/sudo.log",
                "/var/log/secure",
            ],
            "process_commands": True,
            "poll_interval_seconds": 30,
        },
    },
}

logger = logging.getLogger("sentinelai.agent")


# ─── State Persistence ────────────────────────────────────────────────────────

class AgentState:
    """Persists collector offsets and device ID across restarts."""

    def __init__(self, state_path: Path = STATE_FILE):
        self.state_path = state_path
        self.data: Dict[str, Any] = {
            "device_id": str(uuid.uuid4()),
            "file_offsets": {},
            "last_event_record_ids": {},
            "events_shipped": 0,
            "start_time": datetime.now(timezone.utc).isoformat(),
        }
        self._load()

    def _load(self):
        if self.state_path.exists():
            try:
                with open(self.state_path, "r") as f:
                    saved = json.load(f)
                    self.data.update(saved)
            except Exception:
                pass

    def save(self):
        try:
            with open(self.state_path, "w") as f:
                json.dump(self.data, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save state: {e}")

    def get_offset(self, source: str) -> int:
        return self.data.get("file_offsets", {}).get(source, 0)

    def set_offset(self, source: str, offset: int):
        self.data.setdefault("file_offsets", {})[source] = offset

    def get_event_record_id(self, channel: str) -> int:
        return self.data.get("last_event_record_ids", {}).get(channel, 0)

    def set_event_record_id(self, channel: str, record_id: int):
        self.data.setdefault("last_event_record_ids", {})[channel] = record_id


# ─── Local Threat Detection ──────────────────────────────────────────────────

class LocalDetector:
    """Lightweight local detection for high-severity events that should alert immediately."""

    RULES = [
        {
            "name": "failed_logon_bruteforce",
            "description": "Multiple failed logon attempts detected",
            "severity": "HIGH",
            "condition": lambda events: _count_by_type(events, "failed_logon") >= 5,
            "mitre_technique": "T1110",
            "mitre_tactic": "credential-access",
        },
        {
            "name": "service_installed",
            "description": "New service installed on system",
            "severity": "MEDIUM",
            "condition": lambda events: any(e.get("event_type") == "service_install" for e in events),
            "mitre_technique": "T1543",
            "mitre_tactic": "persistence",
        },
        {
            "name": "powershell_script_block",
            "description": "PowerShell script execution detected",
            "severity": "MEDIUM",
            "condition": lambda events: any(e.get("event_type") == "powershell_execution" for e in events),
            "mitre_technique": "T1059.001",
            "mitre_tactic": "execution",
        },
        {
            "name": "audit_log_cleared",
            "description": "Security audit log was cleared",
            "severity": "CRITICAL",
            "condition": lambda events: any(e.get("event_type") == "audit_cleared" for e in events),
            "mitre_technique": "T1070.001",
            "mitre_tactic": "defense-evasion",
        },
        {
            "name": "user_account_created",
            "description": "New user account created",
            "severity": "MEDIUM",
            "condition": lambda events: any(e.get("event_type") == "user_created" for e in events),
            "mitre_technique": "T1136.001",
            "mitre_tactic": "persistence",
        },
        {
            "name": "ssh_bruteforce",
            "description": "Multiple failed SSH login attempts",
            "severity": "HIGH",
            "condition": lambda events: _count_by_type(events, "ssh_failed") >= 5,
            "mitre_technique": "T1110.004",
            "mitre_tactic": "credential-access",
        },
        {
            "name": "sudo_usage",
            "description": "Sudo command executed",
            "severity": "LOW",
            "condition": lambda events: any(e.get("event_type") == "sudo_command" for e in events),
            "mitre_technique": "T1548.003",
            "mitre_tactic": "privilege-escalation",
        },
    ]

    def detect(self, events: List[Dict]) -> List[Dict]:
        triggered = []
        for rule in self.RULES:
            try:
                if rule["condition"](events):
                    triggered.append({
                        "rule": rule["name"],
                        "severity": rule["severity"],
                        "description": rule["description"],
                        "mitre_technique": rule["mitre_technique"],
                        "mitre_tactic": rule["mitre_tactic"],
                        "event_count": len(events),
                    })
            except Exception:
                pass
        return triggered


def _count_by_type(events: List[Dict], event_type: str) -> int:
    return sum(1 for e in events if e.get("event_type") == event_type)


# ─── Windows Event Collector ─────────────────────────────────────────────────

class WindowsCollector:
    """Collects Windows Event Logs via PowerShell wevtutil."""

    EVENT_TYPE_MAP = {
        4625: "failed_logon",
        4624: "successful_logon",
        4648: "explicit_logon",
        4720: "user_created",
        4726: "user_deleted",
        4728: "group_member_added",
        4732: "local_group_member_added",
        7045: "service_install",
        4688: "process_created",
        4104: "powershell_execution",
        4697: "service_installed",
        1102: "audit_cleared",
    }

    def __init__(self, config: Dict, state: AgentState):
        self.config = config
        self.state = state
        self.channels = config.get("channels", ["Security"])
        self.event_ids = config.get("event_ids", [4625, 4624, 4688])

    def collect(self) -> List[Dict]:
        events = []
        for channel in self.channels:
            try:
                events.extend(self._read_channel(channel))
            except Exception as e:
                logger.warning(f"Failed to read channel {channel}: {e}")
        return events

    def _read_channel(self, channel: str) -> List[Dict]:
        last_id = self.state.get_event_record_id(channel)
        event_id_filter = ",".join(str(eid) for eid in self.event_ids)

        # Query for new events since last seen record ID
        query = (
            f'wevtutil qe {channel} /q:"*[System[EventID[{event_id_filter}] '
            f'and EventRecordID>{last_id}]]" /c:100 /f:xml /rd:true'
        )

        try:
            import subprocess
            result = subprocess.run(
                ["powershell", "-Command", query],
                capture_output=True, text=True, timeout=30,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if result.returncode != 0 or not result.stdout.strip():
                return []

            return self._parse_xml_output(result.stdout, channel)
        except Exception as e:
            logger.warning(f"wevtutil query failed for {channel}: {e}")
            return []

    def _parse_xml_output(self, xml_output: str, channel: str) -> List[Dict]:
        import xml.etree.ElementTree as ET

        events = []
        max_record_id = self.state.get_event_record_id(channel)

        # Split by Event tags
        for event_block in xml_output.split("<Event "):
            if not event_block.strip():
                continue
            try:
                xml_str = "<Event " + event_block
                if not xml_str.rstrip().endswith("</Event>"):
                    xml_str += "</Event>"
                root = ET.fromstring(xml_str)

                system = root.find("System")
                if system is None:
                    continue

                event_id_el = system.find("EventID")
                record_id_el = system.find("EventRecordID")
                time_created_el = system.find("TimeCreated")

                if event_id_el is None or record_id_el is None:
                    continue

                event_id = int(event_id_el.text)
                record_id = int(record_id_el.text)
                timestamp = time_created_el.get("SystemTime", "") if time_created_el is not None else ""

                if record_id <= max_record_id:
                    continue

                max_record_id = max(max_record_id, record_id)

                # Extract data from EventData
                event_data = {}
                data_el = root.find("EventData")
                if data_el is not None:
                    for data_item in data_el.findall("Data"):
                        name = data_item.get("Name", "")
                        value = data_item.text or ""
                        event_data[name] = value

                # Map to standard fields
                event_type = self.EVENT_TYPE_MAP.get(event_id, f"event_{event_id}")
                source_ip = event_data.get("IpAddress", event_data.get("IpAddress", ""))
                target_user = event_data.get("TargetUserName", event_data.get("SubjectUserName", ""))
                source_user = event_data.get("SubjectUserName", "")
                logon_type = event_data.get("LogonType", "")
                process_name = event_data.get("NewProcessName", event_data.get("Image", ""))
                command_line = event_data.get("CommandLine", "")
                service_name = event_data.get("ServiceName", "")
                service_file = event_data.get("ImagePath", "")

                events.append({
                    "event_type": event_type,
                    "event_id": event_id,
                    "timestamp": timestamp,
                    "source_ip": source_ip.strip() if source_ip else "",
                    "user": target_user.strip() if target_user else "",
                    "source_user": source_user.strip() if source_user else "",
                    "logon_type": logon_type,
                    "process_name": process_name,
                    "command_line": command_line,
                    "service_name": service_name,
                    "service_file": service_file,
                    "channel": channel,
                    "raw": f"EventID={event_id} User={target_user} IP={source_ip}",
                })

            except ET.ParseError:
                continue
            except Exception as e:
                logger.debug(f"Parse error: {e}")
                continue

        self.state.set_event_record_id(channel, max_record_id)
        return events


# ─── Linux Log Collector ─────────────────────────────────────────────────────

class LinuxCollector:
    """Collects Linux logs via file polling with offset tracking."""

    PATTERNS = [
        {
            "pattern": r"Failed password for (\w+) from ([\d.]+)",
            "event_type": "failed_logon",
            "extract": {"user": 1, "source_ip": 2},
        },
        {
            "pattern": r"Accepted (\w+) for (\w+) from ([\d.]+)",
            "event_type": "successful_logon",
            "extract": {"auth_method": 1, "user": 2, "source_ip": 3},
        },
        {
            "pattern": r"session opened for user (\w+) by \(uid=(\d+)\)",
            "event_type": "session_opened",
            "extract": {"user": 1, "uid": 2},
        },
        {
            "pattern": r"sudo:\s+(\w+)\s*:\s*COMMAND=(.+)",
            "event_type": "sudo_command",
            "extract": {"user": 1, "command": 2},
        },
        {
            "pattern": r"sshd\[\d+\]: Failed password for (.+) from ([\d.]+)",
            "event_type": "ssh_failed",
            "extract": {"user": 1, "source_ip": 2},
        },
        {
            "pattern": r"sshd\[\d+\]: Accepted (\w+) for (.+) from ([\d.]+)",
            "event_type": "ssh_accepted",
            "extract": {"auth_method": 1, "user": 2, "source_ip": 3},
        },
        {
            "pattern": r"kernel:\s*\[.*\]\s*(.+)",
            "event_type": "kernel_message",
            "extract": {"message": 1},
        },
    ]

    def __init__(self, config: Dict, state: AgentState):
        self.config = config
        self.state = state
        self.files = config.get("files", ["/var/log/auth.log", "/var/log/syslog"])

    def collect(self) -> List[Dict]:
        import re
        events = []

        for log_file in self.files:
            try:
                events.extend(self._read_file(log_file, re))
            except FileNotFoundError:
                pass
            except Exception as e:
                logger.warning(f"Failed to read {log_file}: {e}")

        return events

    def _read_file(self, log_file: str, re_module) -> List[Dict]:
        offset = self.state.get_offset(log_file)
        events = []

        with open(log_file, "r", errors="replace") as f:
            f.seek(offset)
            for line_num, line in enumerate(f, start=1):
                for pat_info in self.PATTERNS:
                    match = re_module.search(pat_info["pattern"], line)
                    if match:
                        event_data = {"line": line.strip()}
                        for field_name, group_idx in pat_info["extract"].items():
                            try:
                                event_data[field_name] = match.group(group_idx)
                            except (IndexError, ValueError):
                                event_data[field_name] = ""

                        events.append({
                            "event_type": pat_info["event_type"],
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "source_ip": event_data.get("source_ip", ""),
                            "user": event_data.get("user", ""),
                            "command": event_data.get("command", ""),
                            "auth_method": event_data.get("auth_method", ""),
                            "log_file": log_file,
                            "raw": line.strip()[:500],
                        })
                        break

            new_offset = f.tell()
        self.state.set_offset(log_file, new_offset)
        return events


# ─── Suricata IDS/IPS Log Collector ─────────────────────────────────────────

class SuricataCollector:
    """Collects Suricata eve.json alerts and flow logs."""

    def __init__(self, config: Dict, state: AgentState):
        self.config = config
        self.state = state
        self.eve_path = config.get("eve_json_path", "/var/log/suricata/eve.json")
        self.alert_types = set(config.get("alert_types", ["alert", "anomaly", "dns", "http", "tls", "flow"]))

    def collect(self) -> List[Dict]:
        events = []
        offset = self.state.get_offset("suricata_eve")
        try:
            with open(self.eve_path, "r", errors="replace") as f:
                f.seek(offset)
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        event_type = entry.get("event_type", "")
                        if event_type not in self.alert_types:
                            continue

                        ts = entry.get("timestamp", datetime.now(timezone.utc).isoformat())
                        src_ip = entry.get("src_ip", "")
                        dest_ip = entry.get("dest_ip", "")
                        src_port = entry.get("src_port", 0)
                        dest_port = entry.get("dest_port", 0)
                        proto = entry.get("proto", "")

                        severity = "INFO"
                        description = ""
                        if event_type == "alert":
                            alert = entry.get("alert", {})
                            description = alert.get("signature", "")
                            sev = alert.get("severity", 3)
                            severity = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM"}.get(sev, "LOW")
                        elif event_type == "dns":
                            dns = entry.get("dns", {})
                            rrname = dns.get("rrname", "")
                            rrtype = dns.get("rrtype", "")
                            description = f"DNS {rrtype}: {rrname}"
                        elif event_type == "http":
                            http = entry.get("http", {})
                            description = f"HTTP {http.get('method', '')} {http.get('hostname', '')}{http.get('url', '')}"
                        elif event_type == "tls":
                            tls = entry.get("tls", {})
                            description = f"TLS {tls.get('sni', '')} JA3={tls.get('ja3', {}).get('hash', '')[:16]}"
                        elif event_type == "flow":
                            flow = entry.get("flow", {})
                            description = f"Flow {flow.get('pkts_toserver', 0)}→{flow.get('pkts_toclient', 0)} bytes"

                        events.append({
                            "event_type": f"suricata_{event_type}",
                            "timestamp": ts,
                            "source_ip": src_ip,
                            "dest_ip": dest_ip,
                            "source_port": src_port,
                            "dest_port": dest_port,
                            "protocol": proto,
                            "description": description,
                            "severity": severity,
                            "raw": line[:500],
                        })
                    except json.JSONDecodeError:
                        continue
                    except Exception:
                        continue
                new_offset = f.tell()
            self.state.set_offset("suricata_eve", new_offset)
        except FileNotFoundError:
            pass
        except Exception as e:
            logger.warning(f"Suricata collection error: {e}")
        return events


# ─── Event Shipper ────────────────────────────────────────────────────────────

class EventShipper:
    """Batches events and ships them to the SentinelAI backend."""

    def __init__(self, server_url: str, agent_token: str, batch_size: int = 20):
        self.server_url = server_url.rstrip("/")
        self.agent_token = agent_token
        self.batch_size = batch_size
        self.buffer: List[Dict] = []
        self.lock = threading.Lock()

    def add_events(self, events: List[Dict]):
        with self.lock:
            self.buffer.extend(events)
            if len(self.buffer) >= self.batch_size:
                self._flush()

    def _flush(self):
        if not self.buffer:
            return

        batch = self.buffer[:self.batch_size]
        self.buffer = self.buffer[self.batch_size:]

        headers = {"Content-Type": "application/json"}
        if self.agent_token:
            headers["Authorization"] = f"Bearer {self.agent_token}"

        payload = {"events": [
            {
                "event_type": e.get("event_type", "unknown"),
                "source": e.get("channel", e.get("log_file", "agent")),
                "message": e.get("raw", ""),
                "severity": "MEDIUM",
                "timestamp": e.get("timestamp", datetime.now(timezone.utc).isoformat()),
                "source_ip": e.get("source_ip", ""),
                "dest_ip": "",
                "user": e.get("user", ""),
            }
            for e in batch
        ]}

        try:
            resp = requests.post(
                f"{self.server_url}/ingest/batch",
                json=payload,
                headers=headers,
                timeout=10,
            )
            if resp.status_code == 200:
                logger.info(f"Shipped {len(batch)} events to backend")
            else:
                logger.warning(f"Ship failed ({resp.status_code}): {resp.text[:200]}")
                # Re-queue on failure
                with self.lock:
                    self.buffer = batch + self.buffer
        except requests.RequestException as e:
            logger.warning(f"Ship connection error: {e}")
            with self.lock:
                self.buffer = batch + self.buffer

    def force_flush(self):
        with self.lock:
            self._flush()


# ─── Main Agent Loop ─────────────────────────────────────────────────────────

class SentinelAgent:
    """Main agent orchestrator."""

    def __init__(self, config_path: Path = CONFIG_FILE):
        self.config = self._load_config(config_path)
        self.state = AgentState()
        self.detector = LocalDetector()
        self.shipper = EventShipper(
            server_url=self.config["server_url"],
            agent_token=self.config.get("agent_token", ""),
            batch_size=self.config.get("batch_size", 20),
        )
        self.collectors = []
        self._init_collectors()
        self._running = False

    def _load_config(self, path: Path) -> Dict:
        if path.exists():
            with open(path, "r") as f:
                user_config = yaml.safe_load(f) or {}
                config = {**DEFAULT_CONFIG, **user_config}
                # Deep merge collectors
                if "collectors" in user_config:
                    for collector_type, collector_conf in user_config["collectors"].items():
                        if collector_type in config["collectors"]:
                            config["collectors"][collector_type] = {
                                **config["collectors"][collector_type],
                                **collector_conf,
                            }
                return config
        return DEFAULT_CONFIG.copy()

    def _init_collectors(self):
        system = platform.system()
        collector_config = self.config.get("collectors", {})

        if system == "Windows" and collector_config.get("windows", {}).get("enabled", True):
            self.collectors.append(("windows", WindowsCollector(collector_config["windows"], self.state)))
            logger.info("Windows collector initialized")

        elif system == "Linux" and collector_config.get("linux", {}).get("enabled", True):
            self.collectors.append(("linux", LinuxCollector(collector_config["linux"], self.state)))
            logger.info("Linux collector initialized")

        # Suricata collector (cross-platform)
        if collector_config.get("suricata", {}).get("enabled", False):
            self.collectors.append(("suricata", SuricataCollector(collector_config["suricata"], self.state)))
            logger.info("Suricata collector initialized")

        if not self.collectors:
            logger.warning(f"No collectors available for platform: {system}")

    def register_device(self) -> Optional[str]:
        """Register this agent's device with the backend."""
        hostname = platform.node()
        ip_address = self._get_local_ip()
        os_type = platform.system().lower()

        try:
            resp = requests.post(
                f"{self.config['server_url']}/api/devices/register",
                json={
                    "hostname": hostname,
                    "ip_address": ip_address,
                    "os_type": os_type,
                },
                timeout=10,
            )
            if resp.status_code == 200:
                device_id = resp.json().get("device_id", self.state.data["device_id"])
                self.state.data["device_id"] = device_id
                self.state.save()
                logger.info(f"Device registered: {device_id} ({hostname})")
                return device_id
        except requests.RequestException as e:
            logger.warning(f"Device registration failed: {e}")
        return self.state.data["device_id"]

    def _get_local_ip(self) -> str:
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def run_once(self):
        """Single collection cycle."""
        all_events = []
        for name, collector in self.collectors:
            try:
                events = collector.collect()
                all_events.extend(events)
                if events:
                    logger.info(f"[{name}] Collected {len(events)} events")
            except Exception as e:
                logger.error(f"[{name}] Collection error: {e}")

        if all_events:
            # Local detection
            detections = self.detector.detect(all_events)
            if detections:
                for det in detections:
                    logger.warning(f"LOCAL DETECTION: {det['severity']} — {det['description']}")

            # Ship to backend
            self.shipper.add_events(all_events)
            self.state.data["events_shipped"] = (
                self.state.data.get("events_shipped", 0) + len(all_events)
            )
            self.state.save()

    def run_forever(self):
        """Continuous collection loop."""
        self._running = True
        poll_interval = self.config.get("collectors", {}).get("windows", {}).get(
            "poll_interval_seconds",
            self.config.get("collectors", {}).get("linux", {}).get("poll_interval_seconds", 30),
        )
        flush_interval = self.config.get("flush_interval_seconds", 15)

        logger.info(f"SentinelAI Agent started (poll={poll_interval}s, flush={flush_interval}s)")
        self.register_device()

        last_flush = time.time()
        try:
            while self._running:
                self.run_once()

                # Periodic flush
                if time.time() - last_flush >= flush_interval:
                    self.shipper.force_flush()
                    last_flush = time.time()

                time.sleep(poll_interval)
        except KeyboardInterrupt:
            logger.info("Agent stopped by user")
        finally:
            self.shipper.force_flush()
            self.state.save()

    def stop(self):
        self._running = False


# ─── Windows Service Entry Point ──────────────────────────────────────────────

def run_as_windows_service():
    """Entry point for running as a Windows service via pywin32."""
    try:
        import win32serviceutil
        import win32service
        import win32event
        import servicemanager

        class SentinelService(win32serviceutil.ServiceFramework):
            _svc_name_ = "SentinelAIAgent"
            _svc_display_name_ = "SentinelAI Endpoint Agent"
            _svc_description_ = "Collects OS telemetry and ships to SentinelAI backend"

            def __init__(self, args):
                win32serviceutil.ServiceFramework.__init__(self, args)
                self.stop_event = win32event.CreateEvent(None, 0, 0, None)
                self.agent = None

            def SvcStop(self):
                self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
                if self.agent:
                    self.agent.stop()
                win32event.SetEvent(self.stop_event)

            def SvcDoRun(self):
                servicemanager.LogMsg(
                    servicemanager.EVENTLOG_INFORMATION_TYPE,
                    servicemanager.PYS_SERVICE_STARTED,
                    (self._svc_name_, ""),
                )
                self.agent = SentinelAgent()
                self.agent.run_forever()

        if len(sys.argv) == 1:
            servicemanager.PrepareToHostSingle(SentinelService)
            servicemanager.StartServiceCtrlDispatcher()
        else:
            win32serviceutil.HandleCommandLine(SentinelService)

    except ImportError:
        logger.error("pywin32 not installed. Run: pip install pywin32")
        logger.info("Falling back to console mode")
        agent = SentinelAgent()
        agent.run_forever()


# ─── Linux Systemd Entry Point ────────────────────────────────────────────────

SYSTEMD_UNIT = """[Unit]
Description=SentinelAI Endpoint Agent
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart={python_path} {agent_path} --daemon
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=sentinelai-agent
Environment=PYTHONUNBUFFERED=1

# Security hardening
NoNewPrivileges=no
ProtectSystem=false
ProtectHome=false

[Install]
WantedBy=multi-user.target
"""


def install_systemd_service():
    """Install the agent as a systemd service on Linux."""
    import subprocess

    python_path = sys.executable
    agent_path = str(Path(__file__).resolve())
    unit_content = SYSTEMD_UNIT.format(python_path=python_path, agent_path=agent_path)

    unit_path = Path("/etc/systemd/system/sentinelai-agent.service")
    try:
        with open(unit_path, "w") as f:
            f.write(unit_content)

        subprocess.run(["systemctl", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "enable", "sentinelai-agent"], check=True)
        subprocess.run(["systemctl", "start", "sentinelai-agent"], check=True)

        print(f"Service installed: {unit_path}")
        print("  systemctl status sentinelai-agent")
        print("  systemctl stop sentinelai-agent")
        print("  journalctl -u sentinelai-agent -f")
    except PermissionError:
        print("Error: Run as root to install systemd service")
    except Exception as e:
        print(f"Error installing service: {e}")


# ─── CLI Entry Point ──────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(description="SentinelAI Endpoint Agent")
    parser.add_argument("--config", type=str, default=str(CONFIG_FILE), help="Config file path")
    parser.add_argument("--daemon", action="store_true", help="Run as background daemon")
    parser.add_argument("--once", action="store_true", help="Single collection cycle then exit")
    parser.add_argument("--test", action="store_true", help="Test connection to backend")
    parser.add_argument("--install-service", action="store_true", help="Install as OS service")
    parser.add_argument("--uninstall-service", action="store_true", help="Uninstall OS service")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    if args.install_service:
        if platform.system() == "Linux":
            install_systemd_service()
        else:
            run_as_windows_service()
        return

    if args.uninstall_service and platform.system() == "Linux":
        import subprocess
        subprocess.run(["systemctl", "stop", "sentinelai-agent"], check=False)
        subprocess.run(["systemctl", "disable", "sentinelai-agent"], check=False)
        unit_path = Path("/etc/systemd/system/sentinelai-agent.service")
        if unit_path.exists():
            unit_path.unlink()
        subprocess.run(["systemctl", "daemon-reload"], check=False)
        print("Service uninstalled")
        return

    agent = SentinelAgent(config_path=Path(args.config))

    if args.test:
        print(f"Server: {agent.config['server_url']}")
        print(f"Device ID: {agent.state.data['device_id']}")
        print(f"Collectors: {[name for name, _ in agent.collectors]}")
        try:
            resp = requests.get(f"{agent.config['server_url']}/health", timeout=5)
            print(f"Backend health: {resp.status_code} — {resp.json()}")
        except Exception as e:
            print(f"Backend connection failed: {e}")
        return

    if args.once:
        agent.run_once()
        print(f"Shipped {agent.state.data.get('events_shipped', 0)} total events")
        return

    if platform.system() == "Windows":
        run_as_windows_service()
    else:
        agent.run_forever()


if __name__ == "__main__":
    main()
