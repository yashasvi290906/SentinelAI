"""
Event Normalization Engine for SentinelAI.
Converts raw events from any source into a canonical NormalizedEvent schema.
This is the single source of truth for event structure across the platform.
"""
import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, asdict, field
from enum import Enum


class EventType(str, Enum):
    """Standardized event types across all log sources."""
    # Authentication
    FAILED_LOGIN = "failed_login"
    SUCCESSFUL_LOGIN = "successful_login"
    LOGOUT = "logout"
    EXPLICIT_LOGON = "explicit_logon"
    # Account
    USER_CREATED = "user_created"
    USER_DELETED = "user_deleted"
    USER_MODIFIED = "user_modified"
    PASSWORD_CHANGED = "password_changed"
    GROUP_MEMBER_ADDED = "group_member_added"
    GROUP_MEMBER_REMOVED = "group_member_removed"
    # Process
    PROCESS_CREATED = "process_created"
    PROCESS_TERMINATED = "process_terminated"
    POWERSHELL_EXECUTION = "powershell_execution"
    SCRIPT_EXECUTION = "script_execution"
    # Service
    SERVICE_INSTALLED = "service_installed"
    SERVICE_STARTED = "service_started"
    SERVICE_STOPPED = "service_stopped"
    # Network
    CONNECTION_ATTEMPT = "connection_attempt"
    CONNECTION_ESTABLISHED = "connection_established"
    CONNECTION_FAILED = "connection_failed"
    PORT_SCAN = "port_scan"
    # File
    FILE_CREATED = "file_created"
    FILE_MODIFIED = "file_modified"
    FILE_DELETED = "file_deleted"
    FILE_EXECUTED = "file_executed"
    # Registry
    REGISTRY_MODIFIED = "reg_modified"
    REGISTRY_CREATED = "reg_created"
    # Audit
    AUDIT_LOG_CLEARED = "audit_cleared"
    POLICY_CHANGED = "policy_changed"
    # System
    SERVICE_INSTALL = "service_install"
    SCHEDULED_TASK_CREATED = "scheduled_task_created"
    DRIVER_LOADED = "driver_loaded"
    # Linux
    SUDO_COMMAND = "sudo_command"
    SSH_FAILED = "ssh_failed"
    SSH_ACCEPTED = "ssh_accepted"
    CRONTAB_MODIFIED = "crontab_modified"
    # Network (continued)
    DNS_QUERY = "dns_query"
    HTTP_REQUEST = "http_request"
    # Generic
    UNKNOWN = "unknown"
    GENERIC_EVENT = "generic_event"


class Severity(str, Enum):
    """Standardized severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class NormalizedEvent:
    """
    Canonical event schema. Every event from every source is normalized to this format.
    This is the contract between ingestion, detection, and storage layers.
    """
    # Identity
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # Source identification
    hostname: str = ""
    source_type: str = ""  # windows, linux, network, agent, api
    source_name: str = ""  # Event Viewer, syslog, Suricata, etc.
    agent_id: str = ""

    # Network
    source_ip: str = ""
    destination_ip: str = ""
    source_port: int = 0
    destination_port: int = 0
    protocol: str = ""

    # User
    username: str = ""
    user_domain: str = ""
    logon_type: str = ""

    # Event classification
    event_type: str = "unknown"  # One of EventType values
    severity: str = "INFO"  # One of Severity values
    category: str = ""  # authentication, process, network, file, registry, etc.

    # Content
    message: str = ""
    description: str = ""
    raw_payload: str = ""  # Original raw log line

    # Process context
    process_name: str = ""
    process_id: int = 0
    command_line: str = ""
    parent_process_name: str = ""
    parent_process_id: int = 0

    # File context
    file_path: str = ""
    file_hash: str = ""

    # Service context
    service_name: str = ""
    service_type: str = ""

    # MITRE ATT&CK mapping
    mitre_technique: str = ""
    mitre_tactic: str = ""

    # Enrichment
    enrichment: Dict[str, Any] = field(default_factory=dict)

    # Metadata
    tags: List[str] = field(default_factory=list)
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_db_dict(self) -> Dict[str, Any]:
        """Convert to dict suitable for database storage."""
        import json
        d = self.to_dict()
        d['enrichment'] = json.dumps(d['enrichment'])
        d['tags'] = json.dumps(d['tags'])
        return d


class EventNormalizer:
    """
    Normalizes raw events from various sources into NormalizedEvent.
    Each source type has its own normalization method.
    """

    # Mapping from Windows Event IDs to normalized event types
    WINDOWS_EVENT_TYPE_MAP = {
        4625: EventType.FAILED_LOGIN,
        4624: EventType.SUCCESSFUL_LOGIN,
        4648: EventType.EXPLICIT_LOGON,
        4720: EventType.USER_CREATED,
        4726: EventType.USER_DELETED,
        4728: EventType.GROUP_MEMBER_ADDED,
        4732: EventType.GROUP_MEMBER_ADDED,
        7045: EventType.SERVICE_INSTALLED,
        4688: EventType.PROCESS_CREATED,
        4104: EventType.POWERSHELL_EXECUTION,
        4697: EventType.SERVICE_INSTALLED,
        1102: EventType.AUDIT_LOG_CLEARED,
        4698: EventType.SCHEDULED_TASK_CREATED,
        4663: EventType.FILE_MODIFIED,
        4656: EventType.FILE_CREATED,
    }

    # Mapping from Linux auth patterns to event types
    LINUX_AUTH_EVENT_MAP = {
        "failed_password": EventType.FAILED_LOGIN,
        "accepted": EventType.SUCCESSFUL_LOGIN,
        "session_opened": EventType.SUCCESSFUL_LOGIN,
        "sudo": EventType.SUDO_COMMAND,
        "failed_password": EventType.SSH_FAILED,
        "accepted_password": EventType.SSH_ACCEPTED,
    }

    # Category mapping
    EVENT_CATEGORY_MAP = {
        EventType.FAILED_LOGIN: "authentication",
        EventType.SUCCESSFUL_LOGIN: "authentication",
        EventType.LOGOUT: "authentication",
        EventType.EXPLICIT_LOGON: "authentication",
        EventType.USER_CREATED: "account",
        EventType.USER_DELETED: "account",
        EventType.USER_MODIFIED: "account",
        EventType.PASSWORD_CHANGED: "account",
        EventType.GROUP_MEMBER_ADDED: "account",
        EventType.PROCESS_CREATED: "process",
        EventType.PROCESS_TERMINATED: "process",
        EventType.POWERSHELL_EXECUTION: "process",
        EventType.SCRIPT_EXECUTION: "process",
        EventType.SERVICE_INSTALLED: "service",
        EventType.SERVICE_STARTED: "service",
        EventType.SERVICE_STOPPED: "service",
        EventType.CONNECTION_ATTEMPT: "network",
        EventType.CONNECTION_ESTABLISHED: "network",
        EventType.CONNECTION_FAILED: "network",
        EventType.PORT_SCAN: "network",
        EventType.DNS_QUERY: "network",
        EventType.HTTP_REQUEST: "network",
        EventType.FILE_CREATED: "file",
        EventType.FILE_MODIFIED: "file",
        EventType.FILE_DELETED: "file",
        EventType.FILE_EXECUTED: "file",
        EventType.REGISTRY_MODIFIED: "registry",
        EventType.AUDIT_LOG_CLEARED: "audit",
        EventType.SUDO_COMMAND: "authentication",
        EventType.SSH_FAILED: "authentication",
        EventType.SSH_ACCEPTED: "authentication",
    }

    def normalize(self, raw_event: Dict[str, Any], source_type: str) -> NormalizedEvent:
        """
        Normalize a raw event based on its source type.
        This is the main entry point for normalization.
        """
        if source_type == "windows":
            return self._normalize_windows(raw_event)
        elif source_type == "linux":
            return self._normalize_linux(raw_event)
        elif source_type in ("network", "suricata", "zeek"):
            return self._normalize_network(raw_event)
        elif source_type == "agent":
            return self._normalize_agent(raw_event)
        else:
            return self._normalize_generic(raw_event)

    def _normalize_windows(self, raw: Dict[str, Any]) -> NormalizedEvent:
        """Normalize Windows Event Log entries."""
        event_id = raw.get("event_id", 0)
        event_type = self.WINDOWS_EVENT_TYPE_MAP.get(event_id, EventType.UNKNOWN)
        severity = self._infer_severity(event_id, raw)

        return NormalizedEvent(
            timestamp=raw.get("timestamp", datetime.now(timezone.utc).isoformat()),
            hostname=raw.get("hostname", ""),
            source_type="windows",
            source_name="Event Viewer",
            agent_id=raw.get("agent_id", ""),
            source_ip=raw.get("source_ip", ""),
            destination_ip=raw.get("dest_ip", ""),
            source_port=0,
            destination_port=raw.get("dest_port", 0),
            username=raw.get("user", raw.get("TargetUserName", "")),
            user_domain=raw.get("domain", raw.get("TargetDomainName", "")),
            logon_type=raw.get("logon_type", raw.get("LogonType", "")),
            event_type=event_type.value,
            severity=severity.value,
            category=self.EVENT_CATEGORY_MAP.get(event_type, "unknown"),
            message=raw.get("message", raw.get("raw", "")),
            description=raw.get("description", ""),
            raw_payload=raw.get("raw", raw.get("message", "")),
            process_name=raw.get("process_name", raw.get("NewProcessName", "")),
            command_line=raw.get("command_line", raw.get("CommandLine", "")),
            service_name=raw.get("service_name", raw.get("ServiceName", "")),
        )

    def _normalize_linux(self, raw: Dict[str, Any]) -> NormalizedEvent:
        """Normalize Linux log entries."""
        event_type_str = raw.get("event_type", "unknown")
        event_type = self.LINUX_AUTH_EVENT_MAP.get(event_type_str, EventType.UNKNOWN)
        if event_type == EventType.UNKNOWN:
            event_type = EventType.GENERIC_EVENT

        severity = Severity.LOW
        if event_type in (EventType.FAILED_LOGIN, EventType.SSH_FAILED):
            severity = Severity.MEDIUM
        elif event_type == EventType.SUDO_COMMAND:
            severity = Severity.LOW

        return NormalizedEvent(
            timestamp=raw.get("timestamp", datetime.now(timezone.utc).isoformat()),
            hostname=raw.get("hostname", ""),
            source_type="linux",
            source_name=raw.get("log_file", "syslog"),
            agent_id=raw.get("agent_id", ""),
            source_ip=raw.get("source_ip", ""),
            username=raw.get("user", ""),
            event_type=event_type.value,
            severity=severity.value,
            category=self.EVENT_CATEGORY_MAP.get(event_type, "unknown"),
            message=raw.get("raw", raw.get("message", "")),
            raw_payload=raw.get("raw", raw.get("message", "")),
        )

    def _normalize_network(self, raw: Dict[str, Any]) -> NormalizedEvent:
        """Normalize network events (Suricata, Zeek, generic)."""
        event_type = raw.get("event_type", EventType.CONNECTION_ATTEMPT.value)
        severity = Severity.LOW

        # Check for known attack types
        if "alert" in raw.get("event_type", "").lower():
            severity = Severity.HIGH
            event_type = EventType.CONNECTION_FAILED.value

        return NormalizedEvent(
            timestamp=raw.get("timestamp", datetime.now(timezone.utc).isoformat()),
            hostname=raw.get("hostname", ""),
            source_type="network",
            source_name=raw.get("source", "network"),
            agent_id=raw.get("agent_id", ""),
            source_ip=raw.get("source_ip", ""),
            destination_ip=raw.get("dest_ip", raw.get("destination_ip", "")),
            source_port=raw.get("source_port", 0),
            destination_port=raw.get("dest_port", raw.get("destination_port", 0)),
            protocol=raw.get("protocol", ""),
            event_type=event_type,
            severity=severity.value,
            category="network",
            message=raw.get("message", raw.get("raw", "")),
            raw_payload=raw.get("raw", raw.get("message", "")),
        )

    def _normalize_agent(self, raw: Dict[str, Any]) -> NormalizedEvent:
        """Normalize events from the sentinel agent."""
        event_type_str = raw.get("event_type", "unknown")
        event_type = EventType(event_type_str) if event_type_str in [e.value for e in EventType] else EventType.GENERIC_EVENT

        return NormalizedEvent(
            timestamp=raw.get("timestamp", datetime.now(timezone.utc).isoformat()),
            hostname=raw.get("hostname", ""),
            source_type="agent",
            source_name=raw.get("source", "sentinel-agent"),
            agent_id=raw.get("agent_id", ""),
            source_ip=raw.get("source_ip", ""),
            username=raw.get("user", ""),
            event_type=event_type.value,
            severity=raw.get("severity", Severity.INFO.value),
            category=self.EVENT_CATEGORY_MAP.get(event_type, "unknown"),
            message=raw.get("message", raw.get("raw", "")),
            raw_payload=raw.get("raw", raw.get("message", "")),
            process_name=raw.get("process_name", ""),
            command_line=raw.get("command_line", ""),
        )

    def _normalize_generic(self, raw: Dict[str, Any]) -> NormalizedEvent:
        """Normalize generic/unknown events."""
        return NormalizedEvent(
            timestamp=raw.get("timestamp", datetime.now(timezone.utc).isoformat()),
            hostname=raw.get("hostname", ""),
            source_type=raw.get("source_type", "unknown"),
            source_name=raw.get("source", "unknown"),
            agent_id=raw.get("agent_id", ""),
            source_ip=raw.get("source_ip", ""),
            destination_ip=raw.get("dest_ip", ""),
            event_type=raw.get("event_type", EventType.UNKNOWN.value),
            severity=raw.get("severity", Severity.INFO.value),
            category="unknown",
            message=raw.get("message", raw.get("raw", "")),
            raw_payload=raw.get("raw", raw.get("message", "")),
        )

    def _infer_severity(self, event_id: int, raw: Dict[str, Any]) -> Severity:
        """Infer severity from Windows event ID and context."""
        # Critical events
        if event_id in (1102,):  # Audit log cleared
            return Severity.CRITICAL

        # High severity
        if event_id in (4625,):  # Failed logon
            return Severity.HIGH
        if event_id in (4688,):  # Process created
            cmd = raw.get("command_line", raw.get("CommandLine", "")).lower()
            if any(s in cmd for s in ["powershell", "cmd", "wscript", "cscript", "mshta"]):
                return Severity.HIGH
            return Severity.MEDIUM
        if event_id in (4104,):  # PowerShell script block
            return Severity.HIGH

        # Medium severity
        if event_id in (4624, 4648, 4720, 4726, 7045, 4697):
            return Severity.MEDIUM

        return Severity.LOW


# Singleton
event_normalizer = EventNormalizer()
