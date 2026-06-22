"""
Sigma Rule Engine for SentinelAI.
Evaluates Sigma-format detection rules against incoming events.
Supports: field modifiers (contains, startswith, endswith, re, gt, lt, cidr), 
logical operators (and, or, not), aggregation (N of them, all of them).
"""
import re
import yaml
import json
import uuid
import logging
from fnmatch import fnmatch
from typing import Any, Dict, List, Optional, Set
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("sentinelai.sigma")


class SigmaRuleParser:
    """Parse Sigma YAML rules into evaluable structures."""

    @staticmethod
    def parse_yaml(yaml_text: str) -> Dict[str, Any]:
        """Parse a Sigma rule YAML string into a dict."""
        try:
            rule = yaml.safe_load(yaml_text)
            if not rule or "detection" not in rule:
                raise ValueError("Invalid Sigma rule: missing 'detection' field")
            return rule
        except yaml.YAMLError as e:
            raise ValueError(f"YAML parse error: {e}")

    @staticmethod
    def parse_modifiers(field_name: str) -> tuple:
        """Parse field name into (base_field, modifiers)."""
        parts = field_name.split("|")
        field = parts[0]
        modifiers = set(parts[1:])
        return field, modifiers


class SigmaEvaluator:
    """Evaluate Sigma rules against log events."""

    def __init__(self, rule: Dict[str, Any]):
        self.rule = rule
        self.title = rule.get("title", "Unknown Rule")
        self.level = rule.get("level", "medium")
        self.detection = rule.get("detection", {})
        self.condition = self.detection.get("condition", "selection")
        self.logsource = rule.get("logsource", {})
        self.tags = rule.get("tags", [])
        self.falsepositives = rule.get("falsepositives", [])
        self.fields = rule.get("fields", [])

    def _match_value(self, event_value: str, pattern: str, modifiers: Set[str]) -> bool:
        """Match a single value against a pattern with modifiers."""
        case_sensitive = "cased" in modifiers

        ev = str(event_value) if case_sensitive else str(event_value).lower()
        pat = str(pattern) if case_sensitive else str(pattern).lower()

        # Regex matching
        if "re" in modifiers:
            flags = 0
            if "?i" in modifiers:
                flags |= re.IGNORECASE
            if "?m" in modifiers:
                flags |= re.MULTILINE
            if "?s" in modifiers:
                flags |= re.DOTALL
            try:
                return bool(re.search(pat, ev, flags))
            except re.error:
                return False

        # Apply modifiers to pattern
        if "contains" in modifiers:
            pat = f"*{pat}*"
        elif "startswith" in modifiers:
            pat = f"{pat}*"
        elif "endswith" in modifiers:
            pat = f"*{pat}"

        # Wildcard matching
        if "*" in pat or "?" in pat:
            return fnmatch(ev, pat)

        # Exact match (case-insensitive by default in Sigma)
        return ev == pat

    def _match_field(self, event: Dict, field: str, values: Any, modifiers: Set[str]) -> bool:
        """Match a field in the event against Sigma values."""
        # Field existence check
        if "exists" in modifiers:
            exists = field in event and event[field] is not None
            return exists if values else not exists

        if field not in event:
            return False

        event_val = event[field]
        if event_val is None:
            return False

        # Numeric comparisons
        if "gt" in modifiers:
            try:
                return float(event_val) > float(values)
            except (ValueError, TypeError):
                return False
        if "gte" in modifiers:
            try:
                return float(event_val) >= float(values)
            except (ValueError, TypeError):
                return False
        if "lt" in modifiers:
            try:
                return float(event_val) < float(values)
            except (ValueError, TypeError):
                return False
        if "lte" in modifiers:
            try:
                return float(event_val) <= float(values)
            except (ValueError, TypeError):
                return False

        # CIDR matching
        if "cidr" in modifiers:
            return self._match_cidr(str(event_val), values if isinstance(values, list) else [values])

        # List of values
        if isinstance(values, list):
            if "all" in modifiers:
                return all(self._match_value(str(event_val), str(v), modifiers) for v in values)
            else:
                return any(self._match_value(str(event_val), str(v), modifiers) for v in values)

        # Single value
        return self._match_value(str(event_val), str(values), modifiers)

    def _match_cidr(self, ip: str, cidr_list: List[str]) -> bool:
        """Match an IP against CIDR ranges."""
        try:
            import ipaddress
            ip_addr = ipaddress.ip_address(ip)
            for cidr in cidr_list:
                try:
                    if ip_addr in ipaddress.ip_network(cidr, strict=False):
                        return True
                except ValueError:
                    continue
        except ValueError:
            pass
        return False

    def _evaluate_selection(self, event: Dict, selection: Any) -> bool:
        """Evaluate a single selection block against an event."""
        # List of maps = OR
        if isinstance(selection, list):
            return any(self._evaluate_selection(event, item) for item in selection)

        # String keyword = search across all field values
        if isinstance(selection, str):
            for field_val in event.values():
                if field_val and self._match_value(str(field_val), selection, set()):
                    return True
            return False

        # Map of field:value = AND
        if isinstance(selection, dict):
            for field_or_key, values in selection.items():
                field, modifiers = SigmaRuleParser.parse_modifiers(field_or_key)
                if not self._match_field(event, field, values, modifiers):
                    return False
            return True

        return False

    def _resolve_condition(self, event: Dict, condition_str: str) -> bool:
        """Resolve a condition expression against an event."""
        selections = {k: v for k, v in self.detection.items() if k != "condition"}

        expr = condition_str.strip()

        # Handle "1 of them"
        if "1 of them" in expr:
            results = []
            for name, sel in selections.items():
                if not name.startswith("_"):
                    results.append(self._evaluate_selection(event, sel))
            return any(results)

        # Handle "all of them"
        if "all of them" in expr:
            results = []
            for name, sel in selections.items():
                if not name.startswith("_"):
                    results.append(self._evaluate_selection(event, sel))
            return all(results) if results else False

        # Handle "N of pattern*"
        count_match = re.match(r"(\d+) of (\w+)\*", expr)
        if count_match:
            count = int(count_match.group(1))
            pattern = count_match.group(2)
            matched = sum(
                1 for name, sel in selections.items()
                if name.startswith(pattern) and self._evaluate_selection(event, sel)
            )
            return matched >= count

        # Handle "all of pattern*"
        all_match = re.match(r"all of (\w+)\*", expr)
        if all_match:
            pattern = all_match.group(1)
            matched = [
                self._evaluate_selection(event, sel)
                for name, sel in selections.items()
                if name.startswith(pattern)
            ]
            return all(matched) if matched else False

        # Replace selection names with their evaluated results
        for name, sel in selections.items():
            if name in expr:
                result = self._evaluate_selection(event, sel)
                expr = re.sub(r'\b' + re.escape(name) + r'\b', str(result), expr)

        # Handle NOT
        expr = expr.replace("not True", "False").replace("not False", "True")

        # Evaluate boolean expression safely
        try:
            # Only allow boolean operations
            allowed = set("True False and or not () ")
            if all(c in allowed or c.isalnum() or c == '_' for c in expr.replace(" ", "")):
                return eval(expr, {"__builtins__": {}}, {})
            return False
        except Exception:
            return False

    def matches(self, event: Dict) -> bool:
        """Check if a log event matches this Sigma rule."""
        condition = self.detection.get("condition", "selection")

        if isinstance(condition, list):
            return any(self._resolve_condition(event, c) for c in condition)

        return self._resolve_condition(event, condition)

    def logsource_matches(self, event: Dict) -> bool:
        """Check if event matches the logsource specification."""
        if not self.logsource:
            return True  # No logsource filter = matches everything

        # Map logsource categories to event fields
        category = self.logsource.get("category", "")
        product = self.logsource.get("product", "")
        service = self.logsource.get("service", "")

        event_type = str(event.get("event_type", "")).lower()
        source = str(event.get("source", "")).lower()

        # Check product
        if product:
            if product == "windows" and "windows" not in event_type and "windows" not in source:
                if not any(kw in event_type for kw in ["security", "system", "application", "sysmon"]):
                    return False
            elif product == "linux" and "linux" not in event_type and "linux" not in source:
                if not any(kw in event_type for kw in ["auth", "syslog", "kernel", "auditd"]):
                    return False

        # Check service
        if service:
            if service not in event_type and service not in source:
                return False

        return True


class SigmaEngine:
    """Main Sigma rule engine - manages rules and evaluates events."""

    def __init__(self):
        self.rules: Dict[str, Dict] = {}  # rule_id -> parsed rule
        self.evaluators: Dict[str, SigmaEvaluator] = {}  # rule_id -> evaluator
        self._load_builtin_rules()

    def _load_builtin_rules(self):
        """Load built-in Sigma rules for government/CISA-relevant detections."""
        builtin_rules = [
            {
                "title": "Brute Force - Multiple Failed Logons",
                "id": "sentinelai-bruteforce-001",
                "level": "high",
                "status": "stable",
                "description": "Detects multiple failed logon attempts indicating brute force attack",
                "logsource": {"product": "windows", "service": "security"},
                "tags": ["attack.credential_access", "attack.t1110"],
                "detection": {
                    "selection": {"event_type": "failed_logon"},
                    "condition": "selection"
                },
                "mitre_technique": "T1110",
                "mitre_tactic": "credential_access"
            },
            {
                "title": "Port Scan Detection",
                "id": "sentinelai-portscan-001",
                "level": "medium",
                "status": "stable",
                "description": "Detects port scanning activity from single source",
                "logsource": {"category": "network_connection"},
                "tags": ["attack.discovery", "attack.t1046"],
                "detection": {
                    "selection": {"event_type": "network_connection"},
                    "condition": "selection"
                },
                "mitre_technique": "T1046",
                "mitre_tactic": "discovery"
            },
            {
                "title": "DDoS Attack Detected",
                "id": "sentinelai-ddos-001",
                "level": "critical",
                "status": "stable",
                "description": "Detects distributed denial of service attack patterns",
                "logsource": {"category": "network_traffic"},
                "tags": ["impact", "attack.t1498"],
                "detection": {
                    "selection": {"event_type": "dos"},
                    "condition": "selection"
                },
                "mitre_technique": "T1498",
                "mitre_tactic": "impact"
            },
            {
                "title": "Suspicious PowerShell Execution",
                "id": "sentinelai-powershell-001",
                "level": "high",
                "status": "stable",
                "description": "Detects suspicious PowerShell command execution",
                "logsource": {"product": "windows", "category": "process_creation"},
                "tags": ["attack.execution", "attack.t1059.001"],
                "detection": {
                    "selection": {"event_type": "process_creation"},
                    "condition": "selection"
                },
                "mitre_technique": "T1059.001",
                "mitre_tactic": "execution"
            },
            {
                "title": "Web Application Attack",
                "id": "sentinelai-webattack-001",
                "level": "high",
                "status": "stable",
                "description": "Detects web application attacks (SQLi, XSS, path traversal)",
                "logsource": {"category": "webserver"},
                "tags": ["attack.initial_access", "attack.t1190"],
                "detection": {
                    "selection": {"event_type": "web_attack"},
                    "condition": "selection"
                },
                "mitre_technique": "T1190",
                "mitre_tactic": "initial_access"
            },
            {
                "title": "Data Exfiltration Detected",
                "id": "sentinelai-exfil-001",
                "level": "critical",
                "status": "stable",
                "description": "Detects large data transfers indicating potential exfiltration",
                "logsource": {"category": "network_traffic"},
                "tags": ["attack.exfiltration", "attack.t1041"],
                "detection": {
                    "selection": {"event_type": "data_exfil"},
                    "condition": "selection"
                },
                "mitre_technique": "T1041",
                "mitre_tactic": "exfiltration"
            },
            {
                "title": "Lateral Movement - SMB Relay",
                "id": "sentinelai-lateral-001",
                "level": "critical",
                "status": "stable",
                "description": "Detects lateral movement via SMB relay attacks",
                "logsource": {"product": "windows", "service": "security"},
                "tags": ["attack.lateral_movement", "attack.t1570"],
                "detection": {
                    "selection": {"event_type": "lateral_movement"},
                    "condition": "selection"
                },
                "mitre_technique": "T1570",
                "mitre_tactic": "lateral_movement"
            },
            {
                "title": "C2 Beacon Detected",
                "id": "sentinelai-c2beacon-001",
                "level": "critical",
                "status": "stable",
                "description": "Detects command and control beaconing patterns",
                "logsource": {"category": "network_connection"},
                "tags": ["attack.command_and_control", "attack.t1573"],
                "detection": {
                    "selection": {"event_type": "c2_beacon"},
                    "condition": "selection"
                },
                "mitre_technique": "T1573",
                "mitre_tactic": "command_and_control"
            },
            {
                "title": "Privilege Escalation Attempt",
                "id": "sentinelai-privesc-001",
                "level": "high",
                "status": "stable",
                "description": "Detects privilege escalation attempts",
                "logsource": {"product": "windows", "service": "security"},
                "tags": ["attack.privilege_escalation", "attack.t1548"],
                "detection": {
                    "selection": {"event_type": "privilege_escalation"},
                    "condition": "selection"
                },
                "mitre_technique": "T1548",
                "mitre_tactic": "privilege_escalation"
            },
            {
                "title": "Anomalous Login Pattern",
                "id": "sentinelai-anomalous-login-001",
                "level": "medium",
                "status": "stable",
                "description": "Detects login at unusual time or from unusual location",
                "logsource": {"product": "windows", "service": "security"},
                "tags": ["attack.credential_access", "attack.t1078"],
                "detection": {
                    "selection": {"event_type": "suspicious_auth"},
                    "condition": "selection"
                },
                "mitre_technique": "T1078",
                "mitre_tactic": "credential_access"
            },
            {
                "title": "DNS Tunneling Detected",
                "id": "sentinelai-dns-tunnel-001",
                "level": "high",
                "status": "experimental",
                "description": "Detects DNS tunneling for data exfiltration or C2",
                "logsource": {"category": "network_traffic"},
                "tags": ["attack.exfiltration", "attack.t1048.003"],
                "detection": {
                    "selection": {"event_type": "dns_query"},
                    "condition": "selection"
                },
                "mitre_technique": "T1048.003",
                "mitre_tactic": "exfiltration"
            },
            {
                "title": "Suspicious File Creation",
                "id": "sentinelai-file-create-001",
                "level": "medium",
                "status": "stable",
                "description": "Detects creation of suspicious files (executables in temp directories)",
                "logsource": {"product": "windows", "category": "file_event"},
                "tags": ["attack.persistence", "attack.t1547.001"],
                "detection": {
                    "selection": {"event_type": "file_creation"},
                    "condition": "selection"
                },
                "mitre_technique": "T1547.001",
                "mitre_tactic": "persistence"
            },
            {
                "title": "Registry Persistence",
                "id": "sentinelai-reg-persist-001",
                "level": "high",
                "status": "stable",
                "description": "Detects persistence via registry run keys",
                "logsource": {"product": "windows", "category": "registry"},
                "tags": ["attack.persistence", "attack.t1547.001"],
                "detection": {
                    "selection": {"event_type": "registry_modification"},
                    "condition": "selection"
                },
                "mitre_technique": "T1547.001",
                "mitre_tactic": "persistence"
            },
            {
                "title": "Service Installation",
                "id": "sentinelai-service-install-001",
                "level": "medium",
                "status": "stable",
                "description": "Detects new service installation (potential persistence or lateral movement)",
                "logsource": {"product": "windows", "service": "system"},
                "tags": ["attack.persistence", "attack.t1543.003"],
                "detection": {
                    "selection": {"event_type": "service_install"},
                    "condition": "selection"
                },
                "mitre_technique": "T1543.003",
                "mitre_tactic": "persistence"
            },
            {
                "title": "Audit Log Cleared",
                "id": "sentinelai-log-clear-001",
                "level": "critical",
                "status": "stable",
                "description": "Detects clearing of audit/security logs (anti-forensics)",
                "logsource": {"product": "windows", "service": "security"},
                "tags": ["attack.defense_evasion", "attack.t1070.001"],
                "detection": {
                    "selection": {"event_type": "audit_log_cleared"},
                    "condition": "selection"
                },
                "mitre_technique": "T1070.001",
                "mitre_tactic": "defense_evasion"
            },
        ]

        for rule_data in builtin_rules:
            rule_id = rule_data.get("id", f"sentinelai-{uuid.uuid4().hex[:8]}")
            self.rules[rule_id] = rule_data
            self.evaluators[rule_id] = SigmaEvaluator(rule_data)

        logger.info(f"Loaded {len(builtin_rules)} built-in Sigma rules")

    def add_rule(self, rule_yaml: str) -> str:
        """Add a Sigma rule from YAML string. Returns rule ID."""
        rule = SigmaRuleParser.parse_yaml(rule_yaml)
        rule_id = rule.get("id", f"sigma-{uuid.uuid4().hex[:8]}")
        rule["id"] = rule_id
        self.rules[rule_id] = rule
        self.evaluators[rule_id] = SigmaEvaluator(rule)
        return rule_id

    def add_rule_dict(self, rule: Dict[str, Any]) -> str:
        """Add a Sigma rule from a dict. Returns rule ID."""
        rule_id = rule.get("id", f"sigma-{uuid.uuid4().hex[:8]}")
        rule["id"] = rule_id
        self.rules[rule_id] = rule
        self.evaluators[rule_id] = SigmaEvaluator(rule)
        return rule_id

    def remove_rule(self, rule_id: str):
        """Remove a Sigma rule."""
        self.rules.pop(rule_id, None)
        self.evaluators.pop(rule_id, None)

    def evaluate_event(self, event: Dict) -> List[Dict]:
        """Evaluate an event against all rules. Returns list of matches."""
        matches = []
        for rule_id, evaluator in self.evaluators.items():
            try:
                if evaluator.logsource_matches(event) and evaluator.matches(event):
                    matches.append({
                        "rule_id": rule_id,
                        "title": evaluator.title,
                        "level": evaluator.level,
                        "tags": evaluator.tags,
                        "mitre_technique": self.rules[rule_id].get("mitre_technique", ""),
                        "mitre_tactic": self.rules[rule_id].get("mitre_tactic", ""),
                        "falsepositives": evaluator.falsepositives,
                        "matched_at": datetime.now(timezone.utc).isoformat(),
                    })
            except Exception as e:
                logger.error(f"Error evaluating rule {rule_id}: {e}")
        return matches

    def get_rules(self) -> List[Dict]:
        """Get all loaded rules."""
        return list(self.rules.values())

    def get_rule(self, rule_id: str) -> Optional[Dict]:
        """Get a specific rule."""
        return self.rules.get(rule_id)

    def get_stats(self) -> Dict:
        """Get engine statistics."""
        return {
            "total_rules": len(self.rules),
            "levels": {
                level: sum(1 for r in self.rules.values() if r.get("level") == level)
                for level in ["critical", "high", "medium", "low", "informational"]
            },
            "products": list(set(
                r.get("logsource", {}).get("product", "any")
                for r in self.rules.values()
            )),
        }


# Singleton
sigma_engine = SigmaEngine()
