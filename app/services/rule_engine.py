"""
YAML-driven Detection Rule Engine for SentinelAI.
Loads rules from database, evaluates them against incoming events,
and generates alerts when conditions are met.
"""
import re
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict
from dataclasses import dataclass, asdict


@dataclass
class RuleMatch:
    """A rule that matched against events."""
    rule_id: str
    rule_title: str
    severity: str
    matched_events: List[Dict]
    match_count: int
    mitre_technique: str
    mitre_tactic: str
    confidence: float
    description: str
    recommendations: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class DetectionRuleEngine:
    """
    Evaluates detection rules against incoming events.
    Rules are stored in the database and loaded into memory.
    Supports condition types:
    - count: Count events matching criteria within time window
    - threshold: Metric exceeds threshold
    - sequence: Specific event sequence within time window
    - aggregate: Aggregate condition across multiple event types
    """

    def __init__(self):
        self.rules: List[Dict] = []
        self.event_buffer: Dict[str, List[Dict]] = defaultdict(list)  # rule_id -> events
        self.last_load: Optional[datetime] = None
        self.LOAD_INTERVAL = timedelta(minutes=5)

    def load_rules(self, db) -> None:
        """Load rules from database."""
        try:
            self.rules = db.get_detection_rules(enabled_only=True)
            self.last_load = datetime.now(timezone.utc)
        except Exception:
            pass

    def evaluate(self, event: Dict[str, Any], db) -> List[RuleMatch]:
        """
        Evaluate all rules against an incoming event.
        Returns list of rules that matched.
        """
        now = datetime.now(timezone.utc)

        # Reload rules periodically
        if not self.last_load or (now - self.last_load) > self.LOAD_INTERVAL:
            self.load_rules(db)

        matches = []

        for rule in self.rules:
            try:
                match = self._evaluate_rule(rule, event, now)
                if match:
                    matches.append(match)
            except Exception as e:
                continue

        return matches

    def _evaluate_rule(self, rule: Dict[str, Any], event: Dict[str, Any], now: datetime) -> Optional[RuleMatch]:
        """Evaluate a single rule against an event."""
        condition_str = rule.get("condition", "")
        window_seconds = rule.get("window_seconds", 300)
        threshold = rule.get("threshold", 1.0)
        rule_id = rule.get("id", "")
        title = rule.get("title", "")
        severity = rule.get("severity", "MEDIUM")
        mitre_technique = rule.get("mitre_technique", "")
        mitre_tactic = rule.get("mitre_tactic", "")

        # Parse condition
        condition = self._parse_condition(condition_str)
        if not condition:
            return None

        # Add event to buffer for this rule
        self.event_buffer[rule_id].append(event)

        # Clean old events outside window
        cutoff = now - timedelta(seconds=window_seconds)
        self.event_buffer[rule_id] = [
            e for e in self.event_buffer[rule_id]
            if self._parse_timestamp(e.get("timestamp", "")) > cutoff
        ]

        # Evaluate condition
        matched_events = self._match_condition(condition, self.event_buffer[rule_id])

        if matched_events and len(matched_events) >= threshold:
            confidence = min(0.5 + len(matched_events) * 0.05, 0.99)
            return RuleMatch(
                rule_id=rule_id,
                rule_title=title,
                severity=severity,
                matched_events=matched_events[:50],  # Cap at 50 events
                match_count=len(matched_events),
                mitre_technique=mitre_technique,
                mitre_tactic=mitre_tactic,
                confidence=round(confidence, 3),
                description=f"Rule '{title}' triggered: {len(matched_events)} events matched condition '{condition_str}' within {window_seconds}s",
                recommendations=[
                    f"Investigate {len(matched_events)} matching events",
                    f"Review events from {window_seconds}s window",
                    f"Check source IPs involved",
                ],
            )

        return None

    def _parse_condition(self, condition_str: str) -> Optional[Dict[str, Any]]:
        """
        Parse a condition string into structured format.
        Supported formats:
        - "failed_logins > 20"
        - "event_type = brute_force AND severity = HIGH"
        - "sequence: port_scan, failed_login, successful_login"
        """
        condition_str = condition_str.strip()

        # Sequence condition
        if condition_str.lower().startswith("sequence:"):
            types = [t.strip() for t in condition_str[9:].split(",")]
            return {"type": "sequence", "types": types}

        # AND conditions
        if " AND " in condition_str.upper():
            parts = condition_str.split(" AND ")
            conditions = []
            for part in parts:
                parsed = self._parse_single_condition(part.strip())
                if parsed:
                    conditions.append(parsed)
            return {"type": "and", "conditions": conditions} if conditions else None

        # OR conditions
        if " OR " in condition_str.upper():
            parts = condition_str.split(" OR ")
            conditions = []
            for part in parts:
                parsed = self._parse_single_condition(part.strip())
                if parsed:
                    conditions.append(parsed)
            return {"type": "or", "conditions": conditions} if conditions else None

        # Single condition
        return self._parse_single_condition(condition_str)

    def _parse_single_condition(self, condition: str) -> Optional[Dict[str, Any]]:
        """Parse a single condition like 'failed_logins > 20' or 'event_type = brute_force'."""
        condition = condition.strip()

        # Comparison operators
        for op in [">=", "<=", "!=", ">", "<", "="]:
            if op in condition:
                parts = condition.split(op, 1)
                if len(parts) == 2:
                    field = parts[0].strip()
                    value = parts[1].strip()
                    try:
                        value = float(value)
                    except ValueError:
                        value = value.strip("'\"")
                    return {"type": "comparison", "field": field, "op": op, "value": value}

        return None

    def _match_condition(self, condition: Dict[str, Any], events: List[Dict]) -> List[Dict]:
        """Evaluate condition against a list of events."""
        if not condition:
            return []

        cond_type = condition.get("type", "")

        if cond_type == "comparison":
            return self._match_comparison(condition, events)
        elif cond_type == "sequence":
            return self._match_sequence(condition, events)
        elif cond_type == "and":
            return self._match_and(condition, events)
        elif cond_type == "or":
            return self._match_or(condition, events)

        return []

    def _match_comparison(self, condition: Dict[str, Any], events: List[Dict]) -> List[Dict]:
        """Match a comparison condition."""
        field = condition.get("field", "")
        op = condition.get("op", "")
        value = condition.get("value", 0)

        # Count-based conditions
        if field.endswith("_count") or field in ("count", "total", "events"):
            count = len(events)
            if self._compare(count, op, value):
                return events
            return []

        # Field-based conditions
        matched = []
        for event in events:
            event_value = event.get(field, "")
            if isinstance(event_value, str):
                event_value = event_value.lower()
            if self._compare(event_value, op, value):
                matched.append(event)

        return matched

    def _match_sequence(self, condition: Dict[str, Any], events: List[Dict]) -> List[Dict]:
        """Match a sequence condition (events in specific order)."""
        types = condition.get("types", [])
        if not types or len(events) < len(types):
            return []

        # Check if events contain the required sequence
        event_types = [e.get("event_type", "") for e in events]
        type_str = " ".join(event_types)

        # Check if sequence exists in order
        idx = 0
        for t in types:
            found = False
            while idx < len(event_types):
                if event_types[idx] == t:
                    found = True
                    idx += 1
                    break
                idx += 1
            if not found:
                return []

        return events

    def _match_and(self, condition: Dict[str, Any], events: List[Dict]) -> List[Dict]:
        """Match AND conditions."""
        conditions = condition.get("conditions", [])
        if not conditions:
            return []

        matched = events[:]
        for cond in conditions:
            matched = self._match_condition(cond, matched)

        return matched

    def _match_or(self, condition: Dict[str, Any], events: List[Dict]) -> List[Dict]:
        """Match OR conditions."""
        conditions = condition.get("conditions", [])
        if not conditions:
            return []

        all_matched = []
        for cond in conditions:
            matched = self._match_condition(cond, events)
            all_matched.extend(matched)

        # Deduplicate
        seen_ids = set()
        unique = []
        for e in all_matched:
            eid = e.get("id", id(e))
            if eid not in seen_ids:
                seen_ids.add(eid)
                unique.append(e)

        return unique

    def _compare(self, actual, op: str, expected) -> bool:
        """Compare actual value against expected using operator."""
        try:
            if isinstance(expected, (int, float)):
                actual = float(actual) if actual else 0
            elif isinstance(actual, str):
                actual = actual.lower()
                expected = str(expected).lower()
        except (ValueError, TypeError):
            return False

        if op == "=":
            return actual == expected
        elif op == "!=":
            return actual != expected
        elif op == ">":
            return actual > expected
        elif op == "<":
            return actual < expected
        elif op == ">=":
            return actual >= expected
        elif op == "<=":
            return actual <= expected

        return False

    def _parse_timestamp(self, ts: str) -> datetime:
        """Parse ISO timestamp to datetime."""
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return datetime.now(timezone.utc) - timedelta(hours=1)

    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics."""
        return {
            "total_rules": len(self.rules),
            "active_buffers": len(self.event_buffer),
            "last_reload": self.last_load.isoformat() if self.last_load else None,
        }


# Singleton
detection_rule_engine = DetectionRuleEngine()
