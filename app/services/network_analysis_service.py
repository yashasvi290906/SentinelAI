"""
Network Traffic Analysis Service for SentinelAI.
Provides NetFlow and Zeek log parsing, DNS/HTTP analysis, beacon detection,
data exfiltration detection, and flow analysis for threat identification.
"""
import re
import json
import uuid
import math
import logging
import struct
import socket
from collections import defaultdict, Counter
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Tuple, Optional, Set
from dataclasses import dataclass, field, asdict

from database import db

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# NetFlow v5 Parser
# ---------------------------------------------------------------------------

class NetFlowParser:
    """Parse NetFlow v5 binary records (header + flow set)."""

    HEADER_FORMAT = ">BBHIIIIIIHHBBHHBx"
    HEADER_SIZE = 24
    FLOW_SIZE = 48
    PROTOCOL_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}

    def parse_header(self, data: bytes) -> Optional[Dict[str, Any]]:
        if len(data) < self.HEADER_SIZE:
            logger.warning("NetFlow data too short for header (%d bytes)", len(data))
            return None
        try:
            fields = struct.unpack(self.HEADER_FORMAT, data[:self.HEADER_SIZE])
            return {
                "version": fields[0],
                "count": fields[1],
                "sys_uptime_ms": fields[2],
                "unix_secs": fields[3],
                "unix_nsecs": fields[4],
                "flow_sequence": fields[5],
                "engine_type": fields[6] if len(fields) > 6 else 0,
                "engine_id": fields[7] if len(fields) > 7 else 0,
                "sampling_interval": fields[8] if len(fields) > 8 else 0,
            }
        except struct.error as e:
            logger.error("Failed to unpack NetFlow header: %s", e)
            return None

    def parse_flow(self, data: bytes, offset: int) -> Optional[Dict[str, Any]]:
        if len(data) < offset + self.FLOW_SIZE:
            return None
        try:
            fd = data[offset:offset + self.FLOW_SIZE]
            src_ip_int, dst_ip_int, nexthop_int = struct.unpack("!III", fd[0:12])
            pkts, octets = struct.unpack("!II", fd[16:24])
            first, last = struct.unpack("!II", fd[24:32])
            src_as, dst_as, src_mask, dst_mask = struct.unpack("!HHBB", fd[28:36])
            tcp_flags, protocol, _pad, src_port, dst_port = struct.unpack("!BBBBH", fd[36:42])
            _pad2, tos = struct.unpack("!xB", fd[42:44])

            return {
                "src_ip": socket.inet_ntoa(struct.pack("!I", src_ip_int)),
                "dst_ip": socket.inet_ntoa(struct.pack("!I", dst_ip_int)),
                "next_hop": socket.inet_ntoa(struct.pack("!I", nexthop_int)),
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": self.PROTOCOL_MAP.get(protocol, str(protocol)),
                "protocol_num": protocol,
                "tcp_flags": tcp_flags,
                "tos": tos,
                "packets": pkts,
                "octets": octets,
                "first_switched_ms": first,
                "last_switched_ms": last,
                "src_as": src_as,
                "dst_as": dst_as,
                "src_mask": src_mask,
                "dst_mask": dst_mask,
            }
        except struct.error as e:
            logger.error("Failed to unpack flow record: %s", e)
            return None

    def parse(self, data: bytes) -> Dict[str, Any]:
        header = self.parse_header(data)
        if not header:
            return {"header": None, "flows": [], "error": "Invalid header"}

        count = header.get("count", 0)
        flows: List[Dict[str, Any]] = []
        for i in range(count):
            offset = self.HEADER_SIZE + i * self.FLOW_SIZE
            flow = self.parse_flow(data, offset)
            if flow:
                flow["flow_sequence"] = header["flow_sequence"] + i
                flows.append(flow)

        return {"header": header, "flows": flows}


# ---------------------------------------------------------------------------
# Zeek Log Parser
# ---------------------------------------------------------------------------

class ZeekLogParser:
    """Parse Zeek connection.log, dns.log, http.log (tab-separated)."""

    LOG_PARSERS = {
        "connection": "_parse_connection",
        "dns": "_parse_dns",
        "http": "_parse_http",
    }

    def _parse_timestamp(self, ts_str: str) -> str:
        if not ts_str:
            return ""
        try:
            secs = float(ts_str)
            return datetime.fromtimestamp(secs, tz=timezone.utc).isoformat()
        except (ValueError, TypeError, OSError):
            return ts_str

    def _safe_float(self, val: str, default: float = 0.0) -> float:
        if not val or val == "-":
            return default
        try:
            return float(val)
        except (ValueError, TypeError):
            return default

    def _safe_int(self, val: str, default: int = 0) -> int:
        if not val or val == "-":
            return default
        try:
            return int(val)
        except (ValueError, TypeError):
            return default

    def _split_line(self, line: str) -> List[str]:
        stripped = line.strip()
        if stripped.startswith("#"):
            return []
        parts = stripped.split("\t")
        return parts if stripped else []

    def _parse_connection(self, parts: List[str]) -> Optional[Dict[str, Any]]:
        if len(parts) < 21:
            return None
        return {
            "ts": self._parse_timestamp(parts[0]),
            "uid": parts[1],
            "src_ip": parts[2],
            "src_port": self._safe_int(parts[3]),
            "dst_ip": parts[4],
            "dst_port": self._safe_int(parts[5]),
            "proto": parts[6],
            "service": parts[7],
            "duration": self._safe_float(parts[8]),
            "orig_bytes": self._safe_int(parts[9]),
            "resp_bytes": self._safe_int(parts[10]),
            "conn_state": parts[11],
            "local_orig": parts[12],
            "local_resp": parts[13],
            "missed_bytes": self._safe_int(parts[14]),
            "history": parts[15],
            "orig_pkts": self._safe_int(parts[16]),
            "resp_pkts": self._safe_int(parts[17]),
            "orig_ip_bytes": self._safe_int(parts[18]),
            "resp_ip_bytes": self._safe_int(parts[19]),
            "tunnel_parents": parts[20] if len(parts) > 20 else "",
            "_type": "connection",
        }

    def _parse_dns(self, parts: List[str]) -> Optional[Dict[str, Any]]:
        if len(parts) < 22:
            return None
        return {
            "ts": self._parse_timestamp(parts[0]),
            "uid": parts[1],
            "src_ip": parts[2],
            "src_port": self._safe_int(parts[3]),
            "dst_ip": parts[4],
            "dst_port": self._safe_int(parts[5]),
            "proto": parts[6],
            "trans_id": parts[7],
            "query": parts[8],
            "qclass_name": parts[9],
            "qtype_name": parts[10],
            "rcode_name": parts[11],
            "AA": parts[12],
            "TC": parts[13],
            "RD": parts[14],
            "RA": parts[15],
            "Z": parts[16],
            "answers": parts[17] if len(parts) > 17 else "",
            "TTLs": parts[18] if len(parts) > 18 else "",
            "rejected": parts[19] if len(parts) > 19 else "",
            "qtype": self._safe_int(parts[20]) if len(parts) > 20 else 0,
            "qclass": self._safe_int(parts[21]) if len(parts) > 21 else 0,
            "_type": "dns",
        }

    def _parse_http(self, parts: List[str]) -> Optional[Dict[str, Any]]:
        if len(parts) < 24:
            return None
        return {
            "ts": self._parse_timestamp(parts[0]),
            "uid": parts[1],
            "src_ip": parts[2],
            "src_port": self._safe_int(parts[3]),
            "dst_ip": parts[4],
            "dst_port": self._safe_int(parts[5]),
            "proto": parts[6],
            "trans_depth": self._safe_int(parts[7]),
            "method": parts[8],
            "host": parts[9],
            "uri": parts[10],
            "referrer": parts[11],
            "user_agent": parts[12],
            "request_body_len": self._safe_int(parts[13]),
            "response_body_len": self._safe_int(parts[14]),
            "status_code": self._safe_int(parts[15]),
            "status_msg": parts[16],
            "info_code": parts[17] if len(parts) > 17 else "",
            "info_msg": parts[18] if len(parts) > 18 else "",
            "tags": parts[19] if len(parts) > 19 else "",
            "username": parts[20] if len(parts) > 20 else "",
            "password": parts[21] if len(parts) > 21 else "",
            "proxied": parts[22] if len(parts) > 22 else "",
            "orig_fuids": parts[23] if len(parts) > 23 else "",
            "_type": "http",
        }

    def parse_line(self, log_type: str, line: str) -> Optional[Dict[str, Any]]:
        parts = self._split_line(line)
        if not parts:
            return None
        parser_name = self.LOG_PARSERS.get(log_type)
        if not parser_name:
            logger.warning("Unknown Zeek log type: %s", log_type)
            return None
        parser = getattr(self, parser_name, None)
        if parser:
            return parser(parts)
        return None

    def parse_file(self, log_type: str, content: str) -> List[Dict[str, Any]]:
        records = []
        for line in content.splitlines():
            record = self.parse_line(log_type, line)
            if record:
                records.append(record)
        return records


# ---------------------------------------------------------------------------
# DNS Analyzer
# ---------------------------------------------------------------------------

class DNSAnalyzer:
    """Detect DNS tunneling, DGA domains, and excessive NXDOMAIN."""

    SUSPICIOUS_TXT_TYPES = {"TXT", "SPF", "NULL", "ANY"}
    LARGE_RECORD_TYPES = {"TXT", "MX", "SRV", "SOA"}

    def __init__(self):
        self._nxdomain_counts: Dict[str, int] = defaultdict(int)
        self._domain_query_counts: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self._subdomain_entropy_cache: Dict[str, float] = {}

    def _shannon_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        freq = Counter(text)
        length = len(text)
        return -sum((c / length) * math.log2(c / length) for c in freq.values())

    def _subdomain_from_query(self, query: str) -> str:
        parts = query.rstrip(".").split(".")
        if len(parts) > 2:
            return ".".join(parts[:-2])
        return ""

    def _detect_high_entropy_subdomain(self, query: str, threshold: float = 3.8) -> Tuple[bool, float]:
        subdomain = self._subdomain_from_query(query)
        if not subdomain:
            return False, 0.0
        if query in self._subdomain_entropy_cache:
            cached = self._subdomain_entropy_cache[query]
            return cached >= threshold, cached
        entropy = self._shannon_entropy(subdomain)
        self._subdomain_entropy_cache[query] = entropy
        return entropy >= threshold, entropy

    def _detect_suspicious_txt(self, record: Dict[str, Any]) -> bool:
        qtype_name = record.get("qtype_name", "")
        if qtype_name in self.SUSPICIOUS_TXT_TYPES:
            answers = record.get("answers", "")
            if isinstance(answers, str) and len(answers) > 500:
                return True
            if isinstance(answers, list) and any(len(str(a)) > 500 for a in answers):
                return True
        return False

    def _detect_dga_domain(self, query: str) -> bool:
        subdomain = self._subdomain_from_query(query)
        if not subdomain or len(subdomain) < 8:
            return False
        vowels = sum(1 for c in subdomain.lower() if c in "aeiou")
        consonants = sum(1 for c in subdomain.lower() if c.isalpha() and c not in "aeiou")
        length = len(subdomain)
        vowel_ratio = vowels / length if length > 0 else 0
        consonant_ratio = consonants / length if length > 0 else 0
        digit_ratio = sum(1 for c in subdomain if c.isdigit()) / length if length > 0 else 0
        has_long_run = False
        current_char = ""
        run_length = 0
        for c in subdomain.lower():
            if c == current_char:
                run_length += 1
                if run_length >= 4:
                    has_long_run = True
                    break
            else:
                current_char = c
                run_length = 1
        if vowel_ratio < 0.15 and consonant_ratio > 0.6 and digit_ratio < 0.1:
            return True
        if digit_ratio > 0.5 and length > 12:
            return True
        if has_long_run and length > 10:
            return True
        unique_chars = len(set(subdomain.lower().replace(".", "")))
        char_diversity = unique_chars / length if length > 0 else 0
        if char_diversity < 0.3 and length > 12:
            return True
        return False

    def _detect_nxdomain_abuse(self, record: Dict[str, Any]) -> bool:
        rcode = record.get("rcode_name", "")
        src_ip = record.get("src_ip", "")
        if rcode == "NXDOMAIN":
            self._nxdomain_counts[src_ip] += 1
        if self._nxdomain_counts.get(src_ip, 0) > 100:
            return True
        return False

    def analyze(self, dns_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        anomalies = []
        for record in dns_records:
            query = record.get("query", "")
            if not query:
                continue

            is_high_entropy, entropy = self._detect_high_entropy_subdomain(query)
            if is_high_entropy:
                anomalies.append({
                    "type": "dns_tunneling",
                    "severity": "HIGH",
                    "confidence": min(0.95, 0.5 + entropy * 0.1),
                    "description": f"High-entropy subdomain detected: {query} (entropy={entropy:.2f})",
                    "evidence": {"query": query, "entropy": round(entropy, 3), "src_ip": record.get("src_ip", "")},
                    "mitre_technique": "T1071.004",
                    "mitre_tactic": "Command and Control",
                })

            if self._detect_suspicious_txt(record):
                anomalies.append({
                    "type": "dns_tunneling_txt",
                    "severity": "HIGH",
                    "confidence": 0.85,
                    "description": f"Suspicious large TXT record: {query}",
                    "evidence": {"query": query, "qtype": record.get("qtype_name", "")},
                    "mitre_technique": "T1071.004",
                    "mitre_tactic": "Command and Control",
                })

            if self._detect_dga_domain(query):
                anomalies.append({
                    "type": "dga_domain",
                    "severity": "MEDIUM",
                    "confidence": 0.80,
                    "description": f"Possible DGA domain detected: {query}",
                    "evidence": {"query": query, "src_ip": record.get("src_ip", "")},
                    "mitre_technique": "T1568.002",
                    "mitre_tactic": "Command and Control",
                })

            if self._detect_nxdomain_abuse(record):
                src = record.get("src_ip", "")
                anomalies.append({
                    "type": "nxdomain_abuse",
                    "severity": "MEDIUM",
                    "confidence": 0.75,
                    "description": f"Excessive NXDOMAIN from {src}: {self._nxdomain_counts[src]} queries",
                    "evidence": {"src_ip": src, "nxdomain_count": self._nxdomain_counts[src]},
                    "mitre_technique": "T1568.002",
                    "mitre_tactic": "Command and Control",
                })

        return anomalies


# ---------------------------------------------------------------------------
# HTTP Analyzer
# ---------------------------------------------------------------------------

class HTTPAnalyzer:
    """Detect C2 beaconing, data exfiltration, and suspicious user agents."""

    SUSPICIOUS_UA_PATTERNS = [
        re.compile(r"curl", re.I),
        re.compile(r"wget", re.I),
        re.compile(r"python-requests", re.I),
        re.compile(r"python-urllib", re.I),
        re.compile(r"go-http-client", re.I),
        re.compile(r"java/", re.I),
        re.compile(r"powershell", re.I),
        re.compile(r"msxml", re.I),
        re.compile(r"sqlmap", re.I),
        re.compile(r"nikto", re.I),
        re.compile(r"nmap", re.I),
    ]

    KNOWN_GOOD_USER_AGENTS = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X",
        "Mozilla/5.0 (X11; Linux x86_64)",
        "Mozilla/5.0 (iPhone; CPU iPhone OS",
    }

    LARGE_UPLOAD_THRESHOLD = 10 * 1024 * 1024

    def __init__(self):
        self._host_request_counts: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self._user_agent_events: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    def _is_suspicious_user_agent(self, ua: str) -> bool:
        if not ua or ua == "-":
            return False
        for pattern in self.SUSPICIOUS_UA_PATTERNS:
            if pattern.search(ua):
                return True
        if ua not in self.KNOWN_GOOD_USER_AGENTS:
            if not any(ua.startswith(p) for p in self.KNOWN_GOOD_USER_AGENTS):
                if len(ua) > 0 and "Mozilla" not in ua and "Chrome" not in ua and "Safari" not in ua:
                    return True
        return False

    def _detect_data_exfil(self, record: Dict[str, Any]) -> bool:
        request_len = record.get("request_body_len", 0)
        return request_len > self.LARGE_UPLOAD_THRESHOLD

    def _detect_c2_beaconing(self, host: str, records: List[Dict[str, Any]]) -> bool:
        if len(records) < 5:
            return False
        timestamps = []
        for r in records:
            ts_str = r.get("ts", "")
            if ts_str:
                try:
                    dt = datetime.fromisoformat(ts_str)
                    timestamps.append(dt.timestamp())
                except (ValueError, TypeError):
                    continue
        if len(timestamps) < 5:
            return False
        timestamps.sort()
        intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
        if not intervals:
            return False
        mean = sum(intervals) / len(intervals)
        if mean == 0:
            return False
        variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
        std_dev = math.sqrt(variance)
        cv = std_dev / mean if mean > 0 else float("inf")
        return cv < 0.15 and mean > 5

    def analyze(self, http_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        anomalies = []
        for record in http_records:
            host = record.get("host", "")
            ua = record.get("user_agent", "")

            if self._is_suspicious_user_agent(ua):
                anomalies.append({
                    "type": "suspicious_user_agent",
                    "severity": "MEDIUM",
                    "confidence": 0.75,
                    "description": f"Suspicious user agent: {ua[:100]}",
                    "evidence": {
                        "user_agent": ua, "host": host,
                        "src_ip": record.get("src_ip", ""),
                        "method": record.get("method", ""),
                        "uri": record.get("uri", "")[:200],
                    },
                    "mitre_technique": "T1071.001",
                    "mitre_tactic": "Command and Control",
                })

            if self._detect_data_exfil(record):
                anomalies.append({
                    "type": "data_exfil_upload",
                    "severity": "CRITICAL",
                    "confidence": 0.85,
                    "description": f"Large upload detected: {record.get('request_body_len', 0):,} bytes to {host}",
                    "evidence": {
                        "host": host, "request_body_len": record.get("request_body_len", 0),
                        "src_ip": record.get("src_ip", ""), "uri": record.get("uri", "")[:200],
                    },
                    "mitre_technique": "T1041",
                    "mitre_tactic": "Exfiltration",
                })

            self._host_request_counts[host].append(record)

        for host, records in self._host_request_counts.items():
            if self._detect_c2_beaconing(host, records):
                anomalies.append({
                    "type": "http_c2_beaconing",
                    "severity": "HIGH",
                    "confidence": 0.80,
                    "description": f"Regular HTTP beaconing to {host}",
                    "evidence": {"host": host, "record_count": len(records)},
                    "mitre_technique": "T1071.001",
                    "mitre_tactic": "Command and Control",
                })

        return anomalies


# ---------------------------------------------------------------------------
# Flow Analyzer
# ---------------------------------------------------------------------------

class FlowAnalyzer:
    """Detect lateral movement, port scanning, and unusual connections."""

    LATERAL_MOVEMENT_THRESHOLD = 10
    PORT_SCAN_UNIQUE_PORT_THRESHOLD = 15
    UNUSUAL_CONNECTION_DURATION_THRESHOLD = 3600
    UNUSUAL_PACKET_RATIO_THRESHOLD = 100

    def __init__(self):
        self._src_dst_map: Dict[str, Set[str]] = defaultdict(set)
        self._src_port_map: Dict[str, Set[int]] = defaultdict(set)

    def _is_private_ip(self, ip: str) -> bool:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            first = int(parts[0])
            second = int(parts[1])
        except (ValueError, IndexError):
            return False
        if first == 10:
            return True
        if first == 172 and 16 <= second <= 31:
            return True
        if first == 192 and second == 168:
            return True
        return False

    def _detect_lateral_movement(self, flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        anomalies = []
        src_to_dst: Dict[str, Set[str]] = defaultdict(set)
        for flow in flows:
            src = flow.get("src_ip", "")
            dst = flow.get("dst_ip", "")
            if src and dst and self._is_private_ip(src) and self._is_private_ip(dst):
                src_to_dst[src].add(dst)

        for src_ip, dst_hosts in src_to_dst.items():
            if len(dst_hosts) >= self.LATERAL_MOVEMENT_THRESHOLD:
                confidence = min(0.95, 0.5 + (len(dst_hosts) - self.LATERAL_MOVEMENT_THRESHOLD) * 0.02)
                anomalies.append({
                    "type": "lateral_movement",
                    "severity": "CRITICAL",
                    "confidence": round(confidence, 3),
                    "description": f"{src_ip} connected to {len(dst_hosts)} unique internal hosts",
                    "evidence": {"src_ip": src_ip, "unique_hosts": len(dst_hosts), "hosts": list(dst_hosts)[:20]},
                    "mitre_technique": "T1021",
                    "mitre_tactic": "Lateral Movement",
                })
        return anomalies

    def _detect_port_scan(self, flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        anomalies = []
        src_to_ports: Dict[str, Set[int]] = defaultdict(set)
        for flow in flows:
            src = flow.get("src_ip", "")
            dst_port = flow.get("dst_port", 0)
            if src and dst_port:
                src_to_ports[src].add(dst_port)

        for src_ip, ports in src_to_ports.items():
            if len(ports) >= self.PORT_SCAN_UNIQUE_PORT_THRESHOLD:
                confidence = min(0.95, 0.5 + (len(ports) - self.PORT_SCAN_UNIQUE_PORT_THRESHOLD) * 0.02)
                anomalies.append({
                    "type": "port_scan",
                    "severity": "MEDIUM",
                    "confidence": round(confidence, 3),
                    "description": f"{src_ip} scanned {len(ports)} unique ports",
                    "evidence": {"src_ip": src_ip, "unique_ports": len(ports), "ports": sorted(list(ports))[:50]},
                    "mitre_technique": "T1046",
                    "mitre_tactic": "Discovery",
                })
        return anomalies

    def _detect_unusual_connections(self, flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        anomalies = []
        for flow in flows:
            duration = flow.get("duration", 0) or 0
            orig_pkts = flow.get("orig_pkts", 0) or flow.get("packets", 0) or 0
            resp_pkts = flow.get("resp_pkts", 0) or 0

            if duration > self.UNUSUAL_CONNECTION_DURATION_THRESHOLD:
                anomalies.append({
                    "type": "unusual_long_connection",
                    "severity": "MEDIUM",
                    "confidence": 0.70,
                    "description": f"Very long connection: {duration:.0f}s between {flow.get('src_ip', '')} and {flow.get('dst_ip', '')}",
                    "evidence": {
                        "src_ip": flow.get("src_ip", ""), "dst_ip": flow.get("dst_ip", ""),
                        "duration": duration, "protocol": flow.get("protocol", flow.get("proto", "")),
                    },
                    "mitre_technique": "T1071",
                    "mitre_tactic": "Command and Control",
                })

            if orig_pkts > 0 and resp_pkts > 0:
                ratio = orig_pkts / resp_pkts
                if ratio > self.UNUSUAL_PACKET_RATIO_THRESHOLD or (1 / ratio) > self.UNUSUAL_PACKET_RATIO_THRESHOLD:
                    anomalies.append({
                        "type": "unusual_packet_ratio",
                        "severity": "LOW",
                        "confidence": 0.60,
                        "description": f"Unusual packet ratio: {orig_pkts} orig vs {resp_pkts} resp pkts",
                        "evidence": {"src_ip": flow.get("src_ip", ""), "dst_ip": flow.get("dst_ip", ""),
                                     "orig_pkts": orig_pkts, "resp_pkts": resp_pkts},
                        "mitre_technique": "T1071",
                        "mitre_tactic": "Command and Control",
                    })
        return anomalies

    def analyze(self, flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        anomalies = []
        anomalies.extend(self._detect_lateral_movement(flows))
        anomalies.extend(self._detect_port_scan(flows))
        anomalies.extend(self._detect_unusual_connections(flows))
        return anomalies


# ---------------------------------------------------------------------------
# Beacon Detector
# ---------------------------------------------------------------------------

class BeaconDetector:
    """Detect C2 beaconing using regular interval detection (Jaccard + timing)."""

    MIN_CONNECTIONS = 10
    JACCARD_THRESHOLD = 0.7
    CV_THRESHOLD = 0.2
    TIME_BUCKET_SECONDS = 60

    def __init__(self):
        self._connection_timestamps: Dict[str, List[float]] = defaultdict(list)
        self._interval_histograms: Dict[str, Set[int]] = {}

    def _jaccard_similarity(self, set_a: Set[int], set_b: Set[int]) -> float:
        if not set_a and not set_b:
            return 0.0
        intersection = set_a & set_b
        union = set_a | set_b
        return len(intersection) / len(union) if union else 0.0

    def _build_interval_set(self, timestamps: List[float]) -> Set[int]:
        if len(timestamps) < 2:
            return set()
        sorted_ts = sorted(timestamps)
        intervals = set()
        for i in range(len(sorted_ts) - 1):
            diff = sorted_ts[i + 1] - sorted_ts[i]
            bucketed = int(diff / self.TIME_BUCKET_SECONDS)
            intervals.add(bucketed)
        return intervals

    def _coefficient_of_variation(self, intervals: List[float]) -> float:
        if not intervals:
            return float("inf")
        mean = sum(intervals) / len(intervals)
        if mean == 0:
            return float("inf")
        variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
        return math.sqrt(variance) / mean

    def _detect_pair_beacon(self, src_ip: str, dst_ip: str, timestamps: List[float]) -> Optional[Dict[str, Any]]:
        if len(timestamps) < self.MIN_CONNECTIONS:
            return None

        sorted_ts = sorted(timestamps)
        intervals = [sorted_ts[i + 1] - sorted_ts[i] for i in range(len(sorted_ts) - 1)]

        cv = self._coefficient_of_variation(intervals)
        mean_interval = sum(intervals) / len(intervals)
        interval_set = self._build_interval_set(sorted_ts)

        pair_key = f"{src_ip}:{dst_ip}"
        prev_set = self._interval_histograms.get(pair_key)
        jaccard = 0.0
        if prev_set is not None and interval_set:
            jaccard = self._jaccard_similarity(interval_set, prev_set)
        self._interval_histograms[pair_key] = interval_set

        score = 0.0
        if cv < self.CV_THRESHOLD:
            cv_score = (self.CV_THRESHOLD - cv) / self.CV_THRESHOLD
            score += 0.5 * cv_score
        if jaccard > self.JACCARD_THRESHOLD:
            score += 0.3 * jaccard
        if mean_interval > 10:
            score += 0.2 * min(1.0, mean_interval / 300)

        if score > 0.5:
            confidence = min(0.95, 0.3 + score * 0.6)
            severity = "CRITICAL" if score > 0.8 else "HIGH"
            return {
                "type": "c2_beacon",
                "severity": severity,
                "confidence": round(confidence, 3),
                "description": f"Beaconing detected: {src_ip} -> {dst_ip} every {mean_interval:.1f}s (CV={cv:.3f})",
                "evidence": {
                    "src_ip": src_ip, "dst_ip": dst_ip,
                    "mean_interval_s": round(mean_interval, 2),
                    "cv": round(cv, 4), "jaccard": round(jaccard, 4),
                    "total_connections": len(timestamps), "score": round(score, 4),
                },
                "mitre_technique": "T1573",
                "mitre_tactic": "Command and Control",
            }
        return None

    def detect(self, flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        pair_timestamps: Dict[str, List[float]] = defaultdict(list)

        for flow in flows:
            src_ip = flow.get("src_ip", "")
            dst_ip = flow.get("dst_ip", "")
            ts_str = flow.get("ts", "")
            if not src_ip or not dst_ip or not ts_str:
                continue
            try:
                dt = datetime.fromisoformat(ts_str)
                timestamp = dt.timestamp()
            except (ValueError, TypeError):
                continue
            pair_timestamps[f"{src_ip}:{dst_ip}"].append(timestamp)

        anomalies = []
        for pair_key, timestamps in pair_timestamps.items():
            parts = pair_key.split(":", 1)
            if len(parts) != 2:
                continue
            src_ip, dst_ip = parts
            result = self._detect_pair_beacon(src_ip, dst_ip, timestamps)
            if result:
                anomalies.append(result)

        return anomalies


# ---------------------------------------------------------------------------
# Exfil Detector
# ---------------------------------------------------------------------------

class ExfilDetector:
    """Detect data exfiltration via unusual outbound data volume."""

    OUTBOUND_THRESHOLD_MB = 50
    PER_HOST_THRESHOLD_MB = 20
    TIME_WINDOW_MINUTES = 10
    RATIO_THRESHOLD = 10.0

    def __init__(self):
        self._host_outbound: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self._host_baseline: Dict[str, float] = {}

    def _bytes_to_mb(self, bytes_val: int) -> float:
        return bytes_val / (1024 * 1024)

    def _is_private_ip(self, ip: str) -> bool:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            first = int(parts[0])
            second = int(parts[1])
        except (ValueError, IndexError):
            return False
        if first == 10:
            return True
        if first == 172 and 16 <= second <= 31:
            return True
        if first == 192 and second == 168:
            return True
        return False

    def _detect_large_outbound(self, flow: Dict[str, Any]) -> bool:
        orig_bytes = flow.get("orig_bytes", 0) or flow.get("octets", 0) or 0
        orig_ip = flow.get("src_ip", "")
        if orig_ip and self._is_private_ip(orig_ip) and not self._is_private_ip(flow.get("dst_ip", "")):
            return self._bytes_to_mb(orig_bytes) > self.OUTBOUND_THRESHOLD_MB
        return False

    def _detect_host_volume_anomaly(self, src_ip: str) -> Optional[Dict[str, Any]]:
        records = self._host_outbound.get(src_ip, [])
        if len(records) < 3:
            return None
        total_bytes = sum(r.get("orig_bytes", 0) or r.get("octets", 0) or 0 for r in records)
        total_mb = self._bytes_to_mb(total_bytes)
        if total_mb < self.PER_HOST_THRESHOLD_MB:
            return None
        baseline = self._host_baseline.get(src_ip, 0)
        if baseline > 0 and total_mb > baseline * 3:
            ratio = total_mb / baseline
        else:
            ratio = total_mb / self.PER_HOST_THRESHOLD_MB
        if ratio > self.RATIO_THRESHOLD:
            confidence = min(0.95, 0.5 + (ratio - self.RATIO_THRESHOLD) * 0.03)
            return {
                "type": "volume_exfil",
                "severity": "CRITICAL",
                "confidence": round(confidence, 3),
                "description": f"Unusual outbound volume from {src_ip}: {total_mb:.1f} MB ({ratio:.1f}x baseline)",
                "evidence": {"src_ip": src_ip, "total_outbound_mb": round(total_mb, 2),
                             "ratio_to_baseline": round(ratio, 2), "record_count": len(records)},
                "mitre_technique": "T1041",
                "mitre_tactic": "Exfiltration",
            }
        return None

    def analyze(self, flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        anomalies = []

        for flow in flows:
            src_ip = flow.get("src_ip", "")
            dst_ip = flow.get("dst_ip", "")
            if src_ip and self._is_private_ip(src_ip) and not self._is_private_ip(dst_ip):
                self._host_outbound[src_ip].append(flow)

            if self._detect_large_outbound(flow):
                orig_bytes = flow.get("orig_bytes", 0) or flow.get("octets", 0) or 0
                anomalies.append({
                    "type": "large_outbound_transfer",
                    "severity": "CRITICAL",
                    "confidence": 0.85,
                    "description": f"Large outbound transfer: {self._bytes_to_mb(orig_bytes):.1f} MB from {src_ip} to {dst_ip}",
                    "evidence": {"src_ip": src_ip, "dst_ip": dst_ip, "bytes": orig_bytes,
                                 "mb": round(self._bytes_to_mb(orig_bytes), 2), "dst_port": flow.get("dst_port", 0)},
                    "mitre_technique": "T1041",
                    "mitre_tactic": "Exfiltration",
                })

        for src_ip in self._host_outbound:
            result = self._detect_host_volume_anomaly(src_ip)
            if result:
                anomalies.append(result)

        return anomalies


# ---------------------------------------------------------------------------
# Network Analysis Engine
# ---------------------------------------------------------------------------

class NetworkAnalysisEngine:
    """Main engine that orchestrates all network analyzers."""

    def __init__(self):
        self.netflow_parser = NetFlowParser()
        self.zeek_parser = ZeekLogParser()
        self.dns_analyzer = DNSAnalyzer()
        self.http_analyzer = HTTPAnalyzer()
        self.flow_analyzer = FlowAnalyzer()
        self.beacon_detector = BeaconDetector()
        self.exfil_detector = ExfilDetector()
        self._anomaly_buffer: List[Dict[str, Any]] = []
        self._tables_created = False

    def _ensure_network_tables(self):
        if self._tables_created:
            return
        try:
            with db._cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS network_flows (
                        id TEXT PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        src_ip TEXT NOT NULL,
                        dst_ip TEXT NOT NULL,
                        src_port INTEGER DEFAULT 0,
                        dst_port INTEGER DEFAULT 0,
                        protocol TEXT DEFAULT '',
                        packets INTEGER DEFAULT 0,
                        bytes_transferred INTEGER DEFAULT 0,
                        duration REAL DEFAULT 0.0,
                        metadata TEXT DEFAULT '{}'
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS dns_queries (
                        id TEXT PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        src_ip TEXT DEFAULT '',
                        query TEXT NOT NULL,
                        query_type TEXT DEFAULT '',
                        response_code TEXT DEFAULT '',
                        answers TEXT DEFAULT '[]',
                        ttl INTEGER DEFAULT 0,
                        metadata TEXT DEFAULT '{}'
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS http_metadata (
                        id TEXT PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        src_ip TEXT DEFAULT '',
                        dst_ip TEXT DEFAULT '',
                        host TEXT DEFAULT '',
                        uri TEXT DEFAULT '',
                        method TEXT DEFAULT '',
                        user_agent TEXT DEFAULT '',
                        status_code INTEGER DEFAULT 0,
                        request_bytes INTEGER DEFAULT 0,
                        response_bytes INTEGER DEFAULT 0,
                        metadata TEXT DEFAULT '{}'
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS network_anomalies (
                        id TEXT PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        anomaly_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        confidence REAL NOT NULL,
                        description TEXT DEFAULT '',
                        evidence TEXT DEFAULT '{}',
                        mitre_technique TEXT DEFAULT '',
                        mitre_tactic TEXT DEFAULT '',
                        source_ip TEXT DEFAULT '',
                        dest_ip TEXT DEFAULT '',
                        dest_port INTEGER DEFAULT 0,
                        metadata TEXT DEFAULT '{}'
                    )
                """)
            self._tables_created = True
        except Exception as e:
            logger.error("Failed to create network analysis tables: %s", e)

    def _store_flows(self, flows: List[Dict[str, Any]]) -> int:
        stored = 0
        for flow in flows:
            flow_id = str(uuid.uuid4())
            ts = flow.get("ts", "")
            if not ts:
                dt_val = flow.get("first_switched_ms")
                if dt_val is not None:
                    try:
                        ts = datetime.fromtimestamp(dt_val / 1000.0, tz=timezone.utc).isoformat()
                    except (ValueError, OSError):
                        ts = datetime.now(timezone.utc).isoformat()
                else:
                    ts = datetime.now(timezone.utc).isoformat()
            try:
                with db._cursor() as cur:
                    cur.execute(
                        "INSERT INTO network_flows (id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, bytes_sent, bytes_received, packets_sent, packets_received, flow_duration_ms, flags, application, source, device_id, created_at) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (flow_id, ts, flow.get("src_ip", ""), flow.get("dst_ip", ""),
                         int(flow.get("src_port", 0) or 0), int(flow.get("dst_port", 0) or 0),
                         int(flow.get("protocol", flow.get("proto", 0)) or 0),
                         flow.get("octets", flow.get("orig_bytes", 0)) or 0,
                         flow.get("octets", flow.get("orig_bytes", 0)) or 0,
                         flow.get("packets", flow.get("orig_pkts", 0)) or 0,
                         0,
                         int(flow.get("duration", 0) * 1000 if isinstance(flow.get("duration", 0), float) else flow.get("duration", 0) or 0),
                         flow.get("flags", ""),
                         flow.get("application", ""),
                         "",
                         flow.get("device_id", ""),
                         ts)
                    )
                stored += 1
            except Exception as e:
                logger.error("Failed to store flow: %s", e)
        return stored

    def _store_dns_queries(self, records: List[Dict[str, Any]]) -> int:
        stored = 0
        for record in records:
            record_id = str(uuid.uuid4())
            ts = record.get("ts", "")
            if not ts:
                ts = datetime.now(timezone.utc).isoformat()
            try:
                with db._cursor() as cur:
                    cur.execute(
                        "INSERT INTO dns_queries (id, timestamp, src_ip, query_name, query_type, response_code, response_data, resolved, ttl, source, created_at) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                        (record_id, ts, record.get("src_ip", ""),
                         record.get("query", record.get("query_name", "")),
                         record.get("qtype_name", record.get("query_type", "")),
                         record.get("rcode_name", record.get("response_code", "")),
                         json.dumps(record.get("answers", record.get("response_data", []))),
                         1, record.get("ttl", 0),
                         "", ts)
                    )
                stored += 1
            except Exception as e:
                logger.error("Failed to store DNS query: %s", e)
        return stored

    def _store_http_metadata(self, records: List[Dict[str, Any]]) -> int:
        stored = 0
        for record in records:
            record_id = str(uuid.uuid4())
            ts = record.get("ts", "")
            if not ts:
                ts = datetime.now(timezone.utc).isoformat()
            try:
                with db._cursor() as cur:
                    cur.execute(
                        "INSERT INTO http_metadata (id, timestamp, src_ip, dst_ip, dst_port, method, host, uri, user_agent, status_code, response_size, content_type, tls_version, ja3_hash, source, created_at) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (record_id, ts, record.get("src_ip", ""), record.get("dst_ip", ""),
                         int(record.get("dst_port", 80) or 80),
                         record.get("method", ""),
                         record.get("host", ""),
                         record.get("uri", ""),
                         record.get("user_agent", ""),
                         int(record.get("status_code", 0) or 0),
                         int(record.get("response_body_len", record.get("response_size", 0)) or 0),
                         record.get("content_type", ""),
                         record.get("tls_version", ""),
                         record.get("ja3_hash", ""),
                         "", ts)
                    )
                stored += 1
            except Exception as e:
                logger.error("Failed to store HTTP metadata: %s", e)
        return stored

    def _store_anomalies(self, anomalies: List[Dict[str, Any]], source: str = "") -> int:
        stored = 0
        for anomaly in anomalies:
            anomaly_id = str(uuid.uuid4())
            ts = datetime.now(timezone.utc).isoformat()
            try:
                with db._cursor() as cur:
                    cur.execute(
                        "INSERT INTO network_anomalies (id, anomaly_type, severity, confidence, src_ip, dst_ip, description, evidence, mitre_technique, mitre_tactic, detected_at, resolved) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                        (anomaly_id, anomaly.get("type", ""),
                         anomaly.get("severity", "INFO"), anomaly.get("confidence", 0.0),
                         anomaly.get("src_ip", anomaly.get("evidence", {}).get("src_ip", "")),
                         anomaly.get("dst_ip", anomaly.get("evidence", {}).get("dst_ip", "")),
                         anomaly.get("description", ""),
                         json.dumps(anomaly.get("evidence", {})),
                         anomaly.get("mitre_technique", ""),
                         anomaly.get("mitre_tactic", ""),
                         ts, 0)
                    )
                stored += 1
            except Exception as e:
                logger.error("Failed to store anomaly: %s", e)
        return stored

    def _severity_to_numeric(self, severity: str) -> float:
        mapping = {"INFO": 0.1, "LOW": 0.3, "MEDIUM": 0.5, "HIGH": 0.75, "CRITICAL": 0.95}
        return mapping.get(severity, 0.5)

    def _deduplicate_anomalies(self, anomalies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        unique = []
        sorted_anomalies = sorted(anomalies, key=lambda a: self._severity_to_numeric(a.get("severity", "LOW")), reverse=True)
        for anomaly in sorted_anomalies:
            key = f"{anomaly.get('type', '')}:{anomaly.get('evidence', {}).get('src_ip', '')}:{anomaly.get('severity', '')}"
            if key not in seen:
                seen.add(key)
                unique.append(anomaly)
        return unique

    def analyze_netflow(self, data: bytes) -> Dict[str, Any]:
        self._ensure_network_tables()
        result = self.netflow_parser.parse(data)
        flows = result.get("flows", [])
        if not flows:
            return {"flow_count": 0, "anomalies": [], "error": result.get("error", "")}

        stored = self._store_flows(flows)
        flow_anomalies = self.flow_analyzer.analyze(flows)
        beacon_anomalies = self.beacon_detector.detect(flows)
        exfil_anomalies = self.exfil_detector.analyze(flows)

        all_anomalies = self._deduplicate_anomalies(flow_anomalies + beacon_anomalies + exfil_anomalies)
        anomalies_stored = self._store_anomalies(all_anomalies, source="netflow")

        return {
            "flow_count": len(flows),
            "stored": stored,
            "anomaly_count": len(all_anomalies),
            "anomalies": all_anomalies,
            "anomalies_stored": anomalies_stored,
        }

    def analyze_zeek_connection(self, content: str) -> Dict[str, Any]:
        self._ensure_network_tables()
        records = self.zeek_parser.parse_file("connection", content)
        if not records:
            return {"record_count": 0, "anomalies": []}

        stored = self._store_flows(records)
        flow_anomalies = self.flow_analyzer.analyze(records)
        beacon_anomalies = self.beacon_detector.detect(records)
        exfil_anomalies = self.exfil_detector.analyze(records)

        all_anomalies = self._deduplicate_anomalies(flow_anomalies + beacon_anomalies + exfil_anomalies)
        anomalies_stored = self._store_anomalies(all_anomalies, source="zeek_connection")

        return {
            "record_count": len(records),
            "stored": stored,
            "anomaly_count": len(all_anomalies),
            "anomalies": all_anomalies,
            "anomalies_stored": anomalies_stored,
        }

    def analyze_zeek_dns(self, content: str) -> Dict[str, Any]:
        self._ensure_network_tables()
        records = self.zeek_parser.parse_file("dns", content)
        if not records:
            return {"record_count": 0, "anomalies": []}

        stored = self._store_dns_queries(records)
        dns_anomalies = self.dns_analyzer.analyze(records)

        all_anomalies = self._deduplicate_anomalies(dns_anomalies)
        anomalies_stored = self._store_anomalies(all_anomalies, source="zeek_dns")

        return {
            "record_count": len(records),
            "stored": stored,
            "anomaly_count": len(all_anomalies),
            "anomalies": all_anomalies,
            "anomalies_stored": anomalies_stored,
        }

    def analyze_zeek_http(self, content: str) -> Dict[str, Any]:
        self._ensure_network_tables()
        records = self.zeek_parser.parse_file("http", content)
        if not records:
            return {"record_count": 0, "anomalies": []}

        stored = self._store_http_metadata(records)
        http_anomalies = self.http_analyzer.analyze(records)

        all_anomalies = self._deduplicate_anomalies(http_anomalies)
        anomalies_stored = self._store_anomalies(all_anomalies, source="zeek_http")

        return {
            "record_count": len(records),
            "stored": stored,
            "anomaly_count": len(all_anomalies),
            "anomalies": all_anomalies,
            "anomalies_stored": anomalies_stored,
        }

    def analyze_batch(self, dns_records: List[Dict] = None, http_records: List[Dict] = None,
                      flows: List[Dict] = None) -> Dict[str, Any]:
        self._ensure_network_tables()
        all_anomalies = []
        summary = {"dns": 0, "http": 0, "flow": 0, "total_anomalies": 0}

        if dns_records:
            summary["dns"] = len(dns_records)
            self._store_dns_queries(dns_records)
            all_anomalies.extend(self.dns_analyzer.analyze(dns_records))

        if http_records:
            summary["http"] = len(http_records)
            self._store_http_metadata(http_records)
            all_anomalies.extend(self.http_analyzer.analyze(http_records))

        if flows:
            summary["flow"] = len(flows)
            self._store_flows(flows)
            all_anomalies.extend(self.flow_analyzer.analyze(flows))
            all_anomalies.extend(self.beacon_detector.detect(flows))
            all_anomalies.extend(self.exfil_detector.analyze(flows))

        all_anomalies = self._deduplicate_anomalies(all_anomalies)
        self._store_anomalies(all_anomalies, source="batch")
        summary["total_anomalies"] = len(all_anomalies)

        severity_breakdown = Counter(a.get("severity", "INFO") for a in all_anomalies)
        type_breakdown = Counter(a.get("type", "unknown") for a in all_anomalies)

        return {
            "summary": summary,
            "anomalies": all_anomalies,
            "severity_breakdown": dict(severity_breakdown),
            "type_breakdown": dict(type_breakdown),
        }

    def get_recent_anomalies(self, limit: int = 100) -> List[Dict[str, Any]]:
        try:
            with db._cursor() as cur:
                cur.execute(
                    "SELECT * FROM network_anomalies ORDER BY timestamp DESC LIMIT ?",
                    (limit,)
                )
                rows = cur.fetchall()
                return [dict(row) for row in rows]
        except Exception as e:
            logger.error("Failed to fetch recent anomalies: %s", e)
            return []

    def get_anomaly_stats(self) -> Dict[str, Any]:
        try:
            with db._cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM network_anomalies")
                row = cur.fetchone()
                total = row[0] if row else 0

                cur.execute("SELECT anomaly_type, COUNT(*) FROM network_anomalies GROUP BY anomaly_type ORDER BY COUNT(*) DESC")
                type_rows = cur.fetchall()
                by_type = {r[0]: r[1] for r in type_rows}

                cur.execute("SELECT severity, COUNT(*) FROM network_anomalies GROUP BY severity")
                sev_rows = cur.fetchall()
                by_severity = {r[0]: r[1] for r in sev_rows}

                if db.use_postgresql:
                    cur.execute("SELECT source_ip::text, COUNT(*) FROM network_anomalies WHERE source_ip IS NOT NULL AND source_ip::text != '' GROUP BY source_ip ORDER BY COUNT(*) DESC LIMIT 10")
                else:
                    cur.execute("SELECT source_ip, COUNT(*) FROM network_anomalies WHERE source_ip IS NOT NULL AND source_ip != '' GROUP BY source_ip ORDER BY COUNT(*) DESC LIMIT 10")
                ip_rows = cur.fetchall()
                top_sources = {r[0]: r[1] for r in ip_rows}

                return {
                    "total_anomalies": total,
                    "by_type": by_type,
                    "by_severity": by_severity,
                    "top_source_ips": top_sources,
                }
        except Exception as e:
            logger.error("Failed to fetch anomaly stats: %s", e)
            return {"total_anomalies": 0, "by_type": {}, "by_severity": {}, "top_source_ips": {}}

    def get_flow_stats(self) -> Dict[str, Any]:
        try:
            with db._cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM network_flows")
                row = cur.fetchone()
                total_flows = row[0] if row else 0

                cur.execute("SELECT SUM(bytes_transferred) FROM network_flows")
                row = cur.fetchone()
                total_bytes = row[0] if row and row[0] else 0

                cur.execute("SELECT COUNT(DISTINCT src_ip) FROM network_flows")
                row = cur.fetchone()
                unique_src_ips = row[0] if row else 0

                cur.execute("SELECT COUNT(DISTINCT dst_ip) FROM network_flows")
                row = cur.fetchone()
                unique_dst_ips = row[0] if row else 0

                cur.execute("SELECT protocol, COUNT(*) FROM network_flows GROUP BY protocol ORDER BY COUNT(*) DESC")
                proto_rows = cur.fetchall()
                by_protocol = {r[0]: r[1] for r in proto_rows}

                return {
                    "total_flows": total_flows,
                    "total_bytes": total_bytes,
                    "total_mb": round(total_bytes / (1024 * 1024), 2),
                    "unique_src_ips": unique_src_ips,
                    "unique_dst_ips": unique_dst_ips,
                    "by_protocol": by_protocol,
                }
        except Exception as e:
            logger.error("Failed to fetch flow stats: %s", e)
            return {"total_flows": 0, "total_bytes": 0, "total_mb": 0, "unique_src_ips": 0, "unique_dst_ips": 0, "by_protocol": {}}

    def reset(self):
        self.dns_analyzer = DNSAnalyzer()
        self.http_analyzer = HTTPAnalyzer()
        self.flow_analyzer = FlowAnalyzer()
        self.beacon_detector = BeaconDetector()
        self.exfil_detector = ExfilDetector()
        self._anomaly_buffer = []


network_analysis_engine = NetworkAnalysisEngine()
