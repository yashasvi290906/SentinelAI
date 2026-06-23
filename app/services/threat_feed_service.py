"""
STIX/TAXII Threat Feed Service for SentinelAI.
Connects to TAXII 2.1 servers, parses STIX 2.1 bundles, and stores indicators in SQLite.
Provides IOC matching against collected threat intelligence.
"""
import json
import re
import uuid
import time
import asyncio
import logging
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, asdict
from enum import Enum

import httpx

logger = logging.getLogger("sentinelai.threat_feed")


# ---------------------------------------------------------------------------
# Database tables created on demand via threat_feed_service.init_db()
# ---------------------------------------------------------------------------

class AuthType(Enum):
    NONE = "none"
    BASIC = "basic"
    CERT = "cert"


@dataclass
class FeedConfig:
    name: str
    url: str
    auth_type: str = "none"
    auth_username: str = ""
    auth_password: str = ""
    auth_cert_path: str = ""
    auth_cert_key_path: str = ""
    poll_interval_seconds: int = 3600
    enabled: bool = True
    collection_id: str = ""
    description: str = ""
    tlp: str = "white"
    feed_type: str = "intel"


# ---------------------------------------------------------------------------
# Pre-configured feeds
# ---------------------------------------------------------------------------
DEFAULT_FEEDS: List[FeedConfig] = [
    FeedConfig(
        name="CISA Known Exploited Vulnerabilities",
        url="https://taxii.mitre.org/taxii2",
        auth_type="none",
        collection_id="95ecc380-afe8-47c1-ad19-e67a1b181ea2",
        description="MITRE ATT&CK STIX objects from the official TAXII server",
        poll_interval_seconds=7200,
        tlp="white",
        feed_type="taxii",
    ),
    FeedConfig(
        name="MITRE ATT&CK STIX",
        url="https://cti-taxii.mitre.org/taxii2",
        auth_type="none",
        collection_id="95ecc380-afe8-47c1-ad19-e67a1b181ea2",
        description="ATT&CK Enterprise STIX data",
        poll_interval_seconds=14400,
        tlp="white",
        feed_type="taxii",
    ),
    FeedConfig(
        name="Abuse.ch URLhaus",
        url="https://urlhaus-api.abuse.ch/v1/",
        auth_type="none",
        collection_id="",
        description="Abuse.ch URLhaus malicious URL feed",
        poll_interval_seconds=1800,
        tlp="white",
        feed_type="intel",
    ),
]


# ═══════════════════════════════════════════════════════════════════════════
# TAXIIClient
# ═══════════════════════════════════════════════════════════════════════════

class TAXIIClient:
    """HTTP client for TAXII 2.1 servers with auth support."""

    def __init__(self, base_url: str, auth_type: str = "none",
                 username: str = "", password: str = "",
                 cert_path: str = "", cert_key_path: str = ""):
        self.base_url = base_url.rstrip("/")
        self.auth_type = auth_type
        self.username = username
        self.password = password
        self.cert_path = cert_path
        self.cert_key_path = cert_key_path
        self.headers: Dict[str, str] = {
            "Accept": "application/taxii+json;version=2.1",
        }

    def _build_auth(self) -> Optional[Tuple[str, str]]:
        if self.auth_type == AuthType.BASIC.value:
            return (self.username, self.password)
        return None

    def _build_cert(self) -> Optional[Tuple[str, Optional[str]]]:
        if self.auth_type == AuthType.CERT.value:
            return (self.cert_path, self.cert_key_path or None)
        return None

    async def get_status(self) -> Dict[str, Any]:
        url = f"{self.base_url}/"
        try:
            async with httpx.AsyncClient(timeout=30, verify=True) as client:
                resp = await client.get(url, headers=self.headers)
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPStatusError as exc:
            logger.error("TAXII status error %s: %s", self.base_url, exc.response.status_code)
            return {"error": f"HTTP {exc.response.status_code}"}
        except Exception as exc:
            logger.error("TAXII status request failed for %s: %s", self.base_url, exc)
            return {"error": str(exc)}

    async def get_collections(self) -> List[Dict[str, Any]]:
        url = f"{self.base_url}/collections/"
        try:
            async with httpx.AsyncClient(timeout=30, verify=True) as client:
                resp = await client.get(url, headers=self.headers,
                                        auth=self._build_auth())
                resp.raise_for_status()
                data = resp.json()
                return data.get("collections", [])
        except Exception as exc:
            logger.error("Failed to fetch collections from %s: %s", self.base_url, exc)
            return []

    async def get_collection(self, collection_id: str) -> Dict[str, Any]:
        url = f"{self.base_url}/collections/{collection_id}/"
        try:
            async with httpx.AsyncClient(timeout=30, verify=True) as client:
                resp = await client.get(url, headers=self.headers,
                                        auth=self._build_auth())
                resp.raise_for_status()
                return resp.json()
        except Exception as exc:
            logger.error("Failed to fetch collection %s: %s", collection_id, exc)
            return {}

    async def get_objects(self, collection_id: str,
                          added_after: Optional[str] = None,
                          limit: int = 0) -> List[Dict[str, Any]]:
        url = f"{self.base_url}/collections/{collection_id}/objects/"
        params: Dict[str, Any] = {}
        if added_after:
            params["added_after"] = added_after
        if limit > 0:
            params["limit"] = limit

        all_objects: List[Dict[str, Any]] = []
        try:
            async with httpx.AsyncClient(timeout=60, verify=True) as client:
                while True:
                    resp = await client.get(url, headers=self.headers,
                                            auth=self._build_auth(),
                                            params=params)
                    resp.raise_for_status()
                    data = resp.json()
                    objects = data.get("objects", [])
                    all_objects.extend(objects)

                    more = data.get("more", False)
                    next_url = data.get("next")
                    if not more or not next_url:
                        break
                    url = next_url
                    params = {}
        except Exception as exc:
            logger.error("Failed to fetch objects from collection %s: %s", collection_id, exc)

        return all_objects

    async def post_additions(self, collection_id: str,
                             objects: List[Dict[str, Any]]) -> bool:
        url = f"{self.base_url}/collections/{collection_id}/objects/"
        payload = {"type": "bundle", "objects": objects}
        try:
            async with httpx.AsyncClient(timeout=60, verify=True) as client:
                resp = await client.post(
                    url, headers={**self.headers, "Content-Type": "application/taxii+json;version=2.1"},
                    auth=self._build_auth(),
                    json=payload,
                )
                resp.raise_for_status()
                return True
        except Exception as exc:
            logger.error("Failed to post additions to collection %s: %s", collection_id, exc)
            return False


# ═══════════════════════════════════════════════════════════════════════════
# STIXParser
# ═══════════════════════════════════════════════════════════════════════════

class STIXParser:
    """Parse STIX 2.1 bundles and extract indicators from patterns."""

    INDICATOR_PATTERN_RE = re.compile(
        r"\[(\w[\w\-]*)\s*:\s*value\s*=\s*'([^']+)'\]"
    )

    PATTERN_TYPE_MAP: Dict[str, str] = {
        "ipv4-addr": "ip",
        "ipv6-addr": "ip",
        "domain-name": "domain",
        "file": "file_hash",
        "url": "url",
        "email-addr": "email",
        "mac-addr": "mac",
        "autonomous-system": "asn",
        "process": "process",
        "user-account": "user",
        "x509-certificate": "x509",
        "windows-service": "windows_service",
        "mutex": "mutex",
        "artifact": "artifact",
    }

    HASH_PATTERN_RE = re.compile(
        r"file:hashes\.'(?:MD5|SHA-?1|SHA-?256|SHA-?512)'\s*=\s*'([^']+)'",
        re.IGNORECASE,
    )

    def parse_bundle(self, bundle: Dict[str, Any]) -> Dict[str, Any]:
        if bundle.get("type") != "bundle":
            return {"objects": [], "indicators": [], "errors": ["Not a STIX bundle"]}

        objects = bundle.get("objects", [])
        parsed_objects: List[Dict[str, Any]] = []
        indicators: List[Dict[str, Any]] = []
        errors: List[str] = []

        for obj in objects:
            try:
                parsed_obj = self._parse_object(obj)
                if parsed_obj:
                    parsed_objects.append(parsed_obj)

                if obj.get("type") == "indicator":
                    extracted = self._extract_indicator_from_pattern(obj)
                    if extracted:
                        indicators.extend(extracted)
            except Exception as exc:
                errors.append(f"Error parsing object {obj.get('id', 'unknown')}: {exc}")

        return {
            "objects": parsed_objects,
            "indicators": indicators,
            "errors": errors,
            "bundle_id": bundle.get("id", ""),
            "spec_version": bundle.get("spec_version", "2.1"),
        }

    def _parse_object(self, obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        obj_type = obj.get("type", "")
        parsed: Dict[str, Any] = {
            "stix_id": obj.get("id", ""),
            "type": obj_type,
            "spec_version": obj.get("spec_version", "2.1"),
            "created": obj.get("created", ""),
            "modified": obj.get("modified", ""),
            "revoked": obj.get("revoked", False),
            "confidence": obj.get("confidence", 0),
            "labels": obj.get("labels", []),
            "description": obj.get("description", ""),
            "name": obj.get("name", ""),
        }

        if obj_type == "attack-pattern":
            parsed["external_references"] = obj.get("external_references", [])
            parsed["kill_chain_phases"] = obj.get("kill_chain_phases", [])
        elif obj_type == "malware":
            parsed["is_family"] = obj.get("is_family", False)
            parsed["malware_types"] = obj.get("malware_types", [])
            parsed["external_references"] = obj.get("external_references", [])
        elif obj_type == "threat-actor":
            parsed["threat_actor_types"] = obj.get("threat_actor_types", [])
            parsed["aliases"] = obj.get("aliases", [])
        elif obj_type == "report":
            parsed["report_types"] = obj.get("report_types", [])
            parsed["published"] = obj.get("published", "")
        elif obj_type == "observed-data":
            parsed["objects"] = obj.get("objects", [])
        elif obj_type == "relationship":
            parsed["relationship_type"] = obj.get("relationship_type", "")
            parsed["source_ref"] = obj.get("source_ref", "")
            parsed["target_ref"] = obj.get("target_ref", "")
        elif obj_type == "indicator":
            parsed["pattern"] = obj.get("pattern", "")
            parsed["pattern_type"] = obj.get("pattern_type", "stix")
            parsed["valid_from"] = obj.get("valid_from", "")
            parsed["valid_until"] = obj.get("valid_until", "")
            parsed["indicator_types"] = obj.get("indicator_types", [])

        return parsed

    def _extract_indicator_from_pattern(self, indicator_obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        pattern = indicator_obj.get("pattern", "")
        if not pattern:
            return []

        extracted: List[Dict[str, Any]] = []

        matches = self.INDICATOR_PATTERN_RE.findall(pattern)
        for stix_type, value in matches:
            normalized_type = self.PATTERN_TYPE_MAP.get(stix_type, stix_type)
            if normalized_type == "file_hash":
                extracted.extend(self._extract_hashes(pattern, indicator_obj))
            else:
                extracted.append(self._build_indicator_record(
                    indicator_type=normalized_type,
                    value=value.strip(),
                    indicator_obj=indicator_obj,
                    stix_type=stix_type,
                ))

        if not matches:
            extracted.extend(self._extract_hashes(pattern, indicator_obj))

        return extracted

    def _extract_hashes(self, pattern: str, indicator_obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        records: List[Dict[str, Any]] = []
        hash_matches = self.HASH_PATTERN_RE.findall(pattern)
        for hash_val in hash_matches:
            h = hash_val.strip()
            if len(h) == 32:
                htype = "md5"
            elif len(h) == 40:
                htype = "sha1"
            elif len(h) == 64:
                htype = "sha256"
            else:
                htype = "hash"
            records.append(self._build_indicator_record(
                indicator_type=htype,
                value=h,
                indicator_obj=indicator_obj,
                stix_type="file",
            ))
        return records

    def _build_indicator_record(self, indicator_type: str, value: str,
                                indicator_obj: Dict[str, Any],
                                stix_type: str) -> Dict[str, Any]:
        return {
            "stix_id": indicator_obj.get("id", ""),
            "indicator_type": indicator_type,
            "value": value,
            "stix_type": stix_type,
            "pattern": indicator_obj.get("pattern", ""),
            "confidence": indicator_obj.get("confidence", 0),
            "labels": indicator_obj.get("labels", []),
            "valid_from": indicator_obj.get("valid_from", ""),
            "valid_until": indicator_obj.get("valid_until", ""),
            "description": indicator_obj.get("description", ""),
            "name": indicator_obj.get("name", ""),
        }


# ═══════════════════════════════════════════════════════════════════════════
# Database helpers for threat feed tables
# ═══════════════════════════════════════════════════════════════════════════

def _init_feed_tables():
    """Create threat_feeds, stix_objects, stix_indicators tables."""
    from database import db
    with db._cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS threat_feeds (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                feed_type TEXT NOT NULL DEFAULT 'intel',
                url TEXT NOT NULL,
                auth_type TEXT DEFAULT 'none',
                collection_id TEXT DEFAULT '',
                description TEXT DEFAULT '',
                poll_interval_seconds INTEGER DEFAULT 3600,
                enabled INTEGER DEFAULT 1,
                tlp TEXT DEFAULT 'white',
                last_polled TEXT,
                last_polled_objects INTEGER DEFAULT 0,
                total_objects INTEGER DEFAULT 0,
                total_indicators INTEGER DEFAULT 0,
                status TEXT DEFAULT 'idle',
                error_message TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT
            )
        """)
        # Add feed_type column to existing tables if missing
        try:
            cur.execute("ALTER TABLE threat_feeds ADD COLUMN feed_type TEXT NOT NULL DEFAULT 'intel'")
        except Exception:
            pass
        # Fix NULL feed_type values
        try:
            cur.execute("UPDATE threat_feeds SET feed_type = 'intel' WHERE feed_type IS NULL")
        except Exception:
            pass
        cur.execute("""
            CREATE TABLE IF NOT EXISTS stix_objects (
                id TEXT PRIMARY KEY,
                feed_id TEXT NOT NULL,
                stix_id TEXT NOT NULL,
                stix_type TEXT NOT NULL,
                spec_version TEXT DEFAULT '2.1',
                name TEXT DEFAULT '',
                description TEXT DEFAULT '',
                labels TEXT DEFAULT '[]',
                confidence INTEGER DEFAULT 0,
                created TEXT DEFAULT '',
                modified TEXT DEFAULT '',
                revoked INTEGER DEFAULT 0,
                raw_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (feed_id) REFERENCES threat_feeds(id)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS stix_indicators (
                id TEXT PRIMARY KEY,
                feed_id TEXT NOT NULL,
                stix_object_id TEXT,
                stix_id TEXT NOT NULL,
                indicator_type TEXT NOT NULL,
                value TEXT NOT NULL,
                pattern TEXT DEFAULT '',
                confidence INTEGER DEFAULT 0,
                labels TEXT DEFAULT '[]',
                valid_from TEXT DEFAULT '',
                valid_until TEXT DEFAULT '',
                description TEXT DEFAULT '',
                name TEXT DEFAULT '',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                hit_count INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY (feed_id) REFERENCES threat_feeds(id),
                FOREIGN KEY (stix_object_id) REFERENCES stix_objects(id)
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_stix_indicators_value ON stix_indicators(value)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_stix_indicators_type ON stix_indicators(indicator_type)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_stix_indicators_feed ON stix_indicators(feed_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_stix_objects_stix_id ON stix_objects(stix_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_stix_objects_feed ON stix_objects(feed_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_stix_objects_type ON stix_objects(stix_type)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_feeds_name ON threat_feeds(name)")


def _upsert_feed(feed_cfg: FeedConfig) -> str:
    from database import db
    feed_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    with db._cursor() as cur:
        cur.execute("SELECT id FROM threat_feeds WHERE name = ?", (feed_cfg.name,))
        existing = cur.fetchone()
        if existing:
            feed_id = existing[0] if not isinstance(existing, dict) else existing["id"]
            cur.execute(
                "UPDATE threat_feeds SET url=?, feed_type=?, auth_type=?, collection_id=?, description=?, "
                "poll_interval_seconds=?, enabled=?, tlp=?, updated_at=? WHERE id=?",
                (feed_cfg.url, feed_cfg.feed_type, feed_cfg.auth_type, feed_cfg.collection_id,
                 feed_cfg.description, feed_cfg.poll_interval_seconds,
                 1 if feed_cfg.enabled else 0, feed_cfg.tlp, now, feed_id),
            )
        else:
            cur.execute(
                "INSERT INTO threat_feeds (id, name, feed_type, url, auth_type, collection_id, description, "
                "poll_interval_seconds, enabled, tlp, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (feed_id, feed_cfg.name, feed_cfg.feed_type, feed_cfg.url, feed_cfg.auth_type,
                 feed_cfg.collection_id, feed_cfg.description,
                 feed_cfg.poll_interval_seconds, 1 if feed_cfg.enabled else 0,
                 feed_cfg.tlp, now),
            )
    return feed_id


def _get_enabled_feeds() -> List[Dict[str, Any]]:
    from database import db
    with db._cursor() as cur:
        cur.execute("SELECT * FROM threat_feeds WHERE enabled = 1")
        return [dict(row) for row in cur.fetchall()]


def _update_feed_poll(feed_id: str, object_count: int, indicator_count: int,
                      status: str = "idle", error: str = ""):
    from database import db
    now = datetime.now(timezone.utc).isoformat()
    with db._cursor() as cur:
        cur.execute(
            "UPDATE threat_feeds SET last_polled=?, last_polled_objects=?, "
            "total_objects=total_objects+?, total_indicators=total_indicators+?, "
            "status=?, error_message=?, updated_at=? WHERE id=?",
            (now, object_count, object_count, indicator_count, status, error, now, feed_id),
        )


def _upsert_stix_object(feed_id: str, parsed: Dict[str, Any],
                         raw_json: str) -> Optional[str]:
    from database import db
    stix_id = parsed.get("stix_id", "")
    if not stix_id:
        return None

    obj_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    with db._cursor() as cur:
        cur.execute("SELECT id FROM stix_objects WHERE feed_id=? AND stix_id=?",
                    (feed_id, stix_id))
        existing = cur.fetchone()
        if existing:
            existing_id = existing[0] if not isinstance(existing, dict) else existing["id"]
            cur.execute(
                "UPDATE stix_objects SET name=?, description=?, labels=?, confidence=?, "
                "modified=?, revoked=?, raw_json=? WHERE id=?",
                (parsed.get("name", ""), parsed.get("description", ""),
                 json.dumps(parsed.get("labels", [])), parsed.get("confidence", 0),
                 parsed.get("modified", ""), 1 if parsed.get("revoked") else 0,
                 raw_json, existing_id),
            )
            return existing_id

        cur.execute(
            "INSERT INTO stix_objects (id, feed_id, stix_id, stix_type, spec_version, "
            "name, description, labels, confidence, created, modified, revoked, raw_json, "
            "created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (obj_id, feed_id, stix_id, parsed.get("type", ""),
             parsed.get("spec_version", "2.1"), parsed.get("name", ""),
             parsed.get("description", ""), json.dumps(parsed.get("labels", [])),
             parsed.get("confidence", 0), parsed.get("created", ""),
             parsed.get("modified", ""), 1 if parsed.get("revoked") else 0,
             raw_json, now),
        )
    return obj_id


def _upsert_stix_indicator(feed_id: str, stix_object_id: Optional[str],
                            stix_id: str, indicator: Dict[str, Any]) -> Optional[str]:
    from database import db
    value = indicator.get("value", "")
    if not value:
        return None

    ind_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    with db._cursor() as cur:
        cur.execute(
            "SELECT id FROM stix_indicators WHERE feed_id=? AND indicator_type=? AND value=?",
            (feed_id, indicator.get("indicator_type", ""), value))
        existing = cur.fetchone()
        if existing:
            existing_id = existing[0] if not isinstance(existing, dict) else existing["id"]
            cur.execute(
                "UPDATE stix_indicators SET last_seen=?, hit_count=hit_count+1, "
                "confidence=MAX(confidence, ?), labels=?, description=? WHERE id=?",
                (now, indicator.get("confidence", 0),
                 json.dumps(indicator.get("labels", [])),
                 indicator.get("description", ""), existing_id),
            )
            return existing_id

        cur.execute(
            "INSERT INTO stix_indicators (id, feed_id, stix_object_id, stix_id, "
            "indicator_type, value, pattern, confidence, labels, valid_from, valid_until, "
            "description, name, first_seen, last_seen, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (ind_id, feed_id, stix_object_id, stix_id,
             indicator.get("indicator_type", ""), value,
             indicator.get("pattern", ""), indicator.get("confidence", 0),
             json.dumps(indicator.get("labels", [])),
             indicator.get("valid_from", ""), indicator.get("valid_until", ""),
             indicator.get("description", ""), indicator.get("name", ""),
             now, now, now),
        )
    return ind_id


# ═══════════════════════════════════════════════════════════════════════════
# FeedPoller
# ═══════════════════════════════════════════════════════════════════════════

class FeedPoller:
    """Background poller that polls feeds at configured intervals."""

    def __init__(self):
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._poll_log: List[Dict[str, Any]] = []

    async def poll_all(self) -> Dict[str, Any]:
        _init_feed_tables()
        feeds = _get_enabled_feeds()
        results: Dict[str, Any] = {"feeds_polled": 0, "objects": 0, "indicators": 0, "errors": []}

        for feed in feeds:
            try:
                r = await self._poll_single_feed(feed)
                results["feeds_polled"] += 1
                results["objects"] += r.get("objects", 0)
                results["indicators"] += r.get("indicators", 0)
            except Exception as exc:
                results["errors"].append({"feed": feed.get("name", ""), "error": str(exc)})
                logger.error("Poll failed for %s: %s", feed.get("name"), exc)

        self._poll_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **results,
        })
        if len(self._poll_log) > 100:
            self._poll_log = self._poll_log[-100:]

        return results

    async def poll_feed(self, feed_id: str) -> Dict[str, Any]:
        _init_feed_tables()
        from database import db
        with db._cursor() as cur:
            cur.execute("SELECT * FROM threat_feeds WHERE id = ?", (feed_id,))
            row = cur.fetchone()
        if not row:
            return {"error": "Feed not found"}
        feed = dict(row)
        return await self._poll_single_feed(feed)

    async def _poll_single_feed(self, feed: Dict[str, Any]) -> Dict[str, Any]:
        feed_id = feed["id"]
        feed_name = feed.get("name", "")
        url = feed.get("url", "")

        logger.info("Polling feed: %s", feed_name)
        _update_feed_poll(feed_id, 0, 0, status="polling")

        if "urlhaus-api.abuse.ch" in url:
            return await self._poll_urlhaus(feed)

        client = TAXIIClient(
            base_url=url,
            auth_type=feed.get("auth_type", "none"),
        )

        collection_id = feed.get("collection_id", "")
        if not collection_id:
            collections = await client.get_collections()
            if collections:
                collection_id = collections[0].get("id", "")
            if not collection_id:
                _update_feed_poll(feed_id, 0, 0, status="error",
                                  error="No collections found")
                return {"error": "No collections found"}

        added_after = feed.get("last_polled")
        try:
            objects = await client.get_objects(collection_id, added_after=added_after)
        except Exception as exc:
            _update_feed_poll(feed_id, 0, 0, status="error", error=str(exc))
            return {"error": str(exc)}

        parser = STIXParser()
        object_count = 0
        indicator_count = 0

        for obj in objects:
            raw_json = json.dumps(obj, default=str)
            bundle = {"type": "bundle", "objects": [obj]}
            parsed = parser.parse_bundle(bundle)

            for po in parsed.get("objects", []):
                obj_id = _upsert_stix_object(feed_id, po, raw_json)
                if obj_id:
                    object_count += 1

            for ind in parsed.get("indicators", []):
                stix_id = ind.get("stix_id", "")
                _upsert_stix_indicator(feed_id, None, stix_id, ind)
                indicator_count += 1

        _update_feed_poll(feed_id, object_count, indicator_count, status="idle")
        logger.info("Feed %s: %d objects, %d indicators", feed_name, object_count, indicator_count)

        return {"objects": object_count, "indicators": indicator_count}

    async def _poll_urlhaus(self, feed: Dict[str, Any]) -> Dict[str, Any]:
        feed_id = feed["id"]
        url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
        indicator_count = 0
        now = datetime.now(timezone.utc).isoformat()

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            _update_feed_poll(feed_id, 0, 0, status="error", error=str(exc))
            return {"error": str(exc)}

        urls_list = data.get("urls", [])
        for entry in urls_list:
            url_val = entry.get("url", "")
            if not url_val:
                continue
            threat_type = entry.get("threat", "")
            tags = entry.get("tags", [])
            confidence = 80 if "malware_download" in (tags or []) else 60

            indicator = {
                "indicator_type": "url",
                "value": url_val,
                "pattern": f"[url:value = '{url_val}']",
                "confidence": confidence,
                "labels": tags if isinstance(tags, list) else [],
                "valid_from": entry.get("dateadded", now),
                "valid_until": "",
                "description": threat_type,
                "name": entry.get("url_status", ""),
                "stix_id": f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, url_val)}",
            }
            _upsert_stix_indicator(feed_id, None, indicator["stix_id"], indicator)
            indicator_count += 1

        _update_feed_poll(feed_id, len(urls_list), indicator_count, status="idle")
        logger.info("URLhaus poll: %d indicators", indicator_count)
        return {"objects": len(urls_list), "indicators": indicator_count}

    async def start_background(self, interval_seconds: int = 3600):
        if self._running:
            return
        self._running = True
        logger.info("FeedPoller background loop started (interval=%ds)", interval_seconds)

        async def _loop():
            while self._running:
                try:
                    await self.poll_all()
                except Exception as exc:
                    logger.error("Background poll cycle failed: %s", exc)
                await asyncio.sleep(interval_seconds)

        self._task = asyncio.create_task(_loop())

    def stop_background(self):
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
        logger.info("FeedPoller background loop stopped")

    def get_poll_log(self, limit: int = 20) -> List[Dict[str, Any]]:
        return self._poll_log[-limit:]


# ═══════════════════════════════════════════════════════════════════════════
# IOCMatcher
# ═══════════════════════════════════════════════════════════════════════════

class IOCMatcher:
    """Match IP/domain/hash against stored indicators, return threat info."""

    def match_ip(self, ip: str) -> List[Dict[str, Any]]:
        return self._match_value("ip", ip)

    def match_domain(self, domain: str) -> List[Dict[str, Any]]:
        return self._match_value("domain", domain)

    def match_hash(self, file_hash: str) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for htype in ("md5", "sha1", "sha256"):
            results.extend(self._match_value(htype, file_hash))
        if not results:
            results = self._match_value("file_hash", file_hash)
        return results

    def match_url(self, url: str) -> List[Dict[str, Any]]:
        return self._match_value("url", url)

    def match_email(self, email: str) -> List[Dict[str, Any]]:
        return self._match_value("email", email)

    def match_value(self, indicator_type: str, value: str) -> List[Dict[str, Any]]:
        return self._match_value(indicator_type, value)

    def match_all(self, ip: str = "", domain: str = "", file_hash: str = "",
                  url: str = "", email: str = "") -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        if ip:
            results.extend(self.match_ip(ip))
        if domain:
            results.extend(self.match_domain(domain))
        if file_hash:
            results.extend(self.match_hash(file_hash))
        if url:
            results.extend(self.match_url(url))
        if email:
            results.extend(self.match_email(email))
        return results

    def _match_value(self, indicator_type: str, value: str) -> List[Dict[str, Any]]:
        if not value:
            return []
        from database import db
        with db._cursor() as cur:
            cur.execute(
                "SELECT si.*, tf.name as feed_name, tf.tlp as feed_tlp "
                "FROM stix_indicators si "
                "LEFT JOIN threat_feeds tf ON si.feed_id = tf.id "
                "WHERE si.indicator_type = ? AND si.value = ?",
                (indicator_type, value),
            )
            rows = [dict(row) for row in cur.fetchall()]

            if not rows and indicator_type == "ip":
                cur.execute(
                    "SELECT si.*, tf.name as feed_name, tf.tlp as feed_tlp "
                    "FROM stix_indicators si "
                    "LEFT JOIN threat_feeds tf ON si.feed_id = tf.id "
                    "WHERE si.indicator_type = 'ip' AND si.value = ?",
                    (value,),
                )
                rows = [dict(row) for row in cur.fetchall()]

        for row in rows:
            now = datetime.now(timezone.utc).isoformat()
            try:
                from database import db
                with db._cursor() as cur:
                    cur.execute(
                        "UPDATE stix_indicators SET hit_count=hit_count+1, last_seen=? "
                        "WHERE id=?",
                        (now, row["id"]),
                    )
            except Exception:
                pass

        return rows

    def get_stats(self) -> Dict[str, Any]:
        from database import db
        with db._cursor() as cur:
            cur.execute("SELECT COUNT(*) as total FROM stix_indicators")
            total_row = cur.fetchone()
            total = total_row[0] if not isinstance(total_row, dict) else total_row["total"]

            cur.execute(
                "SELECT indicator_type, COUNT(*) as count FROM stix_indicators "
                "GROUP BY indicator_type ORDER BY count DESC")
            by_type = {}
            for row in cur.fetchall():
                k = row["indicator_type"] if isinstance(row, dict) else row[0]
                v = row["count"] if isinstance(row, dict) else row[1]
                by_type[k] = v

            cur.execute(
                "SELECT feed_id, COUNT(*) as count FROM stix_indicators "
                "GROUP BY feed_id ORDER BY count DESC")
            by_feed = {}
            for row in cur.fetchall():
                k = row["feed_id"] if isinstance(row, dict) else row[0]
                v = row["count"] if isinstance(row, dict) else row[1]
                by_feed[k] = v

            cur.execute(
                "SELECT SUM(hit_count) as total_hits FROM stix_indicators")
            hits_row = cur.fetchone()
            total_hits = hits_row[0] if not isinstance(hits_row, dict) else hits_row["total_hits"]

            cur.execute("SELECT COUNT(*) as total FROM stix_objects")
            obj_row = cur.fetchone()
            total_objects = obj_row[0] if not isinstance(obj_row, dict) else obj_row["total"]

        return {
            "total_indicators": total or 0,
            "total_objects": total_objects or 0,
            "total_hits": total_hits or 0,
            "by_type": by_type,
            "by_feed": by_feed,
        }


# ═══════════════════════════════════════════════════════════════════════════
# ThreatFeedService  (facade)
# ═══════════════════════════════════════════════════════════════════════════

class ThreatFeedService:
    """Facade that ties TAXIIClient, STIXParser, FeedPoller, and IOCMatcher together."""

    def __init__(self):
        self.parser = STIXParser()
        self.poller = FeedPoller()
        self.matcher = IOCMatcher()
        self._initialized = False

    def init_db(self):
        _init_feed_tables()
        self._initialized = True
        self._register_default_feeds()
        logger.info("ThreatFeedService database tables initialised")

    def _register_default_feeds(self):
        for feed_cfg in DEFAULT_FEEDS:
            _upsert_feed(feed_cfg)
        logger.info("Default feeds registered: %s", [f.name for f in DEFAULT_FEEDS])

    def get_feeds(self) -> List[Dict[str, Any]]:
        _init_feed_tables()
        from database import db
        with db._cursor() as cur:
            cur.execute("SELECT * FROM threat_feeds ORDER BY name")
            return [dict(row) for row in cur.fetchall()]

    def get_feed(self, feed_id: str) -> Optional[Dict[str, Any]]:
        _init_feed_tables()
        from database import db
        with db._cursor() as cur:
            cur.execute("SELECT * FROM threat_feeds WHERE id = ?", (feed_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def add_feed(self, feed_cfg: FeedConfig) -> str:
        _init_feed_tables()
        return _upsert_feed(feed_cfg)

    def update_feed(self, feed_id: str, **kwargs) -> bool:
        _init_feed_tables()
        from database import db
        now = datetime.now(timezone.utc).isoformat()
        kwargs["updated_at"] = now
        set_parts = []
        values = []
        for k, v in kwargs.items():
            set_parts.append(f"{k} = ?")
            values.append(v)
        if not set_parts:
            return False
        values.append(feed_id)
        with db._cursor() as cur:
            cur.execute(f"UPDATE threat_feeds SET {', '.join(set_parts)} WHERE id = ?",
                        tuple(values))
            return cur.rowcount > 0

    def delete_feed(self, feed_id: str) -> bool:
        _init_feed_tables()
        from database import db
        with db._cursor() as cur:
            cur.execute("DELETE FROM stix_indicators WHERE feed_id = ?", (feed_id,))
            cur.execute("DELETE FROM stix_objects WHERE feed_id = ?", (feed_id,))
            cur.execute("DELETE FROM threat_feeds WHERE id = ?", (feed_id,))
            return cur.rowcount > 0

    async def poll_all(self) -> Dict[str, Any]:
        return await self.poller.poll_all()

    async def poll_feed(self, feed_id: str) -> Dict[str, Any]:
        return await self.poller.poll_feed(feed_id)

    async def start_background_polling(self, interval_seconds: int = 3600):
        _init_feed_tables()
        await self.poller.start_background(interval_seconds)

    def stop_background_polling(self):
        self.poller.stop_background()

    def match_ip(self, ip: str) -> List[Dict[str, Any]]:
        return self.matcher.match_ip(ip)

    def match_domain(self, domain: str) -> List[Dict[str, Any]]:
        return self.matcher.match_domain(domain)

    def match_hash(self, file_hash: str) -> List[Dict[str, Any]]:
        return self.matcher.match_hash(file_hash)

    def match_url(self, url: str) -> List[Dict[str, Any]]:
        return self.matcher.match_url(url)

    def match_email(self, email: str) -> List[Dict[str, Any]]:
        return self.matcher.match_email(email)

    def match_all(self, ip: str = "", domain: str = "", file_hash: str = "",
                  url: str = "", email: str = "") -> List[Dict[str, Any]]:
        return self.matcher.match_all(ip=ip, domain=domain, file_hash=file_hash,
                                      url=url, email=email)

    def get_indicator_stats(self) -> Dict[str, Any]:
        return self.matcher.get_stats()

    def get_indicators(self, indicator_type: str = None, feed_id: str = None,
                       value_filter: str = "", limit: int = 200) -> List[Dict[str, Any]]:
        _init_feed_tables()
        from database import db
        conditions = []
        params: list = []
        if indicator_type:
            conditions.append("si.indicator_type = ?")
            params.append(indicator_type)
        if feed_id:
            conditions.append("si.feed_id = ?")
            params.append(feed_id)
        if value_filter:
            conditions.append("si.value LIKE ?")
            params.append(f"%{value_filter}%")
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        params.append(limit)
        query = (
            f"SELECT si.*, tf.name as feed_name, tf.tlp as feed_tlp "
            f"FROM stix_indicators si "
            f"LEFT JOIN threat_feeds tf ON si.feed_id = tf.id "
            f"{where} ORDER BY si.last_seen DESC LIMIT ?"
        )
        with db._cursor() as cur:
            cur.execute(query, tuple(params))
            return [dict(row) for row in cur.fetchall()]

    def get_stix_objects(self, feed_id: str = None, stix_type: str = None,
                         limit: int = 200) -> List[Dict[str, Any]]:
        _init_feed_tables()
        from database import db
        conditions = []
        params: list = []
        if feed_id:
            conditions.append("so.feed_id = ?")
            params.append(feed_id)
        if stix_type:
            conditions.append("so.stix_type = ?")
            params.append(stix_type)
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        params.append(limit)
        query = (
            f"SELECT so.*, tf.name as feed_name "
            f"FROM stix_objects so "
            f"LEFT JOIN threat_feeds tf ON so.feed_id = tf.id "
            f"{where} ORDER BY so.created DESC LIMIT ?"
        )
        with db._cursor() as cur:
            cur.execute(query, tuple(params))
            return [dict(row) for row in cur.fetchall()]

    def search_stix_objects(self, query_text: str, limit: int = 100) -> List[Dict[str, Any]]:
        _init_feed_tables()
        from database import db
        with db._cursor() as cur:
            cur.execute(
                "SELECT so.*, tf.name as feed_name "
                "FROM stix_objects so "
                "LEFT JOIN threat_feeds tf ON so.feed_id = tf.id "
                "WHERE so.name LIKE ? OR so.description LIKE ? OR so.stix_id LIKE ? "
                "ORDER BY so.created DESC LIMIT ?",
                (f"%{query_text}%", f"%{query_text}%", f"%{query_text}%", limit),
            )
            return [dict(row) for row in cur.fetchall()]

    def get_poll_log(self, limit: int = 20) -> List[Dict[str, Any]]:
        return self.poller.get_poll_log(limit)

    def get_feed_summary(self) -> Dict[str, Any]:
        _init_feed_tables()
        from database import db
        with db._cursor() as cur:
            cur.execute("SELECT COUNT(*) as total FROM threat_feeds")
            feed_row = cur.fetchone()
            total_feeds = feed_row[0] if not isinstance(feed_row, dict) else feed_row["total"]

            cur.execute("SELECT COUNT(*) as enabled FROM threat_feeds WHERE enabled = 1")
            enabled_row = cur.fetchone()
            enabled_feeds = enabled_row[0] if not isinstance(enabled_row, dict) else enabled_row["enabled"]

            cur.execute("SELECT COUNT(*) as total FROM stix_objects")
            obj_row = cur.fetchone()
            total_objects = obj_row[0] if not isinstance(obj_row, dict) else obj_row["total"]

            cur.execute("SELECT COUNT(*) as total FROM stix_indicators")
            ind_row = cur.fetchone()
            total_indicators = ind_row[0] if not isinstance(ind_row, dict) else ind_row["total"]

            cur.execute(
                "SELECT si.indicator_type, COUNT(*) as count "
                "FROM stix_indicators si GROUP BY si.indicator_type ORDER BY count DESC")
            by_type = {}
            for row in cur.fetchall():
                k = row["indicator_type"] if isinstance(row, dict) else row[0]
                v = row["count"] if isinstance(row, dict) else row[1]
                by_type[k] = v

            cur.execute(
                "SELECT tf.name, tf.status, tf.last_polled, tf.total_indicators, tf.error_message "
                "FROM threat_feeds tf WHERE tf.enabled = 1 ORDER BY tf.name")
            feed_details = [dict(row) for row in cur.fetchall()]

        return {
            "total_feeds": total_feeds,
            "enabled_feeds": enabled_feeds,
            "total_stix_objects": total_objects,
            "total_indicators": total_indicators,
            "indicators_by_type": by_type,
            "feeds": feed_details,
        }


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------
threat_feed_service = ThreatFeedService()
