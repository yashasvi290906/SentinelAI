"""
GeoIP Enrichment Service for SentinelAI.
Enriches IP addresses with geolocation data using free IP-API.
Caches results to avoid repeated API calls.
"""
import time
import json
from typing import Dict, Any, Optional
from datetime import datetime, timezone, timedelta

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False


class GeoIPService:
    """Enriches IP addresses with geolocation data."""

    def __init__(self):
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.cache_ttl = timedelta(hours=24)
        self.api_url = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"

    async def enrich(self, ip: str) -> Dict[str, Any]:
        """Get geolocation data for an IP address."""
        if not ip or ip in ("127.0.0.1", "localhost", "::1", ""):
            return self._empty_result(ip)

        # Check cache
        cached = self.cache.get(ip)
        if cached and self._is_cache_valid(cached):
            return cached

        # Query API
        if not HAS_HTTPX:
            return self._empty_result(ip)

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                url = self.api_url.format(ip=ip)
                resp = await client.get(url)

                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("status") == "success":
                        result = {
                            "ip": ip,
                            "country": data.get("country", "Unknown"),
                            "country_code": data.get("countryCode", ""),
                            "region": data.get("regionName", ""),
                            "city": data.get("city", ""),
                            "latitude": data.get("lat", 0),
                            "longitude": data.get("lon", 0),
                            "timezone": data.get("timezone", ""),
                            "isp": data.get("isp", "Unknown"),
                            "org": data.get("org", "Unknown"),
                            "asn": data.get("as", ""),
                            "asname": data.get("asname", ""),
                            "is_proxy": data.get("proxy", False),
                            "is_hosting": data.get("hosting", False),
                            "is_mobile": data.get("mobile", False),
                            "cached_at": datetime.now(timezone.utc).isoformat(),
                        }
                        self.cache[ip] = result
                        return result

        except Exception:
            pass

        return self._empty_result(ip)

    async def enrich_batch(self, ips: list[str]) -> Dict[str, Dict[str, Any]]:
        """Enrich multiple IPs."""
        results = {}
        for ip in ips:
            results[ip] = await self.enrich(ip)
        return results

    def get_country_stats(self, enrichments: list[Dict]) -> Dict[str, int]:
        """Count attacks by country."""
        stats = {}
        for e in enrichments:
            country = e.get("country", "Unknown")
            stats[country] = stats.get(country, 0) + 1
        return dict(sorted(stats.items(), key=lambda x: -x[1]))

    def _is_cache_valid(self, cached: Dict) -> bool:
        """Check if cache entry is still valid."""
        try:
            cached_at = datetime.fromisoformat(cached.get("cached_at", ""))
            return datetime.now(timezone.utc) - cached_at < self.cache_ttl
        except (ValueError, TypeError):
            return False

    def _empty_result(self, ip: str) -> Dict[str, Any]:
        """Return empty result for unknown IPs."""
        return {
            "ip": ip,
            "country": "Unknown",
            "country_code": "",
            "region": "",
            "city": "",
            "latitude": 0,
            "longitude": 0,
            "timezone": "",
            "isp": "Unknown",
            "org": "Unknown",
            "asn": "",
            "asname": "",
            "is_proxy": False,
            "is_hosting": False,
            "is_mobile": False,
            "cached_at": datetime.now(timezone.utc).isoformat(),
        }


# Singleton
geoip_service = GeoIPService()
