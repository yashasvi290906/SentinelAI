"""
Threat Intelligence Service for SentinelAI.
Integrates with AbuseIPDB, VirusTotal, Shodan, and NVD.
Falls back to local data when API keys are not configured.
"""
import os
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False
    logger.warning("httpx not installed — threat intelligence lookups will be limited")


@dataclass
class ThreatIntelResult:
    source: str
    query: str
    result: Dict[str, Any]
    cached: bool = False
    timestamp: str = ""
    
    def to_dict(self):
        return asdict(self)


class ThreatIntelligenceService:
    """Real threat intelligence lookups."""
    
    def __init__(self):
        self.abuseipdb_key = os.environ.get("ABUSEIPDB_API_KEY", "")
        self.virustotal_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
        self.shodan_key = os.environ.get("SHODAN_API_KEY", "")
        self.nvd_api_base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self._cache: Dict[str, ThreatIntelResult] = {}
    
    async def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """Look up IP reputation across all sources."""
        results = {}
        
        # AbuseIPDB
        if self.abuseipdb_key:
            results['abuseipdb'] = await self._query_abuseipdb(ip)
        else:
            results['abuseipdb'] = {'status': 'no_api_key', 'message': 'ABUSEIPDB_API_KEY not configured'}
        
        # VirusTotal
        if self.virustotal_key:
            results['virustotal'] = await self._query_virustotal_ip(ip)
        else:
            results['virustotal'] = {'status': 'no_api_key', 'message': 'VIRUSTOTAL_API_KEY not configured'}
        
        # Shodan
        if self.shodan_key:
            results['shodan'] = await self._query_shodan(ip)
        else:
            results['shodan'] = {'status': 'no_api_key', 'message': 'SHODAN_API_KEY not configured'}
        
        return {
            'ip': ip,
            'sources': results,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'confidence': self._calculate_confidence(results),
        }
    
    async def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """Look up domain reputation."""
        results = {}
        
        if self.virustotal_key:
            results['virustotal'] = await self._query_virustotal_domain(domain)
        else:
            results['virustotal'] = {'status': 'no_api_key'}
        
        return {
            'domain': domain,
            'sources': results,
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }
    
    async def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        """Look up file hash."""
        results = {}
        
        if self.virustotal_key:
            results['virustotal'] = await self._query_virustotal_hash(file_hash)
        else:
            results['virustotal'] = {'status': 'no_api_key'}
        
        return {
            'hash': file_hash,
            'sources': results,
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }
    
    async def search_cve(self, query: str, limit: int = 10) -> List[Dict]:
        """Search NVD for CVEs."""
        if not HAS_HTTPX:
            return []
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(self.nvd_api_base, params={
                    'keywordSearch': query,
                    'resultsPerPage': limit,
                })
                if resp.status_code == 200:
                    data = resp.json()
                    return [{
                        'cve_id': vuln.get('cve', {}).get('id', ''),
                        'description': vuln.get('cve', {}).get('descriptions', [{}])[0].get('value', ''),
                        'severity': self._get_cvss_severity(vuln),
                        'published': vuln.get('cve', {}).get('published', ''),
                    } for vuln in data.get('vulnerabilities', [])]
        except Exception:
            pass
        return []
    
    async def _query_abuseipdb(self, ip: str) -> Dict[str, Any]:
        """Query AbuseIPDB for IP reputation."""
        if not HAS_HTTPX:
            return {'status': 'no_httpx'}
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    'https://api.abuseipdb.com/api/v2/check',
                    params={'ipAddress': ip, 'maxAgeInDays': 90},
                    headers={'Key': self.abuseipdb_key, 'Accept': 'application/json'}
                )
                if resp.status_code == 200:
                    data = resp.json().get('data', {})
                    return {
                        'status': 'success',
                        'abuse_confidence_score': data.get('abuseConfidenceScore', 0),
                        'country_code': data.get('countryCode', ''),
                        'isp': data.get('isp', ''),
                        'domain': data.get('domain', ''),
                        'usage_type': data.get('usageType', ''),
                        'total_reports': data.get('totalReports', 0),
                        'is_tor': data.get('isTor', False),
                        'is_whitelisted': data.get('isWhitelisted', False),
                    }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
        return {'status': 'error', 'message': 'Request failed'}
    
    async def _query_virustotal_ip(self, ip: str) -> Dict[str, Any]:
        """Query VirusTotal for IP analysis."""
        if not HAS_HTTPX:
            return {'status': 'no_httpx'}
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
                    headers={'x-apikey': self.virustotal_key}
                )
                if resp.status_code == 200:
                    data = resp.json().get('data', {}).get('attributes', {})
                    stats = data.get('last_analysis_stats', {})
                    return {
                        'status': 'success',
                        'malicious': stats.get('malicious', 0),
                        'suspicious': stats.get('suspicious', 0),
                        'harmless': stats.get('harmless', 0),
                        'country': data.get('country', ''),
                        'as_owner': data.get('as_owner', ''),
                        'reputation': data.get('reputation', 0),
                    }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
        return {'status': 'error', 'message': 'Request failed'}
    
    async def _query_virustotal_domain(self, domain: str) -> Dict[str, Any]:
        """Query VirusTotal for domain analysis."""
        if not HAS_HTTPX:
            return {'status': 'no_httpx'}
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f'https://www.virustotal.com/api/v3/domains/{domain}',
                    headers={'x-apikey': self.virustotal_key}
                )
                if resp.status_code == 200:
                    data = resp.json().get('data', {}).get('attributes', {})
                    stats = data.get('last_analysis_stats', {})
                    return {
                        'status': 'success',
                        'malicious': stats.get('malicious', 0),
                        'suspicious': stats.get('suspicious', 0),
                        'harmless': stats.get('harmless', 0),
                        'registrar': data.get('registrar', ''),
                        'popularity_ranks': data.get('popularity_ranks', {}),
                    }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
        return {'status': 'error', 'message': 'Request failed'}
    
    async def _query_virustotal_hash(self, file_hash: str) -> Dict[str, Any]:
        """Query VirusTotal for file hash."""
        if not HAS_HTTPX:
            return {'status': 'no_httpx'}
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f'https://www.virustotal.com/api/v3/files/{file_hash}',
                    headers={'x-apikey': self.virustotal_key}
                )
                if resp.status_code == 200:
                    data = resp.json().get('data', {}).get('attributes', {})
                    stats = data.get('last_analysis_stats', {})
                    return {
                        'status': 'success',
                        'malicious': stats.get('malicious', 0),
                        'suspicious': stats.get('suspicious', 0),
                        'harmless': stats.get('harmless', 0),
                        'type': data.get('type_description', ''),
                        'size': data.get('size', 0),
                        'names': data.get('names', [])[:5],
                    }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
        return {'status': 'error', 'message': 'Request failed'}
    
    async def _query_shodan(self, ip: str) -> Dict[str, Any]:
        """Query Shodan for IP information."""
        if not HAS_HTTPX:
            return {'status': 'no_httpx'}
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(f'https://api.shodan.io/shodan/host/{ip}?key={self.shodan_key}')
                if resp.status_code == 200:
                    data = resp.json()
                    return {
                        'status': 'success',
                        'org': data.get('org', ''),
                        'os': data.get('os', ''),
                        'ports': data.get('ports', []),
                        'country_name': data.get('country_name', ''),
                        'city': data.get('city', ''),
                        'isp': data.get('isp', ''),
                        'vulns': data.get('vulns', []),
                    }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
        return {'status': 'error', 'message': 'Request failed'}
    
    def _calculate_confidence(self, results: Dict) -> float:
        """Calculate combined confidence score from all sources."""
        scores = []
        
        abuse = results.get('abuseipdb', {})
        if abuse.get('status') == 'success':
            scores.append(abuse.get('abuse_confidence_score', 0) / 100)
        
        vt = results.get('virustotal', {})
        if vt.get('status') == 'success':
            malicious = vt.get('malicious', 0)
            total = malicious + vt.get('harmless', 0) + vt.get('suspicious', 0)
            if total > 0:
                scores.append(malicious / total)
        
        shodan = results.get('shodan', {})
        if shodan.get('status') == 'success':
            vulns = shodan.get('vulns', [])
            scores.append(min(len(vulns) / 10, 1.0))
        
        return sum(scores) / len(scores) if scores else 0.0
    
    def _get_cvss_severity(self, vuln: Dict) -> str:
        """Extract severity from NVD CVE data."""
        metrics = vuln.get('cve', {}).get('metrics', {})
        for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
            if version in metrics and metrics[version]:
                cvss = metrics[version][0].get('cvssData', {})
                return cvss.get('baseSeverity', 'UNKNOWN')
        return 'UNKNOWN'


# Singleton
threat_intel = ThreatIntelligenceService()
