"""
Report Generation Service for SentinelAI.
Generates executive, technical, and incident reports from real data.
Supports PDF, CSV, and JSON export formats.
"""
import json
import csv
import io
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict


@dataclass
class ReportSection:
    title: str
    content: Any
    section_type: str  # text, table, chart, metrics
    
    def to_dict(self):
        return asdict(self)


class ReportGenerator:
    """Generate real reports from threat detection and log analysis data."""
    
    def generate_executive_report(self, stats: Dict, detections: List[Dict], anomalies: Dict) -> Dict[str, Any]:
        """High-level report for management."""
        return {
            'type': 'executive',
            'title': 'Security Posture Executive Report',
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'sections': [
                ReportSection(
                    title='Executive Summary',
                    content={
                        'total_threats': stats.get('total_threats', 0),
                        'critical_threats': stats.get('critical_threats', 0),
                        'risk_score': self._calculate_risk_score(detections, anomalies),
                        'status': self._get_risk_status(detections),
                        'key_findings': self._extract_key_findings(detections),
                    },
                    section_type='metrics'
                ).to_dict(),
                ReportSection(
                    title='Threat Overview',
                    content={
                        'by_severity': self._count_by_field(detections, 'severity'),
                        'by_type': self._count_by_field(detections, 'threat_type'),
                        'top_source_ips': self._top_ips(detections, 10),
                    },
                    section_type='chart'
                ).to_dict(),
                ReportSection(
                    title='Anomaly Assessment',
                    content={
                        'anomaly_score': anomalies.get('anomaly_score', 0),
                        'risk_level': anomalies.get('risk_level', 'UNKNOWN'),
                        'summary': anomalies.get('explanation', 'No analysis performed'),
                    },
                    section_type='text'
                ).to_dict(),
                ReportSection(
                    title='Recommendations',
                    content=self._generate_recommendations(detections, anomalies),
                    section_type='text'
                ).to_dict(),
            ],
            'metadata': {
                'report_version': '1.0',
                'generated_by': 'SentinelAI SOC Copilot',
                'classification': 'CONFIDENTIAL',
            }
        }
    
    def generate_technical_report(self, events: List[Dict], detections: List[Dict], anomalies: Dict) -> Dict[str, Any]:
        """Detailed technical report for analysts."""
        return {
            'type': 'technical',
            'title': 'Technical Threat Analysis Report',
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'sections': [
                ReportSection(
                    title='Event Analysis',
                    content={
                        'total_events': len(events),
                        'by_type': self._count_events_by_type(events),
                        'by_severity': self._count_events_by_severity(events),
                        'time_range': self._get_time_range(events),
                        'unique_ips': len(set(e.get('source_ip', '') for e in events if e.get('source_ip'))),
                        'unique_ports': len(set(e.get('dest_port', 0) for e in events if e.get('dest_port'))),
                    },
                    section_type='metrics'
                ).to_dict(),
                ReportSection(
                    title='Threat Detections',
                    content=[{
                        'type': d.get('threat_type'),
                        'severity': d.get('severity'),
                        'confidence': d.get('confidence'),
                        'source_ip': d.get('source_ip'),
                        'description': d.get('description'),
                        'mitre': f"{d.get('mitre_technique', 'N/A')} - {d.get('mitre_tactic', 'N/A')}",
                        'evidence': d.get('evidence', []),
                        'recommendations': d.get('recommendations', []),
                    } for d in detections],
                    section_type='table'
                ).to_dict(),
                ReportSection(
                    title='Anomaly Detection Results',
                    content=anomalies,
                    section_type='chart'
                ).to_dict(),
                ReportSection(
                    title='IP Activity Summary',
                    content=self._ip_activity_summary(events, detections),
                    section_type='table'
                ).to_dict(),
                ReportSection(
                    title='MITRE ATT&CK Coverage',
                    content=self._mitre_coverage(detections),
                    section_type='table'
                ).to_dict(),
            ],
            'metadata': {
                'report_version': '1.0',
                'generated_by': 'SentinelAI SOC Copilot',
                'classification': 'CONFIDENTIAL',
            }
        }
    
    def generate_incident_report(self, detection: Dict, related_events: List[Dict]) -> Dict[str, Any]:
        """Incident-specific report."""
        return {
            'type': 'incident',
            'title': f"Incident Report: {detection.get('threat_type', 'Unknown').upper()}",
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'sections': [
                ReportSection(
                    title='Incident Details',
                    content={
                        'threat_type': detection.get('threat_type'),
                        'severity': detection.get('severity'),
                        'confidence': detection.get('confidence'),
                        'first_seen': detection.get('first_seen'),
                        'last_seen': detection.get('last_seen'),
                        'event_count': detection.get('event_count'),
                    },
                    section_type='metrics'
                ).to_dict(),
                ReportSection(
                    title='Attack Vector',
                    content={
                        'source_ip': detection.get('source_ip'),
                        'dest_ip': detection.get('dest_ip'),
                        'dest_port': detection.get('dest_port'),
                        'description': detection.get('description'),
                    },
                    section_type='text'
                ).to_dict(),
                ReportSection(
                    title='Evidence',
                    content=detection.get('evidence', []),
                    section_type='text'
                ).to_dict(),
                ReportSection(
                    title='MITRE ATT&CK Mapping',
                    content={
                        'technique': detection.get('mitre_technique', 'N/A'),
                        'tactic': detection.get('mitre_tactic', 'N/A'),
                    },
                    section_type='text'
                ).to_dict(),
                ReportSection(
                    title='Timeline',
                    content=self._build_timeline(detection, related_events),
                    section_type='table'
                ).to_dict(),
                ReportSection(
                    title='Response Recommendations',
                    content=detection.get('recommendations', []),
                    section_type='text'
                ).to_dict(),
            ],
            'metadata': {
                'report_version': '1.0',
                'generated_by': 'SentinelAI SOC Copilot',
                'classification': 'CONFIDENTIAL',
                'incident_id': detection.get('id', 'N/A'),
            }
        }
    
    def export_json(self, report: Dict) -> str:
        """Export report as JSON."""
        return json.dumps(report, indent=2, default=str)
    
    def export_csv(self, detections: List[Dict]) -> str:
        """Export detections as CSV."""
        if not detections:
            return ""
        
        output = io.StringIO()
        fields = ['threat_type', 'severity', 'confidence', 'source_ip', 'dest_ip', 'dest_port',
                  'description', 'mitre_technique', 'mitre_tactic', 'first_seen', 'last_seen', 'event_count']
        
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        for det in detections:
            writer.writerow(det)
        
        return output.getvalue()
    
    def _calculate_risk_score(self, detections: List[Dict], anomalies: Dict) -> int:
        """Calculate overall risk score 0-100."""
        if not detections:
            return anomalies.get('anomaly_score', 0) * 30
        
        severity_weights = {'CRITICAL': 25, 'HIGH': 15, 'MEDIUM': 8, 'LOW': 3, 'INFO': 1}
        threat_score = sum(severity_weights.get(d.get('severity', 'INFO'), 1) for d in detections)
        threat_score = min(threat_score, 70)
        
        anomaly_score = anomalies.get('anomaly_score', 0) * 30
        
        return min(100, int(threat_score + anomaly_score))
    
    def _get_risk_status(self, detections: List[Dict]) -> str:
        critical = sum(1 for d in detections if d.get('severity') == 'CRITICAL')
        high = sum(1 for d in detections if d.get('severity') == 'HIGH')
        
        if critical > 0:
            return 'CRITICAL'
        elif high >= 3:
            return 'HIGH'
        elif high > 0:
            return 'ELEVATED'
        elif detections:
            return 'MODERATE'
        return 'LOW'
    
    def _extract_key_findings(self, detections: List[Dict]) -> List[str]:
        findings = []
        type_counts = {}
        for d in detections:
            t = d.get('threat_type', 'unknown')
            type_counts[t] = type_counts.get(t, 0) + 1
        
        for t, count in sorted(type_counts.items(), key=lambda x: -x[1]):
            findings.append(f"{count}x {t.replace('_', ' ').title()} detected")
        
        return findings[:5]
    
    def _count_by_field(self, items: List[Dict], field: str) -> Dict[str, int]:
        counts = {}
        for item in items:
            val = item.get(field, 'unknown')
            counts[val] = counts.get(val, 0) + 1
        return counts
    
    def _top_ips(self, detections: List[Dict], limit: int = 10) -> List[Dict]:
        ip_counts = {}
        for d in detections:
            ip = d.get('source_ip', '')
            if ip:
                if ip not in ip_counts:
                    ip_counts[ip] = {'ip': ip, 'count': 0, 'types': set()}
                ip_counts[ip]['count'] += 1
                ip_counts[ip]['types'].add(d.get('threat_type', ''))
        
        sorted_ips = sorted(ip_counts.values(), key=lambda x: -x['count'])[:limit]
        for ip in sorted_ips:
            ip['types'] = list(ip['types'])
        return sorted_ips
    
    def _count_events_by_type(self, events: List[Dict]) -> Dict[str, int]:
        return self._count_by_field(events, 'event_type')
    
    def _count_events_by_severity(self, events: List[Dict]) -> Dict[str, int]:
        return self._count_by_field(events, 'severity')
    
    def _get_time_range(self, events: List[Dict]) -> Dict[str, str]:
        timestamps = [e.get('timestamp', '') for e in events if e.get('timestamp')]
        if not timestamps:
            return {'start': 'N/A', 'end': 'N/A'}
        timestamps.sort()
        return {'start': timestamps[0], 'end': timestamps[-1]}
    
    def _ip_activity_summary(self, events: List[Dict], detections: List[Dict]) -> List[Dict]:
        ip_data = {}
        for e in events:
            ip = e.get('source_ip', '')
            if ip:
                if ip not in ip_data:
                    ip_data[ip] = {'ip': ip, 'events': 0, 'threats': 0, 'types': set()}
                ip_data[ip]['events'] += 1
                ip_data[ip]['types'].add(e.get('event_type', ''))
        
        for d in detections:
            ip = d.get('source_ip', '')
            if ip in ip_data:
                ip_data[ip]['threats'] += 1
        
        return [{'ip': v['ip'], 'events': v['events'], 'threats': v['threats'], 
                 'types': list(v['types'])} for v in sorted(ip_data.values(), key=lambda x: -x['events'])][:20]
    
    def _mitre_coverage(self, detections: List[Dict]) -> List[Dict]:
        seen = set()
        coverage = []
        for d in detections:
            tech = d.get('mitre_technique', '')
            tactic = d.get('mitre_tactic', '')
            if tech and tech not in seen:
                seen.add(tech)
                coverage.append({
                    'technique_id': tech,
                    'technique_name': d.get('threat_type', '').replace('_', ' ').title(),
                    'tactic': tactic,
                    'detection_count': sum(1 for x in detections if x.get('mitre_technique') == tech),
                })
        return coverage
    
    def _build_timeline(self, detection: Dict, events: List[Dict]) -> List[Dict]:
        timeline = []
        for e in events[:50]:
            timeline.append({
                'timestamp': e.get('timestamp', ''),
                'event_type': e.get('event_type', ''),
                'source_ip': e.get('source_ip', ''),
                'severity': e.get('severity', ''),
                'message': e.get('message', '')[:100],
            })
        timeline.sort(key=lambda x: x.get('timestamp', ''))
        return timeline
    
    def _generate_recommendations(self, detections: List[Dict], anomalies: Dict) -> List[str]:
        recs = []
        for d in detections:
            recs.extend(d.get('recommendations', []))
        
        if anomalies.get('anomaly_score', 0) > 0.7:
            recs.append("Investigate anomalous behavior patterns in detail")
            recs.append("Consider increasing monitoring frequency")
        
        seen = set()
        unique_recs = []
        for r in recs:
            if r not in seen:
                seen.add(r)
                unique_recs.append(r)
        return unique_recs[:10]


# Singleton
report_generator = ReportGenerator()
