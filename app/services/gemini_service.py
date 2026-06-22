"""
Gemini AI Copilot Service for SentinelAI.
Uses Gemini 2.5 Flash for real threat analysis with RAG context.
Falls back to intelligent local responses when API key is not configured.
"""
import os
import json
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False


class GeminiCopilot:
    """Real AI copilot powered by Gemini with RAG context."""
    
    SYSTEM_PROMPT = """You are SentinelAI Copilot, an expert cybersecurity analyst assistant.

You analyze security logs, detect threats, and provide actionable recommendations.

CAPABILITIES:
- Explain threat detections and their severity
- Analyze suspicious patterns in log data
- Map threats to MITRE ATT&CK framework
- Recommend mitigation and response actions
- Summarize security incidents
- Guide threat hunting investigations

RULES:
1. Answer only cybersecurity-related questions
2. Base responses on the actual data provided in context
3. Never hallucinate or fabricate data
4. If information is unavailable, say so clearly
5. Always provide actionable recommendations
6. Use MITRE ATT&CK terminology when relevant
7. Prioritize by severity (CRITICAL > HIGH > MEDIUM > LOW)
8. Explain technical terms when speaking to non-technical users
9. Never expose API keys, passwords, or sensitive system details
10. Format responses clearly with structure

CONTEXT PROVIDED:
- Current threat detections from uploaded logs
- Anomaly detection scores and explanations
- Parsed log event summaries
- MITRE ATT&CK mappings
- System dashboard statistics

When asked about specific IPs, events, or threats, reference the actual data provided.
When generating recommendations, prioritize immediate actions first.
When explaining threats, include the MITRE technique and tactic."""
    
    def __init__(self):
        self.model = "gemini-2.0-flash"
        self.api_base = "https://generativelanguage.googleapis.com/v1beta/models"

    @property
    def api_key(self) -> str:
        return os.environ.get("GEMINI_API_KEY", "")
    
    async def chat(
        self,
        question: str,
        detections: List[Dict] = None,
        anomaly_result: Dict = None,
        events_summary: Dict = None,
        dashboard_stats: Dict = None,
        conversation_history: List[Dict] = None,
        alerts: List[Dict] = None,
        incidents: List[Dict] = None,
        devices: List[Dict] = None,
        incident_context: Dict = None,
    ) -> Dict[str, Any]:
        """Process a copilot question with full RAG context."""
        
        # Build context from real data
        context = self._build_context(
            detections, anomaly_result, events_summary, dashboard_stats,
            alerts=alerts, incidents=incidents, devices=devices,
            incident_context=incident_context,
        )
        
        if self.api_key and HAS_HTTPX:
            return await self._query_gemini(question, context, conversation_history)
        else:
            return self._intelligent_fallback(question, context, detections or [], incident_context=incident_context)
    
    def _build_context(
        self,
        detections: List[Dict] = None,
        anomaly_result: Dict = None,
        events_summary: Dict = None,
        dashboard_stats: Dict = None,
        alerts: List[Dict] = None,
        incidents: List[Dict] = None,
        devices: List[Dict] = None,
        incident_context: Dict = None,
    ) -> str:
        """Build RAG context from real analysis data."""
        parts = []
        
        # ── Specific Incident Context (highest priority) ──
        if incident_context:
            inc = incident_context.get("incident", {})
            parts.append(f"""=== SPECIFIC INCIDENT ANALYSIS ===
Incident ID: {inc.get('id', 'N/A')}
Title: {inc.get('title', 'N/A')}
Severity: {inc.get('severity', 'N/A')}
Status: {inc.get('status', 'N/A')}
Description: {inc.get('description', 'N/A')}
Affected IPs: {', '.join(inc.get('affected_ips', [])) or 'N/A'}
Kill Chain Stages: {', '.join(inc.get('kill_chain_stages', [])) or 'N/A'}
Matched Chain: {inc.get('matched_chain', 'None')}
Confidence: {inc.get('confidence', 0):.0%}
Timeline ({len(inc.get('timeline', []))} events):""")
            for t in inc.get("timeline", [])[:15]:
                parts.append(f"  [{t.get('severity', '')}] {t.get('timestamp', '')[:19]} — {t.get('title', '')} ({t.get('type', '')})")
            
            related = incident_context.get("related_alerts", [])
            if related:
                parts.append(f"\nRelated Alerts ({len(related)}):")
                for a in related[:10]:
                    parts.append(f"  - [{a.get('severity')}] {a.get('alert_type', '')}: {a.get('title', '')[:100]}")
                    parts.append(f"    Source: {a.get('source_ip', 'N/A')} → {a.get('dest_ip', 'N/A')}:{a.get('dest_port', 'N/A')}")
                    parts.append(f"    MITRE: {a.get('mitre_technique', 'N/A')} ({a.get('mitre_tactic', 'N/A')})")
            
            notes = incident_context.get("notes", [])
            if notes:
                parts.append(f"\nInvestigation Notes ({len(notes)}):")
                for n in notes[:5]:
                    parts.append(f"  - {n.get('created_at', '')[:19]}: {n.get('note', '')[:200]}")
        
        # ── Dashboard Stats ──
        if dashboard_stats:
            parts.append(f"""
DASHBOARD STATISTICS:
- Total logs uploaded: {dashboard_stats.get('total_logs', 0)}
- Total events parsed: {dashboard_stats.get('total_events', 0)}
- Total threats detected: {dashboard_stats.get('total_threats', 0)}
- Critical/High threats: {dashboard_stats.get('critical_threats', 0)}
- Unique source IPs: {dashboard_stats.get('unique_source_ips', 0)}
- Average anomaly score: {dashboard_stats.get('avg_anomaly_score', 0)}
- Total alerts: {dashboard_stats.get('total_alerts', 0)}
- Open alerts: {dashboard_stats.get('open_alerts', 0)}
- Critical alerts: {dashboard_stats.get('critical_alerts', 0)}
- Total incidents: {dashboard_stats.get('total_incidents', 0)}
- Open incidents: {dashboard_stats.get('open_incidents', 0)}""")
        
        # ── Alerts ──
        if alerts:
            parts.append(f"\nALERTS ({len(alerts)} total):")
            sev_counts = {}
            for a in alerts:
                s = a.get('severity', 'INFO')
                sev_counts[s] = sev_counts.get(s, 0) + 1
            parts.append(f"By severity: {json.dumps(sev_counts)}")
            for a in alerts[:10]:
                parts.append(f"- [{a.get('severity')}] {a.get('alert_type', '')}: {a.get('title', '')[:100]}")
                parts.append(f"  Source: {a.get('source_ip', 'N/A')} → {a.get('dest_ip', 'N/A')}:{a.get('dest_port', 'N/A')}")
                parts.append(f"  MITRE: {a.get('mitre_technique', 'N/A')} ({a.get('mitre_tactic', 'N/A')})")
        
        # ── Incidents ──
        if incidents:
            parts.append(f"\nINCIDENTS ({len(incidents)} total):")
            for inc in incidents[:10]:
                parts.append(f"- [{inc.get('severity')}] {inc.get('title', '')[:120]}")
                parts.append(f"  Status: {inc.get('status', 'N/A')} | Chain: {inc.get('matched_chain', 'N/A')}")
                parts.append(f"  Affected IPs: {', '.join(inc.get('affected_ips', [])[:5]) or 'N/A'}")
        
        # ── Devices ──
        if devices:
            parts.append(f"\nREGISTERED DEVICES ({len(devices)}):")
            for d in devices[:10]:
                parts.append(f"- {d.get('hostname', 'N/A')} ({d.get('os_type', 'N/A')}) — Last seen: {d.get('last_seen', 'N/A')[:19]}")
        
        # ── Detections ──
        if detections:
            parts.append(f"\nTHREAT DETECTIONS ({len(detections)} total):")
            severity_counts = {}
            for d in detections:
                sev = d.get('severity', 'INFO')
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            parts.append(f"By severity: {json.dumps(severity_counts)}")
            
            for d in detections[:10]:
                parts.append(f"- [{d.get('severity')}] {d.get('threat_type')}: {d.get('description', '')[:150]}")
                parts.append(f"  Source: {d.get('source_ip', 'N/A')} → {d.get('dest_ip', 'N/A')}:{d.get('dest_port', 'N/A')}")
                parts.append(f"  MITRE: {d.get('mitre_technique', 'N/A')} ({d.get('mitre_tactic', 'N/A')})")
                parts.append(f"  Confidence: {d.get('confidence', 0):.0%}")
        
        # ── Anomaly ──
        if anomaly_result:
            parts.append(f"""
ANOMALY ANALYSIS:
- Score: {anomaly_result.get('anomaly_score', 0):.3f} ({anomaly_result.get('risk_level', 'UNKNOWN')})
- Explanation: {anomaly_result.get('explanation', 'N/A')}
- Top anomalous features: {json.dumps(dict(list(anomaly_result.get('feature_scores', {}).items())[:5]))}""")
        
        # ── Events ──
        if events_summary:
            parts.append(f"""
EVENT SUMMARY:
- Total events: {events_summary.get('total', 0)}
- Event types: {json.dumps(events_summary.get('by_type', {}))}
- Top source IPs: {json.dumps(events_summary.get('top_ips', [])[:5])}""")
        
        return "\n".join(parts) if parts else "No analysis data available yet."
    
    async def _query_gemini(self, question: str, context: str, history: List[Dict] = None) -> Dict[str, Any]:
        """Query Gemini API with context."""
        try:
            messages = [{"role": "user", "parts": [{"text": f"{self.SYSTEM_PROMPT}\n\n---CONTEXT---\n{context}\n---END CONTEXT---\n\nQuestion: {question}"}]}]
            
            if history:
                # Add conversation history (limited to last 10 exchanges)
                for msg in history[-10:]:
                    role = msg.get('role', 'user')
                    content = msg.get('content', '')
                    messages.append({"role": role, "parts": [{"text": content}]})
                messages.append({"role": "user", "parts": [{"text": question}]})
            
            payload = {
                "contents": messages,
                "generationConfig": {
                    "temperature": 0.3,
                    "topK": 40,
                    "topP": 0.95,
                    "maxOutputTokens": 2048,
                },
                "safetySettings": [
                    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
                ]
            }
            
            url = f"{self.api_base}/{self.model}:generateContent?key={self.api_key}"
            
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(url, json=payload)
                
                if resp.status_code == 200:
                    data = resp.json()
                    text = data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                    
                    return {
                        "response": text,
                        "source": "gemini",
                        "model": self.model,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                else:
                    return {
                        "response": f"Gemini API error: {resp.status_code}",
                        "source": "gemini_error",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
        
        except Exception as e:
            return {
                "response": f"Gemini API unavailable: {str(e)}",
                "source": "gemini_error",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
    
    def _intelligent_fallback(self, question: str, context: str, detections: List[Dict], incident_context: Dict = None) -> Dict[str, Any]:
        """Intelligent local fallback when Gemini is not available."""
        q = question.lower().strip()
        
        # ── Incident-specific analysis (highest priority) ──
        if incident_context:
            inc = incident_context.get("incident", {})
            related = incident_context.get("related_alerts", [])
            
            if any(w in q for w in ['explain', 'what', 'why', 'how', 'tell', 'describe', 'summary', 'summarize']):
                response = f"**Incident Analysis: {inc.get('title', 'Unknown')}**\n\n"
                response += f"**Severity:** {inc.get('severity', 'N/A')} | **Status:** {inc.get('status', 'N/A')}\n"
                response += f"**Confidence:** {inc.get('confidence', 0):.0%}\n"
                response += f"**Kill Chain:** {' → '.join(inc.get('kill_chain_stages', []))}\n\n"
                response += f"**Description:** {inc.get('description', 'N/A')}\n\n"
                
                if inc.get('matched_chain'):
                    response += f"**Attack Pattern:** {inc.get('matched_chain', '').replace('_', ' ').title()}\n\n"
                
                response += f"**Timeline ({len(inc.get('timeline', []))} events):**\n"
                for t in inc.get("timeline", [])[:10]:
                    response += f"- [{t.get('severity', '')}] {t.get('timestamp', '')[:19]} — {t.get('title', '')}\n"
                
                if related:
                    response += f"\n**Related Alerts ({len(related)}):**\n"
                    for a in related[:5]:
                        response += f"- [{a.get('severity')}] {a.get('alert_type', '')}: {a.get('title', '')[:80]}\n"
                
                if inc.get('recommendations'):
                    response += f"\n**Recommendations:**\n"
                    for r in inc.get('recommendations', [])[:5]:
                        response += f"- {r}\n"
                
                return {"response": response, "source": "local", "timestamp": datetime.now(timezone.utc).isoformat()}
            
            elif any(w in q for w in ['recommend', 'action', 'respond', 'do']):
                response = f"**Response Actions for Incident {inc.get('id', '')[:8]}**\n\n"
                if inc.get('recommendations'):
                    for r in inc.get('recommendations'):
                        response += f"- {r}\n"
                else:
                    response += "- Escalate to senior analyst\n- Preserve forensic evidence\n- Document findings\n"
                return {"response": response, "source": "local", "timestamp": datetime.now(timezone.utc).isoformat()}
        
        # Analyze detections for context
        critical = [d for d in detections if d.get('severity') == 'CRITICAL']
        high = [d for d in detections if d.get('severity') == 'HIGH']
        types = {}
        for d in detections:
            t = d.get('threat_type', 'unknown')
            types[t] = types.get(t, 0) + 1
        
        top_type = max(types.items(), key=lambda x: x[1])[0] if types else 'none'
        
        # Pattern matching for question types
        if any(w in q for w in ['why', 'reason', 'explain', 'cause']):
            if critical:
                d = critical[0]
                response = (
                    f"**Critical Threat Explanation**\n\n"
                    f"A {d.get('threat_type', 'unknown').replace('_', ' ').title()} threat was detected "
                    f"from IP {d.get('source_ip', 'unknown')} targeting {d.get('dest_ip', 'unknown')} "
                    f"on port {d.get('dest_port', 'N/A')}.\n\n"
                    f"**Evidence:**\n"
                )
                for e in d.get('evidence', []):
                    response += f"- {e}\n"
                response += (
                    f"\n**MITRE ATT&CK:** {d.get('mitre_technique', 'N/A')} - {d.get('mitre_tactic', 'N/A')}\n"
                    f"**Confidence:** {d.get('confidence', 0):.0%}\n\n"
                    f"**Immediate Actions:**\n"
                )
                for r in d.get('recommendations', [])[:3]:
                    response += f"- {r}\n"
            else:
                response = f"Based on the analysis, the most common threat type is **{top_type.replace('_', ' ').title()}** ({types.get(top_type, 0)} detections). No critical threats were detected in the current dataset."
        
        elif any(w in q for w in ['what should i do', 'recommend', 'action', 'respond']):
            response = "**Recommended Response Actions:**\n\n"
            if critical:
                response += "**IMMEDIATE (Critical):**\n"
                for d in critical[:3]:
                    response += f"- Block IP {d.get('source_ip', 'unknown')} - {d.get('threat_type', '').replace('_', ' ').title()}\n"
                response += "\n"
            if high:
                response += "**SHORT-TERM (High):**\n"
                for d in high[:3]:
                    response += f"- Investigate {d.get('source_ip', 'unknown')} - {d.get('description', '')[:80]}\n"
                response += "\n"
            response += "**GENERAL:**\n- Review all open threats\n- Update firewall rules\n- Monitor for new activity\n- Document findings for compliance"
        
        elif any(w in q for w in ['pattern', 'trend', 'common', 'frequent']):
            response = f"**Threat Pattern Analysis:**\n\n"
            for t, count in sorted(types.items(), key=lambda x: -x[1]):
                response += f"- **{t.replace('_', ' ').title()}**: {count} detections\n"
            response += f"\n**Top Source IPs:**\n"
            ip_counts = {}
            for d in detections:
                ip = d.get('source_ip', '')
                if ip:
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1
            for ip, count in sorted(ip_counts.items(), key=lambda x: -x[1])[:5]:
                response += f"- {ip}: {count} events\n"
        
        elif any(w in q for w in ['threat score', 'risk', 'posture', 'security']):
            total = len(detections)
            crit = len(critical)
            high_count = len(high)
            score = min(100, crit * 25 + high_count * 15 + (total - crit - high_count) * 3)
            level = 'CRITICAL' if crit > 0 else 'HIGH' if high_count >= 3 else 'MODERATE' if total > 0 else 'LOW'
            
            response = (
                f"**Security Posture Assessment:**\n\n"
                f"**Overall Risk Score:** {score}/100 ({level})\n\n"
                f"**Breakdown:**\n"
                f"- Critical threats: {crit}\n"
                f"- High threats: {high_count}\n"
                f"- Total detections: {total}\n\n"
            )
            if crit > 0:
                response += "**⚠️ URGENT:** Critical threats require immediate attention.\n"
            elif high_count > 0:
                response += "**⚡ ELEVATED:** Multiple high-severity threats detected.\n"
            else:
                response += "**✅ STABLE:** No significant threats in current analysis.\n"
        
        elif any(w in q for w in ['summary', 'overview', 'summarize', 'today']):
            response = (
                f"**Security Summary:**\n\n"
                f"- **Total Detections:** {len(detections)}\n"
                f"- **Critical:** {len(critical)} | **High:** {len(high)}\n"
                f"- **Most Common:** {top_type.replace('_', ' ').title()}\n"
                f"- **Unique Source IPs:** {len(set(d.get('source_ip', '') for d in detections))}\n\n"
            )
            if detections:
                response += "**Recent Detections:**\n"
                for d in detections[:5]:
                    response += f"- [{d.get('severity')}] {d.get('threat_type', '').replace('_', ' ').title()} from {d.get('source_ip', 'N/A')}\n"
        
        elif any(w in q for w in ['ip', 'investigate', 'lookup', 'check']):
            ip = self._extract_ip(q)
            if ip:
                ip_detections = [d for d in detections if d.get('source_ip') == ip]
                if ip_detections:
                    response = f"**Investigation: {ip}**\n\n"
                    response += f"Found {len(ip_detections)} detections from this IP:\n\n"
                    for d in ip_detections[:5]:
                        response += f"- [{d.get('severity')}] {d.get('threat_type', '').replace('_', ' ').title()}\n"
                        response += f"  Target: {d.get('dest_ip', 'N/A')}:{d.get('dest_port', 'N/A')}\n"
                        response += f"  MITRE: {d.get('mitre_technique', 'N/A')}\n\n"
                    response += f"**Recommendation:** Block this IP and investigate all connected systems."
                else:
                    response = f"No detections found for IP {ip} in the current dataset. This IP may not be a threat, or it hasn't been seen in recent logs."
            else:
                response = "Please specify an IP address to investigate. Example: 'Check 192.168.1.100' or 'Investigate 10.0.0.5'"
        
        elif any(w in q for w in ['mitre', 'technique', 'tactic', 'attack']):
            mitre_counts = {}
            for d in detections:
                tech = d.get('mitre_technique', '')
                if tech:
                    mitre_counts[tech] = mitre_counts.get(tech, 0) + 1
            response = "**MITRE ATT&CK Coverage:**\n\n"
            if mitre_counts:
                for tech, count in sorted(mitre_counts.items(), key=lambda x: -x[1]):
                    response += f"- **{tech}**: {count} detections\n"
            else:
                response += "No MITRE mappings available for current detections."
        
        elif any(w in q for w in ['hello', 'hi', 'hey', 'help']):
            response = (
                "**SentinelAI Copilot** - Your Security Analysis Assistant\n\n"
                "I can help you with:\n"
                "- **Threat Analysis** - 'Why was this threat detected?'\n"
                "- **Response Actions** - 'What should I do now?'\n"
                "- **Pattern Detection** - 'What patterns do you see?'\n"
                "- **Risk Assessment** - 'What's my threat score?'\n"
                "- **IP Investigation** - 'Check 192.168.1.100'\n"
                "- **MITRE Mapping** - 'Show MITRE techniques'\n"
                "- **Incident Summary** - 'Summarize today's activity'\n\n"
                "Ask me anything about your security data!"
            )
        
        else:
            response = (
                f"I can help you analyze your security data. Here's what I see:\n\n"
                f"- **{len(detections)} total detections** across {len(types)} threat types\n"
                f"- **Top threat:** {top_type.replace('_', ' ').title()}\n"
                f"- **Severity breakdown:** {json.dumps({k: v for k, v in sorted(types.items(), key=lambda x: -x[1])})}\n\n"
                f"Try asking me:\n"
                f"- 'What patterns do you see?'\n"
                f"- 'What should I do about the critical threats?'\n"
                f"- 'Summarize today's security activity'\n"
                f"- 'Check [IP address]'"
            )
        
        return {
            "response": response,
            "source": "local",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    
    def _extract_ip(self, text: str) -> Optional[str]:
        """Extract IP address from text."""
        import re
        match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
        return match.group(0) if match else None


# Singleton
gemini_copilot = GeminiCopilot()
