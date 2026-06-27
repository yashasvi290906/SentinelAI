'use client';
import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  AlertTriangle, Shield, Clock, Users, FileText, MessageSquare,
  ChevronRight, ChevronDown, Play, Pause, CheckCircle, XCircle,
  Loader2, Plus, Send, Link, BarChart3, Zap, Archive, GitMerge,
  ShieldAlert, Eye, Target, Timer
} from 'lucide-react';
import GlassCard from '@/components/ui/GlassCard';
import { fetchWithAuth } from "@/lib/api";

interface Incident {
  id: string;
  title: string;
  severity: string;
  status: string;
  priority: string;
  category: string;
  confidence: number;
  description: string;
  alert_ids: string | string[];
  timeline: string | any[];
  affected_ips: string | string[];
  mitre_techniques: string | string[];
  mitre_tactics: string | string[];
  recommendations: string | string[];
  assigned_to: string;
  impact_summary: string;
  root_cause: string;
  lessons_learned: string;
  created_at: string;
  updated_at: string;
  resolved_at: string;
  closed_at: string;
  valid_transitions?: string[];
  notes?: IncidentNote[];
  evidence?: EvidenceItem[];
  forensic_timeline?: ForensicEntry[];
}

interface IncidentNote {
  id: string;
  note: string;
  user_id: string;
  created_at: string;
}

interface EvidenceItem {
  id: string;
  evidence_type: string;
  description: string;
  file_name: string;
  source_type: string;
  collected_at: string;
  sha256_hash: string;
}

interface ForensicEntry {
  id: string;
  event_type: string;
  event_time: string;
  description: string;
  source: string;
  confidence: number;
}

const STATUS_COLORS: Record<string, string> = {
  open: 'bg-red-500/20 text-red-400',
  investigating: 'bg-yellow-500/20 text-yellow-400',
  contained: 'bg-blue-500/20 text-blue-400',
  resolved: 'bg-emerald-500/20 text-emerald-400',
  closed: 'bg-white/10 text-white/40',
  archived: 'bg-white/5 text-white/30',
};

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'bg-red-500/20 text-red-400 border-red-500/30',
  HIGH: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  MEDIUM: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  LOW: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
};

const PRIORITY_COLORS: Record<string, string> = {
  P1: 'text-red-400',
  P2: 'text-orange-400',
  P3: 'text-yellow-400',
  P4: 'text-blue-400',
};

function parseJsonField(field: any): any[] {
  if (!field) return [];
  if (Array.isArray(field)) return field;
  try { return JSON.parse(field); } catch { return []; }
}

export default function IncidentsModule() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [notes, setNotes] = useState<IncidentNote[]>([]);
  const [evidence, setEvidence] = useState<EvidenceItem[]>([]);
  const [forensicTimeline, setForensicTimeline] = useState<ForensicEntry[]>([]);
  const [newNote, setNewNote] = useState('');
  const [loading, setLoading] = useState(false);
  const [correlating, setCorrelating] = useState(false);
  const [stats, setStats] = useState<any>(null);
  const [filter, setFilter] = useState({ severity: '', status: '' });
  const [detailTab, setDetailTab] = useState<'overview' | 'timeline' | 'evidence' | 'notes'>('overview');
  const [showEvidenceForm, setShowEvidenceForm] = useState(false);
  const [evidenceForm, setEvidenceForm] = useState({ evidence_type: 'log', description: '', file_name: '' });
  const [selectedForMerge, setSelectedForMerge] = useState<string[]>([]);

  const fetchIncidents = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (filter.severity) params.set('severity', filter.severity);
      if (filter.status) params.set('status', filter.status);
      const [incRes, statsRes] = await Promise.all([
        fetchWithAuth(`/api/incidents?${params.toString()}`),
        fetchWithAuth('/api/incidents/stats'),
      ]);
      const incData = await incRes.json();
      const statsData = await statsRes.json();
      setIncidents(incData.incidents || []);
      setStats(statsData);
    } catch (e) {
      console.error('Failed to fetch incidents');
    }
    setLoading(false);
  }, [filter]);

  const fetchIncidentDetail = useCallback(async (incidentId: string) => {
    try {
      const res = await fetchWithAuth(`/api/incidents/${incidentId}/detail`);
      if (res.ok) {
        const data = await res.json();
        setSelectedIncident(data);
        setNotes(data.notes || []);
        setEvidence(data.evidence || []);
        setForensicTimeline(data.forensic_timeline || []);
      }
    } catch (e) { console.error('Failed to fetch detail'); }
  }, []);

  useEffect(() => { fetchIncidents(); }, [fetchIncidents]);
  useEffect(() => { if (selectedIncident) fetchIncidentDetail(selectedIncident.id); }, [selectedIncident?.id, fetchIncidentDetail]);

  const runCorrelation = async () => {
    setCorrelating(true);
    try {
      const res = await fetchWithAuth('/api/incidents/correlate', { method: 'POST' });
      const data = await res.json();
      alert(`Created ${data.correlated} incidents from correlated alerts`);
      fetchIncidents();
    } catch (e) { alert('Correlation failed'); }
    setCorrelating(false);
  };

  const updateStatus = async (incidentId: string, status: string) => {
    try {
      await fetchWithAuth(`/api/incidents/${incidentId}/status`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status }),
      });
      fetchIncidents();
      fetchIncidentDetail(incidentId);
    } catch (e) { console.error('Failed to update status'); }
  };

  const escalateIncident = async (incidentId: string) => {
    try {
      const res = await fetchWithAuth(`/api/incidents/${incidentId}/escalate`, { method: 'POST' });
      const data = await res.json();
      if (data.success) {
        alert(`Escalated: ${data.previous_severity} → ${data.new_severity}`);
        fetchIncidentDetail(incidentId);
        fetchIncidents();
      } else {
        alert(data.error || 'Escalation failed');
      }
    } catch (e) { alert('Escalation failed'); }
  };

  const archiveIncident = async (incidentId: string) => {
    if (!confirm('Archive this incident?')) return;
    try {
      await fetchWithAuth(`/api/incidents/${incidentId}`, { method: 'DELETE' });
      setSelectedIncident(null);
      fetchIncidents();
    } catch (e) { console.error('Failed to archive'); }
  };

  const addNote = async () => {
    if (!newNote.trim() || !selectedIncident) return;
    try {
      await fetchWithAuth(`/api/incidents/${selectedIncident.id}/notes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ note: newNote }),
      });
      setNewNote('');
      fetchIncidentDetail(selectedIncident.id);
    } catch (e) { console.error('Failed to add note'); }
  };

  const addEvidence = async () => {
    if (!selectedIncident) return;
    try {
      await fetchWithAuth(`/api/incidents/${selectedIncident.id}/evidence`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(evidenceForm),
      });
      setShowEvidenceForm(false);
      setEvidenceForm({ evidence_type: 'log', description: '', file_name: '' });
      fetchIncidentDetail(selectedIncident.id);
    } catch (e) { console.error('Failed to add evidence'); }
  };

  const mergeSelected = async () => {
    if (selectedForMerge.length < 2) return;
    const primary = selectedForMerge[0];
    const secondaries = selectedForMerge.slice(1);
    if (!confirm(`Merge ${secondaries.length} incidents into the first selected?`)) return;
    try {
      const res = await fetchWithAuth('/api/incidents/merge', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ primary_id: primary, secondary_ids: secondaries }),
      });
      const data = await res.json();
      if (data.success) {
        alert(`Merged ${data.merged_count} incidents`);
        setSelectedForMerge([]);
        fetchIncidents();
      } else {
        alert(data.error || 'Merge failed');
      }
    } catch (e) { alert('Merge failed'); }
  };

  const toggleMergeSelect = (id: string) => {
    setSelectedForMerge(prev =>
      prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]
    );
  };

  const validTransitions = selectedIncident?.valid_transitions || [];
  const allStatuses = ['open', 'investigating', 'contained', 'resolved', 'closed', 'archived'];

  return (
    <div className="h-[calc(100vh-120px)] flex gap-4">
      {/* Incident List */}
      <div className="w-96 shrink-0 flex flex-col">
        <GlassCard className="p-4 mb-3">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-medium text-white flex items-center gap-2">
              <Shield className="w-4 h-4 text-cyan-400" />
              Incidents ({incidents.length})
            </h3>
            <div className="flex gap-1">
              {selectedForMerge.length >= 2 && (
                <button onClick={mergeSelected}
                  className="px-2 py-1 bg-purple-500/20 border border-purple-400/30 rounded text-xs text-purple-400 hover:bg-purple-500/30">
                  <GitMerge className="w-3 h-3 inline mr-1" />Merge ({selectedForMerge.length})
                </button>
              )}
              <button onClick={runCorrelation} disabled={correlating}
                className="px-3 py-1 bg-cyan-500/20 border border-cyan-400/30 rounded text-xs text-cyan-400 hover:bg-cyan-500/30 disabled:opacity-50">
                {correlating ? <Loader2 className="w-3 h-3 animate-spin" /> : <Link className="w-3 h-3 inline mr-1" />}
                Correlate
              </button>
            </div>
          </div>

          {stats && (
            <div className="grid grid-cols-4 gap-2 mb-3">
              <div className="text-center p-1.5 rounded bg-white/[0.03]">
                <p className="text-lg font-bold text-cyan-400">{stats.total || 0}</p>
                <p className="text-[10px] text-white/40">Total</p>
              </div>
              {['CRITICAL', 'HIGH', 'MEDIUM'].map(sev => (
                <div key={sev} className="text-center p-1.5 rounded bg-white/[0.03]">
                  <p className={`text-lg font-bold ${
                    sev === 'CRITICAL' ? 'text-red-400' : sev === 'HIGH' ? 'text-orange-400' : 'text-yellow-400'
                  }`}>{stats.by_severity?.[sev] || 0}</p>
                  <p className="text-[10px] text-white/40">{sev}</p>
                </div>
              ))}
            </div>
          )}

          {stats && (stats.mttt_minutes > 0 || stats.mttr_minutes > 0) && (
            <div className="flex gap-3 mb-3 px-2 py-1.5 rounded bg-white/[0.03]">
              <div className="flex items-center gap-1">
                <Timer className="w-3 h-3 text-cyan-400" />
                <span className="text-[10px] text-white/40">MTTT:</span>
                <span className="text-[10px] text-cyan-400 font-mono">{stats.mttt_minutes}m</span>
              </div>
              <div className="flex items-center gap-1">
                <Timer className="w-3 h-3 text-emerald-400" />
                <span className="text-[10px] text-white/40">MTTR:</span>
                <span className="text-[10px] text-emerald-400 font-mono">{stats.mttr_minutes}m</span>
              </div>
            </div>
          )}

          <div className="flex gap-2">
            <select value={filter.severity} onChange={e => setFilter(f => ({...f, severity: e.target.value}))}
              className="flex-1 bg-white/5 border border-white/10 rounded px-2 py-1 text-xs text-white/70 outline-none">
              <option value="">All Severity</option>
              {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => <option key={s} value={s}>{s}</option>)}
            </select>
            <select value={filter.status} onChange={e => setFilter(f => ({...f, status: e.target.value}))}
              className="flex-1 bg-white/5 border border-white/10 rounded px-2 py-1 text-xs text-white/70 outline-none">
              <option value="">All Status</option>
              {allStatuses.map(s => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}
            </select>
          </div>
        </GlassCard>

        <div className="flex-1 overflow-y-auto space-y-1">
          {incidents.map(inc => (
            <motion.div key={inc.id}
              onClick={() => setSelectedIncident(inc)}
              className={`p-3 rounded-lg cursor-pointer transition-colors ${
                selectedIncident?.id === inc.id
                  ? 'bg-cyan-500/10 border border-cyan-400/20'
                  : 'bg-white/[0.02] border border-transparent hover:border-white/5'
              }`}>
              <div className="flex items-center gap-2 mb-1">
                <input type="checkbox" checked={selectedForMerge.includes(inc.id)}
                  onClick={e => e.stopPropagation()}
                  onChange={() => toggleMergeSelect(inc.id)}
                  className="w-3 h-3 accent-cyan-400" />
                <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${SEVERITY_COLORS[inc.severity] || SEVERITY_COLORS.LOW}`}>
                  {inc.severity}
                </span>
                <span className={`px-1.5 py-0.5 rounded text-[10px] ${STATUS_COLORS[inc.status] || STATUS_COLORS.open}`}>
                  {inc.status?.replace('_', ' ')}
                </span>
                {inc.priority && (
                  <span className={`text-[10px] font-bold ${PRIORITY_COLORS[inc.priority] || 'text-white/40'}`}>
                    {inc.priority}
                  </span>
                )}
              </div>
              <p className="text-white text-xs font-medium truncate">{inc.title}</p>
              <div className="flex items-center gap-2 mt-1 text-[10px] text-white/30">
                {inc.category && <span className="px-1 rounded bg-white/5">{inc.category}</span>}
                <span>{parseJsonField(inc.affected_ips).slice(0, 2).join(', ') || 'N/A'}</span>
                <span className="ml-auto">{new Date(inc.created_at).toLocaleDateString()}</span>
              </div>
              {inc.confidence > 0 && (
                <div className="mt-1 h-1 bg-white/5 rounded-full overflow-hidden">
                  <div className="h-full bg-cyan-500 rounded-full" style={{ width: `${inc.confidence * 100}%` }} />
                </div>
              )}
            </motion.div>
          ))}
          {incidents.length === 0 && !loading && (
            <div className="text-center py-8">
              <Shield className="w-12 h-12 text-white/10 mx-auto mb-3" />
              <p className="text-white/30 text-sm">No incidents yet</p>
              <p className="text-white/20 text-xs mt-1">Run correlation on open alerts to create incidents</p>
            </div>
          )}
        </div>
      </div>

      {/* Incident Detail */}
      <div className="flex-1 overflow-y-auto">
        <AnimatePresence mode="wait">
          {!selectedIncident ? (
            <motion.div key="empty" initial={{ opacity: 0 }} animate={{ opacity: 1 }}
              className="h-full flex items-center justify-center">
              <div className="text-center">
                <Shield className="w-20 h-20 text-white/10 mx-auto mb-4" />
                <p className="text-white/40 text-lg">Select an incident to investigate</p>
                <p className="text-white/30 text-sm mt-1">Or run correlation to create incidents from open alerts</p>
              </div>
            </motion.div>
          ) : (
            <motion.div key={selectedIncident.id} initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }}
              className="space-y-4">

              {/* Header */}
              <GlassCard className="p-5">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-2">
                      <span className={`px-2 py-0.5 rounded text-xs font-bold ${SEVERITY_COLORS[selectedIncident.severity]}`}>
                        {selectedIncident.severity}
                      </span>
                      <span className={`px-2 py-0.5 rounded text-xs ${STATUS_COLORS[selectedIncident.status]}`}>
                        {selectedIncident.status?.replace('_', ' ')}
                      </span>
                      {selectedIncident.priority && (
                        <span className={`text-xs font-bold ${PRIORITY_COLORS[selectedIncident.priority]}`}>
                          {selectedIncident.priority}
                        </span>
                      )}
                      {selectedIncident.category && (
                        <span className="px-2 py-0.5 rounded text-xs bg-white/5 text-white/50">
                          {selectedIncident.category}
                        </span>
                      )}
                      <span className="text-white/30 text-xs">
                        Confidence: {(selectedIncident.confidence * 100).toFixed(0)}%
                      </span>
                    </div>
                    <h2 className="text-xl font-semibold text-white">{selectedIncident.title}</h2>
                    <p className="text-white/50 text-sm mt-1">{selectedIncident.description}</p>
                  </div>
                  <div className="flex gap-1 flex-wrap justify-end ml-4">
                    {validTransitions.map(status => (
                      <button key={status} onClick={() => updateStatus(selectedIncident.id, status)}
                        className={`px-2 py-1 rounded text-[10px] ${
                          selectedIncident.status === status ? 'bg-cyan-500/20 text-cyan-400' : 'bg-white/5 text-white/40 hover:bg-white/10'
                        }`}>{status.replace('_', ' ')}</button>
                    ))}
                    <button onClick={() => escalateIncident(selectedIncident.id)}
                      className="px-2 py-1 rounded text-[10px] bg-orange-500/10 text-orange-400 hover:bg-orange-500/20">
                      <Zap className="w-3 h-3 inline mr-1" />Escalate
                    </button>
                    <button onClick={() => archiveIncident(selectedIncident.id)}
                      className="px-2 py-1 rounded text-[10px] bg-white/5 text-white/40 hover:bg-white/10">
                      <Archive className="w-3 h-3 inline mr-1" />Archive
                    </button>
                  </div>
                </div>
              </GlassCard>

              {/* Info Grid */}
              <div className="grid grid-cols-3 gap-4">
                <GlassCard className="p-4">
                  <h3 className="text-sm font-medium text-white/60 mb-2 flex items-center gap-1">
                    <Target className="w-3 h-3 text-cyan-400" />Affected IPs
                  </h3>
                  <div className="space-y-1">
                    {parseJsonField(selectedIncident.affected_ips).map((ip, i) => (
                      <span key={i} className="inline-block px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 text-xs font-mono mr-1 mb-1">{ip}</span>
                    ))}
                    {parseJsonField(selectedIncident.affected_ips).length === 0 && (
                      <span className="text-white/30 text-xs">None</span>
                    )}
                  </div>
                </GlassCard>

                <GlassCard className="p-4">
                  <h3 className="text-sm font-medium text-white/60 mb-2 flex items-center gap-1">
                    <ShieldAlert className="w-3 h-3 text-purple-400" />MITRE ATT&CK
                  </h3>
                  <div className="space-y-1">
                    {parseJsonField(selectedIncident.mitre_techniques).map((tech, i) => (
                      <span key={i} className="inline-block px-2 py-0.5 rounded bg-purple-500/10 text-purple-400 text-xs font-mono mr-1 mb-1">{tech}</span>
                    ))}
                  </div>
                  <div className="mt-2 space-y-1">
                    {parseJsonField(selectedIncident.mitre_tactics).map((tactic, i) => (
                      <span key={i} className="text-xs text-white/50">{tactic}</span>
                    ))}
                  </div>
                </GlassCard>

                <GlassCard className="p-4">
                  <h3 className="text-sm font-medium text-white/60 mb-2 flex items-center gap-1">
                    <Clock className="w-3 h-3 text-emerald-400" />Quick Timeline
                  </h3>
                  <div className="space-y-1 max-h-40 overflow-y-auto">
                    {parseJsonField(selectedIncident.timeline).sort((a: any, b: any) => (a.timestamp || a.time || '').localeCompare(b.timestamp || b.time || '')).slice(-8).map((item: any, i: number) => (
                      <div key={i} className="flex items-center gap-2 text-xs">
                        <span className="text-white/30 font-mono w-16 shrink-0">{(item.timestamp || item.time || '').slice(11, 19)}</span>
                        <span className={`w-1.5 h-1.5 rounded-full ${
                          item.severity === 'CRITICAL' ? 'bg-red-400' :
                          item.severity === 'HIGH' ? 'bg-orange-400' : 'bg-cyan-400'
                        }`} />
                        <span className="text-white/60 truncate">{item.event || item.type?.replace(/_/g, ' ')}</span>
                      </div>
                    ))}
                  </div>
                </GlassCard>
              </div>

              {/* Recommendations */}
              {parseJsonField(selectedIncident.recommendations).length > 0 && (
                <GlassCard className="p-4">
                  <h3 className="text-sm font-medium text-white/60 mb-2">Recommended Actions</h3>
                  <ul className="space-y-1">
                    {parseJsonField(selectedIncident.recommendations).map((rec, i) => (
                      <li key={i} className="text-sm text-white/60 pl-3 border-l-2 border-emerald-500/30">{rec}</li>
                    ))}
                  </ul>
                </GlassCard>
              )}

              {/* Tab Navigation */}
              <div className="flex gap-1 border-b border-white/5 pb-1">
                {(['overview', 'timeline', 'evidence', 'notes'] as const).map(tab => (
                  <button key={tab} onClick={() => setDetailTab(tab)}
                    className={`px-3 py-1.5 rounded text-xs ${
                      detailTab === tab ? 'bg-cyan-500/20 text-cyan-400' : 'text-white/40 hover:text-white/60'
                    }`}>
                    {tab === 'overview' && <Eye className="w-3 h-3 inline mr-1" />}
                    {tab === 'timeline' && <Clock className="w-3 h-3 inline mr-1" />}
                    {tab === 'evidence' && <FileText className="w-3 h-3 inline mr-1" />}
                    {tab === 'notes' && <MessageSquare className="w-3 h-3 inline mr-1" />}
                    {tab.charAt(0).toUpperCase() + tab.slice(1)}
                    {tab === 'evidence' && ` (${evidence.length})`}
                    {tab === 'notes' && ` (${notes.length})`}
                    {tab === 'timeline' && ` (${forensicTimeline.length})`}
                  </button>
                ))}
              </div>

              {/* Tab Content */}
              {detailTab === 'overview' && (
                <div className="grid grid-cols-2 gap-4">
                  <GlassCard className="p-4">
                    <h3 className="text-sm font-medium text-white/60 mb-2">Impact Summary</h3>
                    <p className="text-sm text-white/50">{selectedIncident.impact_summary || 'Not assessed'}</p>
                  </GlassCard>
                  <GlassCard className="p-4">
                    <h3 className="text-sm font-medium text-white/60 mb-2">Root Cause</h3>
                    <p className="text-sm text-white/50">{selectedIncident.root_cause || 'Under investigation'}</p>
                  </GlassCard>
                  <GlassCard className="p-4">
                    <h3 className="text-sm font-medium text-white/60 mb-2">Lessons Learned</h3>
                    <p className="text-sm text-white/50">{selectedIncident.lessons_learned || 'Pending post-incident review'}</p>
                  </GlassCard>
                  <GlassCard className="p-4">
                    <h3 className="text-sm font-medium text-white/60 mb-2">Timeline</h3>
                    <div className="text-xs text-white/40 space-y-1">
                      <p>Created: {new Date(selectedIncident.created_at).toLocaleString()}</p>
                      {selectedIncident.updated_at && <p>Updated: {new Date(selectedIncident.updated_at).toLocaleString()}</p>}
                      {selectedIncident.resolved_at && <p>Resolved: {new Date(selectedIncident.resolved_at).toLocaleString()}</p>}
                      {selectedIncident.closed_at && <p>Closed: {new Date(selectedIncident.closed_at).toLocaleString()}</p>}
                    </div>
                  </GlassCard>
                </div>
              )}

              {detailTab === 'timeline' && (
                <GlassCard className="p-4">
                  <h3 className="text-sm font-medium text-white/60 mb-3 flex items-center gap-2">
                    <Clock className="w-4 h-4 text-cyan-400" />
                    Forensic Timeline ({forensicTimeline.length})
                  </h3>
                  <div className="space-y-2">
                    {forensicTimeline.length === 0 ? (
                      <p className="text-white/30 text-sm">No forensic timeline entries yet</p>
                    ) : forensicTimeline.map(entry => (
                      <div key={entry.id} className="flex items-start gap-3 p-2 rounded bg-white/[0.03]">
                        <div className="text-center shrink-0">
                          <span className="text-[10px] text-white/30 font-mono block">{entry.event_time?.slice(0, 10)}</span>
                          <span className="text-[10px] text-white/20 font-mono">{entry.event_time?.slice(11, 19)}</span>
                        </div>
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            <span className="px-1.5 py-0.5 rounded text-[10px] bg-cyan-500/10 text-cyan-400">{entry.event_type}</span>
                            {entry.source && <span className="text-[10px] text-white/30">via {entry.source}</span>}
                            <span className="text-[10px] text-white/20 ml-auto">{(entry.confidence * 100).toFixed(0)}%</span>
                          </div>
                          <p className="text-xs text-white/60 mt-1">{entry.description}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </GlassCard>
              )}

              {detailTab === 'evidence' && (
                <GlassCard className="p-4">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-sm font-medium text-white/60 flex items-center gap-2">
                      <FileText className="w-4 h-4 text-purple-400" />
                      Evidence ({evidence.length})
                    </h3>
                    <button onClick={() => setShowEvidenceForm(!showEvidenceForm)}
                      className="px-2 py-1 bg-purple-500/20 border border-purple-400/30 rounded text-xs text-purple-400 hover:bg-purple-500/30">
                      <Plus className="w-3 h-3 inline mr-1" />Add Evidence
                    </button>
                  </div>
                  {showEvidenceForm && (
                    <div className="p-3 rounded bg-white/[0.03] mb-3 space-y-2">
                      <select value={evidenceForm.evidence_type}
                        onChange={e => setEvidenceForm(f => ({...f, evidence_type: e.target.value}))}
                        className="w-full bg-white/5 border border-white/10 rounded px-3 py-1.5 text-sm text-white/70 outline-none">
                        <option value="log">Log File</option>
                        <option value="pcap">Network Capture</option>
                        <option value="memory_dump">Memory Dump</option>
                        <option value="disk_image">Disk Image</option>
                        <option value="screenshot">Screenshot</option>
                        <option value="hash">File Hash</option>
                        <option value="ioc">IOC</option>
                      </select>
                      <input type="text" placeholder="Description" value={evidenceForm.description}
                        onChange={e => setEvidenceForm(f => ({...f, description: e.target.value}))}
                        className="w-full bg-white/5 border border-white/10 rounded px-3 py-1.5 text-sm text-white/70 outline-none" />
                      <input type="text" placeholder="File name (optional)" value={evidenceForm.file_name}
                        onChange={e => setEvidenceForm(f => ({...f, file_name: e.target.value}))}
                        className="w-full bg-white/5 border border-white/10 rounded px-3 py-1.5 text-sm text-white/70 outline-none" />
                      <button onClick={addEvidence}
                        className="px-3 py-1.5 bg-purple-500/20 border border-purple-400/30 rounded text-xs text-purple-400">
                        Submit Evidence
                      </button>
                    </div>
                  )}
                  <div className="space-y-2">
                    {evidence.length === 0 ? (
                      <p className="text-white/30 text-sm">No evidence attached</p>
                    ) : evidence.map(ev => (
                      <div key={ev.id} className="p-2 rounded bg-white/[0.03] flex items-center gap-3">
                        <FileText className="w-4 h-4 text-purple-400 shrink-0" />
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            <span className="px-1.5 py-0.5 rounded text-[10px] bg-purple-500/10 text-purple-400">{ev.evidence_type}</span>
                            {ev.file_name && <span className="text-xs text-white/50 font-mono">{ev.file_name}</span>}
                          </div>
                          <p className="text-xs text-white/40 mt-0.5">{ev.description}</p>
                          <p className="text-[10px] text-white/20 font-mono mt-0.5">SHA256: {ev.sha256_hash?.slice(0, 16)}...</p>
                        </div>
                        <span className="text-[10px] text-white/20 shrink-0">{new Date(ev.collected_at).toLocaleDateString()}</span>
                      </div>
                    ))}
                  </div>
                </GlassCard>
              )}

              {detailTab === 'notes' && (
                <GlassCard className="p-4">
                  <h3 className="text-sm font-medium text-white/60 mb-3 flex items-center gap-2">
                    <MessageSquare className="w-4 h-4 text-blue-400" />
                    Investigation Notes ({notes.length})
                  </h3>
                  <div className="space-y-2 mb-3 max-h-64 overflow-y-auto">
                    {notes.length === 0 ? (
                      <p className="text-white/30 text-sm">No notes yet</p>
                    ) : notes.map(note => (
                      <div key={note.id} className="p-2 rounded bg-white/[0.03] text-sm">
                        <p className="text-white/60">{note.note}</p>
                        <p className="text-white/30 text-xs mt-1">{new Date(note.created_at).toLocaleString()}</p>
                      </div>
                    ))}
                  </div>
                  <div className="flex gap-2">
                    <input type="text" value={newNote} onChange={e => setNewNote(e.target.value)}
                      onKeyDown={e => e.key === 'Enter' && addNote()}
                      placeholder="Add investigation note..."
                      className="flex-1 bg-white/5 border border-white/10 rounded px-3 py-2 text-sm text-white/70 outline-none focus:border-cyan-400/50" />
                    <button onClick={addNote} disabled={!newNote.trim()}
                      className="px-4 py-2 bg-cyan-500/20 border border-cyan-400/30 rounded text-cyan-400 text-sm hover:bg-cyan-500/30 disabled:opacity-50">
                      <Send className="w-4 h-4" />
                    </button>
                  </div>
                </GlassCard>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
