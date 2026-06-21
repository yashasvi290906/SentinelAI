'use client';
import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  AlertTriangle, Shield, Clock, Users, FileText, MessageSquare,
  ChevronRight, ChevronDown, Play, Pause, CheckCircle, XCircle,
  Loader2, Plus, Send, Link, BarChart3
} from 'lucide-react';
import GlassCard from '@/components/ui/GlassCard';

interface Incident {
  id: string;
  title: string;
  severity: string;
  status: string;
  confidence: number;
  description: string;
  alert_ids: string;
  timeline: string;
  affected_ips: string;
  mitre_techniques: string;
  mitre_tactics: string;
  recommendations: string;
  assigned_to: string;
  created_at: string;
  updated_at: string;
}

interface IncidentNote {
  id: string;
  note: string;
  user_id: string;
  created_at: string;
}

const STATUS_COLORS: Record<string, string> = {
  open: 'bg-red-500/20 text-red-400',
  investigating: 'bg-yellow-500/20 text-yellow-400',
  contained: 'bg-blue-500/20 text-blue-400',
  resolved: 'bg-emerald-500/20 text-emerald-400',
  false_positive: 'bg-white/10 text-white/40',
};

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'bg-red-500/20 text-red-400 border-red-500/30',
  HIGH: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  MEDIUM: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  LOW: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
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
  const [newNote, setNewNote] = useState('');
  const [loading, setLoading] = useState(false);
  const [correlating, setCorrelating] = useState(false);
  const [stats, setStats] = useState<any>(null);
  const [filter, setFilter] = useState({ severity: '', status: '' });
  const [expandedTimeline, setExpandedTimeline] = useState<string | null>(null);

  const fetchIncidents = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (filter.severity) params.set('severity', filter.severity);
      if (filter.status) params.set('status', filter.status);
      const [incRes, statsRes] = await Promise.all([
        fetch(`/api/incidents?${params.toString()}`),
        fetch('/api/incidents/stats'),
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

  const fetchNotes = useCallback(async (incidentId: string) => {
    try {
      const res = await fetch(`/api/incidents/${incidentId}/notes`);
      const data = await res.json();
      setNotes(data.notes || []);
    } catch (e) { setNotes([]); }
  }, []);

  useEffect(() => { fetchIncidents(); }, [fetchIncidents]);
  useEffect(() => { if (selectedIncident) fetchNotes(selectedIncident.id); }, [selectedIncident, fetchNotes]);

  const runCorrelation = async () => {
    setCorrelating(true);
    try {
      const res = await fetch('/api/incidents/correlate', { method: 'POST' });
      const data = await res.json();
      alert(`Created ${data.correlated} incidents from correlated alerts`);
      fetchIncidents();
    } catch (e) {
      alert('Correlation failed');
    }
    setCorrelating(false);
  };

  const updateStatus = async (incidentId: string, status: string) => {
    try {
      await fetch(`/api/incidents/${incidentId}/status`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status }),
      });
      fetchIncidents();
      if (selectedIncident?.id === incidentId) {
        setSelectedIncident(prev => prev ? { ...prev, status } : null);
      }
    } catch (e) { console.error('Failed to update status'); }
  };

  const addNote = async () => {
    if (!newNote.trim() || !selectedIncident) return;
    try {
      await fetch(`/api/incidents/${selectedIncident.id}/notes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ note: newNote }),
      });
      setNewNote('');
      fetchNotes(selectedIncident.id);
    } catch (e) { console.error('Failed to add note'); }
  };

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
            <button
              onClick={runCorrelation}
              disabled={correlating}
              className="px-3 py-1 bg-cyan-500/20 border border-cyan-400/30 rounded text-xs text-cyan-400 hover:bg-cyan-500/30 disabled:opacity-50"
            >
              {correlating ? <Loader2 className="w-3 h-3 animate-spin" /> : <Link className="w-3 h-3 inline mr-1" />}
              Correlate
            </button>
          </div>
          
          {/* Stats */}
          {stats && (
            <div className="grid grid-cols-3 gap-2 mb-3">
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
          
          <div className="flex gap-2">
            <select value={filter.severity} onChange={e => setFilter(f => ({...f, severity: e.target.value}))}
              className="flex-1 bg-white/5 border border-white/10 rounded px-2 py-1 text-xs text-white/70 outline-none">
              <option value="">All Severity</option>
              {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => <option key={s} value={s}>{s}</option>)}
            </select>
            <select value={filter.status} onChange={e => setFilter(f => ({...f, status: e.target.value}))}
              className="flex-1 bg-white/5 border border-white/10 rounded px-2 py-1 text-xs text-white/70 outline-none">
              <option value="">All Status</option>
              {['open', 'investigating', 'contained', 'resolved', 'false_positive'].map(s => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}
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
              }`}
            >
              <div className="flex items-center gap-2 mb-1">
                <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${SEVERITY_COLORS[inc.severity] || SEVERITY_COLORS.LOW}`}>
                  {inc.severity}
                </span>
                <span className={`px-1.5 py-0.5 rounded text-[10px] ${STATUS_COLORS[inc.status] || STATUS_COLORS.open}`}>
                  {inc.status?.replace('_', ' ')}
                </span>
              </div>
              <p className="text-white text-xs font-medium truncate">{inc.title}</p>
              <div className="flex items-center gap-2 mt-1 text-[10px] text-white/30">
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
                  <div>
                    <div className="flex items-center gap-2 mb-2">
                      <span className={`px-2 py-0.5 rounded text-xs font-bold ${SEVERITY_COLORS[selectedIncident.severity]}`}>
                        {selectedIncident.severity}
                      </span>
                      <span className={`px-2 py-0.5 rounded text-xs ${STATUS_COLORS[selectedIncident.status]}`}>
                        {selectedIncident.status?.replace('_', ' ')}
                      </span>
                      <span className="text-white/30 text-xs">
                        Confidence: {(selectedIncident.confidence * 100).toFixed(0)}%
                      </span>
                    </div>
                    <h2 className="text-xl font-semibold text-white">{selectedIncident.title}</h2>
                    <p className="text-white/50 text-sm mt-1">{selectedIncident.description}</p>
                  </div>
                  <div className="flex gap-1">
                    {['open', 'investigating', 'contained', 'resolved', 'false_positive'].map(status => (
                      <button key={status} onClick={() => updateStatus(selectedIncident.id, status)}
                        className={`px-2 py-1 rounded text-[10px] ${
                          selectedIncident.status === status ? 'bg-cyan-500/20 text-cyan-400' : 'bg-white/5 text-white/40 hover:bg-white/10'
                        }`}>{status.replace('_', ' ')}</button>
                    ))}
                  </div>
                </div>
              </GlassCard>

              {/* Info Grid */}
              <div className="grid grid-cols-3 gap-4">
                <GlassCard className="p-4">
                  <h3 className="text-sm font-medium text-white/60 mb-2">Affected IPs</h3>
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
                  <h3 className="text-sm font-medium text-white/60 mb-2">MITRE ATT&CK</h3>
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
                  <h3 className="text-sm font-medium text-white/60 mb-2">Timeline</h3>
                  <div className="space-y-1 max-h-40 overflow-y-auto">
                    {parseJsonField(selectedIncident.timeline).sort((a: any, b: any) => (a.time || '').localeCompare(b.time || '')).map((item: any, i: number) => (
                      <div key={i} className="flex items-center gap-2 text-xs">
                        <span className="text-white/30 font-mono w-16 shrink-0">{item.time?.slice(11, 19) || '?'}</span>
                        <span className={`w-1.5 h-1.5 rounded-full ${
                          item.severity === 'CRITICAL' ? 'bg-red-400' :
                          item.severity === 'HIGH' ? 'bg-orange-400' : 'bg-yellow-400'
                        }`} />
                        <span className="text-white/60 truncate">{item.type?.replace(/_/g, ' ')}</span>
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

              {/* Notes */}
              <GlassCard className="p-4">
                <h3 className="text-sm font-medium text-white/60 mb-3 flex items-center gap-2">
                  <MessageSquare className="w-4 h-4 text-blue-400" />
                  Investigation Notes ({notes.length})
                </h3>
                <div className="space-y-2 mb-3 max-h-48 overflow-y-auto">
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
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
