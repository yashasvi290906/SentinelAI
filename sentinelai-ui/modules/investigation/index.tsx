'use client';
import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  AlertTriangle, Clock, MapPin, Shield, FileText, MessageSquare,
  ChevronRight, ExternalLink, Loader2, Plus, Send
} from 'lucide-react';
import GlassCard from '@/components/ui/GlassCard';

interface Alert {
  id: string;
  alert_type: string;
  severity: string;
  title: string;
  description: string;
  source_ip: string;
  destination_ip: string;
  source_port: number;
  destination_port: number;
  protocol: string;
  mitre_technique: string;
  mitre_tactic: string;
  evidence: string[];
  recommendations: string[];
  status: string;
  created_at: string;
}

interface InvestigationNote {
  id: string;
  note: string;
  user_id: string;
  created_at: string;
}

export default function InvestigationWorkspace() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [notes, setNotes] = useState<InvestigationNote[]>([]);
  const [newNote, setNewNote] = useState('');
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState({ severity: '', status: '' });

  const fetchAlerts = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (filter.severity) params.set('severity', filter.severity);
      if (filter.status) params.set('status', filter.status);
      const res = await fetch(`/api/alerts?${params.toString()}`);
      const data = await res.json();
      setAlerts(data.alerts || []);
    } catch (e) {
      console.error('Failed to fetch alerts');
    }
    setLoading(false);
  }, [filter]);

  const fetchNotes = useCallback(async (alertId: string) => {
    try {
      const res = await fetch(`/api/alerts/${alertId}/notes`);
      const data = await res.json();
      setNotes(data.notes || []);
    } catch (e) {
      setNotes([]);
    }
  }, []);

  useEffect(() => { fetchAlerts(); }, [fetchAlerts]);
  useEffect(() => { if (selectedAlert) fetchNotes(selectedAlert.id); }, [selectedAlert, fetchNotes]);

  const addNote = async () => {
    if (!newNote.trim() || !selectedAlert) return;
    try {
      await fetch(`/api/alerts/${selectedAlert.id}/notes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ note: newNote }),
      });
      setNewNote('');
      fetchNotes(selectedAlert.id);
    } catch (e) {
      console.error('Failed to add note');
    }
  };

  const updateStatus = async (alertId: string, status: string) => {
    try {
      await fetch(`/api/alerts/${alertId}/status`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status }),
      });
      fetchAlerts();
      if (selectedAlert?.id === alertId) {
        setSelectedAlert(prev => prev ? { ...prev, status } : null);
      }
    } catch (e) {
      console.error('Failed to update status');
    }
  };

  const getSeverityColor = (sev: string) => {
    switch (sev) {
      case 'CRITICAL': return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'HIGH': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'MEDIUM': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      default: return 'bg-white/5 text-white/50 border-white/10';
    }
  };

  return (
    <div className="h-[calc(100vh-120px)] flex gap-4">
      {/* Alert List */}
      <div className="w-96 shrink-0 flex flex-col">
        <GlassCard className="p-4 mb-3">
          <div className="flex items-center gap-2 mb-3">
            <AlertTriangle className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-medium text-white">Alerts ({alerts.length})</h3>
          </div>
          <div className="flex gap-2">
            <select
              value={filter.severity}
              onChange={(e) => setFilter(f => ({ ...f, severity: e.target.value }))}
              className="flex-1 bg-white/5 border border-white/10 rounded px-2 py-1 text-xs text-white/70 outline-none"
            >
              <option value="">All Severity</option>
              {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => <option key={s} value={s}>{s}</option>)}
            </select>
            <select
              value={filter.status}
              onChange={(e) => setFilter(f => ({ ...f, status: e.target.value }))}
              className="flex-1 bg-white/5 border border-white/10 rounded px-2 py-1 text-xs text-white/70 outline-none"
            >
              <option value="">All Status</option>
              {['open', 'investigating', 'resolved', 'false_positive'].map(s => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}
            </select>
          </div>
        </GlassCard>
        
        <div className="flex-1 overflow-y-auto space-y-1">
          {alerts.map(alert => (
            <motion.div
              key={alert.id}
              onClick={() => setSelectedAlert(alert)}
              className={`p-3 rounded-lg cursor-pointer transition-colors ${
                selectedAlert?.id === alert.id 
                  ? 'bg-cyan-500/10 border border-cyan-400/20' 
                  : 'bg-white/[0.02] border border-transparent hover:border-white/5'
              }`}
            >
              <div className="flex items-center gap-2 mb-1">
                <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${getSeverityColor(alert.severity)}`}>
                  {alert.severity}
                </span>
                <span className="text-white/50 text-[10px]">{alert.alert_type?.replace(/_/g, ' ')}</span>
              </div>
              <p className="text-white text-xs font-medium truncate">{alert.title}</p>
              <div className="flex items-center gap-2 mt-1 text-[10px] text-white/30">
                <span>{alert.source_ip}</span>
                <ChevronRight className="w-3 h-3" />
                <span>{alert.destination_ip}:{alert.destination_port}</span>
              </div>
              <p className="text-white/20 text-[10px] mt-1">{new Date(alert.created_at).toLocaleString()}</p>
            </motion.div>
          ))}
          {alerts.length === 0 && !loading && (
            <div className="text-center py-8 text-white/30 text-sm">No alerts found</div>
          )}
        </div>
      </div>

      {/* Investigation Panel */}
      <div className="flex-1 overflow-y-auto">
        <AnimatePresence mode="wait">
          {!selectedAlert ? (
            <motion.div
              key="empty"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="h-full flex items-center justify-center"
            >
              <div className="text-center">
                <Shield className="w-20 h-20 text-white/10 mx-auto mb-4" />
                <p className="text-white/40 text-lg">Select an alert to investigate</p>
                <p className="text-white/30 text-sm mt-1">Click any alert from the list to begin analysis</p>
              </div>
            </motion.div>
          ) : (
            <motion.div
              key={selectedAlert.id}
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              className="space-y-4"
            >
              {/* Alert Header */}
              <GlassCard className="p-5">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center gap-2 mb-2">
                      <span className={`px-2 py-0.5 rounded text-xs font-bold ${getSeverityColor(selectedAlert.severity)}`}>
                        {selectedAlert.severity}
                      </span>
                      <span className="text-white/50 text-xs">{selectedAlert.alert_type?.replace(/_/g, ' ')}</span>
                      <span className={`px-2 py-0.5 rounded text-xs ${
                        selectedAlert.status === 'open' ? 'bg-red-500/10 text-red-400' :
                        selectedAlert.status === 'investigating' ? 'bg-yellow-500/10 text-yellow-400' :
                        'bg-emerald-500/10 text-emerald-400'
                      }`}>{selectedAlert.status?.replace('_', ' ')}</span>
                    </div>
                    <h2 className="text-xl font-semibold text-white">{selectedAlert.title}</h2>
                    <p className="text-white/50 text-sm mt-1">{selectedAlert.description}</p>
                  </div>
                  <div className="flex gap-2">
                    {['open', 'investigating', 'resolved', 'false_positive'].map(status => (
                      <button
                        key={status}
                        onClick={() => updateStatus(selectedAlert.id, status)}
                        className={`px-3 py-1 rounded text-xs ${
                          selectedAlert.status === status 
                            ? 'bg-cyan-500/20 text-cyan-400' 
                            : 'bg-white/5 text-white/40 hover:bg-white/10'
                        }`}
                      >{status.replace('_', ' ')}</button>
                    ))}
                  </div>
                </div>
              </GlassCard>

              {/* Details Grid */}
              <div className="grid grid-cols-2 gap-4">
                {/* Network Info */}
                <GlassCard className="p-4">
                  <h3 className="text-sm font-medium text-white/60 mb-3 flex items-center gap-2">
                    <MapPin className="w-4 h-4 text-cyan-400" /> Network
                  </h3>
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-white/40">Source IP</span>
                      <span className="text-cyan-400 font-mono">{selectedAlert.source_ip || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-white/40">Destination IP</span>
                      <span className="text-cyan-400 font-mono">{selectedAlert.destination_ip || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-white/40">Ports</span>
                      <span className="text-white/70 font-mono">{selectedAlert.source_port || '?'} → {selectedAlert.destination_port || '?'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-white/40">Protocol</span>
                      <span className="text-white/70">{selectedAlert.protocol || 'N/A'}</span>
                    </div>
                  </div>
                </GlassCard>

                {/* MITRE */}
                <GlassCard className="p-4">
                  <h3 className="text-sm font-medium text-white/60 mb-3 flex items-center gap-2">
                    <Shield className="w-4 h-4 text-purple-400" /> MITRE ATT&CK
                  </h3>
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-white/40">Technique</span>
                      <span className="px-2 py-0.5 rounded bg-purple-500/10 text-purple-400 font-mono text-xs">
                        {selectedAlert.mitre_technique || 'N/A'}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-white/40">Tactic</span>
                      <span className="text-white/70">{selectedAlert.mitre_tactic || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-white/40">Time</span>
                      <span className="text-white/50 text-xs">{new Date(selectedAlert.created_at).toLocaleString()}</span>
                    </div>
                  </div>
                </GlassCard>
              </div>

              {/* Evidence */}
              {selectedAlert.evidence?.length > 0 && (
                <GlassCard className="p-4">
                  <h3 className="text-sm font-medium text-white/60 mb-3">Evidence</h3>
                  <ul className="space-y-1">
                    {(Array.isArray(selectedAlert.evidence) ? selectedAlert.evidence : []).map((e, i) => (
                      <li key={i} className="text-sm text-white/60 pl-3 border-l-2 border-cyan-500/30">
                        {typeof e === 'string' ? e : JSON.stringify(e)}
                      </li>
                    ))}
                  </ul>
                </GlassCard>
              )}

              {/* Recommendations */}
              {selectedAlert.recommendations?.length > 0 && (
                <GlassCard className="p-4">
                  <h3 className="text-sm font-medium text-white/60 mb-3">Recommended Actions</h3>
                  <ul className="space-y-1">
                    {(Array.isArray(selectedAlert.recommendations) ? selectedAlert.recommendations : []).map((r, i) => (
                      <li key={i} className="text-sm text-white/60 pl-3 border-l-2 border-emerald-500/30">
                        {typeof r === 'string' ? r : JSON.stringify(r)}
                      </li>
                    ))}
                  </ul>
                </GlassCard>
              )}

              {/* Investigation Notes */}
              <GlassCard className="p-4">
                <h3 className="text-sm font-medium text-white/60 mb-3 flex items-center gap-2">
                  <MessageSquare className="w-4 h-4 text-blue-400" />
                  Investigation Notes ({notes.length})
                </h3>
                <div className="space-y-2 mb-3 max-h-48 overflow-y-auto">
                  {notes.length === 0 ? (
                    <p className="text-white/30 text-sm">No notes yet</p>
                  ) : (
                    notes.map(note => (
                      <div key={note.id} className="p-2 rounded bg-white/[0.03] text-sm">
                        <p className="text-white/60">{note.note}</p>
                        <p className="text-white/30 text-xs mt-1">{new Date(note.created_at).toLocaleString()}</p>
                      </div>
                    ))
                  )}
                </div>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={newNote}
                    onChange={(e) => setNewNote(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && addNote()}
                    placeholder="Add investigation note..."
                    className="flex-1 bg-white/5 border border-white/10 rounded px-3 py-2 text-sm text-white/70 outline-none focus:border-cyan-400/50"
                  />
                  <button
                    onClick={addNote}
                    disabled={!newNote.trim()}
                    className="px-4 py-2 bg-cyan-500/20 border border-cyan-400/30 rounded text-cyan-400 text-sm hover:bg-cyan-500/30 disabled:opacity-50"
                  >
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
