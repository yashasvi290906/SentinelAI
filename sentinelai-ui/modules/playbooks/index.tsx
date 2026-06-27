'use client';
import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Zap, Play, Clock, Plus, X, Loader2, CheckCircle, XCircle,
  ChevronRight, Terminal, Mail, Shield, AlertTriangle, Search
} from 'lucide-react';
import GlassCard from '@/components/ui/GlassCard';
import { Skeleton } from '@/components/ui/Skeleton';
import { fetchWithAuth } from "@/lib/api";

interface Playbook {
  id: string;
  name: string;
  description: string;
  severity_threshold: string;
  mitre_tactics: string[];
  steps: PlaybookStep[];
  execution_count: number;
  enabled: boolean;
  created_at: string;
}

interface PlaybookStep {
  index: number;
  type: string;
  name: string;
  description: string;
  parameters: Record<string, unknown>;
}

interface PlaybookExecution {
  id: string;
  playbook_id: string;
  playbook_name: string;
  status: string;
  triggered_by: string;
  started_at: string;
  completed_at: string;
  duration_seconds: number;
  actions_taken: string[];
  result: string;
}

const STATUS_ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  block_ip: Shield,
  send_alert: AlertTriangle,
  email: Mail,
  api_call: Terminal,
  isolate_host: Shield,
  log: CheckCircle,
  custom: Zap,
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
};

const EXEC_STATUS_COLORS: Record<string, string> = {
  completed: 'bg-emerald-500/20 text-emerald-400',
  running: 'bg-cyan-500/20 text-cyan-400',
  failed: 'bg-red-500/20 text-red-400',
  pending: 'bg-yellow-500/20 text-yellow-400',
};

export default function PlaybooksModule() {
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [executions, setExecutions] = useState<PlaybookExecution[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedPlaybook, setSelectedPlaybook] = useState<Playbook | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [showExecute, setShowExecute] = useState<Playbook | null>(null);
  const [triggerData, setTriggerData] = useState('');
  const [executing, setExecuting] = useState(false);
  const [activeTab, setActiveTab] = useState<'playbooks' | 'history'>('playbooks');
  const [newPlaybook, setNewPlaybook] = useState({
    name: '', description: '', severity_threshold: 'medium', mitre_tactics: '',
  });

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [pbRes, exRes] = await Promise.all([
        fetchWithAuth('/api/playbooks'),
        fetchWithAuth('/api/playbooks/executions'),
      ]);
      const pbData = await pbRes.json();
      const exData = await exRes.json();
      setPlaybooks(pbData.playbooks || []);
      setExecutions(exData.executions || []);
    } catch {
      console.error('Failed to fetch playbook data');
    }
    setLoading(false);
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const handleCreate = async () => {
    if (!newPlaybook.name) return;
    try {
      await fetchWithAuth('/api/playbooks', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...newPlaybook,
          mitre_tactics: newPlaybook.mitre_tactics.split(',').map(s => s.trim()).filter(Boolean),
        }),
      });
      setShowCreate(false);
      setNewPlaybook({ name: '', description: '', severity_threshold: 'medium', mitre_tactics: '' });
      fetchData();
    } catch {
      console.error('Failed to create playbook');
    }
  };

  const handleExecute = async () => {
    if (!showExecute) return;
    setExecuting(true);
    try {
      await fetchWithAuth(`/api/playbooks/${showExecute.id}/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ trigger_data: triggerData }),
      });
      setShowExecute(null);
      setTriggerData('');
      fetchData();
    } catch {
      console.error('Failed to execute playbook');
    }
    setExecuting(false);
  };

  return (
    <div className="h-full p-6 lg:p-8 flex flex-col gap-6 overflow-y-auto">
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}>
        <p className="text-[10px] font-mono tracking-[0.3em] uppercase mb-2" style={{ color: 'var(--accent-cyan)' }}>
          Security Orchestration
        </p>
        <h1 className="text-3xl font-display font-bold" style={{ color: 'var(--text-primary)' }}>
          Automated Response Playbooks
        </h1>
        <p className="text-sm mt-2" style={{ color: 'var(--text-secondary)' }}>
          Create and execute automated incident response workflows.
        </p>
      </motion.div>

      <div className="flex gap-1 p-1 rounded-xl" style={{ background: 'rgba(8,20,32,0.5)', border: '1px solid rgba(0,229,255,0.06)' }}>
        {(['playbooks', 'history'] as const).map((tab) => (
          <button key={tab} onClick={() => setActiveTab(tab)}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg text-xs font-mono font-semibold transition-all flex-1 justify-center"
            style={{
              background: activeTab === tab ? 'rgba(0,229,255,0.1)' : 'transparent',
              color: activeTab === tab ? 'var(--accent-cyan)' : 'var(--text-muted)',
              border: activeTab === tab ? '1px solid rgba(0,229,255,0.15)' : '1px solid transparent',
            }}>
            {tab === 'playbooks' ? <Zap className="w-3.5 h-3.5" /> : <Clock className="w-3.5 h-3.5" />}
            <span className="hidden sm:inline">{tab === 'playbooks' ? 'Playbooks' : 'Execution History'}</span>
          </button>
        ))}
      </div>

      {activeTab === 'playbooks' && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex flex-col gap-4">
          <div className="flex justify-end">
            <button onClick={() => setShowCreate(true)}
              className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-mono font-semibold"
              style={{ background: 'rgba(0,229,255,0.1)', color: 'var(--accent-cyan)', border: '1px solid rgba(0,229,255,0.2)' }}>
              <Plus className="w-3.5 h-3.5" /> Create Playbook
            </button>
          </div>
          {loading ? <Skeleton count={4} height={120} /> : playbooks.length === 0 ? (
            <div className="rounded-xl p-12 text-center" style={{ background: 'rgba(8,20,32,0.7)', border: '1px solid rgba(0,229,255,0.08)' }}>
              <Zap className="w-12 h-12 mx-auto mb-3" style={{ color: 'var(--text-muted)', opacity: 0.3 }} />
              <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>No playbooks created yet</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {playbooks.map((pb) => (
                <motion.div key={pb.id} layout whileHover={{ scale: 1.01 }}
                  className="rounded-xl p-5 cursor-pointer" style={{ background: 'rgba(8,20,32,0.7)', backdropFilter: 'blur(24px)', border: '1px solid rgba(0,229,255,0.08)' }}
                  onClick={() => setSelectedPlaybook(selectedPlaybook?.id === pb.id ? null : pb)}>
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex-1 min-w-0">
                      <h3 className="text-sm font-bold" style={{ color: 'var(--text-primary)' }}>{pb.name}</h3>
                      <p className="text-[10px] mt-1" style={{ color: 'var(--text-muted)' }}>{pb.description}</p>
                    </div>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${SEVERITY_COLORS[pb.severity_threshold] || SEVERITY_COLORS.low}`}>
                      {pb.severity_threshold}
                    </span>
                  </div>
                  <div className="flex flex-wrap gap-1 mb-3">
                    {pb.mitre_tactics?.map((t, i) => (
                      <span key={i} className="px-1.5 py-0.5 rounded text-[9px] font-mono" style={{ background: 'rgba(147,51,234,0.1)', color: '#A78BFA' }}>
                        {t}
                      </span>
                    ))}
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-mono" style={{ color: 'var(--text-muted)' }}>
                      {pb.steps?.length || 0} steps &middot; {pb.execution_count} runs
                    </span>
                    <div className="flex gap-2">
                      <button onClick={(e) => { e.stopPropagation(); setShowExecute(pb); }}
                        className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-[10px] font-mono font-bold"
                        style={{ background: 'rgba(0,255,136,0.15)', color: 'var(--accent-green)', border: '1px solid rgba(0,255,136,0.3)' }}>
                        <Play className="w-3 h-3" /> Execute
                      </button>
                    </div>
                  </div>

                  <AnimatePresence>
                    {selectedPlaybook?.id === pb.id && pb.steps && (
                      <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }}
                        className="overflow-hidden">
                        <div className="mt-4 pt-4 border-t space-y-2" style={{ borderColor: 'rgba(0,229,255,0.06)' }}>
                          <p className="text-[10px] font-mono font-semibold uppercase mb-2" style={{ color: 'var(--text-muted)' }}>Steps</p>
                          {pb.steps.map((step) => {
                            const StepIcon = STATUS_ICONS[step.type] || Zap;
                            return (
                              <div key={step.index} className="flex items-center gap-3 p-2 rounded-lg" style={{ background: 'rgba(255,255,255,0.02)' }}>
                                <span className="w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-mono font-bold"
                                  style={{ background: 'rgba(0,229,255,0.1)', color: 'var(--accent-cyan)' }}>
                                  {step.index}
                                </span>
                                <span style={{ color: 'var(--accent-cyan)' }}>
                                  <StepIcon className="w-3.5 h-3.5" />
                                </span>
                                <div className="flex-1">
                                  <p className="text-xs font-medium" style={{ color: 'var(--text-primary)' }}>{step.name}</p>
                                  <p className="text-[10px]" style={{ color: 'var(--text-muted)' }}>{step.description}</p>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </motion.div>
              ))}
            </div>
          )}
        </motion.div>
      )}

      {activeTab === 'history' && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
          {loading ? <Skeleton count={5} height={60} /> : executions.length === 0 ? (
            <div className="rounded-xl p-12 text-center" style={{ background: 'rgba(8,20,32,0.7)', border: '1px solid rgba(0,229,255,0.08)' }}>
              <Clock className="w-12 h-12 mx-auto mb-3" style={{ color: 'var(--text-muted)', opacity: 0.3 }} />
              <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>No executions recorded</p>
            </div>
          ) : (
            <div className="rounded-xl overflow-hidden" style={{ background: 'rgba(8,20,32,0.7)', border: '1px solid rgba(0,229,255,0.08)' }}>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b" style={{ borderColor: 'rgba(0,229,255,0.06)' }}>
                      {['Time', 'Playbook', 'Status', 'Duration', 'Actions', 'Triggered By'].map(h => (
                        <th key={h} className="text-left py-3 px-4 font-mono font-medium" style={{ color: 'var(--text-muted)' }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {executions.slice(0, 30).map((ex) => (
                      <tr key={ex.id} className="border-b hover:bg-white/[0.02]" style={{ borderColor: 'rgba(0,229,255,0.03)' }}>
                        <td className="py-2.5 px-4 font-mono" style={{ color: 'var(--text-muted)' }}>
                          {new Date(ex.started_at).toLocaleString('en-US', { hour12: false })}
                        </td>
                        <td className="py-2.5 px-4 font-mono font-medium" style={{ color: 'var(--text-primary)' }}>{ex.playbook_name}</td>
                        <td className="py-2.5 px-4">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${EXEC_STATUS_COLORS[ex.status] || EXEC_STATUS_COLORS.pending}`}>
                            {ex.status}
                          </span>
                        </td>
                        <td className="py-2.5 px-4 font-mono" style={{ color: 'var(--text-secondary)' }}>
                          {ex.duration_seconds ? `${ex.duration_seconds}s` : '-'}
                        </td>
                        <td className="py-2.5 px-4 font-mono" style={{ color: 'var(--text-muted)' }}>
                          {ex.actions_taken?.length || 0} actions
                        </td>
                        <td className="py-2.5 px-4 font-mono" style={{ color: 'var(--accent-cyan)' }}>{ex.triggered_by}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </motion.div>
      )}

      <AnimatePresence>
        {showCreate && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 flex items-center justify-center p-4"
            style={{ background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(4px)' }}>
            <motion.div initial={{ scale: 0.95, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.95, opacity: 0 }}
              className="w-full max-w-md rounded-2xl p-6" style={{ background: 'rgba(8,20,32,0.95)', border: '1px solid rgba(0,229,255,0.15)' }}>
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>Create Playbook</h3>
                <button onClick={() => setShowCreate(false)} style={{ color: 'var(--text-muted)' }}><X className="w-5 h-5" /></button>
              </div>
              <div className="space-y-3">
                <div>
                  <label className="text-[10px] font-mono uppercase mb-1 block" style={{ color: 'var(--text-muted)' }}>Name</label>
                  <input type="text" value={newPlaybook.name} onChange={(e) => setNewPlaybook(p => ({ ...p, name: e.target.value }))}
                    className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-xs font-mono outline-none focus:border-cyan-400/50"
                    style={{ color: 'var(--text-primary)' }} />
                </div>
                <div>
                  <label className="text-[10px] font-mono uppercase mb-1 block" style={{ color: 'var(--text-muted)' }}>Description</label>
                  <textarea value={newPlaybook.description} onChange={(e) => setNewPlaybook(p => ({ ...p, description: e.target.value }))}
                    className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-xs font-mono outline-none focus:border-cyan-400/50 resize-none h-20"
                    style={{ color: 'var(--text-primary)' }} />
                </div>
                <div>
                  <label className="text-[10px] font-mono uppercase mb-1 block" style={{ color: 'var(--text-muted)' }}>Severity Threshold</label>
                  <select value={newPlaybook.severity_threshold} onChange={(e) => setNewPlaybook(p => ({ ...p, severity_threshold: e.target.value }))}
                    className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-xs font-mono outline-none" style={{ color: 'var(--text-primary)' }}>
                    {['low', 'medium', 'high', 'critical'].map(s => <option key={s} value={s}>{s}</option>)}
                  </select>
                </div>
                <div>
                  <label className="text-[10px] font-mono uppercase mb-1 block" style={{ color: 'var(--text-muted)' }}>MITRE Tactics (comma-separated)</label>
                  <input type="text" value={newPlaybook.mitre_tactics} onChange={(e) => setNewPlaybook(p => ({ ...p, mitre_tactics: e.target.value }))}
                    placeholder="e.g. TA0001, TA0002"
                    className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-xs font-mono outline-none focus:border-cyan-400/50"
                    style={{ color: 'var(--text-primary)' }} />
                </div>
              </div>
              <div className="flex justify-end gap-3 mt-5">
                <button onClick={() => setShowCreate(false)} className="px-4 py-2 rounded-lg text-xs font-mono" style={{ color: 'var(--text-muted)' }}>Cancel</button>
                <button onClick={handleCreate} disabled={!newPlaybook.name}
                  className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-mono font-semibold disabled:opacity-50"
                  style={{ background: 'rgba(0,229,255,0.15)', color: 'var(--accent-cyan)', border: '1px solid rgba(0,229,255,0.3)' }}>
                  <Plus className="w-3.5 h-3.5" /> Create
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}

        {showExecute && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 flex items-center justify-center p-4"
            style={{ background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(4px)' }}>
            <motion.div initial={{ scale: 0.95, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.95, opacity: 0 }}
              className="w-full max-w-md rounded-2xl p-6" style={{ background: 'rgba(8,20,32,0.95)', border: '1px solid rgba(0,229,255,0.15)' }}>
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>Execute: {showExecute.name}</h3>
                <button onClick={() => setShowExecute(null)} style={{ color: 'var(--text-muted)' }}><X className="w-5 h-5" /></button>
              </div>
              <div>
                <label className="text-[10px] font-mono uppercase mb-1 block" style={{ color: 'var(--text-muted)' }}>Trigger Data (JSON)</label>
                <textarea value={triggerData} onChange={(e) => setTriggerData(e.target.value)}
                  placeholder='{"source_ip": "192.168.1.100", "severity": "HIGH"}'
                  className="w-full h-32 bg-white/5 border border-white/10 rounded-lg p-3 font-mono text-xs outline-none focus:border-cyan-400/50 resize-none"
                  style={{ color: 'var(--text-primary)' }} />
              </div>
              <div className="flex justify-end gap-3 mt-4">
                <button onClick={() => setShowExecute(null)} className="px-4 py-2 rounded-lg text-xs font-mono" style={{ color: 'var(--text-muted)' }}>Cancel</button>
                <button onClick={handleExecute} disabled={executing}
                  className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-mono font-semibold disabled:opacity-50"
                  style={{ background: 'rgba(0,255,136,0.15)', color: 'var(--accent-green)', border: '1px solid rgba(0,255,136,0.3)' }}>
                  {executing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                  Execute
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
