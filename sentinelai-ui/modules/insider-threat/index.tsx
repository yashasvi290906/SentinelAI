'use client';
import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  User, AlertTriangle, Shield, Plus, X, Loader2, Clock, Eye
} from 'lucide-react';
import GlassCard from '@/components/ui/GlassCard';
import { Skeleton } from '@/components/ui/Skeleton';

interface RiskScore {
  user_id: string;
  username: string;
  risk_score: number;
  risk_level: string;
  anomaly_count: number;
  last_activity: string;
}

interface UserAnomaly {
  id: string;
  user_id: string;
  username: string;
  type: string;
  severity: string;
  confidence: number;
  description: string;
  detected_at: string;
}

interface UserBaseline {
  user_id: string;
  metric_type: string;
  baseline_value: number;
  standard_deviation: number;
  current_value: number;
}

interface InvestigationCase {
  id: string;
  user_id: string;
  username: string;
  status: string;
  risk_level: string;
  assigned_to: string;
  created_at: string;
  notes: string;
}

const RISK_COLORS: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400',
  high: 'bg-orange-500/20 text-orange-400',
  medium: 'bg-yellow-500/20 text-yellow-400',
  low: 'bg-blue-500/20 text-blue-400',
};

const CASE_STATUS_COLORS: Record<string, string> = {
  open: 'bg-red-500/20 text-red-400',
  investigating: 'bg-yellow-500/20 text-yellow-400',
  closed: 'bg-emerald-500/20 text-emerald-400',
  escalated: 'bg-purple-500/20 text-purple-400',
};

export default function InsiderThreatModule() {
  const [riskScores, setRiskScores] = useState<RiskScore[]>([]);
  const [anomalies, setAnomalies] = useState<UserAnomaly[]>([]);
  const [baselines, setBaselines] = useState<UserBaseline[]>([]);
  const [cases, setCases] = useState<InvestigationCase[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'risk' | 'anomalies' | 'baselines' | 'cases'>('risk');
  const [showCreateCase, setShowCreateCase] = useState(false);
  const [newCase, setNewCase] = useState({ user_id: '', risk_level: 'medium', notes: '' });

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [riskRes, anomRes, baseRes, caseRes] = await Promise.all([
        fetch('/api/insider/risk-scores'),
        fetch('/api/insider/anomalies'),
        fetch('/api/insider/baselines'),
        fetch('/api/insider/cases'),
      ]);
      const riskData = await riskRes.json();
      const anomData = await anomRes.json();
      const baseData = await baseRes.json();
      const caseData = await caseRes.json();
      setRiskScores(riskData.risk_scores || []);
      setAnomalies(anomData.anomalies || []);
      setBaselines(baseData.baselines || []);
      setCases(caseData.cases || []);
    } catch {
      console.error('Failed to fetch insider threat data');
    }
    setLoading(false);
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const handleCreateCase = async () => {
    if (!newCase.user_id) return;
    try {
      await fetch('/api/insider/cases', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newCase),
      });
      setShowCreateCase(false);
      setNewCase({ user_id: '', risk_level: 'medium', notes: '' });
      fetchData();
    } catch {
      console.error('Failed to create case');
    }
  };

  const topRisk = [...riskScores].sort((a, b) => b.risk_score - a.risk_score).slice(0, 5);

  return (
    <div className="h-full p-6 lg:p-8 flex flex-col gap-6 overflow-y-auto">
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}>
        <p className="text-[10px] font-mono tracking-[0.3em] uppercase mb-2" style={{ color: 'var(--accent-cyan)' }}>
          User Behavior Analytics
        </p>
        <h1 className="text-3xl font-display font-bold" style={{ color: 'var(--text-primary)' }}>
          Insider Threat Detection
        </h1>
        <p className="text-sm mt-2" style={{ color: 'var(--text-secondary)' }}>
          User and Entity Behavior Analytics for insider threat detection.
        </p>
      </motion.div>

      <div className="flex gap-1 p-1 rounded-xl" style={{ background: 'rgba(8,20,32,0.5)', border: '1px solid rgba(0,229,255,0.06)' }}>
        {([
          { id: 'risk' as const, label: 'Risk Scores', icon: Shield },
          { id: 'anomalies' as const, label: 'Anomalies', icon: AlertTriangle },
          { id: 'baselines' as const, label: 'Baselines', icon: Eye },
          { id: 'cases' as const, label: 'Cases', icon: User },
        ]).map((tab) => (
          <button key={tab.id} onClick={() => setActiveTab(tab.id)}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg text-xs font-mono font-semibold transition-all flex-1 justify-center"
            style={{
              background: activeTab === tab.id ? 'rgba(0,229,255,0.1)' : 'transparent',
              color: activeTab === tab.id ? 'var(--accent-cyan)' : 'var(--text-muted)',
              border: activeTab === tab.id ? '1px solid rgba(0,229,255,0.15)' : '1px solid transparent',
            }}>
            <tab.icon className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">{tab.label}</span>
          </button>
        ))}
      </div>

      {loading ? (
        <Skeleton count={6} height={80} />
      ) : (
        <AnimatePresence mode="wait">
          <motion.div key={activeTab} initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="flex flex-col gap-4">

            {activeTab === 'risk' && (
              <>
                <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
                  {topRisk.map((user, i) => (
                    <motion.div key={user.user_id} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}
                      className="rounded-xl p-4" style={{ background: 'rgba(8,20,32,0.7)', backdropFilter: 'blur(24px)', border: '1px solid rgba(0,229,255,0.08)' }}>
                      <div className="flex items-center gap-2 mb-2">
                        <div className="w-8 h-8 rounded-full flex items-center justify-center text-xs font-mono font-bold"
                          style={{ background: 'rgba(0,229,255,0.1)', color: 'var(--accent-cyan)' }}>
                          {user.username?.charAt(0)?.toUpperCase() || '?'}
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium truncate" style={{ color: 'var(--text-primary)' }}>{user.username}</p>
                          <p className="text-[10px] font-mono" style={{ color: 'var(--text-muted)' }}>{user.anomaly_count} anomalies</p>
                        </div>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${RISK_COLORS[user.risk_level] || RISK_COLORS.low}`}>
                          {user.risk_level}
                        </span>
                        <span className="text-lg font-display font-bold" style={{
                          color: user.risk_score >= 80 ? 'var(--accent-red)' : user.risk_score >= 50 ? 'var(--accent-amber)' : 'var(--accent-green)'
                        }}>
                          {Math.round(user.risk_score)}
                        </span>
                      </div>
                      <div className="mt-2 h-1.5 rounded-full overflow-hidden" style={{ background: 'rgba(255,255,255,0.05)' }}>
                        <motion.div className="h-full rounded-full"
                          style={{
                            background: user.risk_score >= 80 ? 'var(--accent-red)' : user.risk_score >= 50 ? 'var(--accent-amber)' : 'var(--accent-green)'
                          }}
                          initial={{ width: 0 }} animate={{ width: `${user.risk_score}%` }} transition={{ duration: 0.5, delay: i * 0.05 }} />
                      </div>
                    </motion.div>
                  ))}
                  {topRisk.length === 0 && (
                    <div className="col-span-5 rounded-xl p-12 text-center" style={{ background: 'rgba(8,20,32,0.7)', border: '1px solid rgba(0,229,255,0.08)' }}>
                      <Shield className="w-12 h-12 mx-auto mb-3" style={{ color: 'var(--text-muted)', opacity: 0.3 }} />
                      <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>No risk scores available</p>
                    </div>
                  )}
                </div>

                <div className="rounded-xl overflow-hidden" style={{ background: 'rgba(8,20,32,0.7)', border: '1px solid rgba(0,229,255,0.08)' }}>
                  <div className="px-5 py-3 border-b" style={{ borderColor: 'rgba(0,229,255,0.06)' }}>
                    <h3 className="text-xs font-mono font-semibold" style={{ color: 'var(--text-muted)' }}>ALL USERS ({riskScores.length})</h3>
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="border-b" style={{ borderColor: 'rgba(0,229,255,0.06)' }}>
                          {['User', 'Risk Score', 'Level', 'Anomalies', 'Last Activity'].map(h => (
                            <th key={h} className="text-left py-3 px-4 font-mono font-medium" style={{ color: 'var(--text-muted)' }}>{h}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {[...riskScores].sort((a, b) => b.risk_score - a.risk_score).map((u) => (
                          <tr key={u.user_id} className="border-b hover:bg-white/[0.02]" style={{ borderColor: 'rgba(0,229,255,0.03)' }}>
                            <td className="py-2.5 px-4 font-mono" style={{ color: 'var(--text-primary)' }}>{u.username}</td>
                            <td className="py-2.5 px-4">
                              <span className="font-mono font-bold" style={{
                                color: u.risk_score >= 80 ? 'var(--accent-red)' : u.risk_score >= 50 ? 'var(--accent-amber)' : 'var(--accent-green)'
                              }}>{Math.round(u.risk_score)}</span>
                            </td>
                            <td className="py-2.5 px-4">
                              <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${RISK_COLORS[u.risk_level] || RISK_COLORS.low}`}>
                                {u.risk_level}
                              </span>
                            </td>
                            <td className="py-2.5 px-4 font-mono" style={{ color: 'var(--text-secondary)' }}>{u.anomaly_count}</td>
                            <td className="py-2.5 px-4 font-mono text-[10px]" style={{ color: 'var(--text-muted)' }}>
                              {u.last_activity ? new Date(u.last_activity).toLocaleString('en-US', { hour12: false }) : 'N/A'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </>
            )}

            {activeTab === 'anomalies' && (
              <div className="space-y-2">
                {anomalies.length === 0 ? (
                  <div className="rounded-xl p-12 text-center" style={{ background: 'rgba(8,20,32,0.7)', border: '1px solid rgba(0,229,255,0.08)' }}>
                    <AlertTriangle className="w-12 h-12 mx-auto mb-3" style={{ color: 'var(--text-muted)', opacity: 0.3 }} />
                    <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>No anomalies detected</p>
                  </div>
                ) : (
                  anomalies.map((a) => (
                    <motion.div key={a.id} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
                      className="rounded-xl p-4" style={{ background: 'rgba(8,20,32,0.7)', backdropFilter: 'blur(24px)', border: '1px solid rgba(0,229,255,0.08)' }}>
                      <div className="flex items-center gap-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${SEVERITY_COLORS[a.severity] || SEVERITY_COLORS.low}`}>
                          {a.severity}
                        </span>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{a.username}</span>
                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded" style={{ background: 'rgba(255,255,255,0.05)', color: 'var(--text-muted)' }}>
                              {a.type}
                            </span>
                          </div>
                          <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-muted)' }}>{a.description}</p>
                        </div>
                        <div className="text-right shrink-0">
                          <p className="text-xs font-mono" style={{ color: 'var(--accent-cyan)' }}>{(a.confidence * 100).toFixed(0)}%</p>
                          <p className="text-[10px] font-mono mt-0.5" style={{ color: 'var(--text-muted)' }}>
                            {new Date(a.detected_at).toLocaleTimeString('en-US', { hour12: false })}
                          </p>
                        </div>
                      </div>
                    </motion.div>
                  ))
                )}
              </div>
            )}

            {activeTab === 'baselines' && (
              <div className="rounded-xl overflow-hidden" style={{ background: 'rgba(8,20,32,0.7)', border: '1px solid rgba(0,229,255,0.08)' }}>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b" style={{ borderColor: 'rgba(0,229,255,0.06)' }}>
                        {['User', 'Metric', 'Baseline', 'Std Dev', 'Current', 'Deviation'].map(h => (
                          <th key={h} className="text-left py-3 px-4 font-mono font-medium" style={{ color: 'var(--text-muted)' }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {baselines.length === 0 ? (
                        <tr><td colSpan={6} className="py-8 text-center" style={{ color: 'var(--text-muted)' }}>No baseline data available</td></tr>
                      ) : baselines.map((b, i) => {
                        const deviation = b.standard_deviation > 0
                          ? Math.abs(b.current_value - b.baseline_value) / b.standard_deviation
                          : 0;
                        return (
                          <tr key={`${b.user_id}-${b.metric_type}-${i}`} className="border-b hover:bg-white/[0.02]" style={{ borderColor: 'rgba(0,229,255,0.03)' }}>
                            <td className="py-2.5 px-4 font-mono" style={{ color: 'var(--text-primary)' }}>{b.user_id}</td>
                            <td className="py-2.5 px-4 font-mono" style={{ color: 'var(--accent-cyan)' }}>{b.metric_type}</td>
                            <td className="py-2.5 px-4 font-mono" style={{ color: 'var(--text-secondary)' }}>{b.baseline_value.toFixed(2)}</td>
                            <td className="py-2.5 px-4 font-mono" style={{ color: 'var(--text-muted)' }}>{b.standard_deviation.toFixed(2)}</td>
                            <td className="py-2.5 px-4 font-mono" style={{ color: 'var(--text-primary)' }}>{b.current_value.toFixed(2)}</td>
                            <td className="py-2.5 px-4">
                              <span className={`font-mono font-bold ${
                                deviation > 3 ? 'text-red-400' : deviation > 2 ? 'text-amber-400' : 'text-emerald-400'
                              }`}>
                                {deviation.toFixed(1)}σ
                              </span>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {activeTab === 'cases' && (
              <>
                <div className="flex justify-end">
                  <button onClick={() => setShowCreateCase(true)}
                    className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-mono font-semibold"
                    style={{ background: 'rgba(0,229,255,0.1)', color: 'var(--accent-cyan)', border: '1px solid rgba(0,229,255,0.2)' }}>
                    <Plus className="w-3.5 h-3.5" /> Create Case
                  </button>
                </div>
                <div className="space-y-2">
                  {cases.length === 0 ? (
                    <div className="rounded-xl p-12 text-center" style={{ background: 'rgba(8,20,32,0.7)', border: '1px solid rgba(0,229,255,0.08)' }}>
                      <User className="w-12 h-12 mx-auto mb-3" style={{ color: 'var(--text-muted)', opacity: 0.3 }} />
                      <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>No investigation cases</p>
                    </div>
                  ) : (
                    cases.map((c) => (
                      <motion.div key={c.id} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
                        className="rounded-xl p-4" style={{ background: 'rgba(8,20,32,0.7)', backdropFilter: 'blur(24px)', border: '1px solid rgba(0,229,255,0.08)' }}>
                        <div className="flex items-center gap-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${RISK_COLORS[c.risk_level] || RISK_COLORS.low}`}>
                            {c.risk_level}
                          </span>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{c.username}</p>
                              <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${CASE_STATUS_COLORS[c.status] || CASE_STATUS_COLORS.open}`}>
                                {c.status}
                              </span>
                            </div>
                            <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-muted)' }}>{c.notes || 'No notes'}</p>
                          </div>
                          <div className="text-right shrink-0">
                            <p className="text-[10px]" style={{ color: 'var(--text-muted)' }}>Assigned to</p>
                            <p className="text-xs font-mono" style={{ color: 'var(--accent-cyan)' }}>{c.assigned_to || 'Unassigned'}</p>
                            <p className="text-[10px] font-mono mt-0.5" style={{ color: 'var(--text-muted)' }}>
                              {new Date(c.created_at).toLocaleDateString()}
                            </p>
                          </div>
                        </div>
                      </motion.div>
                    ))
                  )}
                </div>
              </>
            )}
          </motion.div>
        </AnimatePresence>
      )}

      <AnimatePresence>
        {showCreateCase && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 flex items-center justify-center p-4"
            style={{ background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(4px)' }}>
            <motion.div initial={{ scale: 0.95, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.95, opacity: 0 }}
              className="w-full max-w-md rounded-2xl p-6" style={{ background: 'rgba(8,20,32,0.95)', border: '1px solid rgba(0,229,255,0.15)' }}>
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>Create Investigation Case</h3>
                <button onClick={() => setShowCreateCase(false)} style={{ color: 'var(--text-muted)' }}><X className="w-5 h-5" /></button>
              </div>
              <div className="space-y-3">
                <div>
                  <label className="text-[10px] font-mono uppercase mb-1 block" style={{ color: 'var(--text-muted)' }}>User ID</label>
                  <input type="text" value={newCase.user_id} onChange={(e) => setNewCase(c => ({ ...c, user_id: e.target.value }))}
                    className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-xs font-mono outline-none focus:border-cyan-400/50"
                    style={{ color: 'var(--text-primary)' }} />
                </div>
                <div>
                  <label className="text-[10px] font-mono uppercase mb-1 block" style={{ color: 'var(--text-muted)' }}>Risk Level</label>
                  <select value={newCase.risk_level} onChange={(e) => setNewCase(c => ({ ...c, risk_level: e.target.value }))}
                    className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-xs font-mono outline-none" style={{ color: 'var(--text-primary)' }}>
                    {['low', 'medium', 'high', 'critical'].map(s => <option key={s} value={s}>{s}</option>)}
                  </select>
                </div>
                <div>
                  <label className="text-[10px] font-mono uppercase mb-1 block" style={{ color: 'var(--text-muted)' }}>Notes</label>
                  <textarea value={newCase.notes} onChange={(e) => setNewCase(c => ({ ...c, notes: e.target.value }))}
                    className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-xs font-mono outline-none focus:border-cyan-400/50 resize-none h-20"
                    style={{ color: 'var(--text-primary)' }} />
                </div>
              </div>
              <div className="flex justify-end gap-3 mt-5">
                <button onClick={() => setShowCreateCase(false)} className="px-4 py-2 rounded-lg text-xs font-mono" style={{ color: 'var(--text-muted)' }}>Cancel</button>
                <button onClick={handleCreateCase} disabled={!newCase.user_id}
                  className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-mono font-semibold disabled:opacity-50"
                  style={{ background: 'rgba(0,229,255,0.15)', color: 'var(--accent-cyan)', border: '1px solid rgba(0,229,255,0.3)' }}>
                  <Plus className="w-3.5 h-3.5" /> Create
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
