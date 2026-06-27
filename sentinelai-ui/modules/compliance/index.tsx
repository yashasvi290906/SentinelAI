'use client';
import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield, CheckCircle, XCircle, AlertTriangle, RefreshCw,
  FileText, TrendingUp, BarChart3, Loader2, ChevronDown, ChevronUp
} from 'lucide-react';
import GlassCard from '@/components/ui/GlassCard';
import { Skeleton } from '@/components/ui/Skeleton';
import { fetchWithAuth } from "@/lib/api";

interface ComplianceScore {
  overall_score: number;
  total_controls: number;
  implemented: number;
  partial: number;
  not_implemented: number;
  not_assessed: number;
}

interface ControlFamily {
  family_id: string;
  family_name: string;
  score: number;
  total: number;
  implemented: number;
  partial: number;
}

interface ComplianceControl {
  control_id: string;
  title: string;
  family: string;
  status: string;
  last_assessed: string;
  description: string;
}

interface ComplianceGap {
  control_id: string;
  title: string;
  status: string;
  risk_level: string;
  remediation: string;
  family: string;
}

interface Assessment {
  id: string;
  started_at: string;
  completed_at: string;
  score: number;
  controls_assessed: number;
  status: string;
}

const STATUS_COLORS: Record<string, string> = {
  implemented: 'bg-emerald-500/20 text-emerald-400',
  partial: 'bg-yellow-500/20 text-yellow-400',
  not_implemented: 'bg-red-500/20 text-red-400',
  not_assessed: 'bg-white/10 text-white/40',
};

const RISK_COLORS: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
};

function ScoreGauge({ score }: { score: number }) {
  const circumference = 2 * Math.PI * 54;
  const offset = circumference - (score / 100) * circumference;
  const color = score >= 80 ? 'var(--accent-green)' : score >= 60 ? 'var(--accent-amber)' : 'var(--accent-red)';
  return (
    <div className="relative w-36 h-36">
      <svg className="w-full h-full -rotate-90" viewBox="0 0 120 120">
        <circle cx="60" cy="60" r="54" fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="8" />
        <motion.circle cx="60" cy="60" r="54" fill="none" stroke={color} strokeWidth="8" strokeLinecap="round"
          strokeDasharray={circumference} initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: offset }} transition={{ duration: 1, ease: 'easeOut' }} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <p className="text-3xl font-display font-bold" style={{ color }}>{Math.round(score)}%</p>
        <p className="text-[10px] font-mono" style={{ color: 'var(--text-muted)' }}>Compliance</p>
      </div>
    </div>
  );
}

export default function ComplianceModule() {
  const [score, setScore] = useState<ComplianceScore | null>(null);
  const [families, setFamilies] = useState<ControlFamily[]>([]);
  const [controls, setControls] = useState<ComplianceControl[]>([]);
  const [gaps, setGaps] = useState<ComplianceGap[]>([]);
  const [assessments, setAssessments] = useState<Assessment[]>([]);
  const [loading, setLoading] = useState(true);
  const [assessing, setAssessing] = useState(false);
  const [activeTab, setActiveTab] = useState<'overview' | 'controls' | 'gaps' | 'history'>('overview');
  const [expandedControl, setExpandedControl] = useState<string | null>(null);
  const [filterStatus, setFilterStatus] = useState('');

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [scoreRes, famRes, ctrlRes, gapsRes, assessRes] = await Promise.all([
        fetchWithAuth('/api/compliance/score'),
        fetchWithAuth('/api/compliance/controls'),
        fetchWithAuth('/api/compliance/controls'),
        fetchWithAuth('/api/compliance/gaps'),
        fetchWithAuth('/api/compliance/assessments'),
      ]);
      const scoreData = await scoreRes.json();
      const famData = await famRes.json();
      const ctrlData = await ctrlRes.json();
      const gapsData = await gapsRes.json();
      const assessData = await assessRes.json();
      setScore(scoreData);
      setFamilies(famData.families || []);
      setControls(ctrlData.controls || []);
      setGaps(gapsData.gaps || []);
      setAssessments(assessData.assessments || []);
    } catch {
      console.error('Failed to fetch compliance data');
    }
    setLoading(false);
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const runAssessment = async () => {
    setAssessing(true);
    try {
      await fetchWithAuth('/api/compliance/assess', { method: 'POST' });
      fetchData();
    } catch {
      console.error('Failed to run assessment');
    }
    setAssessing(false);
  };

  const filteredControls = controls.filter(c => !filterStatus || c.status === filterStatus);

  return (
    <div className="h-full p-6 lg:p-8 flex flex-col gap-6 overflow-y-auto">
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}>
        <p className="text-[10px] font-mono tracking-[0.3em] uppercase mb-2" style={{ color: 'var(--accent-cyan)' }}>
          Compliance Management
        </p>
        <h1 className="text-3xl font-display font-bold" style={{ color: 'var(--text-primary)' }}>
          NIST 800-53 Compliance
        </h1>
        <p className="text-sm mt-2" style={{ color: 'var(--text-secondary)' }}>
          Track and maintain compliance with NIST SP 800-53 security controls.
        </p>
      </motion.div>

      <div className="flex gap-1 p-1 rounded-xl" style={{ background: 'rgba(8,20,32,0.5)', border: '1px solid rgba(0,229,255,0.06)' }}>
        {(['overview', 'controls', 'gaps', 'history'] as const).map((tab) => (
          <button key={tab} onClick={() => setActiveTab(tab)}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg text-xs font-mono font-semibold transition-all flex-1 justify-center"
            style={{
              background: activeTab === tab ? 'rgba(0,229,255,0.1)' : 'transparent',
              color: activeTab === tab ? 'var(--accent-cyan)' : 'var(--text-muted)',
              border: activeTab === tab ? '1px solid rgba(0,229,255,0.15)' : '1px solid transparent',
            }}>
            {tab === 'overview' && <BarChart3 className="w-3.5 h-3.5" />}
            {tab === 'controls' && <Shield className="w-3.5 h-3.5" />}
            {tab === 'gaps' && <AlertTriangle className="w-3.5 h-3.5" />}
            {tab === 'history' && <FileText className="w-3.5 h-3.5" />}
            <span className="hidden sm:inline">{tab.charAt(0).toUpperCase() + tab.slice(1)}</span>
          </button>
        ))}
      </div>

      {loading ? (
        <Skeleton count={6} height={80} />
      ) : (
        <AnimatePresence mode="wait">
          <motion.div key={activeTab} initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="flex flex-col gap-4">

            {activeTab === 'overview' && score && (
              <>
                <div className="flex flex-col md:flex-row gap-6 items-center">
                  <div className="rounded-xl p-6 flex items-center justify-center" style={{ background: 'rgba(8,20,32,0.7)', border: '1px solid rgba(0,229,255,0.08)' }}>
                    <ScoreGauge score={score.overall_score} />
                  </div>
                  <div className="flex-1 grid grid-cols-2 md:grid-cols-4 gap-3">
                    {[
                      { label: 'Implemented', value: score.implemented, color: 'var(--accent-green)' },
                      { label: 'Partial', value: score.partial, color: 'var(--accent-amber)' },
                      { label: 'Not Implemented', value: score.not_implemented, color: 'var(--accent-red)' },
                      { label: 'Not Assessed', value: score.not_assessed, color: 'var(--text-muted)' },
                    ].map((s) => (
                      <div key={s.label} className="rounded-xl p-4" style={{ background: 'rgba(8,20,32,0.7)', border: '1px solid rgba(0,229,255,0.08)' }}>
                        <p className="text-[10px] font-mono tracking-wider uppercase" style={{ color: 'var(--text-muted)' }}>{s.label}</p>
                        <p className="text-2xl font-display font-bold mt-1" style={{ color: s.color }}>{s.value}</p>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="rounded-xl p-5" style={{ background: 'rgba(8,20,32,0.7)', border: '1px solid rgba(0,229,255,0.08)' }}>
                  <h3 className="text-sm font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>Control Family Breakdown</h3>
                  <div className="space-y-3">
                    {families.map((fam) => (
                      <div key={fam.family_id} className="flex items-center gap-3">
                        <span className="w-8 text-xs font-mono font-bold" style={{ color: 'var(--accent-cyan)' }}>{fam.family_id}</span>
                        <span className="text-xs w-48 truncate" style={{ color: 'var(--text-secondary)' }}>{fam.family_name}</span>
                        <div className="flex-1 h-2 rounded-full overflow-hidden" style={{ background: 'rgba(255,255,255,0.05)' }}>
                          <motion.div className="h-full rounded-full"
                            style={{ background: fam.score >= 80 ? 'var(--accent-green)' : fam.score >= 60 ? 'var(--accent-amber)' : 'var(--accent-red)' }}
                            initial={{ width: 0 }} animate={{ width: `${fam.score}%` }} transition={{ duration: 0.5 }} />
                        </div>
                        <span className="text-xs font-mono w-10 text-right" style={{ color: 'var(--text-secondary)' }}>{Math.round(fam.score)}%</span>
                        <span className="text-[10px] font-mono w-16 text-right" style={{ color: 'var(--text-muted)' }}>
                          {fam.implemented}/{fam.total}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="flex justify-end">
                  <button onClick={runAssessment} disabled={assessing}
                    className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-mono font-semibold disabled:opacity-50"
                    style={{ background: 'rgba(0,229,255,0.1)', color: 'var(--accent-cyan)', border: '1px solid rgba(0,229,255,0.2)' }}>
                    {assessing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
                    Run Assessment
                  </button>
                </div>
              </>
            )}

            {activeTab === 'controls' && (
              <>
                <div className="flex items-center gap-3">
                  <select value={filterStatus} onChange={(e) => setFilterStatus(e.target.value)}
                    className="bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-xs font-mono outline-none" style={{ color: 'var(--text-secondary)' }}>
                    <option value="">All Statuses</option>
                    {['implemented', 'partial', 'not_implemented', 'not_assessed'].map(s => (
                      <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>
                    ))}
                  </select>
                  <span className="text-[10px] font-mono" style={{ color: 'var(--text-muted)' }}>{filteredControls.length} controls</span>
                </div>
                <div className="space-y-2">
                  {filteredControls.map((ctrl) => (
                    <motion.div key={ctrl.control_id} layout
                      className="rounded-xl p-4" style={{ background: 'rgba(8,20,32,0.7)', backdropFilter: 'blur(24px)', border: '1px solid rgba(0,229,255,0.08)' }}>
                      <div className="flex items-center gap-3 cursor-pointer" onClick={() => setExpandedControl(expandedControl === ctrl.control_id ? null : ctrl.control_id)}>
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono" style={{ background: 'rgba(0,229,255,0.1)', color: 'var(--accent-cyan)' }}>
                          {ctrl.control_id}
                        </span>
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium truncate" style={{ color: 'var(--text-primary)' }}>{ctrl.title}</p>
                          <p className="text-[10px] font-mono" style={{ color: 'var(--text-muted)' }}>{ctrl.family}</p>
                        </div>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${STATUS_COLORS[ctrl.status] || STATUS_COLORS.not_assessed}`}>
                          {ctrl.status?.replace(/_/g, ' ')}
                        </span>
                        {expandedControl === ctrl.control_id ? <ChevronUp className="w-4 h-4" style={{ color: 'var(--text-muted)' }} /> : <ChevronDown className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />}
                      </div>
                      <AnimatePresence>
                        {expandedControl === ctrl.control_id && (
                          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }}
                            className="overflow-hidden">
                            <div className="mt-3 pt-3 border-t" style={{ borderColor: 'rgba(0,229,255,0.06)' }}>
                              <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>{ctrl.description}</p>
                              <p className="text-[10px] font-mono mt-2" style={{ color: 'var(--text-muted)' }}>
                                Last assessed: {ctrl.last_assessed ? new Date(ctrl.last_assessed).toLocaleDateString() : 'Never'}
                              </p>
                            </div>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </motion.div>
                  ))}
                </div>
              </>
            )}

            {activeTab === 'gaps' && (
              <div className="space-y-2">
                {gaps.length === 0 ? (
                  <div className="rounded-xl p-12 text-center" style={{ background: 'rgba(8,20,32,0.7)', border: '1px solid rgba(0,229,255,0.08)' }}>
                    <CheckCircle className="w-12 h-12 mx-auto mb-3" style={{ color: 'var(--accent-green)', opacity: 0.3 }} />
                    <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>No compliance gaps found</p>
                  </div>
                ) : (
                  gaps.map((gap) => (
                    <motion.div key={gap.control_id} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
                      className="rounded-xl p-4" style={{ background: 'rgba(8,20,32,0.7)', backdropFilter: 'blur(24px)', border: '1px solid rgba(0,229,255,0.08)' }}>
                      <div className="flex items-start gap-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${RISK_COLORS[gap.risk_level] || RISK_COLORS.low}`}>
                          {gap.risk_level}
                        </span>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-[10px] font-mono font-bold" style={{ color: 'var(--accent-cyan)' }}>{gap.control_id}</span>
                            <p className="text-sm font-medium truncate" style={{ color: 'var(--text-primary)' }}>{gap.title}</p>
                          </div>
                          <p className="text-xs mt-1" style={{ color: 'var(--text-secondary)' }}>{gap.remediation}</p>
                          <span className="text-[10px] font-mono mt-1 inline-block" style={{ color: 'var(--text-muted)' }}>{gap.family}</span>
                        </div>
                      </div>
                    </motion.div>
                  ))
                )}
              </div>
            )}

            {activeTab === 'history' && (
              <div className="rounded-xl overflow-hidden" style={{ background: 'rgba(8,20,32,0.7)', border: '1px solid rgba(0,229,255,0.08)' }}>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b" style={{ borderColor: 'rgba(0,229,255,0.06)' }}>
                        {['Date', 'Score', 'Controls', 'Status', 'Duration'].map(h => (
                          <th key={h} className="text-left py-3 px-4 font-mono font-medium" style={{ color: 'var(--text-muted)' }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {assessments.length === 0 ? (
                        <tr><td colSpan={5} className="py-8 text-center" style={{ color: 'var(--text-muted)' }}>No assessments run yet</td></tr>
                      ) : assessments.map((a) => (
                        <tr key={a.id} className="border-b hover:bg-white/[0.02]" style={{ borderColor: 'rgba(0,229,255,0.03)' }}>
                          <td className="py-2.5 px-4 font-mono" style={{ color: 'var(--text-secondary)' }}>
                            {new Date(a.started_at).toLocaleDateString()}
                          </td>
                          <td className="py-2.5 px-4">
                            <span className={`font-mono font-bold ${a.score >= 80 ? 'text-emerald-400' : a.score >= 60 ? 'text-amber-400' : 'text-red-400'}`}>
                              {Math.round(a.score)}%
                            </span>
                          </td>
                          <td className="py-2.5 px-4 font-mono" style={{ color: 'var(--text-muted)' }}>{a.controls_assessed}</td>
                          <td className="py-2.5 px-4">
                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${a.status === 'completed' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-yellow-500/20 text-yellow-400'}`}>
                              {a.status}
                            </span>
                          </td>
                          <td className="py-2.5 px-4 font-mono" style={{ color: 'var(--text-muted)' }}>
                            {a.completed_at ? `${((new Date(a.completed_at).getTime() - new Date(a.started_at).getTime()) / 1000).toFixed(0)}s` : '-'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </motion.div>
        </AnimatePresence>
      )}
    </div>
  );
}
