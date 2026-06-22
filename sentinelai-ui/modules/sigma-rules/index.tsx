'use client';
import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield, Search, Filter, Upload, X, Loader2, CheckCircle,
  AlertTriangle, ChevronDown, ChevronUp, FileText, ExternalLink
} from 'lucide-react';
import GlassCard from '@/components/ui/GlassCard';
import { Skeleton } from '@/components/ui/Skeleton';

interface SigmaRule {
  id: string;
  title: string;
  level: string;
  product: string;
  mitre_technique: string;
  mitre_tactic: string;
  status: string;
  match_count: number;
  description: string;
  condition: string;
  logsource: string;
  created_at: string;
}

interface SigmaMatch {
  id: string;
  rule_id: string;
  rule_title: string;
  level: string;
  source_ip: string;
  matched_field: string;
  matched_value: string;
  timestamp: string;
}

interface SigmaStats {
  total_rules: number;
  by_level: Record<string, number>;
  by_status: Record<string, number>;
  total_matches: number;
}

const LEVEL_COLORS: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  information: 'bg-white/5 text-white/50 border-white/10',
};

const STATUS_COLORS: Record<string, string> = {
  enabled: 'bg-emerald-500/20 text-emerald-400',
  disabled: 'bg-white/10 text-white/40',
  draft: 'bg-yellow-500/20 text-yellow-400',
};

export default function SigmaRulesModule() {
  const [rules, setRules] = useState<SigmaRule[]>([]);
  const [stats, setStats] = useState<SigmaStats | null>(null);
  const [matches, setMatches] = useState<SigmaMatch[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [filterLevel, setFilterLevel] = useState('');
  const [filterProduct, setFilterProduct] = useState('');
  const [showImport, setShowImport] = useState(false);
  const [importYaml, setImportYaml] = useState('');
  const [importing, setImporting] = useState(false);
  const [activeTab, setActiveTab] = useState<'rules' | 'matches'>('rules');

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [rulesRes, statsRes, matchesRes] = await Promise.all([
        fetch('/api/sigma/rules'),
        fetch('/api/sigma/stats'),
        fetch('/api/sigma/matches'),
      ]);
      const rulesData = await rulesRes.json();
      const statsData = await statsRes.json();
      const matchesData = await matchesRes.json();
      setRules(rulesData.rules || []);
      setStats(statsData);
      setMatches(matchesData.matches || []);
    } catch {
      console.error('Failed to fetch sigma data');
    }
    setLoading(false);
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const filteredRules = rules.filter((r) => {
    if (search && !r.title.toLowerCase().includes(search.toLowerCase()) && !r.description.toLowerCase().includes(search.toLowerCase())) return false;
    if (filterLevel && r.level !== filterLevel) return false;
    if (filterProduct && r.product !== filterProduct) return false;
    return true;
  });

  const uniqueProducts = [...new Set(rules.map(r => r.product))].sort();

  const handleImport = async () => {
    if (!importYaml.trim()) return;
    setImporting(true);
    try {
      await fetch('/api/sigma/rules/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ yaml: importYaml }),
      });
      setImportYaml('');
      setShowImport(false);
      fetchData();
    } catch {
      console.error('Failed to import rule');
    }
    setImporting(false);
  };

  return (
    <div className="h-full p-6 lg:p-8 flex flex-col gap-6 overflow-y-auto">
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}>
        <p className="text-[10px] font-mono tracking-[0.3em] uppercase mb-2" style={{ color: 'var(--accent-cyan)' }}>
          Detection Engineering
        </p>
        <h1 className="text-3xl font-display font-bold" style={{ color: 'var(--text-primary)' }}>
          Sigma Detection Rules
        </h1>
        <p className="text-sm mt-2" style={{ color: 'var(--text-secondary)' }}>
          Manage and monitor Sigma detection rules across all log sources.
        </p>
      </motion.div>

      {stats && (
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
          className="grid grid-cols-2 md:grid-cols-6 gap-3">
          {[
            { label: 'Total Rules', value: stats.total_rules, color: 'var(--accent-cyan)' },
            { label: 'Critical', value: stats.by_level?.critical || 0, color: 'var(--accent-red)' },
            { label: 'High', value: stats.by_level?.high || 0, color: '#FF6B35' },
            { label: 'Medium', value: stats.by_level?.medium || 0, color: 'var(--accent-amber)' },
            { label: 'Low', value: stats.by_level?.low || 0, color: '#60A5FA' },
            { label: 'Total Matches', value: stats.total_matches, color: 'var(--accent-green)' },
          ].map((s) => (
            <div key={s.label} className="rounded-xl p-4" style={{ background: 'rgba(8,20,32,0.7)', backdropFilter: 'blur(24px)', border: '1px solid rgba(0,229,255,0.08)' }}>
              <p className="text-[10px] font-mono tracking-wider uppercase" style={{ color: 'var(--text-muted)' }}>{s.label}</p>
              <p className="text-2xl font-display font-bold mt-1" style={{ color: s.color }}>{s.value}</p>
            </div>
          ))}
        </motion.div>
      )}

      <div className="flex gap-1 p-1 rounded-xl" style={{ background: 'rgba(8,20,32,0.5)', border: '1px solid rgba(0,229,255,0.06)' }}>
        {(['rules', 'matches'] as const).map((tab) => (
          <button key={tab} onClick={() => setActiveTab(tab)}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg text-xs font-mono font-semibold transition-all flex-1 justify-center"
            style={{
              background: activeTab === tab ? 'rgba(0,229,255,0.1)' : 'transparent',
              color: activeTab === tab ? 'var(--accent-cyan)' : 'var(--text-muted)',
              border: activeTab === tab ? '1px solid rgba(0,229,255,0.15)' : '1px solid transparent',
            }}>
            {tab === 'rules' ? <Shield className="w-3.5 h-3.5" /> : <FileText className="w-3.5 h-3.5" />}
            <span className="hidden sm:inline">{tab === 'rules' ? 'Detection Rules' : 'Match History'}</span>
          </button>
        ))}
      </div>

      {activeTab === 'rules' && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex flex-col gap-4">
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-2 px-3 py-2 rounded-xl flex-1 min-w-[200px]" style={{ background: 'rgba(8,20,32,0.7)', border: '1px solid rgba(0,229,255,0.08)' }}>
              <Search className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />
              <input type="text" placeholder="Search rules..." value={search} onChange={(e) => setSearch(e.target.value)}
                className="flex-1 bg-transparent outline-none text-xs font-mono" style={{ color: 'var(--text-primary)' }} />
            </div>
            <select value={filterLevel} onChange={(e) => setFilterLevel(e.target.value)}
              className="bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-xs font-mono outline-none" style={{ color: 'var(--text-secondary)' }}>
              <option value="">All Levels</option>
              {['critical', 'high', 'medium', 'low', 'information'].map(l => <option key={l} value={l}>{l}</option>)}
            </select>
            <select value={filterProduct} onChange={(e) => setFilterProduct(e.target.value)}
              className="bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-xs font-mono outline-none" style={{ color: 'var(--text-secondary)' }}>
              <option value="">All Products</option>
              {uniqueProducts.map(p => <option key={p} value={p}>{p}</option>)}
            </select>
            <button onClick={() => setShowImport(true)}
              className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-mono font-semibold transition-all"
              style={{ background: 'rgba(0,229,255,0.1)', color: 'var(--accent-cyan)', border: '1px solid rgba(0,229,255,0.2)' }}>
              <Upload className="w-3.5 h-3.5" /> Import YAML
            </button>
          </div>

          {loading ? (
            <Skeleton count={5} height={80} />
          ) : filteredRules.length === 0 ? (
            <div className="rounded-xl p-12 text-center" style={{ background: 'rgba(8,20,32,0.7)', border: '1px solid rgba(0,229,255,0.08)' }}>
              <Shield className="w-12 h-12 mx-auto mb-3" style={{ color: 'var(--text-muted)', opacity: 0.3 }} />
              <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>No rules found</p>
              <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>Import Sigma YAML rules to get started</p>
            </div>
          ) : (
            <div className="space-y-2">
              <AnimatePresence>
                {filteredRules.map((rule) => (
                  <motion.div key={rule.id} layout initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
                    className="rounded-xl p-4" style={{ background: 'rgba(8,20,32,0.7)', backdropFilter: 'blur(24px)', border: '1px solid rgba(0,229,255,0.08)' }}>
                    <div className="flex items-center gap-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${LEVEL_COLORS[rule.level] || LEVEL_COLORS.information}`}>
                        {rule.level}
                      </span>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium truncate" style={{ color: 'var(--text-primary)' }}>{rule.title}</p>
                        <div className="flex items-center gap-3 mt-1">
                          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded" style={{ background: 'rgba(147,51,234,0.1)', color: '#A78BFA' }}>
                            {rule.mitre_technique}
                          </span>
                          <span className="text-[10px] font-mono" style={{ color: 'var(--text-muted)' }}>{rule.product}</span>
                        </div>
                      </div>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono ${STATUS_COLORS[rule.status] || STATUS_COLORS.disabled}`}>
                        {rule.status}
                      </span>
                      <div className="text-right shrink-0 w-16">
                        <p className="text-sm font-mono font-bold" style={{ color: 'var(--accent-cyan)' }}>{rule.match_count}</p>
                        <p className="text-[10px]" style={{ color: 'var(--text-muted)' }}>matches</p>
                      </div>
                    </div>
                  </motion.div>
                ))}
              </AnimatePresence>
            </div>
          )}
        </motion.div>
      )}

      {activeTab === 'matches' && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex flex-col gap-4">
          {loading ? (
            <Skeleton count={5} height={60} />
          ) : matches.length === 0 ? (
            <div className="rounded-xl p-12 text-center" style={{ background: 'rgba(8,20,32,0.7)', border: '1px solid rgba(0,229,255,0.08)' }}>
              <FileText className="w-12 h-12 mx-auto mb-3" style={{ color: 'var(--text-muted)', opacity: 0.3 }} />
              <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>No matches recorded yet</p>
            </div>
          ) : (
            <div className="rounded-xl overflow-hidden" style={{ background: 'rgba(8,20,32,0.7)', border: '1px solid rgba(0,229,255,0.08)' }}>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b" style={{ borderColor: 'rgba(0,229,255,0.06)' }}>
                      <th className="text-left py-3 px-4 font-mono font-medium" style={{ color: 'var(--text-muted)' }}>Time</th>
                      <th className="text-left py-3 px-4 font-mono font-medium" style={{ color: 'var(--text-muted)' }}>Rule</th>
                      <th className="text-left py-3 px-4 font-mono font-medium" style={{ color: 'var(--text-muted)' }}>Level</th>
                      <th className="text-left py-3 px-4 font-mono font-medium" style={{ color: 'var(--text-muted)' }}>Source IP</th>
                      <th className="text-left py-3 px-4 font-mono font-medium" style={{ color: 'var(--text-muted)' }}>Matched</th>
                    </tr>
                  </thead>
                  <tbody>
                    {matches.slice(0, 50).map((m) => (
                      <tr key={m.id} className="border-b hover:bg-white/[0.02]" style={{ borderColor: 'rgba(0,229,255,0.03)' }}>
                        <td className="py-2.5 px-4 font-mono" style={{ color: 'var(--text-muted)' }}>
                          {new Date(m.timestamp).toLocaleTimeString('en-US', { hour12: false })}
                        </td>
                        <td className="py-2.5 px-4 font-mono font-medium" style={{ color: 'var(--text-primary)' }}>{m.rule_title}</td>
                        <td className="py-2.5 px-4">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold border ${LEVEL_COLORS[m.level] || LEVEL_COLORS.information}`}>
                            {m.level}
                          </span>
                        </td>
                        <td className="py-2.5 px-4 font-mono" style={{ color: 'var(--accent-cyan)' }}>{m.source_ip}</td>
                        <td className="py-2.5 px-4 font-mono text-[10px]" style={{ color: 'var(--text-muted)' }}>
                          {m.matched_field}: {m.matched_value}
                        </td>
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
        {showImport && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 flex items-center justify-center p-4"
            style={{ background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(4px)' }}>
            <motion.div initial={{ scale: 0.95, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.95, opacity: 0 }}
              className="w-full max-w-2xl rounded-2xl p-6" style={{ background: 'rgba(8,20,32,0.95)', border: '1px solid rgba(0,229,255,0.15)' }}>
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>Import Sigma Rule (YAML)</h3>
                <button onClick={() => setShowImport(false)} style={{ color: 'var(--text-muted)' }}><X className="w-5 h-5" /></button>
              </div>
              <textarea value={importYaml} onChange={(e) => setImportYaml(e.target.value)}
                placeholder="Paste your Sigma rule YAML here..."
                className="w-full h-64 bg-white/5 border border-white/10 rounded-lg p-3 font-mono text-xs outline-none focus:border-cyan-400/50 resize-none"
                style={{ color: 'var(--text-primary)' }} />
              <div className="flex justify-end gap-3 mt-4">
                <button onClick={() => setShowImport(false)} className="px-4 py-2 rounded-lg text-xs font-mono" style={{ color: 'var(--text-muted)' }}>Cancel</button>
                <button onClick={handleImport} disabled={importing || !importYaml.trim()}
                  className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-mono font-semibold disabled:opacity-50"
                  style={{ background: 'rgba(0,229,255,0.15)', color: 'var(--accent-cyan)', border: '1px solid rgba(0,229,255,0.3)' }}>
                  {importing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Upload className="w-3.5 h-3.5" />}
                  Import
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
