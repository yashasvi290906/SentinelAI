'use client';
import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Search, Plus, X, Loader2, CheckCircle, AlertTriangle,
  Shield, Clock, FileText, Hash, Eye, ChevronRight, Link
} from 'lucide-react';
import GlassCard from '@/components/ui/GlassCard';
import { Skeleton } from '@/components/ui/Skeleton';

interface Evidence {
  id: string;
  type: string;
  description: string;
  sha256_hash: string;
  collected_at: string;
  collected_by: string;
  incident_id: string;
  file_size: number;
  chain_of_custody: ChainEntry[];
}

interface ChainEntry {
  timestamp: string;
  action: string;
  actor: string;
  location: string;
  notes: string;
}

interface TimelineEvent {
  id: string;
  timestamp: string;
  source: string;
  type: string;
  description: string;
  evidence_id?: string;
}

interface VerifyResult {
  valid: boolean;
  hash_match: boolean;
  chain_integrity: boolean;
  verified_at: string;
}

const TYPE_COLORS: Record<string, string> = {
  disk_image: 'bg-cyan-500/15 text-cyan-400',
  memory_dump: 'bg-purple-500/15 text-purple-400',
  network_capture: 'bg-green-500/15 text-green-400',
  log_export: 'bg-amber-500/15 text-amber-400',
  screenshot: 'bg-pink-500/15 text-pink-400',
  file: 'bg-blue-500/15 text-blue-400',
};

export default function ForensicsModule() {
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [timeline, setTimeline] = useState<TimelineEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedEvidence, setSelectedEvidence] = useState<Evidence | null>(null);
  const [showCollect, setShowCollect] = useState(false);
  const [verifyResult, setVerifyResult] = useState<VerifyResult | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [newEvidence, setNewEvidence] = useState({ type: 'disk_image', description: '', incident_id: '' });
  const [activeTab, setActiveTab] = useState<'evidence' | 'timeline'>('evidence');

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const evRes = await fetch('/api/forensics/evidence');
      const evData = await evRes.json();
      setEvidence(evData.evidence || []);

      if (evData.evidence?.length > 0) {
        const tlRes = await fetch(`/api/forensics/timeline/${evData.evidence[0].id}`);
        const tlData = await tlRes.json();
        setTimeline(tlData.timeline || []);
      }
    } catch {
      console.error('Failed to fetch forensics data');
    }
    setLoading(false);
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const handleCollect = async () => {
    if (!newEvidence.description) return;
    try {
      await fetch('/api/forensics/evidence', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newEvidence),
      });
      setShowCollect(false);
      setNewEvidence({ type: 'disk_image', description: '', incident_id: '' });
      fetchData();
    } catch {
      console.error('Failed to collect evidence');
    }
  };

  const verifyEvidence = async (evId: string) => {
    setVerifying(true);
    setVerifyResult(null);
    try {
      const res = await fetch(`/api/forensics/evidence/${evId}/verify`);
      const data = await res.json();
      setVerifyResult(data);
    } catch {
      setVerifyResult({ valid: false, hash_match: false, chain_integrity: false, verified_at: new Date().toISOString() });
    }
    setVerifying(false);
  };

  const loadTimeline = async (evId: string) => {
    try {
      const res = await fetch(`/api/forensics/timeline/${evId}`);
      const data = await res.json();
      setTimeline(data.timeline || []);
    } catch {
      setTimeline([]);
    }
  };

  return (
    <div className="h-full p-6 lg:p-8 flex flex-col gap-6 overflow-y-auto">
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}>
        <p className="text-[10px] font-mono tracking-[0.3em] uppercase mb-2" style={{ color: 'var(--accent-cyan)' }}>
          Forensic Analysis
        </p>
        <h1 className="text-3xl font-display font-bold" style={{ color: 'var(--text-primary)' }}>
          Digital Forensics
        </h1>
        <p className="text-sm mt-2" style={{ color: 'var(--text-secondary)' }}>
          Chain of custody tracking and evidence integrity verification.
        </p>
      </motion.div>

      <div className="flex gap-1 p-1 rounded-xl" style={{ background: 'rgba(8,20,32,0.5)', border: '1px solid rgba(0,229,255,0.06)' }}>
        {(['evidence', 'timeline'] as const).map((tab) => (
          <button key={tab} onClick={() => setActiveTab(tab)}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg text-xs font-mono font-semibold transition-all flex-1 justify-center"
            style={{
              background: activeTab === tab ? 'rgba(0,229,255,0.1)' : 'transparent',
              color: activeTab === tab ? 'var(--accent-cyan)' : 'var(--text-muted)',
              border: activeTab === tab ? '1px solid rgba(0,229,255,0.15)' : '1px solid transparent',
            }}>
            {tab === 'evidence' ? <Shield className="w-3.5 h-3.5" /> : <Clock className="w-3.5 h-3.5" />}
            <span className="hidden sm:inline">{tab === 'evidence' ? 'Evidence Registry' : 'Forensic Timeline'}</span>
          </button>
        ))}
      </div>

      {activeTab === 'evidence' && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex flex-col gap-4">
          <div className="flex justify-end">
            <button onClick={() => setShowCollect(true)}
              className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-mono font-semibold"
              style={{ background: 'rgba(0,229,255,0.1)', color: 'var(--accent-cyan)', border: '1px solid rgba(0,229,255,0.2)' }}>
              <Plus className="w-3.5 h-3.5" /> Collect Evidence
            </button>
          </div>

          <div className="flex gap-4">
            <div className="flex-1 space-y-2">
              {loading ? <Skeleton count={4} height={80} /> : evidence.length === 0 ? (
                <div className="rounded-xl p-12 text-center" style={{ background: 'rgba(8,20,32,0.7)', border: '1px solid rgba(0,229,255,0.08)' }}>
                  <Shield className="w-12 h-12 mx-auto mb-3" style={{ color: 'var(--text-muted)', opacity: 0.3 }} />
                  <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>No evidence collected yet</p>
                </div>
              ) : (
                evidence.map((ev) => (
                  <motion.div key={ev.id} layout
                    onClick={() => { setSelectedEvidence(ev); loadTimeline(ev.id); setVerifyResult(null); }}
                    className="rounded-xl p-4 cursor-pointer transition-all"
                    style={{
                      background: selectedEvidence?.id === ev.id ? 'rgba(0,229,255,0.06)' : 'rgba(8,20,32,0.7)',
                      backdropFilter: 'blur(24px)',
                      border: selectedEvidence?.id === ev.id ? '1px solid rgba(0,229,255,0.2)' : '1px solid rgba(0,229,255,0.08)',
                    }}>
                    <div className="flex items-center gap-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${TYPE_COLORS[ev.type] || TYPE_COLORS.file}`}>
                        {ev.type.replace(/_/g, ' ')}
                      </span>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium truncate" style={{ color: 'var(--text-primary)' }}>{ev.description}</p>
                        <div className="flex items-center gap-2 mt-1">
                          <Hash className="w-3 h-3" style={{ color: 'var(--text-muted)' }} />
                          <span className="text-[9px] font-mono truncate" style={{ color: 'var(--text-muted)' }}>{ev.sha256_hash?.slice(0, 16)}...</span>
                        </div>
                      </div>
                      <div className="text-right shrink-0">
                        <p className="text-[10px]" style={{ color: 'var(--text-muted)' }}>{new Date(ev.collected_at).toLocaleDateString()}</p>
                        <p className="text-[10px] font-mono" style={{ color: 'var(--accent-cyan)' }}>{ev.collected_by}</p>
                      </div>
                      <ChevronRight className="w-4 h-4 shrink-0" style={{ color: 'var(--text-muted)' }} />
                    </div>
                  </motion.div>
                ))
              )}
            </div>

            <AnimatePresence>
              {selectedEvidence && (
                <motion.div initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: 20 }}
                  className="w-96 shrink-0 rounded-xl p-5 space-y-4" style={{ background: 'rgba(8,20,32,0.7)', backdropFilter: 'blur(24px)', border: '1px solid rgba(0,229,255,0.08)' }}>
                  <div>
                    <h3 className="text-sm font-bold mb-2" style={{ color: 'var(--text-primary)' }}>Evidence Details</h3>
                    <div className="space-y-2 text-xs">
                      <div className="flex justify-between"><span style={{ color: 'var(--text-muted)' }}>Type</span><span className="font-mono" style={{ color: 'var(--text-secondary)' }}>{selectedEvidence.type}</span></div>
                      <div className="flex justify-between"><span style={{ color: 'var(--text-muted)' }}>Incident</span><span className="font-mono" style={{ color: 'var(--accent-cyan)' }}>{selectedEvidence.incident_id || 'N/A'}</span></div>
                      <div className="flex justify-between"><span style={{ color: 'var(--text-muted)' }}>Collected By</span><span className="font-mono" style={{ color: 'var(--text-secondary)' }}>{selectedEvidence.collected_by}</span></div>
                      <div>
                        <span style={{ color: 'var(--text-muted)' }}>SHA-256</span>
                        <p className="font-mono text-[9px] break-all mt-0.5" style={{ color: 'var(--text-secondary)' }}>{selectedEvidence.sha256_hash}</p>
                      </div>
                    </div>
                  </div>

                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <h4 className="text-xs font-semibold" style={{ color: 'var(--text-primary)' }}>Verify Integrity</h4>
                      <button onClick={() => verifyEvidence(selectedEvidence.id)} disabled={verifying}
                        className="flex items-center gap-1 px-2 py-1 rounded text-[10px] font-mono disabled:opacity-50"
                        style={{ background: 'rgba(0,229,255,0.1)', color: 'var(--accent-cyan)' }}>
                        {verifying ? <Loader2 className="w-3 h-3 animate-spin" /> : <Eye className="w-3 h-3" />}
                        Verify
                      </button>
                    </div>
                    {verifyResult && (
                      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
                        className={`p-2 rounded-lg text-xs ${verifyResult.valid ? 'bg-emerald-500/10 border border-emerald-500/20' : 'bg-red-500/10 border border-red-500/20'}`}>
                        <div className="flex items-center gap-2">
                          {verifyResult.valid ? <CheckCircle className="w-4 h-4 text-emerald-400" /> : <AlertTriangle className="w-4 h-4 text-red-400" />}
                          <span className={verifyResult.valid ? 'text-emerald-400' : 'text-red-400'}>
                            {verifyResult.valid ? 'Evidence integrity verified' : 'Integrity check failed'}
                          </span>
                        </div>
                        <div className="mt-1 space-y-0.5 text-[10px]" style={{ color: 'var(--text-muted)' }}>
                          <p>Hash match: {verifyResult.hash_match ? 'Yes' : 'No'}</p>
                          <p>Chain integrity: {verifyResult.chain_integrity ? 'Valid' : 'Broken'}</p>
                        </div>
                      </motion.div>
                    )}
                  </div>

                  <div>
                    <h4 className="text-xs font-semibold mb-2" style={{ color: 'var(--text-primary)' }}>Chain of Custody</h4>
                    <div className="space-y-2 max-h-48 overflow-y-auto">
                      {selectedEvidence.chain_of_custody?.length > 0 ? (
                        selectedEvidence.chain_of_custody.map((entry, i) => (
                          <div key={i} className="relative pl-4 border-l border-white/10">
                            <div className="absolute left-0 top-1 w-2 h-2 rounded-full" style={{ background: 'var(--accent-cyan)' }} />
                            <p className="text-[10px] font-mono" style={{ color: 'var(--text-muted)' }}>{new Date(entry.timestamp).toLocaleString()}</p>
                            <p className="text-xs font-medium" style={{ color: 'var(--text-primary)' }}>{entry.action}</p>
                            <p className="text-[10px]" style={{ color: 'var(--text-muted)' }}>by {entry.actor} @ {entry.location}</p>
                            {entry.notes && <p className="text-[10px] italic" style={{ color: 'var(--text-muted)' }}>{entry.notes}</p>}
                          </div>
                        ))
                      ) : (
                        <p className="text-[10px]" style={{ color: 'var(--text-muted)' }}>No custody entries</p>
                      )}
                    </div>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </motion.div>
      )}

      {activeTab === 'timeline' && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
          {loading ? <Skeleton count={8} height={50} /> : timeline.length === 0 ? (
            <div className="rounded-xl p-12 text-center" style={{ background: 'rgba(8,20,32,0.7)', border: '1px solid rgba(0,229,255,0.08)' }}>
              <Clock className="w-12 h-12 mx-auto mb-3" style={{ color: 'var(--text-muted)', opacity: 0.3 }} />
              <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>Select evidence to view forensic timeline</p>
            </div>
          ) : (
            <div className="space-y-2">
              {timeline.map((ev) => (
                <motion.div key={ev.id} initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }}
                  className="rounded-xl p-4" style={{ background: 'rgba(8,20,32,0.7)', backdropFilter: 'blur(24px)', border: '1px solid rgba(0,229,255,0.08)' }}>
                  <div className="flex items-center gap-3">
                    <div className="w-2 h-2 rounded-full shrink-0" style={{ background: 'var(--accent-cyan)' }} />
                    <span className="text-[10px] font-mono shrink-0 w-32" style={{ color: 'var(--text-muted)' }}>
                      {new Date(ev.timestamp).toLocaleString('en-US', { hour12: false })}
                    </span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono shrink-0" style={{ background: 'rgba(0,229,255,0.1)', color: 'var(--accent-cyan)' }}>
                      {ev.source}
                    </span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono shrink-0" style={{ background: 'rgba(255,255,255,0.05)', color: 'var(--text-secondary)' }}>
                      {ev.type}
                    </span>
                    <p className="text-xs flex-1 truncate" style={{ color: 'var(--text-primary)' }}>{ev.description}</p>
                  </div>
                </motion.div>
              ))}
            </div>
          )}
        </motion.div>
      )}

      <AnimatePresence>
        {showCollect && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 flex items-center justify-center p-4"
            style={{ background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(4px)' }}>
            <motion.div initial={{ scale: 0.95, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.95, opacity: 0 }}
              className="w-full max-w-md rounded-2xl p-6" style={{ background: 'rgba(8,20,32,0.95)', border: '1px solid rgba(0,229,255,0.15)' }}>
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>Collect Evidence</h3>
                <button onClick={() => setShowCollect(false)} style={{ color: 'var(--text-muted)' }}><X className="w-5 h-5" /></button>
              </div>
              <div className="space-y-3">
                <div>
                  <label className="text-[10px] font-mono uppercase mb-1 block" style={{ color: 'var(--text-muted)' }}>Type</label>
                  <select value={newEvidence.type} onChange={(e) => setNewEvidence(p => ({ ...p, type: e.target.value }))}
                    className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-xs font-mono outline-none" style={{ color: 'var(--text-primary)' }}>
                    {['disk_image', 'memory_dump', 'network_capture', 'log_export', 'screenshot', 'file'].map(t => (
                      <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="text-[10px] font-mono uppercase mb-1 block" style={{ color: 'var(--text-muted)' }}>Description</label>
                  <textarea value={newEvidence.description} onChange={(e) => setNewEvidence(p => ({ ...p, description: e.target.value }))}
                    className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-xs font-mono outline-none focus:border-cyan-400/50 resize-none h-20"
                    style={{ color: 'var(--text-primary)' }} />
                </div>
                <div>
                  <label className="text-[10px] font-mono uppercase mb-1 block" style={{ color: 'var(--text-muted)' }}>Incident ID</label>
                  <input type="text" value={newEvidence.incident_id} onChange={(e) => setNewEvidence(p => ({ ...p, incident_id: e.target.value }))}
                    className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-xs font-mono outline-none focus:border-cyan-400/50"
                    style={{ color: 'var(--text-primary)' }} />
                </div>
              </div>
              <div className="flex justify-end gap-3 mt-5">
                <button onClick={() => setShowCollect(false)} className="px-4 py-2 rounded-lg text-xs font-mono" style={{ color: 'var(--text-muted)' }}>Cancel</button>
                <button onClick={handleCollect} disabled={!newEvidence.description}
                  className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-mono font-semibold disabled:opacity-50"
                  style={{ background: 'rgba(0,229,255,0.15)', color: 'var(--accent-cyan)', border: '1px solid rgba(0,229,255,0.3)' }}>
                  <Plus className="w-3.5 h-3.5" /> Collect
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
