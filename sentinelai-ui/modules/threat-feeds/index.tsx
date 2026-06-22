'use client';
import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Rss, Search, Plus, X, Loader2, CheckCircle, Ban, Globe,
  Shield, AlertTriangle, ExternalLink, RefreshCw, Eye
} from 'lucide-react';
import GlassCard from '@/components/ui/GlassCard';
import { Skeleton } from '@/components/ui/Skeleton';

interface ThreatFeed {
  id: string;
  name: string;
  type: string;
  url: string;
  enabled: boolean;
  last_polled: string;
  indicator_count: number;
  status: string;
  auth_type: string;
}

interface StixObject {
  id: string;
  type: string;
  name: string;
  description: string;
  created: string;
  modified: string;
  labels: string[];
}

interface StixIndicator {
  id: string;
  type: string;
  pattern: string;
  valid_from: string;
  valid_until: string;
  confidence: number;
  labels: string[];
  indicator_type: string;
  value: string;
}

interface MatchResult {
  found: boolean;
  indicator?: StixIndicator;
  feed_name?: string;
}

const FEED_TYPE_COLORS: Record<string, string> = {
  taxii: 'bg-cyan-500/15 text-cyan-400',
  stix: 'bg-purple-500/15 text-purple-400',
  csv: 'bg-green-500/15 text-green-400',
  json: 'bg-amber-500/15 text-amber-400',
  custom: 'bg-white/10 text-white/50',
};

const OBJECT_TYPE_COLORS: Record<string, string> = {
  indicator: 'bg-cyan-500/15 text-cyan-400',
  malware: 'bg-red-500/15 text-red-400',
  'threat-actor': 'bg-orange-500/15 text-orange-400',
  campaign: 'bg-purple-500/15 text-purple-400',
  'attack-pattern': 'bg-pink-500/15 text-pink-400',
  relationship: 'bg-blue-500/15 text-blue-400',
};

export default function ThreatFeedsModule() {
  const [feeds, setFeeds] = useState<ThreatFeed[]>([]);
  const [stixObjects, setStixObjects] = useState<StixObject[]>([]);
  const [indicators, setIndicators] = useState<StixIndicator[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'feeds' | 'objects' | 'indicators'>('feeds');
  const [showAddFeed, setShowAddFeed] = useState(false);
  const [iocInput, setIocInput] = useState('');
  const [iocResult, setIocResult] = useState<MatchResult | null>(null);
  const [checkingIoc, setCheckingIoc] = useState(false);
  const [filterType, setFilterType] = useState('');
  const [newFeed, setNewFeed] = useState({ name: '', type: 'taxii', url: '', auth_type: '', auth_key: '' });

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [feedsRes, objectsRes, indRes] = await Promise.all([
        fetch('/api/feeds'),
        fetch('/api/stix/objects'),
        fetch('/api/stix/indicators'),
      ]);
      const feedsData = await feedsRes.json();
      const objectsData = await objectsRes.json();
      const indData = await indRes.json();
      setFeeds(feedsData.feeds || []);
      setStixObjects(objectsData.objects || []);
      setIndicators(indData.indicators || []);
    } catch {
      console.error('Failed to fetch threat feed data');
    }
    setLoading(false);
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const handleAddFeed = async () => {
    if (!newFeed.name || !newFeed.url) return;
    try {
      await fetch('/api/feeds', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newFeed),
      });
      setShowAddFeed(false);
      setNewFeed({ name: '', type: 'taxii', url: '', auth_type: '', auth_key: '' });
      fetchData();
    } catch {
      console.error('Failed to add feed');
    }
  };

  const toggleFeed = async (feedId: string, enabled: boolean) => {
    try {
      await fetch(`/api/feeds/${feedId}/toggle`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !enabled }),
      });
      fetchData();
    } catch {
      console.error('Failed to toggle feed');
    }
  };

  const checkIoc = async () => {
    if (!iocInput.trim()) return;
    setCheckingIoc(true);
    setIocResult(null);
    try {
      const res = await fetch(`/api/stix/match/${encodeURIComponent(iocInput.trim())}`);
      const data = await res.json();
      setIocResult(data);
    } catch {
      setIocResult({ found: false });
    }
    setCheckingIoc(false);
  };

  const filteredObjects = stixObjects.filter(o => !filterType || o.type === filterType);
  const uniqueObjectTypes = [...new Set(stixObjects.map(o => o.type))].sort();

  return (
    <div className="h-full p-6 lg:p-8 flex flex-col gap-6 overflow-y-auto">
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}>
        <p className="text-[10px] font-mono tracking-[0.3em] uppercase mb-2" style={{ color: 'var(--accent-cyan)' }}>
          Intelligence Feeds
        </p>
        <h1 className="text-3xl font-display font-bold" style={{ color: 'var(--text-primary)' }}>
          Threat Intelligence Feeds
        </h1>
        <p className="text-sm mt-2" style={{ color: 'var(--text-secondary)' }}>
          Manage STIX/TAXII feeds, browse threat objects, and check IOCs.
        </p>
      </motion.div>

      <div className="flex gap-1 p-1 rounded-xl" style={{ background: 'rgba(8,20,32,0.5)', border: '1px solid rgba(0,229,255,0.06)' }}>
        {(['feeds', 'objects', 'indicators'] as const).map((tab) => (
          <button key={tab} onClick={() => setActiveTab(tab)}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg text-xs font-mono font-semibold transition-all flex-1 justify-center"
            style={{
              background: activeTab === tab ? 'rgba(0,229,255,0.1)' : 'transparent',
              color: activeTab === tab ? 'var(--accent-cyan)' : 'var(--text-muted)',
              border: activeTab === tab ? '1px solid rgba(0,229,255,0.15)' : '1px solid transparent',
            }}>
            {tab === 'feeds' && <Rss className="w-3.5 h-3.5" />}
            {tab === 'objects' && <Shield className="w-3.5 h-3.5" />}
            {tab === 'indicators' && <Eye className="w-3.5 h-3.5" />}
            <span className="hidden sm:inline">{tab === 'feeds' ? 'Feeds' : tab === 'objects' ? 'STIX Objects' : 'Indicators'}</span>
          </button>
        ))}
      </div>

      {activeTab === 'feeds' && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex flex-col gap-4">
          <div className="flex justify-end">
            <button onClick={() => setShowAddFeed(true)}
              className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-mono font-semibold"
              style={{ background: 'rgba(0,229,255,0.1)', color: 'var(--accent-cyan)', border: '1px solid rgba(0,229,255,0.2)' }}>
              <Plus className="w-3.5 h-3.5" /> Add Feed
            </button>
          </div>
          {loading ? <Skeleton count={4} height={80} /> : feeds.length === 0 ? (
            <div className="rounded-xl p-12 text-center" style={{ background: 'rgba(8,20,32,0.7)', border: '1px solid rgba(0,229,255,0.08)' }}>
              <Rss className="w-12 h-12 mx-auto mb-3" style={{ color: 'var(--text-muted)', opacity: 0.3 }} />
              <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>No feeds configured</p>
              <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>Add a STIX/TAXII feed to begin ingestion</p>
            </div>
          ) : (
            <div className="space-y-2">
              {feeds.map((feed) => (
                <motion.div key={feed.id} layout initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
                  className="rounded-xl p-4" style={{ background: 'rgba(8,20,32,0.7)', backdropFilter: 'blur(24px)', border: '1px solid rgba(0,229,255,0.08)' }}>
                  <div className="flex items-center gap-3">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${FEED_TYPE_COLORS[feed.type] || FEED_TYPE_COLORS.custom}`}>
                      {feed.type}
                    </span>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium truncate" style={{ color: 'var(--text-primary)' }}>{feed.name}</p>
                      <p className="text-[10px] font-mono truncate mt-0.5" style={{ color: 'var(--text-muted)' }}>{feed.url}</p>
                    </div>
                    <div className="text-right shrink-0">
                      <p className="text-sm font-mono" style={{ color: 'var(--accent-cyan)' }}>{feed.indicator_count}</p>
                      <p className="text-[10px]" style={{ color: 'var(--text-muted)' }}>indicators</p>
                    </div>
                    <div className="text-right shrink-0">
                      <p className="text-[10px]" style={{ color: 'var(--text-muted)' }}>Last polled</p>
                      <p className="text-[10px] font-mono" style={{ color: 'var(--text-secondary)' }}>
                        {feed.last_polled ? new Date(feed.last_polled).toLocaleTimeString('en-US', { hour12: false }) : 'Never'}
                      </p>
                    </div>
                    <button onClick={() => toggleFeed(feed.id, feed.enabled)}
                      className={`px-3 py-1.5 rounded-lg text-[10px] font-mono font-bold transition-all ${
                        feed.enabled ? 'bg-emerald-500/20 text-emerald-400' : 'bg-white/5 text-white/30'
                      }`}>
                      {feed.enabled ? 'ENABLED' : 'DISABLED'}
                    </button>
                  </div>
                </motion.div>
              ))}
            </div>
          )}
        </motion.div>
      )}

      {activeTab === 'objects' && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex flex-col gap-4">
          <div className="flex items-center gap-3">
            <select value={filterType} onChange={(e) => setFilterType(e.target.value)}
              className="bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-xs font-mono outline-none" style={{ color: 'var(--text-secondary)' }}>
              <option value="">All Types</option>
              {uniqueObjectTypes.map(t => <option key={t} value={t}>{t}</option>)}
            </select>
            <span className="text-[10px] font-mono" style={{ color: 'var(--text-muted)' }}>{filteredObjects.length} objects</span>
          </div>
          {loading ? <Skeleton count={5} height={70} /> : (
            <div className="space-y-2">
              {filteredObjects.map((obj) => (
                <div key={obj.id} className="rounded-xl p-4" style={{ background: 'rgba(8,20,32,0.7)', backdropFilter: 'blur(24px)', border: '1px solid rgba(0,229,255,0.08)' }}>
                  <div className="flex items-center gap-3">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${OBJECT_TYPE_COLORS[obj.type] || OBJECT_TYPE_COLORS.indicator}`}>
                      {obj.type}
                    </span>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium truncate" style={{ color: 'var(--text-primary)' }}>{obj.name || obj.id}</p>
                      {obj.description && <p className="text-[10px] truncate mt-0.5" style={{ color: 'var(--text-muted)' }}>{obj.description}</p>}
                    </div>
                    <div className="flex gap-1">
                      {obj.labels?.slice(0, 3).map((l, i) => (
                        <span key={i} className="px-1.5 py-0.5 rounded text-[9px] font-mono" style={{ background: 'rgba(255,255,255,0.05)', color: 'var(--text-muted)' }}>{l}</span>
                      ))}
                    </div>
                    <span className="text-[10px] font-mono shrink-0" style={{ color: 'var(--text-muted)' }}>
                      {new Date(obj.created).toLocaleDateString()}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </motion.div>
      )}

      {activeTab === 'indicators' && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex flex-col gap-4">
          <div className="rounded-xl p-4" style={{ background: 'rgba(8,20,32,0.7)', border: '1px solid rgba(0,229,255,0.08)' }}>
            <p className="text-xs font-mono font-semibold mb-2" style={{ color: 'var(--text-secondary)' }}>IOC Lookup</p>
            <div className="flex gap-2">
              <input type="text" value={iocInput} onChange={(e) => setIocInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && checkIoc()}
                placeholder="Enter IP, domain, or hash to check..."
                className="flex-1 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-xs font-mono outline-none focus:border-cyan-400/50"
                style={{ color: 'var(--text-primary)' }} />
              <button onClick={checkIoc} disabled={checkingIoc}
                className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-mono font-semibold disabled:opacity-50"
                style={{ background: 'rgba(0,229,255,0.15)', color: 'var(--accent-cyan)', border: '1px solid rgba(0,229,255,0.3)' }}>
                {checkingIoc ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Search className="w-3.5 h-3.5" />}
                Check
              </button>
            </div>
            {iocResult && (
              <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }}
                className={`mt-3 p-3 rounded-lg border ${iocResult.found ? 'bg-red-500/10 border-red-500/20' : 'bg-emerald-500/10 border-emerald-500/20'}`}>
                {iocResult.found ? (
                  <div className="flex items-start gap-2">
                    <AlertTriangle className="w-4 h-4 text-red-400 mt-0.5 shrink-0" />
                    <div>
                      <p className="text-sm font-medium text-red-400">Malicious IOC Detected</p>
                      <p className="text-xs mt-1" style={{ color: 'var(--text-secondary)' }}>Pattern: {iocResult.indicator?.pattern}</p>
                      <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-muted)' }}>Source: {iocResult.feed_name}</p>
                    </div>
                  </div>
                ) : (
                  <div className="flex items-center gap-2">
                    <CheckCircle className="w-4 h-4 text-emerald-400" />
                    <p className="text-sm text-emerald-400">No matches found in threat intelligence feeds</p>
                  </div>
                )}
              </motion.div>
            )}
          </div>

          {loading ? <Skeleton count={5} height={60} /> : (
            <div className="rounded-xl overflow-hidden" style={{ background: 'rgba(8,20,32,0.7)', border: '1px solid rgba(0,229,255,0.08)' }}>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b" style={{ borderColor: 'rgba(0,229,255,0.06)' }}>
                      <th className="text-left py-3 px-4 font-mono font-medium" style={{ color: 'var(--text-muted)' }}>Type</th>
                      <th className="text-left py-3 px-4 font-mono font-medium" style={{ color: 'var(--text-muted)' }}>Value</th>
                      <th className="text-left py-3 px-4 font-mono font-medium" style={{ color: 'var(--text-muted)' }}>Confidence</th>
                      <th className="text-left py-3 px-4 font-mono font-medium" style={{ color: 'var(--text-muted)' }}>Labels</th>
                      <th className="text-left py-3 px-4 font-mono font-medium" style={{ color: 'var(--text-muted)' }}>Valid</th>
                    </tr>
                  </thead>
                  <tbody>
                    {indicators.slice(0, 50).map((ind) => (
                      <tr key={ind.id} className="border-b hover:bg-white/[0.02]" style={{ borderColor: 'rgba(0,229,255,0.03)' }}>
                        <td className="py-2.5 px-4">
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-bold" style={{ background: 'rgba(0,229,255,0.1)', color: 'var(--accent-cyan)' }}>
                            {ind.indicator_type}
                          </span>
                        </td>
                        <td className="py-2.5 px-4 font-mono" style={{ color: 'var(--text-primary)' }}>{ind.value}</td>
                        <td className="py-2.5 px-4">
                          <span className={`font-mono ${ind.confidence >= 80 ? 'text-red-400' : ind.confidence >= 50 ? 'text-amber-400' : 'text-emerald-400'}`}>
                            {ind.confidence}%
                          </span>
                        </td>
                        <td className="py-2.5 px-4">
                          <div className="flex gap-1 flex-wrap">
                            {ind.labels?.slice(0, 2).map((l, i) => (
                              <span key={i} className="px-1 py-0.5 rounded text-[9px]" style={{ background: 'rgba(255,255,255,0.05)', color: 'var(--text-muted)' }}>{l}</span>
                            ))}
                          </div>
                        </td>
                        <td className="py-2.5 px-4 text-[10px] font-mono" style={{ color: 'var(--text-muted)' }}>
                          {ind.valid_from?.slice(0, 10)}
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
        {showAddFeed && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 flex items-center justify-center p-4"
            style={{ background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(4px)' }}>
            <motion.div initial={{ scale: 0.95, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.95, opacity: 0 }}
              className="w-full max-w-md rounded-2xl p-6" style={{ background: 'rgba(8,20,32,0.95)', border: '1px solid rgba(0,229,255,0.15)' }}>
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>Add Threat Feed</h3>
                <button onClick={() => setShowAddFeed(false)} style={{ color: 'var(--text-muted)' }}><X className="w-5 h-5" /></button>
              </div>
              <div className="space-y-3">
                <div>
                  <label className="text-[10px] font-mono uppercase mb-1 block" style={{ color: 'var(--text-muted)' }}>Name</label>
                  <input type="text" value={newFeed.name} onChange={(e) => setNewFeed(f => ({ ...f, name: e.target.value }))}
                    className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-xs font-mono outline-none focus:border-cyan-400/50"
                    style={{ color: 'var(--text-primary)' }} />
                </div>
                <div>
                  <label className="text-[10px] font-mono uppercase mb-1 block" style={{ color: 'var(--text-muted)' }}>Type</label>
                  <select value={newFeed.type} onChange={(e) => setNewFeed(f => ({ ...f, type: e.target.value }))}
                    className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-xs font-mono outline-none" style={{ color: 'var(--text-primary)' }}>
                    <option value="taxii">TAXII</option>
                    <option value="stix">STIX</option>
                    <option value="csv">CSV</option>
                    <option value="json">JSON</option>
                  </select>
                </div>
                <div>
                  <label className="text-[10px] font-mono uppercase mb-1 block" style={{ color: 'var(--text-muted)' }}>URL</label>
                  <input type="url" value={newFeed.url} onChange={(e) => setNewFeed(f => ({ ...f, url: e.target.value }))}
                    className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-xs font-mono outline-none focus:border-cyan-400/50"
                    style={{ color: 'var(--text-primary)' }} />
                </div>
                <div>
                  <label className="text-[10px] font-mono uppercase mb-1 block" style={{ color: 'var(--text-muted)' }}>Auth Key (optional)</label>
                  <input type="password" value={newFeed.auth_key} onChange={(e) => setNewFeed(f => ({ ...f, auth_key: e.target.value }))}
                    className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-xs font-mono outline-none focus:border-cyan-400/50"
                    style={{ color: 'var(--text-primary)' }} />
                </div>
              </div>
              <div className="flex justify-end gap-3 mt-5">
                <button onClick={() => setShowAddFeed(false)} className="px-4 py-2 rounded-lg text-xs font-mono" style={{ color: 'var(--text-muted)' }}>Cancel</button>
                <button onClick={handleAddFeed} disabled={!newFeed.name || !newFeed.url}
                  className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-mono font-semibold disabled:opacity-50"
                  style={{ background: 'rgba(0,229,255,0.15)', color: 'var(--accent-cyan)', border: '1px solid rgba(0,229,255,0.3)' }}>
                  <Plus className="w-3.5 h-3.5" /> Add Feed
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
