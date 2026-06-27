'use client';
import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Network, Wifi, Globe, AlertTriangle, Search, Filter,
  RefreshCw, ArrowRightLeft, Loader2, Activity, CheckCircle
} from 'lucide-react';
import GlassCard from '@/components/ui/GlassCard';
import { Skeleton } from '@/components/ui/Skeleton';
import { fetchWithAuth } from "@/lib/api";

interface NetworkFlow {
  id: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  bytes: number;
  duration: number;
  timestamp: string;
}

interface DnsQuery {
  id: string;
  query_name: string;
  query_type: string;
  response_code: string;
  src_ip: string;
  timestamp: string;
}

interface HttpRequest {
  id: string;
  method: string;
  host: string;
  uri: string;
  status_code: number;
  user_agent: string;
  src_ip: string;
  timestamp: string;
}

interface NetworkAnomaly {
  id: string;
  type: string;
  severity: string;
  src_ip: string;
  dst_ip: string;
  description: string;
  confidence: number;
  timestamp: string;
}

interface NetworkStats {
  total_flows: number;
  dns_queries: number;
  http_requests: number;
  anomalies: number;
  unique_src_ips: number;
  unique_dst_ips: number;
}

type TabId = 'flows' | 'dns' | 'http' | 'anomalies';

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
};

const PROTO_COLORS: Record<string, string> = {
  TCP: 'bg-cyan-500/15 text-cyan-400',
  UDP: 'bg-purple-500/15 text-purple-400',
  ICMP: 'bg-amber-500/15 text-amber-400',
  DNS: 'bg-green-500/15 text-green-400',
};

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

export default function NetworkAnalysisModule() {
  const [flows, setFlows] = useState<NetworkFlow[]>([]);
  const [dns, setDns] = useState<DnsQuery[]>([]);
  const [http, setHttp] = useState<HttpRequest[]>([]);
  const [anomalies, setAnomalies] = useState<NetworkAnomaly[]>([]);
  const [stats, setStats] = useState<NetworkStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<TabId>('flows');
  const [search, setSearch] = useState('');

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [flowsRes, dnsRes, httpRes, anomRes, statsRes] = await Promise.all([
        fetchWithAuth('/api/network/flows'),
        fetchWithAuth('/api/network/dns'),
        fetchWithAuth('/api/network/http'),
        fetchWithAuth('/api/network/anomalies'),
        fetchWithAuth('/api/network/stats'),
      ]);
      const flowsData = await flowsRes.json();
      const dnsData = await dnsRes.json();
      const httpData = await httpRes.json();
      const anomData = await anomRes.json();
      const statsData = await statsRes.json();
      setFlows(flowsData.flows || []);
      setDns(dnsData.queries || []);
      setHttp(httpData.requests || []);
      setAnomalies(anomData.anomalies || []);
      if (statsData && !statsData.error) setStats(statsData);
    } catch {
      console.error('Failed to fetch network data');
    }
    setLoading(false);
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const filteredFlows = flows.filter(f => !search || f.src_ip.includes(search) || f.dst_ip.includes(search) || f.protocol.toLowerCase().includes(search.toLowerCase()));
  const filteredDns = dns.filter(d => !search || d.query_name.includes(search) || d.src_ip.includes(search));
  const filteredHttp = http.filter(h => !search || h.host.includes(search) || h.uri.includes(search) || h.src_ip.includes(search));

  return (
    <div className="h-full p-6 lg:p-8 flex flex-col gap-6 overflow-y-auto">
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}>
        <p className="text-[10px] font-mono tracking-[0.3em] uppercase mb-2" style={{ color: 'var(--accent-cyan)' }}>
          Traffic Analysis
        </p>
        <h1 className="text-3xl font-display font-bold" style={{ color: 'var(--text-primary)' }}>
          Network Traffic Analysis
        </h1>
        <p className="text-sm mt-2" style={{ color: 'var(--text-secondary)' }}>
          Deep packet inspection and traffic flow analysis.
        </p>
      </motion.div>

      {stats && (
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
          className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {[
            { label: 'Total Flows', value: stats.total_flows.toLocaleString(), icon: ArrowRightLeft, color: 'var(--accent-cyan)' },
            { label: 'DNS Queries', value: stats.dns_queries.toLocaleString(), icon: Globe, color: 'var(--accent-purple)' },
            { label: 'HTTP Requests', value: stats.http_requests.toLocaleString(), icon: Activity, color: 'var(--accent-green)' },
            { label: 'Anomalies', value: stats.anomalies.toLocaleString(), icon: AlertTriangle, color: 'var(--accent-red)' },
          ].map((s) => (
            <div key={s.label} className="rounded-xl p-4" style={{ background: 'rgba(8,20,32,0.7)', backdropFilter: 'blur(24px)', border: '1px solid rgba(0,229,255,0.08)' }}>
              <div className="flex items-center gap-2 mb-1">
                <s.icon className="w-4 h-4" style={{ color: s.color }} />
                <p className="text-[10px] font-mono tracking-wider uppercase" style={{ color: 'var(--text-muted)' }}>{s.label}</p>
              </div>
              <p className="text-2xl font-display font-bold" style={{ color: s.color }}>{s.value}</p>
            </div>
          ))}
        </motion.div>
      )}

      <div className="flex flex-wrap items-center gap-3">
        <div className="flex gap-1 p-1 rounded-xl flex-1" style={{ background: 'rgba(8,20,32,0.5)', border: '1px solid rgba(0,229,255,0.06)' }}>
          {([
            { id: 'flows' as TabId, label: 'Flows', icon: ArrowRightLeft },
            { id: 'dns' as TabId, label: 'DNS', icon: Globe },
            { id: 'http' as TabId, label: 'HTTP', icon: Activity },
            { id: 'anomalies' as TabId, label: 'Anomalies', icon: AlertTriangle },
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
        <div className="flex items-center gap-2 px-3 py-2 rounded-xl" style={{ background: 'rgba(8,20,32,0.7)', border: '1px solid rgba(0,229,255,0.08)' }}>
          <Search className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />
          <input type="text" placeholder="Search..." value={search} onChange={(e) => setSearch(e.target.value)}
            className="bg-transparent outline-none text-xs font-mono w-40" style={{ color: 'var(--text-primary)' }} />
        </div>
        <button onClick={fetchData} className="p-2 rounded-lg transition-colors" style={{ color: 'var(--text-muted)' }}>
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {loading ? (
        <Skeleton count={8} height={50} />
      ) : (
        <AnimatePresence mode="wait">
          <motion.div key={activeTab} initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
            {activeTab === 'flows' && (
              <div className="rounded-xl overflow-hidden" style={{ background: 'rgba(8,20,32,0.7)', border: '1px solid rgba(0,229,255,0.08)' }}>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b" style={{ borderColor: 'rgba(0,229,255,0.06)' }}>
                        {['Source IP', 'Dest IP', 'Src Port', 'Dst Port', 'Proto', 'Bytes', 'Duration'].map(h => (
                          <th key={h} className="text-left py-3 px-4 font-mono font-medium" style={{ color: 'var(--text-muted)' }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {filteredFlows.slice(0, 100).map((f) => (
                        <tr key={f.id} className="border-b hover:bg-white/[0.02]" style={{ borderColor: 'rgba(0,229,255,0.03)' }}>
                          <td className="py-2 px-4 font-mono" style={{ color: 'var(--accent-cyan)' }}>{f.src_ip}</td>
                          <td className="py-2 px-4 font-mono" style={{ color: 'var(--accent-cyan)' }}>{f.dst_ip}</td>
                          <td className="py-2 px-4 font-mono" style={{ color: 'var(--text-secondary)' }}>{f.src_port}</td>
                          <td className="py-2 px-4 font-mono" style={{ color: 'var(--text-secondary)' }}>{f.dst_port}</td>
                          <td className="py-2 px-4">
                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${PROTO_COLORS[f.protocol] || 'bg-white/10 text-white/50'}`}>
                              {f.protocol}
                            </span>
                          </td>
                          <td className="py-2 px-4 font-mono" style={{ color: 'var(--text-secondary)' }}>{formatBytes(f.bytes)}</td>
                          <td className="py-2 px-4 font-mono" style={{ color: 'var(--text-muted)' }}>{f.duration.toFixed(2)}s</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {filteredFlows.length === 0 && (
                  <div className="p-8 text-center">
                    <Network className="w-8 h-8 mx-auto mb-2" style={{ color: 'var(--text-muted)', opacity: 0.3 }} />
                    <p className="text-xs" style={{ color: 'var(--text-muted)' }}>No flows match your search</p>
                  </div>
                )}
              </div>
            )}

            {activeTab === 'dns' && (
              <div className="rounded-xl overflow-hidden" style={{ background: 'rgba(8,20,32,0.7)', border: '1px solid rgba(0,229,255,0.08)' }}>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b" style={{ borderColor: 'rgba(0,229,255,0.06)' }}>
                        {['Query Name', 'Type', 'Response', 'Source IP', 'Time'].map(h => (
                          <th key={h} className="text-left py-3 px-4 font-mono font-medium" style={{ color: 'var(--text-muted)' }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {filteredDns.slice(0, 100).map((d) => (
                        <tr key={d.id} className="border-b hover:bg-white/[0.02]" style={{ borderColor: 'rgba(0,229,255,0.03)' }}>
                          <td className="py-2 px-4 font-mono" style={{ color: 'var(--text-primary)' }}>{d.query_name}</td>
                          <td className="py-2 px-4 font-mono" style={{ color: 'var(--accent-purple)' }}>{d.query_type}</td>
                          <td className="py-2 px-4">
                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                              d.response_code === 'NOERROR' ? 'bg-emerald-500/15 text-emerald-400' : 'bg-red-500/15 text-red-400'
                            }`}>{d.response_code}</span>
                          </td>
                          <td className="py-2 px-4 font-mono" style={{ color: 'var(--accent-cyan)' }}>{d.src_ip}</td>
                          <td className="py-2 px-4 font-mono text-[10px]" style={{ color: 'var(--text-muted)' }}>
                            {new Date(d.timestamp).toLocaleTimeString('en-US', { hour12: false })}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {activeTab === 'http' && (
              <div className="rounded-xl overflow-hidden" style={{ background: 'rgba(8,20,32,0.7)', border: '1px solid rgba(0,229,255,0.08)' }}>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b" style={{ borderColor: 'rgba(0,229,255,0.06)' }}>
                        {['Method', 'Host', 'URI', 'Status', 'User Agent', 'Source IP'].map(h => (
                          <th key={h} className="text-left py-3 px-4 font-mono font-medium" style={{ color: 'var(--text-muted)' }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {filteredHttp.slice(0, 100).map((h) => (
                        <tr key={h.id} className="border-b hover:bg-white/[0.02]" style={{ borderColor: 'rgba(0,229,255,0.03)' }}>
                          <td className="py-2 px-4">
                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                              h.method === 'GET' ? 'bg-green-500/15 text-green-400' :
                              h.method === 'POST' ? 'bg-blue-500/15 text-blue-400' :
                              'bg-amber-500/15 text-amber-400'
                            }`}>{h.method}</span>
                          </td>
                          <td className="py-2 px-4 font-mono" style={{ color: 'var(--text-primary)' }}>{h.host}</td>
                          <td className="py-2 px-4 font-mono truncate max-w-[200px]" style={{ color: 'var(--text-secondary)' }}>{h.uri}</td>
                          <td className="py-2 px-4">
                            <span className={`font-mono text-[10px] ${
                              h.status_code < 300 ? 'text-emerald-400' : h.status_code < 400 ? 'text-amber-400' : 'text-red-400'
                            }`}>{h.status_code}</span>
                          </td>
                          <td className="py-2 px-4 font-mono text-[10px] truncate max-w-[150px]" style={{ color: 'var(--text-muted)' }}>{h.user_agent}</td>
                          <td className="py-2 px-4 font-mono" style={{ color: 'var(--accent-cyan)' }}>{h.src_ip}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {activeTab === 'anomalies' && (
              <div className="space-y-2">
                {anomalies.length === 0 ? (
                  <div className="rounded-xl p-12 text-center" style={{ background: 'rgba(8,20,32,0.7)', border: '1px solid rgba(0,229,255,0.08)' }}>
                    <CheckCircle className="w-12 h-12 mx-auto mb-3" style={{ color: 'var(--accent-green)', opacity: 0.3 }} />
                    <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>No anomalies detected</p>
                  </div>
                ) : (
                  anomalies.map((a) => (
                    <motion.div key={a.id} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
                      className="rounded-xl p-4" style={{ background: 'rgba(8,20,32,0.7)', backdropFilter: 'blur(24px)', border: '1px solid rgba(0,229,255,0.08)' }}>
                      <div className="flex items-center gap-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${SEVERITY_COLORS[a.severity] || SEVERITY_COLORS.low}`}>
                          {a.severity}
                        </span>
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{a.type}</p>
                          <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-muted)' }}>{a.description}</p>
                        </div>
                        <div className="text-right shrink-0">
                          <p className="text-[10px] font-mono" style={{ color: 'var(--accent-cyan)' }}>{a.src_ip} → {a.dst_ip}</p>
                          <p className="text-[10px] font-mono mt-0.5" style={{ color: 'var(--text-muted)' }}>
                            Confidence: {(a.confidence * 100).toFixed(0)}%
                          </p>
                        </div>
                      </div>
                    </motion.div>
                  ))
                )}
              </div>
            )}
          </motion.div>
        </AnimatePresence>
      )}
    </div>
  );
}
