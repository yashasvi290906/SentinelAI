'use client';
import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, AlertTriangle, Search, Filter, ExternalLink, ChevronDown, ChevronUp } from 'lucide-react';
import { useLogStore, ThreatDetection } from '@/stores/logStore';
import { getThreatsAPI, getThreatSummaryAPI } from '@/lib/api';
import GlassCard from '@/components/ui/GlassCard';

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'bg-red-500/20 text-red-400 border-red-500/30',
  HIGH: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  MEDIUM: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  LOW: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  INFO: 'bg-white/5 text-white/50 border-white/10',
};

export default function ThreatDetectionModule() {
  const { threats, setThreats, threatSummary, setThreatSummary } = useLogStore();
  const [loading, setLoading] = useState(false);
  const [filters, setFilters] = useState({ severity: '', threat_type: '', source_ip: '' });
  const [expandedThreat, setExpandedThreat] = useState<string | null>(null);
  const [sortBy, setSortBy] = useState<'severity' | 'time' | 'confidence'>('severity');

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [threatsData, summaryData] = await Promise.all([
        getThreatsAPI({ limit: 200 }),
        getThreatSummaryAPI(),
      ]);
      setThreats(threatsData.threats || []);
      setThreatSummary(summaryData);
    } catch (e) {
      console.error('Failed to fetch threats');
    }
    setLoading(false);
  }, [setThreats, setThreatSummary]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const filteredThreats = threats.filter((t) => {
    if (filters.severity && t.severity !== filters.severity) return false;
    if (filters.threat_type && t.threat_type !== filters.threat_type) return false;
    if (filters.source_ip && !t.source_ip.includes(filters.source_ip)) return false;
    return true;
  }).sort((a, b) => {
    if (sortBy === 'severity') {
      const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
      return (order[a.severity as keyof typeof order] || 5) - (order[b.severity as keyof typeof order] || 5);
    }
    if (sortBy === 'confidence') return b.confidence - a.confidence;
    return new Date(b.detection_time).getTime() - new Date(a.detection_time).getTime();
  });

  const uniqueTypes = [...new Set(threats.map(t => t.threat_type))];

  return (
    <div className="space-y-6">
      {/* Summary Cards */}
      {threatSummary && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((sev) => (
            <GlassCard key={sev} className="p-4 text-center">
              <p className="text-xs text-white/40 uppercase">{sev}</p>
              <p className={`text-2xl font-bold mt-1 ${
                sev === 'CRITICAL' ? 'text-red-400' :
                sev === 'HIGH' ? 'text-orange-400' :
                sev === 'MEDIUM' ? 'text-yellow-400' :
                sev === 'LOW' ? 'text-blue-400' : 'text-white/50'
              }`}>{threatSummary.by_severity?.[sev] || 0}</p>
            </GlassCard>
          ))}
        </div>
      )}

      {/* Threat Types Summary */}
      {threatSummary && Object.keys(threatSummary.by_type || {}).length > 0 && (
        <GlassCard className="p-4">
          <h3 className="text-sm font-medium text-white/60 mb-3">Threat Distribution</h3>
          <div className="flex flex-wrap gap-2">
            {Object.entries(threatSummary.by_type || {}).sort((a, b) => b[1] - a[1]).map(([type, count]) => (
              <span key={type} className="px-3 py-1.5 rounded-lg bg-white/5 text-white/70 text-sm">
                {type.replace(/_/g, ' ')} <span className="text-cyan-400 ml-1">{count}</span>
              </span>
            ))}
          </div>
        </GlassCard>
      )}

      {/* Filters */}
      <GlassCard className="p-4">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-white/40" />
            <span className="text-sm text-white/60">Filters:</span>
          </div>
          
          <select
            value={filters.severity}
            onChange={(e) => setFilters(f => ({ ...f, severity: e.target.value }))}
            className="bg-white/5 border border-white/10 rounded-lg px-3 py-1.5 text-sm text-white/70 outline-none focus:border-cyan-400/50"
          >
            <option value="">All Severities</option>
            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(s => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
          
          <select
            value={filters.threat_type}
            onChange={(e) => setFilters(f => ({ ...f, threat_type: e.target.value }))}
            className="bg-white/5 border border-white/10 rounded-lg px-3 py-1.5 text-sm text-white/70 outline-none focus:border-cyan-400/50"
          >
            <option value="">All Types</option>
            {uniqueTypes.map(t => (
              <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>
            ))}
          </select>
          
          <input
            type="text"
            placeholder="Filter by source IP..."
            value={filters.source_ip}
            onChange={(e) => setFilters(f => ({ ...f, source_ip: e.target.value }))}
            className="bg-white/5 border border-white/10 rounded-lg px-3 py-1.5 text-sm text-white/70 outline-none focus:border-cyan-400/50 w-40"
          />
          
          <div className="flex items-center gap-1 ml-auto">
            <span className="text-xs text-white/40">Sort:</span>
            {(['severity', 'confidence', 'time'] as const).map((s) => (
              <button
                key={s}
                onClick={() => setSortBy(s)}
                className={`px-2 py-1 rounded text-xs ${
                  sortBy === s ? 'bg-cyan-500/20 text-cyan-400' : 'text-white/40 hover:text-white/60'
                }`}
              >{s}</button>
            ))}
          </div>
          
          <button onClick={fetchData} className="text-sm text-cyan-400 hover:text-cyan-300">
            {loading ? 'Loading...' : 'Refresh'}
          </button>
        </div>
      </GlassCard>

      {/* Threats List */}
      <div className="space-y-2">
        <AnimatePresence>
          {filteredThreats.length === 0 ? (
            <GlassCard className="p-8 text-center">
              <Shield className="w-12 h-12 text-white/20 mx-auto mb-3" />
              <p className="text-white/40">
                {loading ? 'Loading threats...' : 'No threats detected yet. Upload logs to begin analysis.'}
              </p>
            </GlassCard>
          ) : (
            filteredThreats.map((threat) => (
              <motion.div
                key={threat.id}
                layout
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0 }}
              >
                <GlassCard className="p-4">
                  <div
                    className="flex items-center gap-3 cursor-pointer"
                    onClick={() => setExpandedThreat(expandedThreat === threat.id ? null : threat.id)}
                  >
                    <span className={`px-2 py-0.5 rounded text-xs font-bold ${SEVERITY_COLORS[threat.severity] || SEVERITY_COLORS.INFO}`}>
                      {threat.severity}
                    </span>
                    
                    <div className="flex-1 min-w-0">
                      <p className="text-white font-medium text-sm">
                        {threat.threat_type?.replace(/_/g, ' ')}
                      </p>
                      <p className="text-white/40 text-xs mt-0.5 truncate">{threat.description}</p>
                    </div>
                    
                    <div className="text-right shrink-0">
                      <p className="text-cyan-400 text-sm font-mono">{(threat.confidence * 100).toFixed(0)}%</p>
                      <p className="text-white/30 text-xs">{threat.mitre_technique}</p>
                    </div>
                    
                    <div className="text-right shrink-0">
                      <p className="text-white/50 text-xs font-mono">{threat.source_ip}</p>
                      <p className="text-white/30 text-xs">→ {threat.dest_ip}:{threat.dest_port}</p>
                    </div>
                    
                    {expandedThreat === threat.id ? (
                      <ChevronUp className="w-4 h-4 text-white/30" />
                    ) : (
                      <ChevronDown className="w-4 h-4 text-white/30" />
                    )}
                  </div>
                  
                  <AnimatePresence>
                    {expandedThreat === threat.id && (
                      <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        className="overflow-hidden"
                      >
                        <div className="mt-4 pt-4 border-t border-white/5 space-y-3">
                          {/* MITRE */}
                          <div className="flex items-center gap-4 text-sm">
                            <span className="text-white/40">MITRE ATT&CK:</span>
                            <span className="px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 text-xs font-mono">
                              {threat.mitre_technique}
                            </span>
                            <span className="text-white/50">{threat.mitre_tactic}</span>
                          </div>
                          
                          {/* Evidence */}
                          {threat.evidence?.length > 0 && (
                            <div>
                              <p className="text-white/40 text-xs mb-1">Evidence:</p>
                              <ul className="space-y-1">
                                {threat.evidence.map((e, i) => (
                                  <li key={i} className="text-white/60 text-sm pl-3 border-l border-white/10">
                                    {typeof e === 'string' ? e : JSON.stringify(e)}
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}
                          
                          {/* Recommendations */}
                          {threat.recommendations?.length > 0 && (
                            <div>
                              <p className="text-white/40 text-xs mb-1">Recommendations:</p>
                              <ul className="space-y-1">
                                {threat.recommendations.map((r, i) => (
                                  <li key={i} className="text-white/60 text-sm pl-3 border-l border-emerald-500/30">
                                    {typeof r === 'string' ? r : JSON.stringify(r)}
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}
                          
                          {/* Time Range */}
                          <div className="flex items-center gap-4 text-xs text-white/40">
                            <span>First seen: {threat.first_seen?.slice(0, 19)}</span>
                            <span>Last seen: {threat.last_seen?.slice(0, 19)}</span>
                            <span>Events: {threat.event_count}</span>
                          </div>
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </GlassCard>
              </motion.div>
            ))
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
