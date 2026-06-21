'use client';
import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Search, Globe, Shield, AlertTriangle, MapPin, Server, Loader2, ExternalLink } from 'lucide-react';
import { investigateIPAPI } from '@/lib/api';
import GlassCard from '@/components/ui/GlassCard';

export default function InvestigationModule() {
  const [query, setQuery] = useState('');
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSearch = async () => {
    if (!query.trim()) return;
    setLoading(true);
    setError('');
    setResult(null);
    
    try {
      const data = await investigateIPAPI(query.trim());
      setResult(data);
    } catch (e: any) {
      setError(e.response?.data?.detail || 'Investigation failed');
    }
    setLoading(false);
  };

  return (
    <div className="space-y-6">
      {/* Search */}
      <GlassCard className="p-6">
        <h2 className="text-xl font-semibold text-white mb-4 flex items-center gap-2">
          <Search className="w-5 h-5 text-cyan-400" />
          IP Investigation
        </h2>
        <p className="text-white/40 text-sm mb-4">
          Investigate an IP address across all logs and threat intelligence sources.
        </p>
        
        <div className="flex gap-3">
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
            placeholder="Enter IP address (e.g., 192.168.1.100)"
            className="flex-1 bg-white/5 border border-white/10 rounded-lg px-4 py-2.5 text-white placeholder-white/30 outline-none focus:border-cyan-400/50 font-mono"
          />
          <button
            onClick={handleSearch}
            disabled={loading || !query.trim()}
            className="px-6 py-2.5 bg-cyan-500/20 border border-cyan-400/30 rounded-lg text-cyan-400 font-medium hover:bg-cyan-500/30 transition-colors disabled:opacity-50"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Investigate'}
          </button>
        </div>
      </GlassCard>

      {/* Results */}
      <AnimatePresence>
        {error && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
            <GlassCard className="p-4 border-red-500/20">
              <div className="flex items-center gap-2 text-red-400">
                <AlertTriangle className="w-4 h-4" />
                <p className="text-sm">{error}</p>
              </div>
            </GlassCard>
          </motion.div>
        )}

        {result && (
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="space-y-4">
            {/* IP Header */}
            <GlassCard className="p-6">
              <div className="flex items-center gap-4">
                <div className="w-12 h-12 rounded-xl bg-cyan-500/10 flex items-center justify-center">
                  <Globe className="w-6 h-6 text-cyan-400" />
                </div>
                <div>
                  <h3 className="text-xl font-mono font-bold text-white">{result.ip}</h3>
                  <p className="text-white/40 text-sm">
                    Investigated at {new Date(result.timestamp).toLocaleString()}
                  </p>
                </div>
                <div className="ml-auto text-right">
                  <p className="text-sm text-white/40">Confidence</p>
                  <p className={`text-2xl font-bold ${
                    result.confidence > 0.6 ? 'text-red-400' :
                    result.confidence > 0.3 ? 'text-orange-400' : 'text-emerald-400'
                  }`}>
                    {(result.confidence * 100).toFixed(0)}%
                  </p>
                </div>
              </div>
            </GlassCard>

            {/* Intelligence Sources */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* AbuseIPDB */}
              <GlassCard className="p-5">
                <h4 className="text-sm font-medium text-white/60 mb-3 flex items-center gap-2">
                  <Shield className="w-4 h-4 text-orange-400" />
                  AbuseIPDB
                </h4>
                {result.sources?.abuseipdb?.status === 'success' ? (
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-white/40">Abuse Score</span>
                      <span className={`font-bold ${
                        result.sources.abuseipdb.abuse_confidence_score > 50 ? 'text-red-400' :
                        result.sources.abuseipdb.abuse_confidence_score > 20 ? 'text-orange-400' : 'text-emerald-400'
                      }`}>{result.sources.abuseipdb.abuse_confidence_score}%</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-white/40">Country</span>
                      <span className="text-white/70">{result.sources.abuseipdb.country_code || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-white/40">ISP</span>
                      <span className="text-white/70 text-xs truncate max-w-[150px]">{result.sources.abuseipdb.isp || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-white/40">Total Reports</span>
                      <span className="text-white/70">{result.sources.abuseipdb.total_reports || 0}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-white/40">Tor Exit Node</span>
                      <span className={result.sources.abuseipdb.is_tor ? 'text-orange-400' : 'text-white/50'}>
                        {result.sources.abuseipdb.is_tor ? 'Yes' : 'No'}
                      </span>
                    </div>
                  </div>
                ) : (
                  <p className="text-white/30 text-sm">{result.sources?.abuseipdb?.message || 'No data'}</p>
                )}
              </GlassCard>

              {/* VirusTotal */}
              <GlassCard className="p-5">
                <h4 className="text-sm font-medium text-white/60 mb-3 flex items-center gap-2">
                  <Shield className="w-4 h-4 text-purple-400" />
                  VirusTotal
                </h4>
                {result.sources?.virustotal?.status === 'success' ? (
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-white/40">Malicious</span>
                      <span className={`font-bold ${result.sources.virustotal.malicious > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                        {result.sources.virustotal.malicious}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-white/40">Suspicious</span>
                      <span className="text-orange-400">{result.sources.virustotal.suspicious}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-white/40">Harmless</span>
                      <span className="text-white/50">{result.sources.virustotal.harmless}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-white/40">Country</span>
                      <span className="text-white/70">{result.sources.virustotal.country || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-white/40">ASN Owner</span>
                      <span className="text-white/70 text-xs truncate max-w-[150px]">{result.sources.virustotal.as_owner || 'N/A'}</span>
                    </div>
                  </div>
                ) : (
                  <p className="text-white/30 text-sm">{result.sources?.virustotal?.message || 'No data'}</p>
                )}
              </GlassCard>

              {/* Shodan */}
              <GlassCard className="p-5">
                <h4 className="text-sm font-medium text-white/60 mb-3 flex items-center gap-2">
                  <Server className="w-4 h-4 text-blue-400" />
                  Shodan
                </h4>
                {result.sources?.shodan?.status === 'success' ? (
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-white/40">Organization</span>
                      <span className="text-white/70 text-xs truncate max-w-[150px]">{result.sources.shodan.org || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-white/40">OS</span>
                      <span className="text-white/70">{result.sources.shodan.os || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-white/40">ISP</span>
                      <span className="text-white/70 text-xs truncate max-w-[150px]">{result.sources.shodan.isp || 'N/A'}</span>
                    </div>
                    <div>
                      <span className="text-white/40 text-xs">Open Ports</span>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {(result.sources.shodan.ports || []).map((p: number) => (
                          <span key={p} className="px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 text-xs font-mono">{p}</span>
                        ))}
                        {(!result.sources.shodan.ports || result.sources.shodan.ports.length === 0) && (
                          <span className="text-white/30 text-xs">None detected</span>
                        )}
                      </div>
                    </div>
                    {result.sources.shodan.vulns?.length > 0 && (
                      <div>
                        <span className="text-white/40 text-xs">Known Vulnerabilities</span>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {result.sources.shodan.vulns.slice(0, 5).map((v: string) => (
                            <span key={v} className="px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 text-xs font-mono">{v}</span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ) : (
                  <p className="text-white/30 text-sm">{result.sources?.shodan?.message || 'No data'}</p>
                )}
              </GlassCard>
            </div>

            {/* Local Detections */}
            {result.local_detections?.length > 0 && (
              <GlassCard className="p-5">
                <h4 className="text-sm font-medium text-white/60 mb-3">Local Detections from Uploaded Logs</h4>
                <div className="space-y-2">
                  {result.local_detections.map((d: any, i: number) => (
                    <div key={i} className="flex items-center gap-3 p-2 rounded bg-white/[0.02] text-sm">
                      <span className={`px-2 py-0.5 rounded text-xs font-bold ${
                        d.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400' :
                        d.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400' :
                        'bg-yellow-500/20 text-yellow-400'
                      }`}>{d.severity}</span>
                      <span className="text-white/70">{d.threat_type?.replace(/_/g, ' ')}</span>
                      <span className="text-white/40 ml-auto">{d.mitre_technique}</span>
                    </div>
                  ))}
                </div>
              </GlassCard>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
