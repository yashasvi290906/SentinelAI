"use client";
import { useState, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { threatHuntSearchAPI } from "@/lib/api";
import GlassCard from "@/components/ui/GlassCard";
import { Search, Filter, Clock, AlertTriangle, Shield, Activity, ChevronRight, X } from "lucide-react";

interface HuntResult {
  detections: any[];
  alerts: any[];
  events: any[];
  timeline: any[];
  total: number;
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "text-red-400 bg-red-500/10 border-red-500/20",
  HIGH: "text-orange-400 bg-orange-500/10 border-orange-500/20",
  MEDIUM: "text-amber-400 bg-amber-500/10 border-amber-500/20",
  LOW: "text-cyan-400 bg-cyan-500/10 border-cyan-500/20",
  INFO: "text-slate-400 bg-slate-500/10 border-slate-500/20",
};

const QUICK_SEARCHES = [
  { label: "Critical threats", query: "severity:CRITICAL" },
  { label: "Brute force attacks", query: "bruteforce" },
  { label: "Port scans", query: "portscan" },
  { label: "Web attacks", query: "webattack" },
  { label: "Data exfiltration", query: "infiltration" },
  { label: "All alerts", query: "type:alert" },
];

export default function ThreatHunt() {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<HuntResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<"timeline" | "detections" | "alerts" | "events">("timeline");
  const [filters, setFilters] = useState({ severity: "", attack_type: "", source_ip: "" });
  const [showFilters, setShowFilters] = useState(false);

  const handleSearch = useCallback(async (searchQuery?: string) => {
    const q = searchQuery || query;
    if (!q && !filters.severity && !filters.attack_type && !filters.source_ip) return;

    setLoading(true);
    try {
      const data = await threatHuntSearchAPI({
        q,
        severity: filters.severity,
        attack_type: filters.attack_type,
        source_ip: filters.source_ip,
        limit: 200,
      });
      setResults(data);
    } catch {
      setResults({ detections: [], alerts: [], events: [], timeline: [], total: 0 });
    } finally {
      setLoading(false);
    }
  }, [query, filters]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") handleSearch();
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-[var(--text-primary)] flex items-center gap-2">
            <Search className="w-6 h-6 text-[var(--accent-cyan)]" />
            Threat Hunting
          </h1>
          <p className="text-sm text-[var(--text-muted)] mt-1">
            Search across detections, alerts, and events
          </p>
        </div>
      </div>

      {/* Search Bar */}
      <GlassCard className="p-4">
        <div className="flex items-center gap-3">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-[var(--text-muted)]" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Search by IP, hostname, attack type, severity... (e.g., ip:45.67.23.19, severity:critical)"
              className="w-full pl-11 pr-4 py-3 bg-[var(--bg-deep)]/50 border border-[var(--accent-cyan)]/10 rounded-lg text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:outline-none focus:border-[var(--accent-cyan)]/30 transition-colors"
            />
          </div>
          <button
            onClick={() => setShowFilters(!showFilters)}
            className={`px-4 py-3 rounded-lg border transition-colors flex items-center gap-2 ${
              showFilters
                ? "bg-[var(--accent-cyan)]/10 border-[var(--accent-cyan)]/30 text-[var(--accent-cyan)]"
                : "bg-[var(--bg-deep)]/50 border-[var(--accent-cyan)]/10 text-[var(--text-muted)] hover:text-[var(--text-primary)]"
            }`}
          >
            <Filter className="w-4 h-4" />
            Filters
          </button>
          <button
            onClick={() => handleSearch()}
            disabled={loading}
            className="px-6 py-3 bg-[var(--accent-cyan)]/20 border border-[var(--accent-cyan)]/30 rounded-lg text-[var(--accent-cyan)] font-medium hover:bg-[var(--accent-cyan)]/30 transition-colors disabled:opacity-50"
          >
            {loading ? "Searching..." : "Hunt"}
          </button>
        </div>

        {/* Filters */}
        <AnimatePresence>
          {showFilters && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: "auto", opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              className="overflow-hidden"
            >
              <div className="grid grid-cols-3 gap-4 mt-4 pt-4 border-t border-[var(--accent-cyan)]/10">
                <div>
                  <label className="text-xs text-[var(--text-muted)] mb-1 block">Severity</label>
                  <select
                    value={filters.severity}
                    onChange={(e) => setFilters(f => ({ ...f, severity: e.target.value }))}
                    className="w-full px-3 py-2 bg-[var(--bg-deep)]/50 border border-[var(--accent-cyan)]/10 rounded-lg text-[var(--text-primary)] text-sm focus:outline-none focus:border-[var(--accent-cyan)]/30"
                  >
                    <option value="">All</option>
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                  </select>
                </div>
                <div>
                  <label className="text-xs text-[var(--text-muted)] mb-1 block">Attack Type</label>
                  <select
                    value={filters.attack_type}
                    onChange={(e) => setFilters(f => ({ ...f, attack_type: e.target.value }))}
                    className="w-full px-3 py-2 bg-[var(--bg-deep)]/50 border border-[var(--accent-cyan)]/10 rounded-lg text-[var(--text-primary)] text-sm focus:outline-none focus:border-[var(--accent-cyan)]/30"
                  >
                    <option value="">All</option>
                    <option value="brute_force">Brute Force</option>
                    <option value="port_scan">Port Scan</option>
                    <option value="dos">DoS</option>
                    <option value="web_attack">Web Attack</option>
                    <option value="data_exfiltration">Data Exfiltration</option>
                    <option value="lateral_movement">Lateral Movement</option>
                  </select>
                </div>
                <div>
                  <label className="text-xs text-[var(--text-muted)] mb-1 block">Source IP</label>
                  <input
                    type="text"
                    value={filters.source_ip}
                    onChange={(e) => setFilters(f => ({ ...f, source_ip: e.target.value }))}
                    placeholder="e.g., 10.0.0.1"
                    className="w-full px-3 py-2 bg-[var(--bg-deep)]/50 border border-[var(--accent-cyan)]/10 rounded-lg text-[var(--text-primary)] text-sm placeholder:text-[var(--text-muted)] focus:outline-none focus:border-[var(--accent-cyan)]/30"
                  />
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Quick Searches */}
        <div className="flex flex-wrap gap-2 mt-3">
          {QUICK_SEARCHES.map((qs) => (
            <button
              key={qs.label}
              onClick={() => { setQuery(qs.query); handleSearch(qs.query); }}
              className="px-3 py-1 text-xs bg-[var(--bg-deep)]/50 border border-[var(--accent-cyan)]/10 rounded-full text-[var(--text-muted)] hover:text-[var(--accent-cyan)] hover:border-[var(--accent-cyan)]/30 transition-colors"
            >
              {qs.label}
            </button>
          ))}
        </div>
      </GlassCard>

      {/* Results */}
      {results && (
        <div className="space-y-4">
          {/* Stats */}
          <div className="grid grid-cols-4 gap-4">
            {[
              { label: "Total Results", value: results.total, icon: Search, color: "cyan" },
              { label: "Detections", value: results.detections.length, icon: Shield, color: "red" },
              { label: "Alerts", value: results.alerts.length, icon: AlertTriangle, color: "amber" },
              { label: "Events", value: results.events.length, icon: Activity, color: "green" },
            ].map((stat) => (
              <GlassCard key={stat.label} className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-xs text-[var(--text-muted)]">{stat.label}</p>
                    <p className="text-2xl font-bold text-[var(--text-primary)]">{stat.value}</p>
                  </div>
                  <stat.icon className={`w-8 h-8 text-[var(--accent-${stat.color})]/30`} />
                </div>
              </GlassCard>
            ))}
          </div>

          {/* Tabs */}
          <div className="flex gap-1 p-1 bg-[var(--bg-deep)]/30 rounded-lg border border-[var(--accent-cyan)]/5">
            {(["timeline", "detections", "alerts", "events"] as const).map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`flex-1 px-4 py-2 rounded-md text-sm font-medium transition-all ${
                  activeTab === tab
                    ? "bg-[var(--accent-cyan)]/15 text-[var(--accent-cyan)]"
                    : "text-[var(--text-muted)] hover:text-[var(--text-primary)]"
                }`}
              >
                {tab.charAt(0).toUpperCase() + tab.slice(1)}
                <span className="ml-2 text-xs opacity-60">
                  {tab === "timeline" ? results.timeline.length :
                   tab === "detections" ? results.detections.length :
                   tab === "alerts" ? results.alerts.length :
                   results.events.length}
                </span>
              </button>
            ))}
          </div>

          {/* Tab Content */}
          <GlassCard className="p-4 max-h-[600px] overflow-y-auto">
            {activeTab === "timeline" && (
              <div className="space-y-2">
                {results.timeline.length === 0 ? (
                  <p className="text-center text-[var(--text-muted)] py-8">No timeline data</p>
                ) : (
                  results.timeline.map((item, i) => (
                    <motion.div
                      key={i}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: i * 0.02 }}
                      className="flex items-start gap-3 p-3 rounded-lg bg-[var(--bg-deep)]/30 hover:bg-[var(--bg-deep)]/50 transition-colors"
                    >
                      <div className="mt-1">
                        {item.type === "detection" ? (
                          <Shield className="w-4 h-4 text-red-400" />
                        ) : (
                          <AlertTriangle className="w-4 h-4 text-amber-400" />
                        )}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium text-[var(--text-primary)]">{item.title}</span>
                          <span className={`px-2 py-0.5 text-xs rounded-full border ${SEVERITY_COLORS[item.severity] || SEVERITY_COLORS.INFO}`}>
                            {item.severity}
                          </span>
                          <span className="text-xs text-[var(--text-muted)]">{item.type}</span>
                        </div>
                        {item.description && (
                          <p className="text-xs text-[var(--text-muted)] mt-1 truncate">{item.description}</p>
                        )}
                        <div className="flex items-center gap-4 mt-1 text-xs text-[var(--text-muted)]">
                          {item.source_ip && <span>IP: {item.source_ip}</span>}
                          {item.timestamp && (
                            <span className="flex items-center gap-1">
                              <Clock className="w-3 h-3" />
                              {new Date(item.timestamp).toLocaleString()}
                            </span>
                          )}
                        </div>
                      </div>
                      <ChevronRight className="w-4 h-4 text-[var(--text-muted)] mt-1" />
                    </motion.div>
                  ))
                )}
              </div>
            )}

            {activeTab === "detections" && (
              <div className="space-y-2">
                {results.detections.length === 0 ? (
                  <p className="text-center text-[var(--text-muted)] py-8">No detections found</p>
                ) : (
                  results.detections.map((det, i) => (
                    <motion.div
                      key={det.id || i}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: i * 0.02 }}
                      className="p-3 rounded-lg bg-[var(--bg-deep)]/30 hover:bg-[var(--bg-deep)]/50 transition-colors"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Shield className="w-4 h-4 text-red-400" />
                          <span className="text-sm font-medium text-[var(--text-primary)]">{det.threat_type}</span>
                          <span className={`px-2 py-0.5 text-xs rounded-full border ${SEVERITY_COLORS[det.severity] || SEVERITY_COLORS.INFO}`}>
                            {det.severity}
                          </span>
                        </div>
                        <span className="text-xs text-[var(--text-muted)]">
                          Confidence: {((det.confidence || 0) * 100).toFixed(0)}%
                        </span>
                      </div>
                      <p className="text-xs text-[var(--text-muted)] mt-1">{det.description}</p>
                      <div className="flex items-center gap-4 mt-2 text-xs text-[var(--text-muted)]">
                        {det.source_ip && <span>Source: {det.source_ip}</span>}
                        {det.dest_ip && <span>Dest: {det.dest_ip}</span>}
                        {det.mitre_technique && <span>MITRE: {det.mitre_technique}</span>}
                      </div>
                    </motion.div>
                  ))
                )}
              </div>
            )}

            {activeTab === "alerts" && (
              <div className="space-y-2">
                {results.alerts.length === 0 ? (
                  <p className="text-center text-[var(--text-muted)] py-8">No alerts found</p>
                ) : (
                  results.alerts.map((alert, i) => (
                    <motion.div
                      key={alert.id || i}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: i * 0.02 }}
                      className="p-3 rounded-lg bg-[var(--bg-deep)]/30 hover:bg-[var(--bg-deep)]/50 transition-colors"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <AlertTriangle className="w-4 h-4 text-amber-400" />
                          <span className="text-sm font-medium text-[var(--text-primary)]">{alert.title}</span>
                          <span className={`px-2 py-0.5 text-xs rounded-full border ${SEVERITY_COLORS[alert.severity] || SEVERITY_COLORS.INFO}`}>
                            {alert.severity}
                          </span>
                        </div>
                        <span className={`text-xs px-2 py-0.5 rounded-full ${
                          alert.status === "open" ? "bg-red-500/10 text-red-400" : "bg-green-500/10 text-green-400"
                        }`}>
                          {alert.status}
                        </span>
                      </div>
                      <p className="text-xs text-[var(--text-muted)] mt-1">{alert.description}</p>
                      <div className="flex items-center gap-4 mt-2 text-xs text-[var(--text-muted)]">
                        {alert.source_ip && <span>Source: {alert.source_ip}</span>}
                        {alert.mitre_technique && <span>MITRE: {alert.mitre_technique}</span>}
                        {alert.created_at && <span>{new Date(alert.created_at).toLocaleString()}</span>}
                      </div>
                    </motion.div>
                  ))
                )}
              </div>
            )}

            {activeTab === "events" && (
              <div className="space-y-2">
                {results.events.length === 0 ? (
                  <p className="text-center text-[var(--text-muted)] py-8">No events found</p>
                ) : (
                  results.events.map((evt, i) => (
                    <motion.div
                      key={i}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: i * 0.02 }}
                      className="p-3 rounded-lg bg-[var(--bg-deep)]/30 hover:bg-[var(--bg-deep)]/50 transition-colors font-mono text-xs"
                    >
                      <div className="flex items-center gap-2">
                        <Activity className="w-3 h-3 text-[var(--accent-cyan)]" />
                        <span className="text-[var(--text-primary)]">{evt.event_type || "unknown"}</span>
                        {evt.source_ip && <span className="text-[var(--text-muted)]">from {evt.source_ip}</span>}
                        {evt.hostname && <span className="text-[var(--text-muted)]">host: {evt.hostname}</span>}
                        {evt.source && <span className="text-[var(--text-muted)]">src: {evt.source}</span>}
                      </div>
                      {evt.message && (
                        <p className="text-[var(--text-muted)] mt-1 truncate">{evt.message}</p>
                      )}
                    </motion.div>
                  ))
                )}
              </div>
            )}
          </GlassCard>
        </div>
      )}

      {/* Empty State */}
      {!results && !loading && (
        <GlassCard className="p-12 text-center">
          <Search className="w-12 h-12 text-[var(--accent-cyan)]/30 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-[var(--text-primary)] mb-2">Start Hunting</h3>
          <p className="text-sm text-[var(--text-muted)] max-w-md mx-auto">
            Search across all detections, alerts, and events. Use keywords like IP addresses,
            hostnames, attack types, or severity levels. Try the quick searches above.
          </p>
        </GlassCard>
      )}
    </div>
  );
}
