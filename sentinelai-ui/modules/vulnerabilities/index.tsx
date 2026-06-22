"use client";
import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import { searchVulnerabilitiesAPI } from "@/lib/api";
import GlassCard from "@/components/ui/GlassCard";
import { Bug, Search, ExternalLink, Shield, AlertTriangle, ChevronDown, ChevronUp } from "lucide-react";

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "text-red-400 bg-red-500/10 border-red-500/20",
  HIGH: "text-orange-400 bg-orange-500/10 border-orange-500/20",
  MEDIUM: "text-amber-400 bg-amber-500/10 border-amber-500/20",
  LOW: "text-cyan-400 bg-cyan-500/10 border-cyan-500/20",
};

export default function Vulnerabilities() {
  const [vulns, setVulns] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [cvssFilter, setCvssFilter] = useState(0);

  const fetchData = useCallback(async (keyword?: string, min?: number) => {
    setLoading(true);
    try {
      const data = await searchVulnerabilitiesAPI(keyword || "", min || cvssFilter, 30);
      setVulns(data.vulnerabilities || []);
    } catch {
      setVulns([]);
    } finally {
      setLoading(false);
    }
  }, [cvssFilter]);

  useEffect(() => { fetchData(); }, []);

  const handleSearch = () => { fetchData(search); };

  const stats = {
    total: vulns.length,
    critical: vulns.filter(v => v.severity === "CRITICAL").length,
    high: vulns.filter(v => v.severity === "HIGH").length,
    medium: vulns.filter(v => v.severity === "MEDIUM").length,
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-[var(--text-primary)] flex items-center gap-2">
            <Bug className="w-6 h-6 text-[var(--accent-cyan)]" />
            Vulnerability Dashboard
          </h1>
          <p className="text-sm text-[var(--text-muted)] mt-1">NVD CVE database — search and track vulnerabilities</p>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: "Total CVEs", value: stats.total, color: "cyan" },
          { label: "Critical", value: stats.critical, color: "red" },
          { label: "High", value: stats.high, color: "orange" },
          { label: "Medium", value: stats.medium, color: "amber" },
        ].map(s => (
          <GlassCard key={s.label} className="p-4">
            <p className="text-xs text-[var(--text-muted)]">{s.label}</p>
            <p className={`text-2xl font-bold text-[var(--accent-${s.color})]`}>{s.value}</p>
          </GlassCard>
        ))}
      </div>

      {/* Search */}
      <GlassCard className="p-4">
        <div className="flex items-center gap-3">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-muted)]" />
            <input
              type="text" value={search} onChange={e => setSearch(e.target.value)}
              onKeyDown={e => e.key === "Enter" && handleSearch()}
              placeholder="Search CVEs (e.g., apache, log4j, windows)..."
              className="w-full pl-10 pr-4 py-2 bg-[var(--bg-deep)]/50 border border-[var(--accent-cyan)]/10 rounded-lg text-[var(--text-primary)] text-sm placeholder:text-[var(--text-muted)] focus:outline-none focus:border-[var(--accent-cyan)]/30"
            />
          </div>
          <select
            value={cvssFilter} onChange={e => { setCvssFilter(Number(e.target.value)); fetchData(search, Number(e.target.value)); }}
            className="px-3 py-2 bg-[var(--bg-deep)]/50 border border-[var(--accent-cyan)]/10 rounded-lg text-[var(--text-primary)] text-sm"
          >
            <option value={0}>All Severity</option>
            <option value={9}>Critical (9+)</option>
            <option value={7}>High (7+)</option>
            <option value={4}>Medium (4+)</option>
          </select>
          <button onClick={handleSearch} className="px-4 py-2 bg-[var(--accent-cyan)]/20 border border-[var(--accent-cyan)]/30 rounded-lg text-[var(--accent-cyan)] text-sm font-medium hover:bg-[var(--accent-cyan)]/30">
            Search NVD
          </button>
        </div>
      </GlassCard>

      {/* Results */}
      {loading ? (
        <GlassCard className="p-8 text-center text-[var(--text-muted)]">Loading vulnerabilities...</GlassCard>
      ) : vulns.length === 0 ? (
        <GlassCard className="p-12 text-center">
          <Bug className="w-10 h-10 text-[var(--accent-cyan)]/30 mx-auto mb-3" />
          <p className="text-[var(--text-muted)]">No vulnerabilities found. Try a different search.</p>
        </GlassCard>
      ) : (
        <div className="space-y-2">
          {vulns.map((vuln, i) => (
            <motion.div key={vuln.id} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.03 }}>
              <GlassCard className="p-4">
                <div className="flex items-start justify-between cursor-pointer" onClick={() => setExpanded(expanded === vuln.id ? null : vuln.id)}>
                  <div className="flex items-center gap-3 flex-1 min-w-0">
                    <Shield className={`w-5 h-5 ${vuln.severity === "CRITICAL" ? "text-red-400" : vuln.severity === "HIGH" ? "text-orange-400" : "text-amber-400"}`} />
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-bold text-[var(--accent-cyan)]">{vuln.id}</span>
                        <span className={`px-2 py-0.5 text-xs rounded-full border ${SEVERITY_COLORS[vuln.severity] || "text-slate-400 bg-slate-500/10 border-slate-500/20"}`}>
                          {vuln.severity} — CVSS {vuln.cvss_score}
                        </span>
                      </div>
                      <p className="text-xs text-[var(--text-muted)] mt-1 line-clamp-1">{vuln.description}</p>
                    </div>
                  </div>
                  {expanded === vuln.id ? <ChevronUp className="w-4 h-4 text-[var(--text-muted)]" /> : <ChevronDown className="w-4 h-4 text-[var(--text-muted)]" />}
                </div>

                {expanded === vuln.id && (
                  <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }} className="mt-3 pt-3 border-t border-[var(--accent-cyan)]/10 space-y-2">
                    <p className="text-xs text-[var(--text-muted)]">{vuln.description}</p>
                    {vuln.vector && <p className="text-xs text-[var(--text-muted)]"><strong>Vector:</strong> {vuln.vector}</p>}
                    {vuln.weaknesses?.length > 0 && (
                      <div className="flex flex-wrap gap-1">
                        {vuln.weaknesses.map((w: string, j: number) => (
                          <span key={j} className="px-2 py-0.5 text-xs bg-[var(--bg-deep)]/50 border border-[var(--accent-cyan)]/10 rounded text-[var(--text-muted)]">{w}</span>
                        ))}
                      </div>
                    )}
                    {vuln.references?.length > 0 && (
                      <div className="flex flex-wrap gap-2 mt-2">
                        {vuln.references.slice(0, 3).map((ref: string, j: number) => (
                          <a key={j} href={ref} target="_blank" rel="noopener noreferrer" className="flex items-center gap-1 text-xs text-[var(--accent-cyan)] hover:underline">
                            <ExternalLink className="w-3 h-3" /> Reference {j + 1}
                          </a>
                        ))}
                      </div>
                    )}
                    {vuln.published && <p className="text-xs text-[var(--text-muted)]">Published: {new Date(vuln.published).toLocaleDateString()}</p>}
                  </motion.div>
                )}
              </GlassCard>
            </motion.div>
          ))}
        </div>
      )}
    </div>
  );
}
