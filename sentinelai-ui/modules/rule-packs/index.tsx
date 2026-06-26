"use client";

import React, { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Package, Shield, AlertTriangle, CheckCircle, XCircle, Plus,
  Trash2, Eye, EyeOff, ChevronDown, ChevronRight, FileCode,
  TestTube, RefreshCw, Download, Upload, Filter
} from "lucide-react";

interface RulePack {
  id: string;
  name: string;
  description: string;
  version: string;
  author: string;
  enabled: boolean;
  rule_count: number;
  source: "built-in" | "custom";
  file?: string;
}

interface Rule {
  id: string;
  name: string;
  description: string;
  severity: string;
  mitre_technique?: string;
  mitre_tactic?: string;
  condition?: { field: string; op: string; value: string };
  filter?: { field: string; op: string; value: string };
  aggregation?: { field: string; threshold: number; window_minutes: number; distinct_field?: string };
  actions?: { type: string; title?: string; severity?: string }[];
}

interface PackDetail extends RulePack {
  rules: Rule[];
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "bg-red-500/20 text-red-400 border-red-500/30",
  HIGH: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  MEDIUM: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  LOW: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  INFO: "bg-gray-500/20 text-gray-400 border-gray-500/30",
};

export default function RulePacks() {
  const [packs, setPacks] = useState<RulePack[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedPack, setSelectedPack] = useState<PackDetail | null>(null);
  const [expandedRule, setExpandedRule] = useState<string | null>(null);
  const [showTestPanel, setShowTestPanel] = useState(false);
  const [testRule, setTestRule] = useState<Rule | null>(null);
  const [testEvents, setTestEvents] = useState("[]");
  const [testResult, setTestResult] = useState<{ matches: number; matched_events: any[]; total_tested: number } | null>(null);
  const [filter, setFilter] = useState<"all" | "built-in" | "custom">("all");
  const [severityFilter, setSeverityFilter] = useState<string>("");

  const fetchPacks = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/rule-packs");
      const data = await res.json();
      setPacks(data.packs || []);
    } catch (err) {
      console.error("Failed to fetch rule packs:", err);
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchPackDetail = async (packId: string) => {
    try {
      const res = await fetch(`/api/rule-packs/${packId}`);
      const data = await res.json();
      setSelectedPack(data);
    } catch (err) {
      console.error("Failed to fetch pack detail:", err);
    }
  };

  const togglePack = async (packId: string) => {
    try {
      await fetch(`/api/rule-packs/${packId}/toggle`, { method: "POST" });
      fetchPacks();
      if (selectedPack?.id === packId) {
        fetchPackDetail(packId);
      }
    } catch {}
  };

  const deletePack = async (packId: string) => {
    if (!confirm("Delete this custom rule pack?")) return;
    try {
      await fetch(`/api/rule-packs/${packId}`, { method: "DELETE" });
      if (selectedPack?.id === packId) setSelectedPack(null);
      fetchPacks();
    } catch {}
  };

  const testRuleAgainstEvents = async () => {
    if (!testRule) return;
    try {
      const events = JSON.parse(testEvents);
      const res = await fetch("/api/rule-packs/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ rule: testRule, events }),
      });
      const data = await res.json();
      setTestResult(data);
    } catch (err) {
      console.error("Test failed:", err);
    }
  };

  useEffect(() => { fetchPacks(); }, [fetchPacks]);

  const filteredPacks = packs.filter(p => {
    if (filter !== "all" && p.source !== filter) return false;
    return true;
  });

  const filteredRules = selectedPack?.rules.filter(r => {
    if (severityFilter && r.severity !== severityFilter) return false;
    return true;
  }) || [];

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Package className="w-6 h-6 text-cyan-400" />
            Detection Rule Packs
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Manage detection rules organized by attack category. Toggle packs on/off to control what gets detected.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={fetchPacks}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-700/50 text-slate-300 hover:bg-slate-600/50 text-sm transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-1 bg-slate-800/40 rounded-lg p-1">
          {(["all", "built-in", "custom"] as const).map(f => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                filter === f ? "bg-cyan-500/20 text-cyan-400" : "text-slate-400 hover:text-slate-300"
              }`}
            >
              {f.charAt(0).toUpperCase() + f.slice(1)}
            </button>
          ))}
        </div>
        <span className="text-sm text-slate-500">
          {filteredPacks.length} packs, {filteredPacks.reduce((a, p) => a + p.rule_count, 0)} rules
        </span>
      </div>

      <div className="flex gap-6">
        {/* Pack List */}
        <div className="w-80 shrink-0 space-y-2">
          {loading ? (
            <div className="text-center py-8 text-slate-500">
              <RefreshCw className="w-6 h-6 mx-auto mb-2 animate-spin" />
              Loading...
            </div>
          ) : filteredPacks.length === 0 ? (
            <div className="text-center py-8 text-slate-500">
              <Package className="w-6 h-6 mx-auto mb-2 opacity-50" />
              No rule packs found
            </div>
          ) : (
            filteredPacks.map(pack => (
              <motion.div
                key={pack.id}
                initial={{ opacity: 0, y: 5 }}
                animate={{ opacity: 1, y: 0 }}
                className={`p-3 rounded-xl border cursor-pointer transition-all ${
                  selectedPack?.id === pack.id
                    ? "bg-cyan-500/10 border-cyan-500/30"
                    : "bg-slate-800/30 border-slate-600/20 hover:bg-slate-700/30"
                }`}
                onClick={() => fetchPackDetail(pack.id)}
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <h3 className="text-sm font-medium text-white truncate">{pack.name}</h3>
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${
                        pack.source === "built-in" ? "bg-cyan-500/20 text-cyan-400" : "bg-purple-500/20 text-purple-400"
                      }`}>
                        {pack.source}
                      </span>
                    </div>
                    <p className="text-xs text-slate-500 mt-0.5 line-clamp-2">{pack.description}</p>
                    <div className="flex items-center gap-3 mt-2 text-xs text-slate-600">
                      <span>{pack.rule_count} rules</span>
                      <span>v{pack.version}</span>
                      {pack.author && <span>by {pack.author}</span>}
                    </div>
                  </div>
                  <button
                    onClick={e => { e.stopPropagation(); togglePack(pack.id); }}
                    className={`p-1.5 rounded-lg transition-colors ${
                      pack.enabled ? "text-green-400 hover:bg-green-500/20" : "text-slate-500 hover:bg-slate-600/30"
                    }`}
                    title={pack.enabled ? "Disable pack" : "Enable pack"}
                  >
                    {pack.enabled ? <Eye className="w-4 h-4" /> : <EyeOff className="w-4 h-4" />}
                  </button>
                </div>
                {!pack.enabled && (
                  <div className="mt-2 text-xs text-amber-500/80 bg-amber-500/10 rounded px-2 py-1">
                    Pack is disabled - rules not active
                  </div>
                )}
              </motion.div>
            ))
          )}
        </div>

        {/* Pack Detail */}
        <div className="flex-1">
          {selectedPack ? (
            <div className="space-y-4">
              <div className="bg-slate-800/40 border border-slate-600/30 rounded-xl p-5">
                <div className="flex items-center justify-between mb-3">
                  <div>
                    <h2 className="text-lg font-bold text-white">{selectedPack.name}</h2>
                    <p className="text-sm text-slate-400 mt-1">{selectedPack.description}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    {selectedPack.source === "custom" && (
                      <button
                        onClick={() => deletePack(selectedPack.id)}
                        className="p-2 rounded-lg bg-red-500/10 text-red-400 hover:bg-red-500/20"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-4 text-sm text-slate-400">
                  <span>Version: {selectedPack.version}</span>
                  <span>Author: {selectedPack.author}</span>
                  <span>{selectedPack.rules.length} rules</span>
                  <span className={`px-2 py-0.5 rounded text-xs ${selectedPack.enabled ? "bg-green-500/20 text-green-400" : "bg-slate-600/30 text-slate-500"}`}>
                    {selectedPack.enabled ? "Enabled" : "Disabled"}
                  </span>
                </div>
              </div>

              {/* Severity Filter */}
              <div className="flex items-center gap-2">
                <Filter className="w-4 h-4 text-slate-500" />
                <span className="text-xs text-slate-500">Filter by severity:</span>
                {(["", "CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map(s => (
                  <button
                    key={s}
                    onClick={() => setSeverityFilter(s)}
                    className={`px-2 py-1 rounded text-xs font-medium transition-colors ${
                      severityFilter === s
                        ? s ? `${SEVERITY_COLORS[s]}` : "bg-cyan-500/20 text-cyan-400"
                        : "bg-slate-700/30 text-slate-400 hover:bg-slate-700/50"
                    }`}
                  >
                    {s || "All"}
                  </button>
                ))}
              </div>

              {/* Rules List */}
              <div className="space-y-2">
                {filteredRules.map(rule => (
                  <motion.div
                    key={rule.id}
                    initial={{ opacity: 0, y: 5 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="bg-slate-800/30 border border-slate-600/20 rounded-xl overflow-hidden"
                  >
                    <div
                      className="flex items-center gap-3 px-4 py-3 cursor-pointer hover:bg-slate-700/20 transition-colors"
                      onClick={() => setExpandedRule(expandedRule === rule.id ? null : rule.id)}
                    >
                      {expandedRule === rule.id ? (
                        <ChevronDown className="w-4 h-4 text-slate-500 shrink-0" />
                      ) : (
                        <ChevronRight className="w-4 h-4 text-slate-500 shrink-0" />
                      )}
                      <span className={`px-2 py-0.5 rounded text-xs font-medium border ${SEVERITY_COLORS[rule.severity] || SEVERITY_COLORS.INFO}`}>
                        {rule.severity}
                      </span>
                      <span className="text-sm text-white font-medium flex-1">{rule.name}</span>
                      {rule.mitre_technique && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-700/50 text-slate-400">
                          {rule.mitre_technique}
                        </span>
                      )}
                      <button
                        onClick={e => { e.stopPropagation(); setTestRule(rule); setShowTestPanel(true); }}
                        className="p-1 text-slate-500 hover:text-cyan-400"
                        title="Test rule"
                      >
                        <TestTube className="w-3.5 h-3.5" />
                      </button>
                    </div>

                    <AnimatePresence>
                      {expandedRule === rule.id && (
                        <motion.div
                          initial={{ height: 0, opacity: 0 }}
                          animate={{ height: "auto", opacity: 1 }}
                          exit={{ height: 0, opacity: 0 }}
                          className="overflow-hidden"
                        >
                          <div className="px-4 pb-4 pt-1 border-t border-slate-700/30 space-y-3">
                            <p className="text-sm text-slate-400">{rule.description}</p>

                            {rule.condition && (
                              <div>
                                <div className="text-xs text-slate-500 mb-1">Condition</div>
                                <code className="text-xs bg-slate-900/50 text-cyan-300 px-2 py-1 rounded">
                                  {rule.condition.field} {rule.condition.op} "{rule.condition.value}"
                                </code>
                              </div>
                            )}

                            {rule.filter && (
                              <div>
                                <div className="text-xs text-slate-500 mb-1">Filter</div>
                                <code className="text-xs bg-slate-900/50 text-amber-300 px-2 py-1 rounded">
                                  {rule.filter.field} {rule.filter.op} "{rule.filter.value}"
                                </code>
                              </div>
                            )}

                            {rule.aggregation && (
                              <div>
                                <div className="text-xs text-slate-500 mb-1">Aggregation</div>
                                <code className="text-xs bg-slate-900/50 text-green-300 px-2 py-1 rounded">
                                  COUNT({rule.aggregation.field}) {rule.aggregation.distinct_field ? `DISTINCT(${rule.aggregation.distinct_field}) ` : ""}
                                  &gt;= {rule.aggregation.threshold} within {rule.aggregation.window_minutes}m
                                </code>
                              </div>
                            )}

                            {rule.mitre_technique && (
                              <div className="flex items-center gap-2">
                                <span className="text-xs text-slate-500">MITRE:</span>
                                <span className="text-xs text-cyan-400">{rule.mitre_technique}</span>
                                {rule.mitre_tactic && (
                                  <span className="text-xs text-slate-500">({rule.mitre_tactic})</span>
                                )}
                              </div>
                            )}

                            {rule.actions && rule.actions.length > 0 && (
                              <div>
                                <div className="text-xs text-slate-500 mb-1">Actions</div>
                                <div className="flex flex-wrap gap-1.5">
                                  {rule.actions.map((action, i) => (
                                    <span key={i} className="px-2 py-0.5 rounded text-xs bg-slate-700/50 text-slate-300">
                                      {action.type}: {action.title || ""}
                                    </span>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </motion.div>
                ))}
              </div>
            </div>
          ) : (
            <div className="text-center py-20">
              <Package className="w-12 h-12 mx-auto mb-4 text-slate-600" />
              <h3 className="text-lg font-medium text-slate-400 mb-2">Select a Rule Pack</h3>
              <p className="text-sm text-slate-600">
                Choose a rule pack from the left to view its detection rules.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Test Panel */}
      <AnimatePresence>
        {showTestPanel && testRule && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
            onClick={() => { setShowTestPanel(false); setTestResult(null); }}
          >
            <motion.div
              initial={{ scale: 0.95 }}
              animate={{ scale: 1 }}
              exit={{ scale: 0.95 }}
              onClick={e => e.stopPropagation()}
              className="bg-slate-800 border border-slate-600/50 rounded-xl p-6 w-[600px] max-h-[80vh] overflow-y-auto"
            >
              <h3 className="text-lg font-semibold text-white mb-1">Test Rule: {testRule.name}</h3>
              <p className="text-sm text-slate-400 mb-4">Paste sample events as JSON array to test this rule against.</p>

              <textarea
                value={testEvents}
                onChange={e => setTestEvents(e.target.value)}
                className="w-full h-40 px-3 py-2 bg-slate-900/50 border border-slate-600/30 rounded-lg text-sm text-white font-mono placeholder-slate-600 focus:outline-none focus:border-cyan-500/50"
                placeholder='[{"event_type": "failed_logon", "source_ip": "192.168.1.100", "severity": "HIGH"}]'
              />

              <div className="flex justify-end gap-2 mt-4">
                <button
                  onClick={() => { setShowTestPanel(false); setTestResult(null); }}
                  className="px-4 py-2 rounded-lg bg-slate-700/50 text-slate-300 hover:bg-slate-600/50 text-sm"
                >
                  Close
                </button>
                <button
                  onClick={testRuleAgainstEvents}
                  className="px-4 py-2 rounded-lg bg-cyan-600 text-white hover:bg-cyan-500 text-sm"
                >
                  Run Test
                </button>
              </div>

              {testResult && (
                <div className="mt-4 p-4 bg-slate-900/50 rounded-lg">
                  <div className="flex items-center gap-2 mb-2">
                    {testResult.matches > 0 ? (
                      <CheckCircle className="w-5 h-5 text-green-400" />
                    ) : (
                      <XCircle className="w-5 h-5 text-slate-500" />
                    )}
                    <span className="text-sm font-medium text-white">
                      {testResult.matches} of {testResult.total_tested} events matched
                    </span>
                  </div>
                  {testResult.matched_events.length > 0 && (
                    <pre className="text-xs text-slate-400 overflow-auto max-h-40">
                      {JSON.stringify(testResult.matched_events, null, 2)}
                    </pre>
                  )}
                </div>
              )}
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
