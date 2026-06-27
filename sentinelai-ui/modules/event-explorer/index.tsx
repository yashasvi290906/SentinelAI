"use client";

import React, { useState, useCallback, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Search, Filter, Download, Clock, AlertTriangle, Shield, Activity,
  ChevronDown, ChevronRight, X, Plus, Bookmark, BookmarkCheck,
  SlidersHorizontal, ArrowUpDown, RefreshCw, Trash2, Eye, Copy,
  Calendar, Globe, Server, FileText, ChevronUp
} from "lucide-react";
import { fetchWithAuth } from "@/lib/api";

interface SearchFilter {
  field: string;
  op: string;
  value: string;
  negate: boolean;
}

interface SearchResult {
  detections: any[];
  alerts: any[];
  events: any[];
  total: number;
  timeline: any[];
  field_stats: {
    by_severity: Record<string, number>;
    by_type: Record<string, number>;
    top_source_ips: { ip: string; count: number }[];
  };
}

interface SavedSearch {
  id: string;
  name: string;
  query_text: string;
  filters_json: string;
  created_at: string;
}

interface Bookmark {
  id: string;
  event_type: string;
  event_id: string;
  note: string;
  created_at: string;
}

const FIELDS = [
  { value: "threat_type", label: "Threat Type" },
  { value: "severity", label: "Severity" },
  { value: "source_ip", label: "Source IP" },
  { value: "dest_ip", label: "Dest IP" },
  { value: "description", label: "Description" },
  { value: "mitre_technique", label: "MITRE Technique" },
  { value: "mitre_tactic", label: "MITRE Tactic" },
  { value: "hostname", label: "Hostname" },
  { value: "event_type", label: "Event Type" },
  { value: "alert_type", label: "Alert Type" },
  { value: "title", label: "Title" },
  { value: "source", label: "Source" },
  { value: "message", label: "Message" },
  { value: "status", label: "Status" },
];

const OPERATORS = [
  { value: "contains", label: "contains" },
  { value: "equals", label: "equals" },
  { value: "starts_with", label: "starts with" },
  { value: "ends_with", label: "ends with" },
  { value: "gt", label: "greater than" },
  { value: "lt", label: "less than" },
  { value: "in", label: "in (comma-separated)" },
];

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "bg-red-500/20 text-red-400 border-red-500/30",
  HIGH: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  MEDIUM: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  LOW: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  INFO: "bg-gray-500/20 text-gray-400 border-gray-500/30",
};

const TYPE_ICONS: Record<string, React.ReactNode> = {
  detection: <Shield className="w-3.5 h-3.5 text-red-400" />,
  alert: <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />,
  event: <Activity className="w-3.5 h-3.5 text-cyan-400" />,
};

export default function EventExplorer() {
  const [query, setQuery] = useState("");
  const [filters, setFilters] = useState<SearchFilter[]>([]);
  const [results, setResults] = useState<SearchResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"all" | "detections" | "alerts" | "events">("all");
  const [savedSearches, setSavedSearches] = useState<SavedSearch[]>([]);
  const [bookmarks, setBookmarks] = useState<Bookmark[]>([]);
  const [showFilters, setShowFilters] = useState(false);
  const [showSaved, setShowSaved] = useState(false);
  const [sortField, setSortField] = useState("timestamp");
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [page, setPage] = useState(0);
  const [saveName, setSaveName] = useState("");
  const [showSaveDialog, setShowSaveDialog] = useState(false);
  const [exportFormat, setExportFormat] = useState<"json" | "csv">("json");
  const [copied, setCopied] = useState(false);
  const searchTimeout = useRef<NodeJS.Timeout | null>(null);

  const addFilter = () => {
    setFilters([...filters, { field: "severity", op: "contains", value: "", negate: false }]);
  };

  const updateFilter = (index: number, key: keyof SearchFilter, value: any) => {
    const updated = [...filters];
    (updated[index] as any)[key] = value;
    setFilters(updated);
  };

  const removeFilter = (index: number) => {
    setFilters(filters.filter((_, i) => i !== index));
  };

  const toggleNegate = (index: number) => {
    const updated = [...filters];
    updated[index].negate = !updated[index].negate;
    setFilters(updated);
  };

  const executeSearch = useCallback(async () => {
    setLoading(true);
    try {
      const body = {
        q: query,
        filters: filters.filter(f => f.value),
        date_from: dateFrom,
        date_to: dateTo,
        limit: 500,
        offset: page * 500,
        sort_by: sortField,
        sort_order: sortOrder,
      };

      const res = await fetchWithAuth("/api/events/search", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });

      if (!res.ok) throw new Error("Search failed");
      const data = await res.json();
      setResults(data);
    } catch (err) {
      console.error("Search error:", err);
      setResults(null);
    } finally {
      setLoading(false);
    }
  }, [query, filters, dateFrom, dateTo, page, sortField, sortOrder]);

  useEffect(() => {
    if (searchTimeout.current) clearTimeout(searchTimeout.current);
    searchTimeout.current = setTimeout(() => {
      executeSearch();
    }, 300);
    return () => { if (searchTimeout.current) clearTimeout(searchTimeout.current); };
  }, [query, filters, dateFrom, dateTo, sortField, sortOrder, page]);

  const loadSavedSearches = async () => {
    try {
      const res = await fetchWithAuth("/api/hunt/saved");
      const data = await res.json();
      setSavedSearches(data.searches || []);
    } catch {}
  };

  const loadBookmarks = async () => {
    try {
      const res = await fetchWithAuth("/api/events/bookmarks");
      const data = await res.json();
      setBookmarks(data.bookmarks || []);
    } catch {}
  };

  const saveSearch = async () => {
    if (!saveName) return;
    try {
      await fetchWithAuth("/api/hunt/saved", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: saveName, query, filters }),
      });
      setSaveName("");
      setShowSaveDialog(false);
      loadSavedSearches();
    } catch {}
  };

  const deleteSavedSearch = async (id: string) => {
    try {
      await fetchWithAuth(`/api/hunt/saved/${id}`, { method: "DELETE" });
      loadSavedSearches();
    } catch {}
  };

  const applySavedSearch = (search: SavedSearch) => {
    setQuery(search.query_text);
    try {
      setFilters(JSON.parse(search.filters_json || "[]"));
    } catch {
      setFilters([]);
    }
    setShowSaved(false);
  };

  const addBookmark = async (eventType: string, eventId: string) => {
    try {
      await fetchWithAuth("/api/events/bookmarks", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ event_type: eventType, event_id: eventId }),
      });
      loadBookmarks();
    } catch {}
  };

  const removeBookmark = async (id: string) => {
    try {
      await fetchWithAuth(`/api/events/bookmarks/${id}`, { method: "DELETE" });
      loadBookmarks();
    } catch {}
  };

  const exportResults = async () => {
    try {
      const res = await fetchWithAuth(`/api/events/export?format=${exportFormat}&limit=5000`);
      if (exportFormat === "csv") {
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "sentinelai_events.csv";
        a.click();
        URL.revokeObjectURL(url);
      } else {
        const data = await res.json();
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "sentinelai_events.json";
        a.click();
        URL.revokeObjectURL(url);
      }
    } catch {}
  };

  const copyRow = (row: any) => {
    navigator.clipboard.writeText(JSON.stringify(row, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const displayedResults = (() => {
    if (!results) return [];
    let items: any[] = [];
    if (activeTab === "all" || activeTab === "detections") {
      items = [...items, ...results.detections.map(d => ({ ...d, _type: "detection" }))];
    }
    if (activeTab === "all" || activeTab === "alerts") {
      items = [...items, ...results.alerts.map(a => ({ ...a, _type: "alert" }))];
    }
    if (activeTab === "all" || activeTab === "events") {
      items = [...items, ...results.events.map(e => ({ ...e, _type: "event" }))];
    }
    items.sort((a, b) => {
      const aVal = a.timestamp || a.created_at || a.detection_time || "";
      const bVal = b.timestamp || b.created_at || b.detection_time || "";
      return sortOrder === "desc" ? (bVal > aVal ? 1 : -1) : (aVal > bVal ? 1 : -1);
    });
    return items;
  })();

  const getRowId = (row: any) => row.id || `${row._type}-${row.timestamp || row.created_at}`;

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Search className="w-6 h-6 text-cyan-400" />
            Event Explorer
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Advanced SIEM search with AND/OR/NOT filtering across all detections, alerts, and events
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => { setShowSaved(!showSaved); loadSavedSearches(); }}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-700/50 text-slate-300 hover:bg-slate-600/50 text-sm transition-colors"
          >
            <Bookmark className="w-3.5 h-3.5" />
            Saved
          </button>
          <button
            onClick={() => { setShowFilters(!showFilters); }}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm transition-colors ${
              showFilters ? "bg-cyan-500/20 text-cyan-400" : "bg-slate-700/50 text-slate-300 hover:bg-slate-600/50"
            }`}
          >
            <SlidersHorizontal className="w-3.5 h-3.5" />
            Filters ({filters.length})
          </button>
          <button
            onClick={exportResults}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-700/50 text-slate-300 hover:bg-slate-600/50 text-sm transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            Export
          </button>
        </div>
      </div>

      {/* Search Bar */}
      <div className="relative">
        <div className="flex items-center gap-2">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
            <input
              type="text"
              value={query}
              onChange={e => setQuery(e.target.value)}
              placeholder='Search events... (e.g., "failed login", "192.168.1.100", "brute_force")'
              className="w-full pl-10 pr-4 py-3 bg-slate-800/60 border border-slate-600/50 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 text-sm"
            />
          </div>
          <button
            onClick={() => setShowSaveDialog(true)}
            className="px-3 py-3 rounded-xl bg-cyan-500/20 text-cyan-400 hover:bg-cyan-500/30 transition-colors"
            title="Save search"
          >
            <BookmarkCheck className="w-4 h-4" />
          </button>
          <button
            onClick={executeSearch}
            disabled={loading}
            className="px-4 py-3 rounded-xl bg-cyan-600 text-white hover:bg-cyan-500 transition-colors disabled:opacity-50"
          >
            {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : "Search"}
          </button>
        </div>
      </div>

      {/* Saved Searches Panel */}
      <AnimatePresence>
        {showSaved && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden"
          >
            <div className="bg-slate-800/40 border border-slate-600/30 rounded-xl p-4">
              <h3 className="text-sm font-medium text-slate-300 mb-3">Saved Searches</h3>
              {savedSearches.length === 0 ? (
                <p className="text-sm text-slate-500">No saved searches yet.</p>
              ) : (
                <div className="space-y-2">
                  {savedSearches.map(s => (
                    <div key={s.id} className="flex items-center justify-between p-2 rounded-lg bg-slate-700/30 hover:bg-slate-700/50">
                      <button onClick={() => applySavedSearch(s)} className="text-left flex-1">
                        <div className="text-sm text-white">{s.name}</div>
                        <div className="text-xs text-slate-500 truncate">{s.query_text || "No query"}</div>
                      </button>
                      <button onClick={() => deleteSavedSearch(s.id)} className="p-1 text-slate-500 hover:text-red-400">
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Filter Builder */}
      <AnimatePresence>
        {showFilters && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden"
          >
            <div className="bg-slate-800/40 border border-slate-600/30 rounded-xl p-4 space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-medium text-slate-300">Advanced Filters</h3>
                <button onClick={addFilter} className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300">
                  <Plus className="w-3 h-3" /> Add Filter
                </button>
              </div>

              {/* Time Range */}
              <div className="flex items-center gap-3">
                <Calendar className="w-4 h-4 text-slate-500" />
                <input
                  type="datetime-local"
                  value={dateFrom}
                  onChange={e => setDateFrom(e.target.value)}
                  className="px-3 py-1.5 bg-slate-700/50 border border-slate-600/30 rounded-lg text-sm text-white focus:outline-none focus:border-cyan-500/50"
                  placeholder="From"
                />
                <span className="text-slate-500 text-sm">to</span>
                <input
                  type="datetime-local"
                  value={dateTo}
                  onChange={e => setDateTo(e.target.value)}
                  className="px-3 py-1.5 bg-slate-700/50 border border-slate-600/30 rounded-lg text-sm text-white focus:outline-none focus:border-cyan-500/50"
                  placeholder="To"
                />
              </div>

              {/* Filter Rows */}
              {filters.map((f, i) => (
                <div key={i} className="flex items-center gap-2">
                  <button
                    onClick={() => toggleNegate(i)}
                    className={`px-2 py-1.5 rounded-lg text-xs font-mono font-bold ${
                      f.negate ? "bg-red-500/20 text-red-400" : "bg-slate-700/50 text-slate-400"
                    }`}
                  >
                    {f.negate ? "NOT" : "AND"}
                  </button>
                  <select
                    value={f.field}
                    onChange={e => updateFilter(i, "field", e.target.value)}
                    className="px-2 py-1.5 bg-slate-700/50 border border-slate-600/30 rounded-lg text-sm text-white focus:outline-none"
                  >
                    {FIELDS.map(fld => (
                      <option key={fld.value} value={fld.value}>{fld.label}</option>
                    ))}
                  </select>
                  <select
                    value={f.op}
                    onChange={e => updateFilter(i, "op", e.target.value)}
                    className="px-2 py-1.5 bg-slate-700/50 border border-slate-600/30 rounded-lg text-sm text-white focus:outline-none"
                  >
                    {OPERATORS.map(op => (
                      <option key={op.value} value={op.value}>{op.label}</option>
                    ))}
                  </select>
                  <input
                    type="text"
                    value={f.value}
                    onChange={e => updateFilter(i, "value", e.target.value)}
                    placeholder="value"
                    className="flex-1 px-3 py-1.5 bg-slate-700/50 border border-slate-600/30 rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/50"
                  />
                  <button onClick={() => removeFilter(i)} className="p-1 text-slate-500 hover:text-red-400">
                    <X className="w-4 h-4" />
                  </button>
                </div>
              ))}

              {filters.length === 0 && (
                <p className="text-xs text-slate-500">No filters applied. Click "Add Filter" to create one.</p>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Save Search Dialog */}
      <AnimatePresence>
        {showSaveDialog && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
            onClick={() => setShowSaveDialog(false)}
          >
            <motion.div
              initial={{ scale: 0.95 }}
              animate={{ scale: 1 }}
              exit={{ scale: 0.95 }}
              onClick={e => e.stopPropagation()}
              className="bg-slate-800 border border-slate-600/50 rounded-xl p-6 w-96"
            >
              <h3 className="text-lg font-semibold text-white mb-4">Save Search</h3>
              <input
                type="text"
                value={saveName}
                onChange={e => setSaveName(e.target.value)}
                placeholder="Search name"
                className="w-full px-3 py-2 bg-slate-700/50 border border-slate-600/30 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/50 mb-4"
                autoFocus
              />
              <div className="flex justify-end gap-2">
                <button
                  onClick={() => setShowSaveDialog(false)}
                  className="px-4 py-2 rounded-lg bg-slate-700/50 text-slate-300 hover:bg-slate-600/50 text-sm"
                >
                  Cancel
                </button>
                <button
                  onClick={saveSearch}
                  className="px-4 py-2 rounded-lg bg-cyan-600 text-white hover:bg-cyan-500 text-sm"
                >
                  Save
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Results */}
      {results && (
        <div className="space-y-4">
          {/* Stats Bar */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="bg-slate-800/40 border border-slate-600/30 rounded-xl p-3">
              <div className="text-xs text-slate-500 mb-1">Total Results</div>
              <div className="text-xl font-bold text-white">{results.total.toLocaleString()}</div>
            </div>
            <div className="bg-slate-800/40 border border-slate-600/30 rounded-xl p-3">
              <div className="text-xs text-slate-500 mb-1">Detections</div>
              <div className="text-xl font-bold text-red-400">{results.detections.length}</div>
            </div>
            <div className="bg-slate-800/40 border border-slate-600/30 rounded-xl p-3">
              <div className="text-xs text-slate-500 mb-1">Alerts</div>
              <div className="text-xl font-bold text-amber-400">{results.alerts.length}</div>
            </div>
            <div className="bg-slate-800/40 border border-slate-600/30 rounded-xl p-3">
              <div className="text-xs text-slate-500 mb-1">Events</div>
              <div className="text-xl font-bold text-cyan-400">{results.events.length}</div>
            </div>
          </div>

          <div className="flex gap-4">
            {/* Results Table */}
            <div className="flex-1">
              {/* Tabs */}
              <div className="flex items-center gap-1 mb-3">
                {(["all", "detections", "alerts", "events"] as const).map(tab => (
                  <button
                    key={tab}
                    onClick={() => setActiveTab(tab)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                      activeTab === tab
                        ? "bg-cyan-500/20 text-cyan-400"
                        : "bg-slate-700/30 text-slate-400 hover:bg-slate-700/50"
                    }`}
                  >
                    {tab.charAt(0).toUpperCase() + tab.slice(1)}
                    <span className="ml-1.5 text-slate-500">
                      {tab === "all"
                        ? displayedResults.length
                        : tab === "detections"
                        ? results.detections.length
                        : tab === "alerts"
                        ? results.alerts.length
                        : results.events.length}
                    </span>
                  </button>
                ))}
                <div className="flex-1" />
                <button
                  onClick={() => setSortOrder(sortOrder === "desc" ? "asc" : "desc")}
                  className="flex items-center gap-1 px-2 py-1.5 rounded-lg bg-slate-700/30 text-slate-400 hover:bg-slate-700/50 text-xs"
                >
                  <ArrowUpDown className="w-3 h-3" />
                  {sortOrder === "desc" ? "Newest" : "Oldest"}
                </button>
              </div>

              {/* Results List */}
              <div className="space-y-1 max-h-[600px] overflow-y-auto">
                {displayedResults.length === 0 ? (
                  <div className="text-center py-12 text-slate-500">
                    <Search className="w-8 h-8 mx-auto mb-2 opacity-50" />
                    <p className="text-sm">No results found. Try adjusting your search or filters.</p>
                  </div>
                ) : (
                  displayedResults.map((row, idx) => {
                    const rowId = getRowId(row);
                    const isExpanded = expandedRow === rowId;
                    const sev = (row.severity || "INFO").toUpperCase();
                    const ts = row.timestamp || row.created_at || row.detection_time || "";

                    return (
                      <motion.div
                        key={rowId}
                        initial={{ opacity: 0, y: 5 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: idx * 0.02 }}
                        className="bg-slate-800/30 border border-slate-600/20 rounded-lg overflow-hidden"
                      >
                        <div
                          className="flex items-center gap-3 px-4 py-2.5 cursor-pointer hover:bg-slate-700/30 transition-colors"
                          onClick={() => setExpandedRow(isExpanded ? null : rowId)}
                        >
                          {isExpanded ? (
                            <ChevronDown className="w-4 h-4 text-slate-500 shrink-0" />
                          ) : (
                            <ChevronRight className="w-4 h-4 text-slate-500 shrink-0" />
                          )}
                          {TYPE_ICONS[row._type] || <Activity className="w-3.5 h-3.5 text-slate-400" />}
                          <span className={`px-2 py-0.5 rounded text-xs font-medium border ${SEVERITY_COLORS[sev] || SEVERITY_COLORS.INFO}`}>
                            {sev}
                          </span>
                          <span className="text-sm text-white font-medium truncate flex-1">
                            {row.threat_type || row.alert_type || row.event_type || row.title || "Unknown"}
                          </span>
                          <span className="text-xs text-slate-500 shrink-0">
                            {row.source_ip || ""}
                          </span>
                          <span className="text-xs text-slate-600 shrink-0">
                            {ts ? new Date(ts).toLocaleString() : ""}
                          </span>
                          <button
                            onClick={e => { e.stopPropagation(); addBookmark(row._type, rowId); }}
                            className="p-1 text-slate-600 hover:text-cyan-400 shrink-0"
                            title="Bookmark"
                          >
                            <Bookmark className="w-3.5 h-3.5" />
                          </button>
                        </div>

                        <AnimatePresence>
                          {isExpanded && (
                            <motion.div
                              initial={{ height: 0, opacity: 0 }}
                              animate={{ height: "auto", opacity: 1 }}
                              exit={{ height: 0, opacity: 0 }}
                              className="overflow-hidden"
                            >
                              <div className="px-4 pb-3 pt-1 border-t border-slate-700/30">
                                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                                  {Object.entries(row).filter(([k]) => !k.startsWith("_") && k !== "id").map(([k, v]) => (
                                    <div key={k}>
                                      <div className="text-slate-500 mb-0.5">{k.replace(/_/g, " ")}</div>
                                      <div className="text-slate-300 break-all">
                                        {typeof v === "object" ? JSON.stringify(v) : String(v ?? "")}
                                      </div>
                                    </div>
                                  ))}
                                </div>
                                <div className="flex items-center gap-2 mt-3">
                                  <button
                                    onClick={() => copyRow(row)}
                                    className="flex items-center gap-1 px-2 py-1 rounded bg-slate-700/50 text-slate-400 hover:text-white text-xs"
                                  >
                                    {copied ? <BookmarkCheck className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                                    {copied ? "Copied" : "Copy JSON"}
                                  </button>
                                  <button
                                    onClick={() => addBookmark(row._type, rowId)}
                                    className="flex items-center gap-1 px-2 py-1 rounded bg-slate-700/50 text-slate-400 hover:text-cyan-400 text-xs"
                                  >
                                    <Bookmark className="w-3 h-3" />
                                    Bookmark
                                  </button>
                                </div>
                              </div>
                            </motion.div>
                          )}
                        </AnimatePresence>
                      </motion.div>
                    );
                  })
                )}
              </div>

              {/* Pagination */}
              {displayedResults.length >= 500 && (
                <div className="flex items-center justify-center gap-2 mt-4">
                  <button
                    onClick={() => setPage(Math.max(0, page - 1))}
                    disabled={page === 0}
                    className="px-3 py-1.5 rounded-lg bg-slate-700/50 text-slate-300 hover:bg-slate-600/50 text-sm disabled:opacity-50"
                  >
                    Previous
                  </button>
                  <span className="text-sm text-slate-400">Page {page + 1}</span>
                  <button
                    onClick={() => setPage(page + 1)}
                    className="px-3 py-1.5 rounded-lg bg-slate-700/50 text-slate-300 hover:bg-slate-600/50 text-sm"
                  >
                    Next
                  </button>
                </div>
              )}
            </div>

            {/* Sidebar Stats */}
            <div className="w-72 shrink-0 space-y-3">
              {/* Severity Breakdown */}
              <div className="bg-slate-800/40 border border-slate-600/30 rounded-xl p-4">
                <h4 className="text-xs font-medium text-slate-400 mb-3">Severity Distribution</h4>
                {Object.entries(results.field_stats.by_severity).length === 0 ? (
                  <p className="text-xs text-slate-600">No data</p>
                ) : (
                  <div className="space-y-2">
                    {Object.entries(results.field_stats.by_severity)
                      .sort(([, a], [, b]) => (b as number) - (a as number))
                      .map(([sev, count]) => {
                        const total = results.total || 1;
                        const pct = Math.round(((count as number) / total) * 100);
                        return (
                          <div key={sev}>
                            <div className="flex items-center justify-between text-xs mb-1">
                              <span className={`font-medium ${(SEVERITY_COLORS[sev.toUpperCase()] || "").split(" ").find(s => s.startsWith("text-")) || "text-slate-400"}`}>
                                {sev}
                              </span>
                              <span className="text-slate-500">{String(count)} ({pct}%)</span>
                            </div>
                            <div className="h-1.5 bg-slate-700/50 rounded-full overflow-hidden">
                              <div
                                className={`h-full rounded-full ${
                                  sev.toUpperCase() === "CRITICAL" ? "bg-red-500" :
                                  sev.toUpperCase() === "HIGH" ? "bg-orange-500" :
                                  sev.toUpperCase() === "MEDIUM" ? "bg-yellow-500" :
                                  sev.toUpperCase() === "LOW" ? "bg-blue-500" : "bg-slate-500"
                                }`}
                                style={{ width: `${pct}%` }}
                              />
                            </div>
                          </div>
                        );
                      })}
                  </div>
                )}
              </div>

              {/* Top Source IPs */}
              <div className="bg-slate-800/40 border border-slate-600/30 rounded-xl p-4">
                <h4 className="text-xs font-medium text-slate-400 mb-3">Top Source IPs</h4>
                {results.field_stats.top_source_ips.length === 0 ? (
                  <p className="text-xs text-slate-600">No data</p>
                ) : (
                  <div className="space-y-1.5">
                    {results.field_stats.top_source_ips.slice(0, 10).map((item, i) => (
                      <div key={i} className="flex items-center justify-between text-xs">
                        <span className="text-slate-300 font-mono">{item.ip}</span>
                        <span className="text-slate-500">{item.count}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Threat Types */}
              <div className="bg-slate-800/40 border border-slate-600/30 rounded-xl p-4">
                <h4 className="text-xs font-medium text-slate-400 mb-3">Threat Types</h4>
                {Object.entries(results.field_stats.by_type).length === 0 ? (
                  <p className="text-xs text-slate-600">No data</p>
                ) : (
                  <div className="space-y-1.5">
                    {Object.entries(results.field_stats.by_type)
                      .sort(([, a], [, b]) => (b as number) - (a as number))
                      .slice(0, 10)
                      .map(([type, count]) => (
                        <div key={type} className="flex items-center justify-between text-xs">
                          <span className="text-slate-300 truncate">{type}</span>
                          <span className="text-slate-500">{String(count)}</span>
                        </div>
                      ))}
                  </div>
                )}
              </div>

              {/* Bookmarks */}
              <div className="bg-slate-800/40 border border-slate-600/30 rounded-xl p-4">
                <div className="flex items-center justify-between mb-3">
                  <h4 className="text-xs font-medium text-slate-400">Bookmarks</h4>
                  <button onClick={loadBookmarks} className="text-slate-500 hover:text-slate-300">
                    <RefreshCw className="w-3 h-3" />
                  </button>
                </div>
                {bookmarks.length === 0 ? (
                  <p className="text-xs text-slate-600">No bookmarks yet.</p>
                ) : (
                  <div className="space-y-1.5">
                    {bookmarks.slice(0, 10).map(b => (
                      <div key={b.id} className="flex items-center justify-between p-1.5 rounded bg-slate-700/20">
                        <div className="flex items-center gap-1.5">
                          {TYPE_ICONS[b.event_type] || <Activity className="w-3 h-3 text-slate-500" />}
                          <span className="text-xs text-slate-300 truncate">{b.event_id.slice(0, 12)}...</span>
                        </div>
                        <button onClick={() => removeBookmark(b.id)} className="text-slate-600 hover:text-red-400">
                          <X className="w-3 h-3" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Initial State */}
      {!results && !loading && (
        <div className="text-center py-20">
          <Search className="w-12 h-12 mx-auto mb-4 text-slate-600" />
          <h3 className="text-lg font-medium text-slate-400 mb-2">Search Your Security Events</h3>
          <p className="text-sm text-slate-600 max-w-md mx-auto">
            Use the search bar above or apply advanced filters to search across all detections,
            alerts, and events. Supports AND/OR/NOT logic and field-level filtering.
          </p>
        </div>
      )}
    </div>
  );
}
