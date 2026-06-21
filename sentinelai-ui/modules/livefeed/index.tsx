"use client";

import { useState, useMemo, useRef, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import GlassPanel from "@/components/ui/GlassPanel";
import { RiskBadge } from "@/components/ui/RiskBadge";
import { usePredictionStore } from "@/stores/predictionStore";
import { useEventStore, type EventType } from "@/stores/eventStore";
import {
  Activity,
  Upload,
  Pause,
  Play,
  Filter,
  FileText,
  AlertTriangle,
  Shield,
  Cpu,
  X,
  Clock,
} from "lucide-react";

type FilterType = "all" | "prediction" | "compare" | "system" | "error";

interface UploadedEvent {
  id: string;
  timestamp: string;
  type: EventType;
  message: string;
  details?: Record<string, unknown>;
}

const FILTER_OPTIONS: { key: FilterType; label: string }[] = [
  { key: "all", label: "All" },
  { key: "prediction", label: "Predictions" },
  { key: "compare", label: "Compares" },
  { key: "system", label: "System" },
  { key: "error", label: "Errors" },
];

const EVENT_TYPE_COLORS: Record<EventType, { bg: string; text: string; border: string }> = {
  prediction: { bg: "rgba(0,229,255,0.1)", text: "var(--accent-cyan)", border: "rgba(0,229,255,0.3)" },
  compare: { bg: "rgba(168,85,247,0.1)", text: "#a855f7", border: "rgba(168,85,247,0.3)" },
  system: { bg: "rgba(0,229,255,0.06)", text: "var(--text-secondary)", border: "rgba(0,229,255,0.15)" },
  error: { bg: "rgba(255,77,109,0.1)", text: "var(--accent-red)", border: "rgba(255,77,109,0.3)" },
  user_action: { bg: "rgba(34,197,94,0.1)", text: "var(--accent-green)", border: "rgba(34,197,94,0.3)" },
};

function parseCSV(text: string): UploadedEvent[] {
  const lines = text.trim().split("\n");
  if (lines.length < 2) return [];
  const headers = lines[0].split(",").map((h) => h.trim().toLowerCase());
  return lines.slice(1).map((line, i) => {
    const values = line.split(",").map((v) => v.trim());
    const row: Record<string, string> = {};
    headers.forEach((h, idx) => {
      row[h] = values[idx] || "";
    });
    return {
      id: `upload_csv_${i}`,
      timestamp: row.timestamp || row.time || new Date().toISOString(),
      type: (row.type as EventType) || "system",
      message: row.message || row.attack_type || row.attacktype || row.event || `Event ${i + 1}`,
      details: Object.fromEntries(Object.entries(row).filter(([k]) => !["timestamp", "time", "type", "message"].includes(k))),
    };
  });
}

function parseJSON(text: string): UploadedEvent[] {
  try {
    const data = JSON.parse(text);
    const arr = Array.isArray(data) ? data : [data];
    return arr.map((item: Record<string, unknown>, i: number) => ({
      id: `upload_json_${i}`,
      timestamp: (item.timestamp as string) || (item.time as string) || new Date().toISOString(),
      type: (item.type as EventType) || "system",
      message: (item.message as string) || (item.attack_type as string) || (item.attackType as string) || `Event ${i + 1}`,
      details: Object.fromEntries(
        Object.entries(item).filter(([k]) => !["timestamp", "time", "type", "message"].includes(k))
      ),
    }));
  } catch {
    return [];
  }
}

export default function LiveFeed() {
  const [isPaused, setIsPaused] = useState(false);
  const [activeFilter, setActiveFilter] = useState<FilterType>("all");
  const [uploadedEvents, setUploadedEvents] = useState<UploadedEvent[]>([]);
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const predictionHistory = usePredictionStore((s) => s.predictionHistory);
  const storeEvents = useEventStore((s) => s.events);

  const timelineEvents = useMemo(() => {
    const combined: Array<{
      id: string;
      timestamp: string;
      source: "store" | "upload";
      storeType?: EventType;
      uploadEvent?: UploadedEvent;
    }> = [];

    predictionHistory.forEach((pred) => {
      combined.push({
        id: pred.id,
        timestamp: pred.timestamp,
        source: "store",
        storeType: "prediction",
      });
    });

    storeEvents.forEach((evt) => {
      combined.push({
        id: evt.id,
        timestamp: evt.timestamp,
        source: "store",
        storeType: evt.type,
      });
    });

    uploadedEvents.forEach((evt) => {
      combined.push({
        id: evt.id,
        timestamp: evt.timestamp,
        source: "upload",
        uploadEvent: evt,
      });
    });

    combined.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
    return combined;
  }, [predictionHistory, storeEvents, uploadedEvents]);

  const filteredEvents = useMemo(() => {
    if (activeFilter === "all") return timelineEvents;
    return timelineEvents.filter((e) => {
      if (e.source === "upload" && e.uploadEvent) {
        return e.uploadEvent.type === activeFilter;
      }
      return e.storeType === activeFilter;
    });
  }, [timelineEvents, activeFilter]);

  const handleFiles = useCallback((files: FileList | null) => {
    if (!files) return;
    Array.from(files).forEach((file) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        const text = e.target?.result as string;
        if (file.name.endsWith(".csv")) {
          const parsed = parseCSV(text);
          setUploadedEvents((prev) => [...parsed, ...prev]);
        } else if (file.name.endsWith(".json")) {
          const parsed = parseJSON(text);
          setUploadedEvents((prev) => [...parsed, ...prev]);
        }
      };
      reader.readAsText(file);
    });
  }, []);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setIsDragOver(false);
      handleFiles(e.dataTransfer.files);
    },
    [handleFiles]
  );

  const removeUploaded = useCallback((id: string) => {
    setUploadedEvents((prev) => prev.filter((e) => e.id !== id));
  }, []);

  const clearUploaded = useCallback(() => {
    setUploadedEvents([]);
  }, []);

  const displayItems = isPaused ? filteredEvents : filteredEvents;

  return (
    <div className="h-full p-6 lg:p-8 flex flex-col gap-6 overflow-hidden">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <p
          className="text-[10px] font-mono tracking-[0.3em] uppercase mb-2"
          style={{ color: "var(--accent-cyan)" }}
        >
          Live Intelligence
        </p>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <h1
              className="text-3xl font-display font-bold"
              style={{ color: "var(--text-primary)" }}
            >
              Live Feed
            </h1>
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg" style={{ border: "1px solid rgba(0,229,255,0.15)", background: "rgba(0,229,255,0.04)" }}>
              <div
                className="w-2 h-2 rounded-full"
                style={{
                  background: isPaused ? "var(--accent-amber)" : "var(--accent-green)",
                  boxShadow: isPaused ? "0 0 8px rgba(255,176,32,0.5)" : "0 0 8px rgba(34,197,94,0.5)",
                }}
              />
              <span
                className="text-[10px] font-mono uppercase tracking-wider"
                style={{ color: "var(--text-muted)" }}
              >
                {isPaused ? "PAUSED" : "STREAMING"}
              </span>
            </div>
          </div>
          <button
            onClick={() => setIsPaused(!isPaused)}
            className="flex items-center gap-2 text-[10px] font-bold tracking-widest uppercase px-4 py-2 rounded-lg transition-all duration-300"
            style={{
              border: `1px solid ${isPaused ? "rgba(34,197,94,0.4)" : "rgba(255,176,32,0.4)"}`,
              color: isPaused ? "var(--accent-green)" : "var(--accent-amber)",
              background: isPaused ? "rgba(34,197,94,0.08)" : "rgba(255,176,32,0.08)",
            }}
          >
            {isPaused ? <Play className="w-3 h-3" /> : <Pause className="w-3 h-3" />}
            {isPaused ? "Resume" : "Pause"}
          </button>
        </div>
        <p
          className="text-sm mt-2"
          style={{ color: "var(--text-secondary)" }}
        >
          Real-time event stream from predictions, system events, and uploads
        </p>
      </motion.div>

      {/* Filter Bar */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.1 }}
        className="flex items-center gap-2 flex-wrap"
      >
        <Filter className="w-3.5 h-3.5" style={{ color: "var(--text-muted)" }} />
        {FILTER_OPTIONS.map((opt) => (
          <button
            key={opt.key}
            onClick={() => setActiveFilter(opt.key)}
            className="px-3 py-1.5 rounded-lg text-[10px] font-bold uppercase tracking-wider transition-all duration-200"
            style={{
              border: `1px solid ${activeFilter === opt.key ? "rgba(0,229,255,0.4)" : "rgba(0,229,255,0.1)"}`,
              background: activeFilter === opt.key ? "rgba(0,229,255,0.12)" : "transparent",
              color: activeFilter === opt.key ? "var(--accent-cyan)" : "var(--text-muted)",
            }}
          >
            {opt.label}
          </button>
        ))}
        <div className="ml-auto flex items-center gap-3">
          {uploadedEvents.length > 0 && (
            <button
              onClick={clearUploaded}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[10px] font-bold uppercase tracking-wider transition-all duration-200"
              style={{
                border: "1px solid rgba(255,77,109,0.3)",
                color: "var(--accent-red)",
                background: "rgba(255,77,109,0.06)",
              }}
            >
              <X className="w-3 h-3" />
              Clear Uploads ({uploadedEvents.length})
            </button>
          )}
          <span
            className="text-[10px] font-mono"
            style={{ color: "var(--text-muted)" }}
          >
            {displayItems.length} events
          </span>
        </div>
      </motion.div>

      {/* Main Content */}
      <div className="flex-1 grid grid-cols-1 lg:grid-cols-3 gap-6 min-h-0">
        {/* Timeline Column */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.5, delay: 0.15 }}
          className="lg:col-span-2 min-h-0"
        >
          <GlassPanel title="Event Timeline" icon={<Clock className="w-4 h-4" />} className="h-full">
            <div className="space-y-2 overflow-y-auto pr-2" style={{ maxHeight: "calc(100% - 20px)" }}>
              <AnimatePresence initial={false}>
                {displayItems.map((item, index) => {
                  const isUpload = item.source === "upload";
                  const evt = item.uploadEvent;
                  const pred = !isUpload
                    ? predictionHistory.find((p) => p.id === item.id)
                    : null;
                  const storeEvt = !isUpload
                    ? storeEvents.find((e) => e.id === item.id)
                    : null;

                  const eventType = isUpload ? (evt?.type || "system") as EventType : (item.storeType || "system") as EventType;
                  const typeColors = EVENT_TYPE_COLORS[eventType] || EVENT_TYPE_COLORS.system;
                  const message = isUpload
                    ? evt?.message || "Uploaded event"
                    : pred
                    ? `Predicted: ${pred.predictedAttack} (${(pred.confidence * 100).toFixed(1)}%)`
                    : storeEvt?.message || "System event";

                  return (
                    <motion.div
                      key={item.id}
                      initial={{ opacity: 0, x: 30, scale: 0.95 }}
                      animate={{ opacity: 1, x: 0, scale: 1 }}
                      exit={{ opacity: 0, x: -30, scale: 0.95 }}
                      transition={{ delay: index * 0.02, duration: 0.3 }}
                      className="relative p-4 rounded-xl transition-all duration-300 group"
                      style={{
                        border: `1px solid ${typeColors.border}`,
                        background: typeColors.bg,
                      }}
                    >
                      {/* Timeline connector */}
                      {index < displayItems.length - 1 && (
                        <div
                          className="absolute left-6 top-full w-px h-2"
                          style={{ background: "rgba(0,229,255,0.15)" }}
                        />
                      )}

                      <div className="flex items-start justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <span
                            className="px-2 py-0.5 rounded-md text-[9px] font-mono font-bold uppercase tracking-wider"
                            style={{
                              background: typeColors.bg,
                              color: typeColors.text,
                              border: `1px solid ${typeColors.border}`,
                            }}
                          >
                            {eventType}
                          </span>
                          {isUpload && (
                            <span
                              className="px-1.5 py-0.5 rounded text-[8px] font-mono uppercase"
                              style={{ background: "rgba(168,85,247,0.12)", color: "#a855f7" }}
                            >
                              UPLOADED
                            </span>
                          )}
                        </div>
                        <span
                          className="text-[10px] font-mono"
                          style={{ color: "var(--text-muted)" }}
                        >
                          {new Date(item.timestamp).toLocaleTimeString()}
                        </span>
                      </div>

                      <p
                        className="text-sm font-medium mb-2"
                        style={{ color: "var(--text-primary)" }}
                      >
                        {message}
                      </p>

                      {pred && (
                        <div className="flex items-center gap-3">
                          <div className="flex items-center gap-1">
                            <Shield className="w-3 h-3" style={{ color: "var(--text-muted)" }} />
                            <span
                              className="text-[10px] font-mono"
                              style={{ color: "var(--text-muted)" }}
                            >
                              {pred.model}
                            </span>
                          </div>
                          <RiskBadge level={pred.riskLevel} />
                          <div className="flex gap-1 flex-wrap">
                            {pred.sequence.slice(0, 4).map((atk, i) => (
                              <span
                                key={i}
                                className="px-1.5 py-0.5 rounded text-[9px] font-mono"
                                style={{ background: "rgba(0,229,255,0.08)", color: "var(--accent-cyan)" }}
                              >
                                {atk}
                              </span>
                            ))}
                            {pred.sequence.length > 4 && (
                              <span
                                className="px-1.5 py-0.5 rounded text-[9px] font-mono"
                                style={{ color: "var(--text-muted)" }}
                              >
                                +{pred.sequence.length - 4}
                              </span>
                            )}
                          </div>
                        </div>
                      )}

                      {isUpload && evt?.details && Object.keys(evt.details).length > 0 && (
                        <div className="flex flex-wrap gap-2 mt-1">
                          {Object.entries(evt.details).slice(0, 4).map(([k, v]) => (
                            <span
                              key={k}
                              className="text-[9px] font-mono"
                              style={{ color: "var(--text-muted)" }}
                            >
                              {k}: {String(v)}
                            </span>
                          ))}
                        </div>
                      )}

                      {!pred && !isUpload && storeEvt && (
                        <div className="flex items-center gap-2">
                          <AlertTriangle className="w-3 h-3" style={{ color: "var(--text-muted)" }} />
                          <span
                            className="text-[10px] font-mono"
                            style={{ color: "var(--text-muted)" }}
                          >
                            {storeEvt.details ? JSON.stringify(storeEvt.details).slice(0, 80) : ""}
                          </span>
                        </div>
                      )}
                    </motion.div>
                  );
                })}
              </AnimatePresence>

              {displayItems.length === 0 && (
                <div className="text-center py-16">
                  <Cpu
                    className="w-10 h-10 mx-auto mb-4"
                    style={{ color: "var(--text-muted)", opacity: 0.3 }}
                  />
                  <p
                    className="text-sm font-medium mb-1"
                    style={{ color: "var(--text-secondary)" }}
                  >
                    No live traffic source connected.
                  </p>
                  <p
                    className="text-xs"
                    style={{ color: "var(--text-muted)" }}
                  >
                    Upload a CSV or JSON file to replay events.
                  </p>
                </div>
              )}
            </div>
          </GlassPanel>
        </motion.div>

        {/* Right Column - Upload & Summary */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.5, delay: 0.25 }}
          className="flex flex-col gap-4 min-h-0"
        >
          {/* Upload Zone */}
          <GlassPanel title="Import Data" icon={<Upload className="w-4 h-4" />} className="flex-shrink-0">
            <div
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className="flex flex-col items-center justify-center gap-3 p-6 rounded-xl cursor-pointer transition-all duration-300"
              style={{
                border: `2px dashed ${isDragOver ? "rgba(0,229,255,0.5)" : "rgba(0,229,255,0.15)"}`,
                background: isDragOver ? "rgba(0,229,255,0.06)" : "rgba(0,229,255,0.02)",
              }}
            >
              <Upload
                className="w-8 h-8"
                style={{ color: isDragOver ? "var(--accent-cyan)" : "var(--text-muted)" }}
              />
              <div className="text-center">
                <p
                  className="text-xs font-medium mb-1"
                  style={{ color: "var(--text-primary)" }}
                >
                  Drop CSV or JSON files here
                </p>
                <p
                  className="text-[10px]"
                  style={{ color: "var(--text-muted)" }}
                >
                  or click to browse
                </p>
              </div>
              <input
                ref={fileInputRef}
                type="file"
                accept=".csv,.json"
                multiple
                onChange={(e) => handleFiles(e.target.files)}
                className="hidden"
              />
            </div>
            {uploadedEvents.length > 0 && (
              <div
                className="mt-3 px-3 py-2 rounded-lg flex items-center gap-2"
                style={{ background: "rgba(168,85,247,0.06)", border: "1px solid rgba(168,85,247,0.15)" }}
              >
                <FileText className="w-3.5 h-3.5" style={{ color: "#a855f7" }} />
                <span className="text-[10px] font-mono" style={{ color: "#a855f7" }}>
                  {uploadedEvents.length} events loaded from file
                </span>
              </div>
            )}
          </GlassPanel>

          {/* Summary Stats */}
          <GlassPanel title="Summary" icon={<Activity className="w-4 h-4" />} className="flex-shrink-0">
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div
                  className="text-center p-3 rounded-xl"
                  style={{
                    background: "rgba(0,229,255,0.06)",
                    border: "1px solid rgba(0,229,255,0.15)",
                  }}
                >
                  <p
                    className="text-2xl font-display font-bold"
                    style={{ color: "var(--accent-cyan)" }}
                  >
                    {predictionHistory.length}
                  </p>
                  <p
                    className="text-[9px] uppercase tracking-wider"
                    style={{ color: "var(--accent-cyan)" }}
                  >
                    Predictions
                  </p>
                </div>
                <div
                  className="text-center p-3 rounded-xl"
                  style={{
                    background: "rgba(255,77,109,0.08)",
                    border: "1px solid rgba(255,77,109,0.2)",
                  }}
                >
                  <p
                    className="text-2xl font-display font-bold"
                    style={{ color: "var(--accent-red)" }}
                  >
                    {predictionHistory.filter((p) => p.riskLevel === "CRITICAL").length}
                  </p>
                  <p
                    className="text-[9px] uppercase tracking-wider"
                    style={{ color: "var(--accent-red)" }}
                  >
                    Critical
                  </p>
                </div>
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs" style={{ color: "var(--text-muted)" }}>System Events</span>
                  <span className="text-xs font-mono font-bold" style={{ color: "var(--accent-cyan)" }}>
                    {storeEvents.length}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs" style={{ color: "var(--text-muted)" }}>Uploaded</span>
                  <span className="text-xs font-mono font-bold" style={{ color: "#a855f7" }}>
                    {uploadedEvents.length}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs" style={{ color: "var(--text-muted)" }}>Total Events</span>
                  <span className="text-xs font-mono font-bold" style={{ color: "var(--text-primary)" }}>
                    {predictionHistory.length + storeEvents.length + uploadedEvents.length}
                  </span>
                </div>
              </div>
            </div>
          </GlassPanel>

          {/* Uploaded Events List */}
          {uploadedEvents.length > 0 && (
            <GlassPanel title="Uploaded Events" icon={<FileText className="w-4 h-4" />} className="flex-1 min-h-0">
              <div className="space-y-2 overflow-y-auto" style={{ maxHeight: "200px" }}>
                {uploadedEvents.slice(0, 20).map((evt) => {
                  const colors = EVENT_TYPE_COLORS[evt.type] || EVENT_TYPE_COLORS.system;
                  return (
                    <div
                      key={evt.id}
                      className="flex items-start justify-between p-2.5 rounded-lg"
                      style={{
                        border: `1px solid ${colors.border}`,
                        background: colors.bg,
                      }}
                    >
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <span
                            className="text-[9px] font-mono font-bold uppercase"
                            style={{ color: colors.text }}
                          >
                            {evt.type}
                          </span>
                          <span
                            className="text-[9px] font-mono"
                            style={{ color: "var(--text-muted)" }}
                          >
                            {new Date(evt.timestamp).toLocaleTimeString()}
                          </span>
                        </div>
                        <p
                          className="text-[11px] truncate"
                          style={{ color: "var(--text-primary)" }}
                        >
                          {evt.message}
                        </p>
                      </div>
                      <button
                        onClick={() => removeUploaded(evt.id)}
                        className="ml-2 p-1 rounded hover:bg-white/5 transition-colors"
                      >
                        <X className="w-3 h-3" style={{ color: "var(--text-muted)" }} />
                      </button>
                    </div>
                  );
                })}
              </div>
            </GlassPanel>
          )}
        </motion.div>
      </div>
    </div>
  );
}
