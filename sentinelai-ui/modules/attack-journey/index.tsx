"use client";

import { useEffect, useMemo, useState } from "react";
import { motion } from "framer-motion";
import { Globe, Shield, Server, Database, AlertTriangle, Wifi } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { getThreatsAPI, getAlertsAPI, getDashboardStatsAPI, getIncidentsAPI } from "@/lib/api";

interface JourneyNode {
  id: string;
  label: string;
  icon: LucideIcon;
  ip: string;
  status: "safe" | "warning" | "compromised";
  riskScore: number;
  eventCount: number;
  lastActivity: string;
}

const STATUS_COLORS: Record<string, string> = {
  safe: "#00ff88",
  warning: "#ff9500",
  compromised: "#ff4d6d",
};

const NODE_ICONS: Record<string, LucideIcon> = {
  internet: Globe,
  firewall: Shield,
  server: Server,
  database: Database,
  network: Wifi,
  endpoint: AlertTriangle,
};

export default function AttackJourney() {
  const [loading, setLoading] = useState(true);
  const [threats, setThreats] = useState<any[]>([]);
  const [alerts, setAlerts] = useState<any[]>([]);
  const [events, setEvents] = useState<any[]>([]);
  const [incidents, setIncidents] = useState<any[]>([]);
  const [animating, setAnimating] = useState(false);
  const [activeIdx, setActiveIdx] = useState(-1);
  const [selectedAlert, setSelectedAlert] = useState<any>(null);

  useEffect(() => {
    loadRealData();
  }, []);

  const loadRealData = async () => {
    setLoading(true);
    try {
      const [threatsRes, alertsRes, statsRes, incidentsRes] = await Promise.all([
        getThreatsAPI({ limit: 100 }),
        getAlertsAPI({ limit: 100 }),
        getDashboardStatsAPI(),
        getIncidentsAPI({ limit: 50 }),
      ]);
      setThreats(threatsRes.threats || []);
      setAlerts(alertsRes.alerts || []);
      setEvents([]); // Events come from WebSocket, not API
      setIncidents(incidentsRes.incidents || []);
    } catch (e) {
      console.error("Failed to load attack journey data:", e);
    } finally {
      setLoading(false);
    }
  };

  const journey = useMemo(() => {
    if (loading) return [];

    // Build nodes from real IP data
    const ipMap = new Map<string, { threats: number; alerts: number; severity: string; lastSeen: string }>();

    for (const t of threats) {
      const ip = t.source_ip || "unknown";
      const existing = ipMap.get(ip) || { threats: 0, alerts: 0, severity: "LOW", lastSeen: "" };
      existing.threats++;
      const sevOrder = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
      if ((sevOrder[t.severity as keyof typeof sevOrder] || 0) > (sevOrder[existing.severity as keyof typeof sevOrder] || 0)) {
        existing.severity = t.severity;
      }
      if (t.detection_time > existing.lastSeen) existing.lastSeen = t.detection_time;
      ipMap.set(ip, existing);
    }

    for (const a of alerts) {
      const ip = a.source_ip || "unknown";
      const existing = ipMap.get(ip) || { threats: 0, alerts: 0, severity: "LOW", lastSeen: "" };
      existing.alerts++;
      if (a.severity === "CRITICAL" || a.severity === "HIGH") {
        existing.severity = a.severity;
      }
      if (a.created_at > existing.lastSeen) existing.lastSeen = a.created_at;
      ipMap.set(ip, existing);
    }

    // Sort by threat count descending
    const sortedIps = Array.from(ipMap.entries())
      .sort((a, b) => (b[1].threats + b[1].alerts) - (a[1].threats + a[1].alerts))
      .slice(0, 8);

    if (sortedIps.length === 0) {
      // No real data — show empty state
      return [];
    }

    const nodes: JourneyNode[] = sortedIps.map(([ip, data], idx) => {
      const riskScore = Math.min(100, data.threats * 10 + data.alerts * 5);
      const status = data.severity === "CRITICAL" ? "compromised"
        : data.severity === "HIGH" ? "compromised"
        : data.severity === "MEDIUM" ? "warning"
        : "safe";

      const icon = idx === 0 ? Globe
        : idx === 1 ? Shield
        : idx === 2 ? Server
        : idx === 3 ? Database
        : idx === 4 ? Wifi
        : AlertTriangle;

      return {
        id: `node-${idx}`,
        label: idx === 0 ? "Primary Attacker" : idx === 1 ? "Secondary Source" : `Source ${idx + 1}`,
        icon,
        ip,
        status: status as "safe" | "warning" | "compromised",
        riskScore,
        eventCount: data.threats + data.alerts,
        lastActivity: data.lastSeen,
      };
    });

    return nodes;
  }, [threats, alerts, events, incidents, loading]);

  const replay = () => {
    if (animating || journey.length === 0) return;
    setAnimating(true);
    setActiveIdx(-1);
    let i = 0;
    const interval = setInterval(() => {
      setActiveIdx(i);
      i++;
      if (i >= journey.length) {
        clearInterval(interval);
        setTimeout(() => setAnimating(false), 1000);
      }
    }, 600);
  };

  if (loading) {
    return (
      <div className="h-full flex items-center justify-center">
        <div className="text-center">
          <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
          <p className="text-xs font-mono" style={{ color: "var(--text-muted)" }}>Loading attack data...</p>
        </div>
      </div>
    );
  }

  if (journey.length === 0) {
    return (
      <div className="h-full flex items-center justify-center p-6">
        <div className="text-center max-w-md">
          <div className="w-16 h-16 rounded-2xl mx-auto mb-4 flex items-center justify-center" style={{ background: "rgba(0,229,255,0.08)", border: "1px solid rgba(0,229,255,0.15)" }}>
            <Shield className="w-8 h-8" style={{ color: "var(--accent-cyan)" }} />
          </div>
          <h2 className="text-xl font-bold mb-2" style={{ color: "var(--text-primary)" }}>No Attack Data Yet</h2>
          <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
            Install the SentinelAI agent on your endpoints and generate some traffic. Attack paths will appear here once threats are detected.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full overflow-y-auto p-6 lg:p-8">
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="mb-6">
        <p className="text-[10px] font-mono tracking-[0.3em] uppercase mb-2" style={{ color: "var(--accent-cyan)" }}>
          Real-Time Threat Visualization
        </p>
        <h1 className="text-3xl font-display font-bold" style={{ color: "var(--text-primary)" }}>
          Attack Journey
        </h1>
        <p className="text-sm mt-2" style={{ color: "var(--text-secondary)" }}>
          Source IPs from {threats.length} detections and {alerts.length} alerts. Click any node for details.
        </p>
      </motion.div>

      <div className="flex items-center gap-4 mb-8">
        <button
          onClick={replay}
          disabled={animating}
          className="px-4 py-2 rounded-xl text-[10px] font-mono font-bold tracking-wider transition-all"
          style={{
            background: animating ? "rgba(0,229,255,0.05)" : "rgba(0,229,255,0.12)",
            color: animating ? "var(--text-muted)" : "var(--accent-cyan)",
            border: "1px solid rgba(0,229,255,0.2)",
            cursor: animating ? "not-allowed" : "pointer",
          }}
        >
          {animating ? "Replaying..." : "Replay Attack Path"}
        </button>
        <span className="text-[10px] font-mono" style={{ color: "var(--text-muted)" }}>
          {journey.length} source IPs tracked
        </span>
      </div>

      <div className="flex gap-6">
        {/* Attack Path */}
        <div className="flex-1 flex flex-col items-center gap-0">
          {journey.map((node, i) => {
            const isActive = i <= activeIdx;
            const color = STATUS_COLORS[node.status];
            const Icon = node.icon;
            return (
              <div key={node.id} className="flex flex-col items-center">
                <motion.div
                  className="relative rounded-2xl p-5 w-[340px] cursor-pointer"
                  style={{
                    background: isActive ? `${color}08` : "rgba(8,20,32,0.5)",
                    border: `1px solid ${isActive ? `${color}30` : "rgba(0,229,255,0.06)"}`,
                    backdropFilter: "blur(12px)",
                  }}
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{
                    opacity: isActive ? 1 : 0.4,
                    scale: isActive ? 1 : 0.95,
                  }}
                  transition={{ duration: 0.4 }}
                  onClick={() => setSelectedAlert(selectedAlert?.source_ip === node.ip ? null : { source_ip: node.ip })}
                >
                  {isActive && (
                    <motion.div
                      className="absolute inset-0 rounded-2xl"
                      style={{ boxShadow: `0 0 20px ${color}15` }}
                      animate={{ opacity: [0.5, 1, 0.5] }}
                      transition={{ duration: 2, repeat: Infinity }}
                    />
                  )}
                  <div className="relative flex items-center gap-3">
                    <div
                      className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0"
                      style={{ background: `${color}15`, border: `1px solid ${color}25` }}
                    >
                      <Icon className="w-5 h-5" style={{ color }} />
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-mono font-bold" style={{ color: isActive ? "var(--text-primary)" : "var(--text-muted)" }}>
                          {node.label}
                        </span>
                        <span
                          className="px-1.5 py-0.5 rounded text-[7px] font-mono font-bold"
                          style={{
                            background: `${color}15`,
                            color,
                            border: `1px solid ${color}25`,
                          }}
                        >
                          {node.status.toUpperCase()}
                        </span>
                      </div>
                      <div className="flex items-center gap-3 mt-1 text-[9px] font-mono" style={{ color: "var(--text-muted)" }}>
                        <span>{node.ip}</span>
                        <span style={{ color }}>{node.riskScore}% risk</span>
                        <span>{node.eventCount} events</span>
                      </div>
                      {node.lastActivity && (
                        <div className="text-[8px] font-mono mt-0.5" style={{ color: "var(--text-muted)" }}>
                          Last: {node.lastActivity.slice(0, 19)}
                        </div>
                      )}
                    </div>
                  </div>
                </motion.div>
                {i < journey.length - 1 && (
                  <div className="relative h-8 w-px" style={{ background: "rgba(0,229,255,0.1)" }}>
                    {isActive && i < activeIdx && (
                      <motion.div
                        className="absolute top-0 left-0 w-full rounded-full"
                        style={{ background: STATUS_COLORS[journey[i + 1].status] }}
                        initial={{ height: 0 }}
                        animate={{ height: "100%" }}
                        transition={{ duration: 0.4 }}
                      />
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Detail Panel */}
        {selectedAlert && (
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            className="w-80 rounded-2xl p-5"
            style={{ background: "rgba(8,20,32,0.7)", border: "1px solid rgba(0,229,255,0.1)", backdropFilter: "blur(24px)" }}
          >
            <h3 className="text-sm font-mono font-bold mb-3" style={{ color: "var(--accent-cyan)" }}>
              Source IP Details
            </h3>
            <div className="space-y-2 text-[10px] font-mono" style={{ color: "var(--text-secondary)" }}>
              <div className="flex justify-between">
                <span>IP Address</span>
                <span style={{ color: "var(--text-primary)" }}>{selectedAlert.source_ip}</span>
              </div>
              <div className="flex justify-between">
                <span>Threats from this IP</span>
                <span style={{ color: "var(--text-primary)" }}>
                  {threats.filter((t) => t.source_ip === selectedAlert.source_ip).length}
                </span>
              </div>
              <div className="flex justify-between">
                <span>Alerts from this IP</span>
                <span style={{ color: "var(--text-primary)" }}>
                  {alerts.filter((a) => a.source_ip === selectedAlert.source_ip).length}
                </span>
              </div>
            </div>

            <div className="mt-4">
              <h4 className="text-[10px] font-mono font-bold mb-2" style={{ color: "var(--text-muted)" }}>
                Recent Threats
              </h4>
              <div className="space-y-2 max-h-60 overflow-y-auto">
                {threats
                  .filter((t) => t.source_ip === selectedAlert.source_ip)
                  .slice(0, 5)
                  .map((t, idx) => (
                    <div
                      key={idx}
                      className="rounded-lg p-2"
                      style={{ background: "rgba(0,229,255,0.03)", border: "1px solid rgba(0,229,255,0.06)" }}
                    >
                      <div className="flex items-center gap-2">
                        <span
                          className="text-[8px] font-mono font-bold px-1 py-0.5 rounded"
                          style={{
                            background: t.severity === "CRITICAL" ? "rgba(255,77,109,0.15)" : t.severity === "HIGH" ? "rgba(255,149,0,0.15)" : "rgba(0,229,255,0.1)",
                            color: t.severity === "CRITICAL" ? "#ff4d6d" : t.severity === "HIGH" ? "#ff9500" : "var(--accent-cyan)",
                          }}
                        >
                          {t.severity}
                        </span>
                        <span className="text-[9px] font-mono" style={{ color: "var(--text-primary)" }}>
                          {t.threat_type?.replace(/_/g, " ")}
                        </span>
                      </div>
                      <div className="text-[8px] font-mono mt-1" style={{ color: "var(--text-muted)" }}>
                        {t.description?.slice(0, 80)}
                      </div>
                    </div>
                  ))}
                {threats.filter((t) => t.source_ip === selectedAlert.source_ip).length === 0 && (
                  <p className="text-[9px] font-mono" style={{ color: "var(--text-muted)" }}>No threats recorded</p>
                )}
              </div>
            </div>
          </motion.div>
        )}
      </div>
    </div>
  );
}
