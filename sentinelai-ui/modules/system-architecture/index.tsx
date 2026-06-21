"use client";

import { useMemo } from "react";
import { motion } from "framer-motion";
import { useSystemStore } from "@/stores/systemStore";
import { usePredictionStore } from "@/stores/predictionStore";
import { Globe, Server, Brain, Database, Activity, Shield, Wifi, Cpu } from "lucide-react";
import type { LucideIcon } from "lucide-react";

interface ServiceNode {
  id: string;
  label: string;
  icon: LucideIcon;
  status: "online" | "degraded" | "offline";
  latency: number;
  description: string;
  color: string;
}

const stagger = {
  hidden: { opacity: 0 },
  show: { opacity: 1, transition: { staggerChildren: 0.08 } },
};
const fadeUp = {
  hidden: { opacity: 0, y: 16 },
  show: { opacity: 1, y: 0, transition: { duration: 0.4, ease: [0.22, 1, 0.36, 1] as const } },
};

export default function SystemArchitecture() {
  const backendStatus = useSystemStore((s) => s.backendStatus);
  const apiLatency = useSystemStore((s) => s.apiLatency);
  const predictionHistory = usePredictionStore((s) => s.predictionHistory);

  const isOnline = backendStatus === "online";

  const services: ServiceNode[] = useMemo(() => [
    {
      id: "frontend", label: "Next.js Frontend", icon: Globe,
      status: "online", latency: 0,
      description: "React SPA with Zustand state management",
      color: "#00e5ff",
    },
    {
      id: "gateway", label: "FastAPI Gateway", icon: Server,
      status: isOnline ? "online" : "offline", latency: apiLatency,
      description: "REST API + WebSocket event stream",
      color: isOnline ? "#00ff88" : "#ff4d6d",
    },
    {
      id: "ml", label: "ML Prediction Engine", icon: Brain,
      status: isOnline ? "online" : "offline",
      latency: predictionHistory[0]?.latencyMs || 0,
      description: "Neural Network + Markov Chain hybrid",
      color: isOnline ? "#00e5ff" : "#ff9500",
    },
    {
      id: "analytics", label: "Analytics Engine", icon: Activity,
      status: "online", latency: 0,
      description: "Real-time metrics and drift detection",
      color: "#00e5ff",
    },
    {
      id: "db", label: "SQLite Database", icon: Database,
      status: "online", latency: 0,
      description: "WAL mode, thread-safe persistence",
      color: "#00ff88",
    },
    {
      id: "auth", label: "Auth Service", icon: Shield,
      status: "online", latency: 0,
      description: "JWT + bcrypt + rate limiting",
      color: "#00ff88",
    },
    {
      id: "ws", label: "WebSocket Stream", icon: Wifi,
      status: isOnline ? "online" : "offline", latency: 0,
      description: "Real-time event broadcasting",
      color: isOnline ? "#00ff88" : "#ff4d6d",
    },
    {
      id: "gemini", label: "Gemini AI Copilot", icon: Cpu,
      status: "online", latency: 0,
      description: "Gemini 2.0 Flash with context injection",
      color: "#a855f7",
    },
  ], [isOnline, apiLatency, predictionHistory]);

  const connections = [
    { from: "frontend", to: "gateway", label: "HTTP/WS" },
    { from: "gateway", to: "ml", label: "Predict" },
    { from: "gateway", to: "analytics", label: "Metrics" },
    { from: "gateway", to: "auth", label: "JWT" },
    { from: "gateway", to: "ws", label: "Events" },
    { from: "ml", to: "db", label: "Store" },
    { from: "analytics", to: "db", label: "Query" },
    { from: "gateway", to: "gemini", label: "Copilot" },
  ];

  return (
    <div className="h-full overflow-y-auto p-6 lg:p-8">
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="mb-6">
        <p className="text-[10px] font-mono tracking-[0.3em] uppercase mb-2" style={{ color: "var(--accent-cyan)" }}>
          System Overview
        </p>
        <h1 className="text-3xl font-display font-bold" style={{ color: "var(--text-primary)" }}>
          Architecture
        </h1>
        <p className="text-sm mt-2" style={{ color: "var(--text-secondary)" }}>
          Live status of all SentinelAI backend services and their interconnections.
        </p>
      </motion.div>

      <motion.div variants={stagger} initial="hidden" animate="show" className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {services.map((svc) => (
          <motion.div
            key={svc.id}
            variants={fadeUp}
            className="rounded-2xl p-5 relative overflow-hidden"
            style={{
              background: "rgba(8,20,32,0.7)",
              backdropFilter: "blur(24px)",
              border: `1px solid ${svc.color}15`,
            }}
          >
            <div className="flex items-center gap-3 mb-3">
              <div
                className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0"
                style={{ background: `${svc.color}10`, border: `1px solid ${svc.color}20` }}
              >
                <svc.icon className="w-5 h-5" style={{ color: svc.color }} />
              </div>
              <div>
                <span className="text-xs font-mono font-bold block" style={{ color: "var(--text-primary)" }}>
                  {svc.label}
                </span>
                <span className="text-[8px] font-mono" style={{ color: "var(--text-muted)" }}>
                  {svc.description}
                </span>
              </div>
            </div>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5">
                <span className="relative flex h-2 w-2 shrink-0">
                  {svc.status === "online" && (
                    <span className="absolute inline-flex h-full w-full animate-ping rounded-full opacity-75" style={{ background: svc.color }} />
                  )}
                  <span className="relative inline-flex h-2 w-2 rounded-full" style={{ background: svc.color }} />
                </span>
                <span className="text-[9px] font-mono font-bold" style={{ color: svc.color }}>
                  {svc.status.toUpperCase()}
                </span>
              </div>
              {svc.latency > 0 && (
                <span className="text-[8px] font-mono" style={{ color: "var(--text-muted)" }}>
                  {svc.latency}ms
                </span>
              )}
            </div>
          </motion.div>
        ))}
      </motion.div>

      <div className="mt-8 rounded-2xl p-6" style={{ background: "rgba(8,20,32,0.5)", border: "1px solid rgba(0,229,255,0.06)" }}>
        <span className="text-[10px] font-mono tracking-[0.2em] uppercase mb-4 block" style={{ color: "var(--text-muted)" }}>
          Data Flow
        </span>
        <div className="flex flex-wrap gap-3">
          {connections.map((conn) => (
            <div key={`${conn.from}-${conn.to}`} className="flex items-center gap-2 rounded-lg px-3 py-1.5"
              style={{ background: "rgba(0,229,255,0.04)", border: "1px solid rgba(0,229,255,0.08)" }}>
              <span className="text-[9px] font-mono" style={{ color: "var(--accent-cyan)" }}>{conn.from}</span>
              <span className="text-[9px] font-mono" style={{ color: "var(--text-muted)" }}>→</span>
              <span className="text-[9px] font-mono" style={{ color: "var(--accent-cyan)" }}>{conn.to}</span>
              <span className="text-[7px] font-mono px-1.5 py-0.5 rounded" style={{ background: "rgba(0,229,255,0.08)", color: "var(--text-muted)" }}>
                {conn.label}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
