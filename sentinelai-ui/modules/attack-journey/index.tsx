"use client";

import { useMemo, useState } from "react";
import { motion } from "framer-motion";
import { usePredictionStore } from "@/stores/predictionStore";
import { useEventStore } from "@/stores/eventStore";
import { Globe, Shield, Server, Database } from "lucide-react";
import type { LucideIcon } from "lucide-react";

interface JourneyNode {
  id: string;
  label: string;
  icon: LucideIcon;
  ip: string;
  status: "safe" | "warning" | "compromised";
  riskScore: number;
  responseTime: number;
}

const STATUS_COLORS: Record<string, string> = {
  safe: "#00ff88",
  warning: "#ff9500",
  compromised: "#ff4d6d",
};

const defaultJourney: JourneyNode[] = [
  { id: "1", label: "Internet", icon: Globe, ip: "0.0.0.0/0", status: "safe", riskScore: 0, responseTime: 0 },
  { id: "2", label: "Firewall", icon: Shield, ip: "10.0.0.1", status: "safe", riskScore: 10, responseTime: 2 },
  { id: "3", label: "Web Server", icon: Server, ip: "10.0.1.100", status: "safe", riskScore: 0, responseTime: 15 },
  { id: "4", label: "Database", icon: Database, ip: "10.0.2.50", status: "safe", riskScore: 0, responseTime: 8 },
];

export default function AttackJourney() {
  const predictionHistory = usePredictionStore((s) => s.predictionHistory);
  const events = useEventStore((s) => s.events);
  const [animating, setAnimating] = useState(false);
  const [activeIdx, setActiveIdx] = useState(-1);

  const journey = useMemo(() => {
    const nodes = [...defaultJourney];
    const latest = predictionHistory[0];
    if (!latest) return nodes;

    const attack = latest.predictedAttack;
    const severity = latest.riskLevel;

    if (attack === "BruteForce" || attack === "WebAttack") {
      nodes[1].status = "warning";
      nodes[1].riskScore = 45;
      nodes[2].status = severity === "CRITICAL" ? "compromised" : "warning";
      nodes[2].riskScore = severity === "CRITICAL" ? 85 : 55;
    } else if (attack === "Infiltration") {
      nodes[1].status = "warning";
      nodes[1].riskScore = 30;
      nodes[2].status = "warning";
      nodes[2].riskScore = 60;
      nodes[3].status = "compromised";
      nodes[3].riskScore = 90;
    } else if (attack === "DDoS" || attack === "DoS") {
      nodes[0].status = "warning";
      nodes[0].riskScore = 70;
      nodes[1].status = "compromised";
      nodes[1].riskScore = 80;
    } else if (attack === "PortScan") {
      nodes[0].status = "warning";
      nodes[0].riskScore = 40;
      nodes[1].status = "warning";
      nodes[1].riskScore = 35;
    }

    const wsEvent = events.find((e) => {
      const d = e.details as Record<string, unknown> | undefined;
      return d && "attack_type" in d;
    });
    if (wsEvent) {
      const d = wsEvent.details as Record<string, unknown>;
      nodes[1].ip = (d.source_ip as string) || nodes[1].ip;
    }

    return nodes;
  }, [predictionHistory, events]);

  const replay = () => {
    if (animating) return;
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

  return (
    <div className="h-full overflow-y-auto p-6 lg:p-8">
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="mb-6">
        <p className="text-[10px] font-mono tracking-[0.3em] uppercase mb-2" style={{ color: "var(--accent-cyan)" }}>
          Attack Visualization
        </p>
        <h1 className="text-3xl font-display font-bold" style={{ color: "var(--text-primary)" }}>
          Attack Journey
        </h1>
        <p className="text-sm mt-2" style={{ color: "var(--text-secondary)" }}>
          Visualize the path of an attack through your network infrastructure.
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
          {animating ? "Replaying..." : "Replay Attack"}
        </button>
      </div>

      <div className="flex flex-col items-center gap-0">
        {journey.map((node, i) => {
          const isActive = i <= activeIdx;
          const color = STATUS_COLORS[node.status];
          const Icon = node.icon;
          return (
            <div key={node.id} className="flex flex-col items-center">
              <motion.div
                className="relative rounded-2xl p-5 w-[320px] cursor-pointer"
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
                      {node.riskScore > 0 && (
                        <span style={{ color }}>Risk: {node.riskScore}%</span>
                      )}
                      {node.responseTime > 0 && (
                        <span>{node.responseTime}ms</span>
                      )}
                    </div>
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
                  {isActive && (
                    <motion.div
                      className="absolute left-1/2 -translate-x-1/2 w-1.5 h-1.5 rounded-full"
                      style={{ background: STATUS_COLORS[journey[i + 1]?.status || "safe"] }}
                      animate={{ top: ["0%", "100%", "0%"] }}
                      transition={{ duration: 1.5, repeat: Infinity, ease: "linear" }}
                    />
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}