"use client";

import { useState, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { RiskBadge } from "@/components/ui/RiskBadge";
import { usePredictionStore } from "@/stores/predictionStore";
import {
  Shield,
  ChevronDown,
  ChevronUp,
  Clock,
  Cpu,
  AlertTriangle,
  Zap,
  ArrowDown,
} from "lucide-react";

const RISK_GLOW: Record<string, string> = {
  CRITICAL: "0 0 20px rgba(255,77,109,0.3), 0 0 40px rgba(255,77,109,0.1)",
  HIGH: "0 0 20px rgba(255,176,32,0.3), 0 0 40px rgba(255,176,32,0.1)",
  MEDIUM: "0 0 15px rgba(255,176,32,0.2)",
  LOW: "0 0 15px rgba(34,197,94,0.2)",
};

const RISK_BORDER: Record<string, string> = {
  CRITICAL: "rgba(255,77,109,0.4)",
  HIGH: "rgba(255,176,32,0.4)",
  MEDIUM: "rgba(255,176,32,0.25)",
  LOW: "rgba(34,197,94,0.25)",
};

const RISK_BG: Record<string, string> = {
  CRITICAL: "rgba(255,77,109,0.06)",
  HIGH: "rgba(255,176,32,0.06)",
  MEDIUM: "rgba(255,176,32,0.04)",
  LOW: "rgba(34,197,94,0.04)",
};

const ATTACK_CHIP_COLORS: Record<string, { bg: string; text: string }> = {
  DDoS: { bg: "rgba(255,77,109,0.15)", text: "var(--accent-red)" },
  DoS: { bg: "rgba(255,77,109,0.1)", text: "var(--accent-red)" },
  PortScan: { bg: "rgba(0,229,255,0.12)", text: "var(--accent-cyan)" },
  Bot: { bg: "rgba(168,85,247,0.12)", text: "#a855f7" },
  WebAttack: { bg: "rgba(255,176,32,0.12)", text: "var(--accent-amber)" },
  BruteForce: { bg: "rgba(255,176,32,0.15)", text: "var(--accent-amber)" },
  Infiltration: { bg: "rgba(239,68,68,0.12)", text: "#ef4444" },
  BENIGN: { bg: "rgba(34,197,94,0.08)", text: "var(--accent-green)" },
};

function getAttackChipColor(attack: string) {
  return ATTACK_CHIP_COLORS[attack] || { bg: "rgba(0,229,255,0.08)", text: "var(--accent-cyan)" };
}

function TimelineNode({
  pred,
  index,
  isExpanded,
  onToggle,
  isLast,
}: {
  pred: {
    id: string;
    timestamp: string;
    predictedAttack: string;
    confidence: number;
    riskLevel: string;
    model: string;
    sequence: string[];
  };
  index: number;
  isExpanded: boolean;
  onToggle: () => void;
  isLast: boolean;
}) {
  const risk = pred.riskLevel || "LOW";
  const chipColor = getAttackChipColor(pred.predictedAttack);
  const confidencePercent = Math.round(pred.confidence * 100);

  return (
    <motion.div
      initial={{ opacity: 0, y: 40, scale: 0.9 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      transition={{
        delay: index * 0.12,
        duration: 0.5,
        ease: [0.25, 0.46, 0.45, 0.94],
      }}
      className="relative flex gap-4"
    >
      {/* Vertical connector line */}
      {!isLast && (
        <div className="absolute left-5 top-12 bottom-0 w-px" style={{ zIndex: 0 }}>
          <motion.div
            className="w-full"
            style={{
              height: "100%",
              background: `linear-gradient(180deg, ${RISK_BORDER[risk] || "rgba(0,229,255,0.2)"}, rgba(0,229,255,0.08))`,
            }}
            initial={{ scaleY: 0 }}
            animate={{ scaleY: 1 }}
            transition={{ delay: index * 0.12 + 0.3, duration: 0.4 }}
          />
          {/* Glow on line */}
          <div
            className="absolute top-0 left-0 w-full h-4"
            style={{
              background: `linear-gradient(180deg, ${RISK_BORDER[risk] || "rgba(0,229,255,0.3)"}, transparent)`,
              filter: "blur(4px)",
            }}
          />
        </div>
      )}

      {/* Node circle */}
      <div className="relative flex-shrink-0" style={{ zIndex: 1 }}>
        <motion.div
          className="w-10 h-10 rounded-full flex items-center justify-center"
          style={{
            background: RISK_BG[risk],
            border: `2px solid ${RISK_BORDER[risk]}`,
            boxShadow: RISK_GLOW[risk] || "none",
          }}
          whileHover={{ scale: 1.15 }}
          transition={{ type: "spring", stiffness: 400, damping: 20 }}
        >
          <Shield
            className="w-4 h-4"
            style={{ color: RISK_BORDER[risk] }}
          />
        </motion.div>
        {/* Pulse ring for CRITICAL */}
        {risk === "CRITICAL" && (
          <motion.div
            className="absolute inset-0 rounded-full"
            style={{ border: "1px solid rgba(255,77,109,0.3)" }}
            animate={{ scale: [1, 1.6, 1], opacity: [0.6, 0, 0.6] }}
            transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}
          />
        )}
      </div>

      {/* Node content */}
      <motion.div
        className="flex-1 rounded-xl p-4 cursor-pointer transition-all duration-300"
        style={{
          border: `1px solid ${RISK_BORDER[risk]}`,
          background: RISK_BG[risk],
          boxShadow: isExpanded ? RISK_GLOW[risk] : "none",
        }}
        onClick={onToggle}
        whileHover={{ scale: 1.005 }}
      >
        {/* Header row */}
        <div className="flex items-start justify-between mb-2">
          <div className="flex items-center gap-2 flex-wrap">
            <span
              className="px-2.5 py-1 rounded-lg text-[10px] font-mono font-bold uppercase tracking-wider"
              style={{
                background: chipColor.bg,
                color: chipColor.text,
                border: `1px solid ${chipColor.text}33`,
              }}
            >
              {pred.predictedAttack}
            </span>
            <RiskBadge level={risk as "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"} />
          </div>
          <div className="flex items-center gap-2">
            <span
              className="text-[10px] font-mono flex items-center gap-1"
              style={{ color: "var(--text-muted)" }}
            >
              <Clock className="w-3 h-3" />
              {new Date(pred.timestamp).toLocaleTimeString()}
            </span>
            {isExpanded ? (
              <ChevronUp className="w-4 h-4" style={{ color: "var(--text-muted)" }} />
            ) : (
              <ChevronDown className="w-4 h-4" style={{ color: "var(--text-muted)" }} />
            )}
          </div>
        </div>

        {/* Confidence bar */}
        <div className="mb-3">
          <div className="flex items-center justify-between mb-1">
            <span className="text-[10px] font-mono" style={{ color: "var(--text-muted)" }}>
              Confidence
            </span>
            <span
              className="text-[10px] font-mono font-bold"
              style={{ color: "var(--accent-cyan)" }}
            >
              {confidencePercent}%
            </span>
          </div>
          <div
            className="h-1.5 rounded-full overflow-hidden"
            style={{ background: "rgba(0,229,255,0.08)" }}
          >
            <motion.div
              className="h-full rounded-full"
              style={{
                background:
                  confidencePercent >= 80
                    ? "var(--accent-green)"
                    : confidencePercent >= 50
                    ? "var(--accent-amber)"
                    : "var(--accent-red)",
              }}
              initial={{ width: 0 }}
              animate={{ width: `${confidencePercent}%` }}
              transition={{ delay: index * 0.12 + 0.3, duration: 0.6, ease: "easeOut" }}
            />
          </div>
        </div>

        {/* Sequence chips */}
        <div className="flex flex-wrap gap-1.5 mb-2">
          {pred.sequence.slice(0, isExpanded ? pred.sequence.length : 5).map((atk, i) => {
            const sc = getAttackChipColor(atk);
            return (
              <motion.span
                key={i}
                initial={{ opacity: 0, scale: 0.8 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ delay: index * 0.12 + 0.4 + i * 0.03 }}
                className="px-2 py-0.5 rounded-md text-[9px] font-mono font-medium"
                style={{
                  background: sc.bg,
                  color: sc.text,
                }}
              >
                {atk}
              </motion.span>
            );
          })}
          {!isExpanded && pred.sequence.length > 5 && (
            <span
              className="px-2 py-0.5 rounded-md text-[9px] font-mono"
              style={{ color: "var(--text-muted)" }}
            >
              +{pred.sequence.length - 5}
            </span>
          )}
        </div>

        {/* Expanded details */}
        <AnimatePresence>
          {isExpanded && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: "auto", opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.3 }}
              className="overflow-hidden"
            >
              <div
                className="mt-3 pt-3 space-y-2"
                style={{ borderTop: "1px solid rgba(0,229,255,0.08)" }}
              >
                <div className="grid grid-cols-2 gap-3">
                  <div className="flex items-center gap-2">
                    <Cpu className="w-3 h-3" style={{ color: "var(--text-muted)" }} />
                    <span className="text-[10px] font-mono" style={{ color: "var(--text-muted)" }}>
                      Model: <span style={{ color: "var(--text-primary)" }}>{pred.model}</span>
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Zap className="w-3 h-3" style={{ color: "var(--text-muted)" }} />
                    <span className="text-[10px] font-mono" style={{ color: "var(--text-muted)" }}>
                      Risk: <span style={{ color: "var(--text-primary)" }}>{risk}</span>
                    </span>
                  </div>
                </div>
                <div className="flex items-start gap-2">
                  <AlertTriangle className="w-3 h-3 mt-0.5 flex-shrink-0" style={{ color: "var(--text-muted)" }} />
                  <span className="text-[10px] font-mono" style={{ color: "var(--text-muted)" }}>
                    Full sequence ({pred.sequence.length} events):{" "}
                    <span style={{ color: "var(--text-secondary)" }}>
                      {pred.sequence.join(" → ")}
                    </span>
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <Clock className="w-3 h-3" style={{ color: "var(--text-muted)" }} />
                  <span className="text-[10px] font-mono" style={{ color: "var(--text-muted)" }}>
                    Timestamp:{" "}
                    <span style={{ color: "var(--text-primary)" }}>
                      {new Date(pred.timestamp).toLocaleString()}
                    </span>
                  </span>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>
    </motion.div>
  );
}

export default function Timeline() {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const predictionHistory = usePredictionStore((s) => s.predictionHistory);

  const timelineData = useMemo(() => {
    return [...predictionHistory].reverse();
  }, [predictionHistory]);

  const toggleNode = (id: string) => {
    setExpandedId((prev) => (prev === id ? null : id));
  };

  return (
    <div className="h-full p-6 lg:p-8 flex flex-col gap-6 overflow-hidden">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <p
          className="text-[10px] font-mono tracking-[0.3em] uppercase mb-2"
          style={{ color: "var(--accent-cyan)" }}
        >
          Attack Progression
        </p>
        <h1
          className="text-3xl font-display font-bold"
          style={{ color: "var(--text-primary)" }}
        >
          Prediction Timeline
        </h1>
        <p
          className="text-sm mt-2"
          style={{ color: "var(--text-secondary)" }}
        >
          Attack sequence chain — each node is a prediction event
        </p>
      </motion.div>

      {/* Timeline Content */}
      <div className="flex-1 overflow-y-auto pr-2">
        {timelineData.length > 0 ? (
          <div className="relative">
            {/* Animated arrow indicator */}
            <motion.div
              className="flex justify-center mb-6"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.5 }}
            >
              <motion.div
                animate={{ y: [0, 6, 0] }}
                transition={{ duration: 1.5, repeat: Infinity, ease: "easeInOut" }}
              >
                <ArrowDown
                  className="w-5 h-5"
                  style={{ color: "var(--accent-cyan)", opacity: 0.5 }}
                />
              </motion.div>
            </motion.div>

            <div className="space-y-6">
              {timelineData.map((pred, index) => (
                <TimelineNode
                  key={pred.id}
                  pred={pred}
                  index={index}
                  isExpanded={expandedId === pred.id}
                  onToggle={() => toggleNode(pred.id)}
                  isLast={index === timelineData.length - 1}
                />
              ))}
            </div>

            {/* Bottom sentinel */}
            <motion.div
              className="flex justify-center mt-8"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: timelineData.length * 0.12 + 0.5 }}
            >
              <div
                className="px-4 py-2 rounded-full text-[10px] font-mono uppercase tracking-widest"
                style={{
                  border: "1px solid rgba(0,229,255,0.15)",
                  background: "rgba(0,229,255,0.04)",
                  color: "var(--text-muted)",
                }}
              >
                Start of chain — {timelineData.length} predictions
              </div>
            </motion.div>
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center h-full gap-4">
            <motion.div
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.6 }}
              className="relative"
            >
              <div
                className="w-20 h-20 rounded-full flex items-center justify-center"
                style={{
                  background: "rgba(0,229,255,0.04)",
                  border: "1px solid rgba(0,229,255,0.1)",
                }}
              >
                <Shield
                  className="w-8 h-8"
                  style={{ color: "var(--text-muted)", opacity: 0.4 }}
                />
              </div>
              <motion.div
                className="absolute inset-0 rounded-full"
                style={{ border: "1px solid rgba(0,229,255,0.15)" }}
                animate={{ scale: [1, 1.4, 1], opacity: [0.4, 0, 0.4] }}
                transition={{ duration: 3, repeat: Infinity, ease: "easeInOut" }}
              />
            </motion.div>
            <div className="text-center">
              <p
                className="text-sm font-medium mb-1"
                style={{ color: "var(--text-secondary)" }}
              >
                No prediction timeline yet.
              </p>
              <p
                className="text-xs"
                style={{ color: "var(--text-muted)" }}
              >
                Run predictions to see the attack progression.
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
