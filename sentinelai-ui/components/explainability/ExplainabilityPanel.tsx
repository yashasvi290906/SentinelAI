"use client";

import { motion } from "framer-motion";
import { ArrowRight, Layers } from "lucide-react";
import { ATTACK_COLORS } from "@/lib/config";

interface ImportanceItem {
  token: string;
  position: number;
  weight: number;
  label: string;
}

interface Explanation {
  reasoning: string[];
  pattern_match: string;
  similar_sequences: number;
  input_pattern: string;
}

interface ExplainabilityPanelProps {
  importance: ImportanceItem[];
  prediction: string;
  confidence: number;
  explanation: Explanation;
}

function getWeightColor(weight: number): string {
  if (weight >= 0.7) return "var(--accent-red)";
  if (weight >= 0.4) return "var(--accent-amber)";
  return "var(--accent-cyan)";
}

export default function ExplainabilityPanel({
  importance,
  explanation,
}: ExplainabilityPanelProps) {
  const maxWeight = importance.length > 0
    ? Math.max(...importance.map((imp) => imp.weight))
    : 1;

  return (
    <div className="space-y-4">
      {/* Feature Importance Bars */}
      {importance.length > 0 && (
        <div
          className="rounded-2xl overflow-hidden"
          style={{
            background: "rgba(8,20,32,0.7)",
            backdropFilter: "blur(24px)",
            border: "1px solid rgba(0,229,255,0.08)",
          }}
        >
          <div
            className="flex items-center gap-2.5 px-5 py-3.5 border-b"
            style={{ borderColor: "rgba(0,229,255,0.06)" }}
          >
            <Layers className="w-4 h-4" style={{ color: "var(--accent-cyan)" }} />
            <h3
              className="text-[11px] font-bold tracking-[0.12em] uppercase"
              style={{ color: "var(--text-secondary)" }}
            >
              Token Feature Importance
            </h3>
          </div>
          <div className="p-5 space-y-3">
            {importance.map((imp, i) => {
              const normalizedWeight = maxWeight > 0 ? (imp.weight / maxWeight) * 100 : 0;
              const color = getWeightColor(imp.weight);
              const textColor = ATTACK_COLORS[imp.token] || color;

              return (
                <motion.div
                  key={`${imp.token}-${imp.position}`}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.08, duration: 0.4 }}
                  className="space-y-1.5"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span
                        className="text-xs font-mono font-semibold"
                        style={{ color: textColor }}
                      >
                        {imp.token}
                      </span>
                      <span
                        className="text-[9px] font-mono px-1.5 py-0.5 rounded"
                        style={{
                          background: "rgba(255,255,255,0.03)",
                          color: "var(--text-muted)",
                        }}
                      >
                        pos {imp.position}
                      </span>
                    </div>
                    <span
                      className="text-[10px] font-mono font-bold"
                      style={{ color: color }}
                    >
                      {(imp.weight * 100).toFixed(1)}%
                    </span>
                  </div>
                  <div
                    className="h-2.5 rounded-full overflow-hidden"
                    style={{ background: "rgba(0,229,255,0.06)" }}
                  >
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${normalizedWeight}%` }}
                      transition={{
                        duration: 0.8,
                        ease: "easeOut",
                        delay: 0.2 + i * 0.08,
                      }}
                      className="h-full rounded-full"
                      style={{
                        background: color,
                        boxShadow: `0 0 8px ${color}40`,
                      }}
                    />
                  </div>
                  <p
                    className="text-[10px] font-mono"
                    style={{ color: "var(--text-muted)" }}
                  >
                    {imp.label}
                  </p>
                </motion.div>
              );
            })}
          </div>
        </div>
      )}

      {/* Attention Timeline */}
      {importance.length > 1 && (
        <div
          className="rounded-2xl overflow-hidden"
          style={{
            background: "rgba(8,20,32,0.7)",
            backdropFilter: "blur(24px)",
            border: "1px solid rgba(0,229,255,0.08)",
          }}
        >
          <div
            className="flex items-center gap-2.5 px-5 py-3.5 border-b"
            style={{ borderColor: "rgba(0,229,255,0.06)" }}
          >
            <ArrowRight className="w-4 h-4" style={{ color: "var(--accent-cyan)" }} />
            <h3
              className="text-[11px] font-bold tracking-[0.12em] uppercase"
              style={{ color: "var(--text-secondary)" }}
            >
              Attention Timeline
            </h3>
          </div>
          <div className="p-5">
            <div className="flex items-center gap-1 flex-wrap">
              {importance.map((imp, i) => {
                const color = ATTACK_COLORS[imp.token] || getWeightColor(imp.weight);

                return (
                  <motion.div
                    key={`${imp.token}-${imp.position}`}
                    initial={{ opacity: 0, scale: 0.7 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ delay: i * 0.1, duration: 0.4 }}
                    className="flex items-center gap-1"
                  >
                    <div className="flex flex-col items-center gap-1">
                      <span
                        className="px-3 py-1.5 rounded-lg text-[11px] font-mono font-semibold"
                        style={{
                          background: `${color}15`,
                          border: `1px solid ${color}30`,
                          color: color,
                        }}
                      >
                        {imp.token}
                      </span>
                      <span
                        className="text-[9px] font-mono font-bold"
                        style={{ color: getWeightColor(imp.weight) }}
                      >
                        {(imp.weight * 100).toFixed(0)}%
                      </span>
                    </div>
                    {i < importance.length - 1 && (
                      <div className="flex flex-col items-center gap-0.5 mx-1">
                        <ArrowRight
                          className="w-4 h-4"
                          style={{ color: "var(--text-muted)" }}
                        />
                        <div
                          className="h-[2px] w-6 rounded-full"
                          style={{
                            background: `linear-gradient(90deg, ${color}40, ${ATTACK_COLORS[importance[i + 1].token] || getWeightColor(importance[i + 1].weight)}40)`,
                          }}
                        />
                      </div>
                    )}
                  </motion.div>
                );
              })}
            </div>

            {/* Connection Strength */}
            <div className="mt-4 pt-3 border-t" style={{ borderColor: "rgba(0,229,255,0.06)" }}>
              <p
                className="text-[10px] font-mono tracking-widest uppercase mb-2"
                style={{ color: "var(--text-muted)" }}
              >
                Transition Weights
              </p>
              <div className="space-y-1.5">
                {importance.slice(0, -1).map((imp, i) => {
                  const next = importance[i + 1];
                  const transitionWeight = (imp.weight + next.weight) / 2;

                  return (
                    <motion.div
                      key={`trans-${i}`}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ delay: 0.3 + i * 0.08 }}
                      className="flex items-center gap-2"
                    >
                      <span
                        className="text-[10px] font-mono w-16 text-right"
                        style={{ color: ATTACK_COLORS[imp.token] || "var(--text-secondary)" }}
                      >
                        {imp.token}
                      </span>
                      <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ background: "rgba(0,229,255,0.06)" }}>
                        <motion.div
                          initial={{ width: 0 }}
                          animate={{ width: `${transitionWeight * 100}%` }}
                          transition={{ duration: 0.6, delay: 0.4 + i * 0.08 }}
                          className="h-full rounded-full"
                          style={{ background: getWeightColor(transitionWeight) }}
                        />
                      </div>
                      <span
                        className="text-[10px] font-mono w-16"
                        style={{ color: ATTACK_COLORS[next.token] || "var(--text-secondary)" }}
                      >
                        {next.token}
                      </span>
                      <span
                        className="text-[10px] font-mono w-10 text-right"
                        style={{ color: "var(--text-muted)" }}
                      >
                        {(transitionWeight * 100).toFixed(0)}%
                      </span>
                    </motion.div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Reasoning Bullets */}
      {explanation.reasoning.length > 0 && (
        <div
          className="rounded-2xl overflow-hidden"
          style={{
            background: "rgba(8,20,32,0.7)",
            backdropFilter: "blur(24px)",
            border: "1px solid rgba(0,229,255,0.08)",
          }}
        >
          <div
            className="flex items-center gap-2.5 px-5 py-3.5 border-b"
            style={{ borderColor: "rgba(0,229,255,0.06)" }}
          >
            <Layers className="w-4 h-4" style={{ color: "var(--accent-cyan)" }} />
            <h3
              className="text-[11px] font-bold tracking-[0.12em] uppercase"
              style={{ color: "var(--text-secondary)" }}
            >
              Reasoning
            </h3>
          </div>
          <div className="p-5">
            <ul className="space-y-2">
              {explanation.reasoning.map((r, i) => (
                <motion.li
                  key={i}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.06 }}
                  className="text-xs font-mono flex items-start gap-2"
                  style={{ color: "var(--text-secondary)" }}
                >
                  <span
                    className="shrink-0 mt-0.5 w-1.5 h-1.5 rounded-full"
                    style={{ background: "var(--accent-cyan)" }}
                  />
                  {r}
                </motion.li>
              ))}
            </ul>
            <div
              className="mt-3 pt-3 border-t flex flex-wrap items-center gap-4"
              style={{ borderColor: "rgba(0,229,255,0.06)" }}
            >
              <span className="text-[10px] font-mono" style={{ color: "var(--text-muted)" }}>
                Pattern:{" "}
                <span style={{ color: "var(--text-secondary)" }}>{explanation.pattern_match}</span>
              </span>
              <span className="text-[10px] font-mono" style={{ color: "var(--text-muted)" }}>
                Input:{" "}
                <span style={{ color: "var(--text-secondary)" }}>{explanation.input_pattern}</span>
              </span>
              <span className="text-[10px] font-mono" style={{ color: "var(--text-muted)" }}>
                Similar:{" "}
                <span style={{ color: "var(--accent-cyan)" }}>{explanation.similar_sequences}</span>
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
