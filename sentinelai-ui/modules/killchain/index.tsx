"use client";

import { useState, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Shield,
  Search,
  Hammer,
  Send,
  Zap,
  Download,
  Terminal,
  Target,
  ChevronRight,
  CheckCircle2,
  Circle,
  Clock,
} from "lucide-react";
import { killchainAPI } from "@/lib/api";
import { ATTACK_TYPES, ATTACK_COLORS } from "@/lib/config";
import type { KillChainStage } from "@/lib/api";
import "./styles.css";

const ICON_MAP: Record<string, React.ElementType> = {
  Shield,
  Search,
  Hammer,
  Send,
  Zap,
  Download,
  Terminal,
  Target,
};

const STAGE_COLORS: Record<string, string> = {
  completed: "#00E676",
  active: "#00E5FF",
  pending: "#4A5568",
};

export default function KillChain() {
  const [selectedAttack, setSelectedAttack] = useState<string | null>(null);
  const [stages, setStages] = useState<KillChainStage[]>([]);
  const [progress, setProgress] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadKillChain = useCallback(async (attack: string) => {
    setSelectedAttack(attack);
    setLoading(true);
    setError(null);
    try {
      const res = await killchainAPI(attack);
      setStages(res.stages);
      setProgress(res.progress);
    } catch {
      setError("Failed to load kill chain data");
      setStages([]);
      setProgress(0);
    } finally {
      setLoading(false);
    }
  }, []);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
      <div
        style={{
          background: "rgba(8,20,32,0.7)",
          backdropFilter: "blur(24px)",
          border: "1px solid rgba(0,229,255,0.08)",
          borderRadius: 16,
          padding: "24px 28px",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
          <Target size={22} style={{ color: "#00E5FF" }} />
          <h2
            style={{
              fontSize: 20,
              fontWeight: 700,
              color: "var(--text-primary, #E2E8F0)",
              margin: 0,
            }}
          >
            Cyber Kill Chain
          </h2>
        </div>
        <p
          style={{
            fontSize: 13,
            color: "var(--text-muted, #8892A4)",
            margin: 0,
            lineHeight: 1.6,
          }}
        >
          Visualize the Lockheed Martin Cyber Kill Chain — a 7-stage framework
          modeling the progression of a cyber attack from reconnaissance to
          actions on objectives.
        </p>
      </div>

      <div
        style={{
          background: "rgba(8,20,32,0.7)",
          backdropFilter: "blur(24px)",
          border: "1px solid rgba(0,229,255,0.08)",
          borderRadius: 16,
          padding: "20px 28px",
        }}
      >
        <p
          style={{
            fontSize: 12,
            fontWeight: 600,
            color: "var(--text-muted, #8892A4)",
            textTransform: "uppercase",
            letterSpacing: 1,
            margin: "0 0 14px 0",
          }}
        >
          Select Attack Type
        </p>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
          {ATTACK_TYPES.map((type) => {
            const isSelected = selectedAttack === type;
            const color = ATTACK_COLORS[type] || "#00E5FF";
            return (
              <button
                key={type}
                onClick={() => loadKillChain(type)}
                disabled={loading}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                  padding: "8px 16px",
                  borderRadius: 8,
                  border: `1px solid ${isSelected ? color : "rgba(255,255,255,0.08)"}`,
                  background: isSelected ? `${color}20` : "rgba(255,255,255,0.03)",
                  color: isSelected ? color : "var(--text-muted, #8892A4)",
                  fontSize: 13,
                  fontWeight: 600,
                  cursor: loading ? "wait" : "pointer",
                  transition: "all 0.2s ease",
                  fontFamily: "inherit",
                  opacity: loading && !isSelected ? 0.5 : 1,
                }}
              >
                <ChevronRight size={14} />
                {type}
              </button>
            );
          })}
        </div>
      </div>

      {loading && (
        <div
          style={{
            background: "rgba(8,20,32,0.7)",
            backdropFilter: "blur(24px)",
            border: "1px solid rgba(0,229,255,0.08)",
            borderRadius: 16,
            padding: 48,
            textAlign: "center",
          }}
        >
          <div
            style={{
              width: 40,
              height: 40,
              border: "3px solid rgba(0,229,255,0.2)",
              borderTopColor: "#00E5FF",
              borderRadius: "50%",
              animation: "spin 0.8s linear infinite",
              margin: "0 auto 16px",
            }}
          />
          <p style={{ color: "var(--text-muted, #8892A4)", fontSize: 14 }}>
            Analyzing kill chain for{" "}
            <span style={{ color: ATTACK_COLORS[selectedAttack || ""] || "#00E5FF" }}>
              {selectedAttack}
            </span>
            ...
          </p>
          <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
        </div>
      )}

      {error && (
        <div
          style={{
            background: "rgba(239,68,68,0.1)",
            border: "1px solid rgba(239,68,68,0.2)",
            borderRadius: 12,
            padding: "14px 20px",
            color: "#EF4444",
            fontSize: 13,
          }}
        >
          {error}
        </div>
      )}

      {!loading && !error && stages.length === 0 && (
        <div
          style={{
            background: "rgba(8,20,32,0.7)",
            backdropFilter: "blur(24px)",
            border: "1px solid rgba(0,229,255,0.08)",
            borderRadius: 16,
            padding: 64,
            textAlign: "center",
          }}
        >
          <Shield
            size={48}
            style={{ color: "rgba(0,229,255,0.15)", marginBottom: 16 }}
          />
          <p
            style={{
              fontSize: 15,
              color: "var(--text-muted, #8892A4)",
              margin: 0,
            }}
          >
            Select an attack type above to visualize its kill chain
          </p>
        </div>
      )}

      {!loading && stages.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4 }}
          style={{
            background: "rgba(8,20,32,0.7)",
            backdropFilter: "blur(24px)",
            border: "1px solid rgba(0,229,255,0.08)",
            borderRadius: 16,
            padding: "28px 32px",
          }}
        >
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              marginBottom: 20,
            }}
          >
            <div>
              <h3
                style={{
                  fontSize: 16,
                  fontWeight: 700,
                  color: "var(--text-primary, #E2E8F0)",
                  margin: 0,
                }}
              >
                Kill Chain Progress
              </h3>
              <p
                style={{
                  fontSize: 12,
                  color: "var(--text-muted, #8892A4)",
                  margin: "4px 0 0 0",
                }}
              >
                <span
                  style={{
                    color: ATTACK_COLORS[selectedAttack || ""] || "#00E5FF",
                    fontWeight: 600,
                  }}
                >
                  {selectedAttack}
                </span>{" "}
                attack progression
              </p>
            </div>
            <span
              style={{
                fontSize: 28,
                fontWeight: 800,
                color:
                  progress >= 100
                    ? "#00E676"
                    : progress > 50
                    ? "#00E5FF"
                    : "var(--text-primary, #E2E8F0)",
                fontVariantNumeric: "tabular-nums",
              }}
            >
              {Math.round(progress)}%
            </span>
          </div>

          <div
            style={{
              height: 6,
              borderRadius: 3,
              background: "rgba(255,255,255,0.06)",
              overflow: "hidden",
              marginBottom: 32,
            }}
          >
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${progress}%` }}
              transition={{ duration: 0.8, ease: "easeOut" }}
              style={{
                height: "100%",
                borderRadius: 3,
                background:
                  progress >= 100
                    ? "linear-gradient(90deg, #00E5FF, #00E676)"
                    : "linear-gradient(90deg, #00E5FF, #7C3AED)",
              }}
            />
          </div>

          <div style={{ position: "relative" }}>
            <AnimatePresence mode="popLayout">
              {stages.map((stage, i) => {
                const IconComp = ICON_MAP[stage.icon] || Circle;
                const isCompleted = stage.status === "completed";
                const isActive = stage.status === "active";
                const color = STAGE_COLORS[stage.status];

                return (
                  <motion.div
                    key={stage.id}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.08, duration: 0.35 }}
                    style={{
                      display: "flex",
                      gap: 16,
                      position: "relative",
                      paddingBottom: i < stages.length - 1 ? 28 : 0,
                    }}
                  >
                    {i < stages.length - 1 && (
                      <div
                        style={{
                          position: "absolute",
                          left: 18,
                          top: 44,
                          bottom: 0,
                          width: 2,
                          overflow: "hidden",
                        }}
                      >
                        <div
                          className={
                            isCompleted || isActive ? "killchain-beam" : ""
                          }
                          style={{
                            width: "100%",
                            height: "100%",
                            background:
                              isCompleted || isActive
                                ? undefined
                                : "rgba(255,255,255,0.06)",
                          }}
                        />
                      </div>
                    )}

                    <div
                      className={isActive ? "killchain-active" : ""}
                      style={{
                        width: isActive ? 44 : 38,
                        height: isActive ? 44 : 38,
                        minWidth: isActive ? 44 : 38,
                        borderRadius: "50%",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        border: `2px solid ${color}`,
                        background: isActive
                          ? `${color}18`
                          : isCompleted
                          ? `${color}10`
                          : "rgba(255,255,255,0.03)",
                        transition: "all 0.3s ease",
                        position: "relative",
                        zIndex: 1,
                      }}
                    >
                      {isCompleted ? (
                        <CheckCircle2 size={18} style={{ color }} />
                      ) : (
                        <IconComp size={isActive ? 20 : 16} style={{ color }} />
                      )}
                    </div>

                    <div
                      style={{
                        flex: 1,
                        paddingTop: isActive ? 2 : 0,
                      }}
                    >
                      <div
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: 8,
                          marginBottom: 4,
                        }}
                      >
                        <span
                          style={{
                            fontSize: isActive ? 15 : 14,
                            fontWeight: isActive ? 700 : 600,
                            color: isCompleted
                              ? "#00E676"
                              : isActive
                              ? "#00E5FF"
                              : "var(--text-muted, #8892A4)",
                            transition: "all 0.3s ease",
                          }}
                        >
                          {stage.name}
                        </span>
                        {isActive && (
                          <span
                            style={{
                              fontSize: 10,
                              fontWeight: 700,
                              textTransform: "uppercase",
                              letterSpacing: 1,
                              color: "#00E5FF",
                              background: "rgba(0,229,255,0.1)",
                              padding: "2px 8px",
                              borderRadius: 4,
                            }}
                          >
                            Active
                          </span>
                        )}
                        {isCompleted && (
                          <CheckCircle2
                            size={13}
                            style={{ color: "#00E676" }}
                          />
                        )}
                      </div>
                      <p
                        style={{
                          fontSize: 12,
                          lineHeight: 1.5,
                          color: isActive
                            ? "var(--text-secondary, #A0AEC0)"
                            : "var(--text-muted, #8892A4)",
                          margin: 0,
                          opacity: isActive ? 1 : 0.7,
                        }}
                      >
                        {stage.description}
                      </p>
                    </div>

                    {isActive && (
                      <div
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: 4,
                          alignSelf: "flex-start",
                          marginTop: 4,
                        }}
                      >
                        <Clock size={12} style={{ color: "#00E5FF" }} />
                        <span
                          style={{
                            fontSize: 11,
                            color: "#00E5FF",
                            fontWeight: 600,
                          }}
                        >
                          Current
                        </span>
                      </div>
                    )}
                  </motion.div>
                );
              })}
            </AnimatePresence>
          </div>

          {progress >= 100 && (
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              style={{
                marginTop: 24,
                padding: "14px 20px",
                borderRadius: 10,
                background: "rgba(0,230,118,0.08)",
                border: "1px solid rgba(0,230,118,0.2)",
                display: "flex",
                alignItems: "center",
                gap: 10,
              }}
            >
              <CheckCircle2 size={18} style={{ color: "#00E676" }} />
              <span
                style={{
                  fontSize: 13,
                  fontWeight: 600,
                  color: "#00E676",
                }}
              >
                Kill chain complete — all stages traversed
              </span>
            </motion.div>
          )}
        </motion.div>
      )}
    </div>
  );
}
