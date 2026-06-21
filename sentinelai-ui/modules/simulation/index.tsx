"use client";

import { useState, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  FlaskConical,
  Play,
  ArrowRight,
  Zap,
  Clock,
  Activity,
  Brain,
  Target,
  Trash2,
} from "lucide-react";
import { usePredictionStore } from "@/stores/predictionStore";
import { useNotificationStore } from "@/stores/notificationStore";
import { predictAPI } from "@/lib/api";
import type { AttackType, SimulationStep, SimulationRecord } from "@/lib/types";
import {
  ATTACK_TYPES,
  ATTACK_COLORS,
  ATTACK_TO_NUMERIC,
} from "@/lib/config";
import Provenance from "@/components/ui/Provenance";
import Explanation from "@/components/ui/Explanation";

function calcRisk(confidence: number): "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" {
  if (confidence >= 0.85) return "CRITICAL";
  if (confidence >= 0.75) return "HIGH";
  if (confidence >= 0.60) return "MEDIUM";
  return "LOW";
}

const SAMPLE_SEQUENCES: { label: string; attacks: AttackType[] }[] = [
  { label: "DDoS Recon", attacks: ["DDoS", "PortScan", "Bot"] },
  { label: "Web Attack Chain", attacks: ["PortScan", "WebAttack", "BruteForce"] },
  { label: "Infiltration", attacks: ["PortScan", "Bot", "Infiltration"] },
  { label: "DoS Escalation", attacks: ["DoS", "DoS", "DDoS"] },
];

export default function Simulation() {
  const [sequence, setSequence] = useState<AttackType[]>([]);
  const [simHistory, setSimHistory] = useState<SimulationRecord[]>([]);
  const [running, setRunning] = useState(false);
  const [steps, setSteps] = useState<SimulationStep[]>([]);
  const [startedAt, setStartedAt] = useState<string | null>(null);

  const addPrediction = usePredictionStore((s) => s.addPrediction);
  const addNotification = useNotificationStore((s) => s.addNotification);

  const addAttack = useCallback(
    (attack: AttackType) => {
      if (sequence.length >= 10 || running) return;
      setSequence((prev) => [...prev, attack]);
    },
    [sequence.length, running]
  );

  const removeLast = useCallback(() => {
    if (running) return;
    setSequence((prev) => prev.slice(0, -1));
  }, [running]);

  const clearSequence = useCallback(() => {
    if (running) return;
    setSequence([]);
    setSteps([]);
  }, [running]);

  const loadSample = useCallback(
    (attacks: AttackType[]) => {
      if (running) return;
      setSequence(attacks);
      setSteps([]);
    },
    [running]
  );

  const runSimulation = useCallback(async () => {
    if (sequence.length < 1 || running) return;

    setRunning(true);
    setSteps([]);
    const simId = `sim-${Date.now()}`;
    const start = Date.now();
    const startTime = new Date().toISOString();
    setStartedAt(startTime);
    const allSteps: SimulationStep[] = [];
    const attackFlow: string[] = [...sequence.map((a) => a)];

    try {
      for (let i = 0; i < sequence.length; i++) {
        const subSequence = sequence.slice(0, i + 1);
        const numeric = subSequence.map((a) => ATTACK_TO_NUMERIC[a] ?? 0);

        const data = await predictAPI(numeric);
        const predictedAttack = data.prediction;
        const confidence = data.confidence ?? 0.5;
        const severityScore = data.severity_score ?? 0;
        const riskLevel = calcRisk(severityScore);

        const step: SimulationStep = {
          index: i,
          inputSequence: subSequence,
          predictedAttack,
          confidence,
          severityScore,
          riskLevel,
          model: data.model || "ML",
          timestamp: new Date().toISOString(),
        };

        allSteps.push(step);
        setSteps([...allSteps]);
        attackFlow.push(predictedAttack);

        addPrediction({
          id: `${simId}-step-${i}`,
          timestamp: step.timestamp,
          sequence: subSequence,
          predictedAttack,
          confidence,
          severityScore,
          riskLevel,
          model: step.model,
          latencyMs: data.latency_ms ?? 0,
          topPredictions: data.top_predictions ?? [],
          explanation: data.explanation ?? { reasoning: [], pattern_match: "N/A", similar_sequences: 0, input_pattern: "" },
          rawResponse: data,
        });

        await new Promise((r) => setTimeout(r, 300));
      }

      const avgConfidence =
        allSteps.reduce((sum, s) => sum + s.confidence, 0) / allSteps.length;
      const avgSeverityScore =
        allSteps.reduce((sum, s) => sum + (s.severityScore || 0), 0) / allSteps.length;

      const record: SimulationRecord = {
        id: simId,
        name: `Simulation ${simHistory.length + 1}`,
        startedAt: startTime,
        completedAt: new Date().toISOString(),
        steps: allSteps,
        totalSteps: allSteps.length,
        averageConfidence: avgConfidence,
        averageSeverityScore: avgSeverityScore,
        executionTimeMs: Date.now() - start,
        attackFlow,
        status: "completed",
        error: null,
      };

      setSimHistory((prev) => [record, ...prev].slice(0, 20));
      addNotification({
        type: "success",
        title: "Simulation Complete",
        message: `Executed ${allSteps.length} steps in ${record.executionTimeMs}ms. Avg confidence: ${(avgConfidence * 100).toFixed(1)}%`,
      });
    } catch (err) {
      const record: SimulationRecord = {
        id: simId,
        name: `Simulation ${simHistory.length + 1}`,
        startedAt: startTime,
        completedAt: new Date().toISOString(),
        steps: allSteps,
        totalSteps: allSteps.length,
        averageConfidence: 0,
        averageSeverityScore: 0,
        executionTimeMs: Date.now() - start,
        attackFlow,
        status: "error",
        error: err instanceof Error ? err.message : "Simulation failed",
      };
      setSimHistory((prev) => [record, ...prev].slice(0, 20));
      addNotification({
        type: "error",
        title: "Simulation Failed",
        message: err instanceof Error ? err.message : "Unknown error occurred",
      });
    } finally {
      setRunning(false);
    }
  }, [sequence, running, simHistory.length, addPrediction, addNotification]);

  return (
    <div className="h-full p-6 lg:p-8 flex flex-col gap-6 overflow-y-auto">
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
          Attack Simulation Engine
        </p>
        <h1 className="text-3xl font-display font-bold" style={{ color: "var(--text-primary)" }}>
          Simulation Lab
        </h1>
        <p className="text-sm mt-2" style={{ color: "var(--text-secondary)" }}>
          Build attack sequences and simulate step-by-step predictions to visualize the attack flow.
        </p>
      </motion.div>

      <Explanation text="Build an attack sequence and run the simulation. Each step calls the ML prediction API to forecast the next likely attack, creating an animated attack flow graph showing how threats escalate." />

      {/* Sequence Builder */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
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
          <FlaskConical className="w-4 h-4" style={{ color: "var(--accent-cyan)" }} />
          <h3 className="text-[11px] font-bold tracking-[0.12em] uppercase" style={{ color: "var(--text-secondary)" }}>
            Attack Sequence Builder
          </h3>
        </div>
        <div className="p-5 space-y-4">
          {/* Attack type buttons */}
          <div className="flex flex-wrap gap-2">
            {ATTACK_TYPES.map((type) => (
              <button
                key={type}
                onClick={() => addAttack(type as AttackType)}
                disabled={sequence.length >= 10 || running}
                className="px-4 py-2 text-xs font-mono font-semibold rounded-xl transition-all duration-300 disabled:opacity-30 disabled:cursor-not-allowed hover:scale-105"
                style={{
                  background: "rgba(255,255,255,0.03)",
                  border: "1px solid rgba(0,229,255,0.08)",
                  color: "var(--text-secondary)",
                }}
              >
                + {type}
              </button>
            ))}
          </div>

          {/* Sample sequences */}
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-mono" style={{ color: "var(--text-muted)" }}>
              Samples:
            </span>
            {SAMPLE_SEQUENCES.map((sample) => (
              <button
                key={sample.label}
                onClick={() => loadSample(sample.attacks)}
                disabled={running}
                className="px-3 py-1 text-[10px] font-mono rounded-lg transition-all disabled:opacity-30 hover:bg-white/[0.04]"
                style={{
                  border: "1px solid rgba(0,229,255,0.06)",
                  color: "var(--text-muted)",
                }}
              >
                {sample.label}
              </button>
            ))}
          </div>

          {/* Current sequence */}
          <AnimatePresence mode="popLayout">
            {sequence.length > 0 && (
              <motion.div
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, height: 0 }}
                className="flex items-center gap-2 flex-wrap p-4 rounded-xl"
                style={{
                  background: "rgba(0,229,255,0.03)",
                  border: "1px solid rgba(0,229,255,0.08)",
                }}
              >
                {sequence.map((attack, i) => (
                  <motion.div
                    key={`${i}-${attack}`}
                    initial={{ opacity: 0, scale: 0.8 }}
                    animate={{ opacity: 1, scale: 1 }}
                    exit={{ opacity: 0, scale: 0.8 }}
                    transition={{ delay: i * 0.05 }}
                    className="flex items-center gap-1"
                  >
                    <span
                      className="px-3 py-1.5 rounded-lg text-xs font-mono font-semibold"
                      style={{
                        background: `${ATTACK_COLORS[attack] || "var(--accent-cyan)"}15`,
                        border: `1px solid ${ATTACK_COLORS[attack] || "var(--accent-cyan)"}30`,
                        color: ATTACK_COLORS[attack] || "var(--accent-cyan)",
                      }}
                    >
                      {attack}
                    </span>
                    {i < sequence.length - 1 && (
                      <ArrowRight className="w-3 h-3" style={{ color: "var(--text-muted)" }} />
                    )}
                  </motion.div>
                ))}
              </motion.div>
            )}
          </AnimatePresence>

          {/* Controls */}
          {sequence.length > 0 && (
            <div
              className="flex items-center gap-3 pt-3 border-t"
              style={{ borderColor: "rgba(0,229,255,0.06)" }}
            >
              <button
                onClick={removeLast}
                disabled={running}
                className="px-4 py-2 text-xs font-mono rounded-xl transition-colors disabled:opacity-30"
                style={{ border: "1px solid rgba(0,229,255,0.08)", color: "var(--text-muted)" }}
              >
                &larr; Remove
              </button>
              <button
                onClick={clearSequence}
                disabled={running}
                className="px-4 py-2 text-xs font-mono rounded-xl transition-colors flex items-center gap-1.5 disabled:opacity-30"
                style={{ border: "1px solid rgba(0,229,255,0.08)", color: "var(--text-muted)" }}
              >
                <Trash2 className="w-3 h-3" /> Clear
              </button>
              <span className="text-[10px] font-mono ml-2" style={{ color: "var(--text-muted)" }}>
                {sequence.length}/10
              </span>
              <button
                onClick={runSimulation}
                disabled={running}
                className="ml-auto px-6 py-2 text-xs font-mono font-bold rounded-xl transition-all duration-300 disabled:opacity-50 flex items-center gap-2"
                style={{
                  background: running
                    ? "rgba(255,176,32,0.2)"
                    : "linear-gradient(135deg, var(--accent-cyan), #00B8D4)",
                  color: "var(--bg-deep)",
                  boxShadow: "0 0 20px rgba(0,229,255,0.2)",
                }}
              >
                {running ? (
                  <>
                    <Activity className="w-4 h-4 animate-spin" />
                    Running...
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4" />
                    Run Simulation
                  </>
                )}
              </button>
            </div>
          )}
        </div>
      </motion.div>

      {/* Attack Flow Graph */}
      <AnimatePresence>
        {steps.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
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
              <Target className="w-4 h-4" style={{ color: "var(--accent-cyan)" }} />
              <h3 className="text-[11px] font-bold tracking-[0.12em] uppercase" style={{ color: "var(--text-secondary)" }}>
                Attack Flow Graph
              </h3>
            </div>
            <div className="p-5">
              <div className="flex flex-col items-center gap-1">
                {sequence.map((attack, i) => (
                  <motion.div
                    key={`flow-${i}`}
                    initial={{ opacity: 0, scale: 0.8 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ delay: i * 0.15 }}
                    className="flex flex-col items-center"
                  >
                    <span
                      className="px-4 py-2 rounded-xl text-xs font-mono font-bold"
                      style={{
                        background: `${ATTACK_COLORS[attack] || "var(--accent-cyan)"}15`,
                        border: `1px solid ${ATTACK_COLORS[attack] || "var(--accent-cyan)"}30`,
                        color: ATTACK_COLORS[attack] || "var(--accent-cyan)",
                        boxShadow: `0 0 15px ${ATTACK_COLORS[attack] || "var(--accent-cyan)"}15`,
                      }}
                    >
                      {attack}
                    </span>
                    {i < sequence.length - 1 && (
                      <motion.div
                        initial={{ scaleY: 0 }}
                        animate={{ scaleY: 1 }}
                        transition={{ delay: i * 0.15 + 0.1 }}
                        className="w-px h-6"
                        style={{ background: "rgba(0,229,255,0.2)" }}
                      />
                    )}
                  </motion.div>
                ))}

                {/* Predicted next attack */}
                {steps.length > 0 && (
                  <motion.div
                    initial={{ opacity: 0, scale: 0.5 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ delay: steps.length * 0.15 }}
                    className="flex flex-col items-center"
                  >
                    <div className="w-px h-6" style={{ background: "rgba(0,229,255,0.2)" }} />
                    <motion.div
                      className="px-4 py-2 rounded-xl text-xs font-mono font-bold"
                      style={{
                        background: "rgba(0,229,255,0.15)",
                        border: "2px solid var(--accent-cyan)",
                        color: "var(--accent-cyan)",
                        boxShadow: "0 0 20px rgba(0,229,255,0.3)",
                      }}
                      animate={{ boxShadow: ["0 0 20px rgba(0,229,255,0.3)", "0 0 30px rgba(0,229,255,0.5)", "0 0 20px rgba(0,229,255,0.3)"] }}
                      transition={{ duration: 2, repeat: Infinity }}
                    >
                      Predicted: {steps[steps.length - 1]?.predictedAttack}
                    </motion.div>
                  </motion.div>
                )}
              </div>
            </div>
            <Provenance source="FastAPI Backend" lastUpdated={startedAt} className="px-5 pb-4" />
          </motion.div>
        )}
      </AnimatePresence>

      {/* Simulation Metrics */}
      {steps.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className="grid grid-cols-2 lg:grid-cols-4 gap-4"
        >
          {[
            { label: "Prediction Count", value: String(steps.length), icon: Brain, color: "var(--accent-cyan)" },
            {
              label: "Avg Confidence",
              value: `${((steps.reduce((s, st) => s + st.confidence, 0) / steps.length) * 100).toFixed(1)}%`,
              icon: Target,
              color: "var(--accent-green)",
            },
            {
              label: "Execution Time",
              value: `${steps.length * 300}ms`,
              icon: Clock,
              color: "var(--accent-amber)",
            },
            {
              label: "Model Agreement",
              value: steps.length > 0 ? `${new Set(steps.map((s) => s.predictedAttack)).size}/${steps.length}` : "—",
              icon: Zap,
              color: "var(--accent-purple)",
            },
          ].map((metric, i) => (
            <motion.div
              key={metric.label}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.05 }}
              className="rounded-2xl p-4"
              style={{
                background: "rgba(8,20,32,0.7)",
                backdropFilter: "blur(24px)",
                border: "1px solid rgba(0,229,255,0.08)",
              }}
            >
              <div className="flex items-center gap-2 mb-2">
                <metric.icon className="w-3.5 h-3.5" style={{ color: metric.color }} />
                <span className="text-[10px] font-mono tracking-wider uppercase" style={{ color: "var(--text-muted)" }}>
                  {metric.label}
                </span>
              </div>
              <p className="text-2xl font-display font-bold" style={{ color: metric.color }}>
                {metric.value}
              </p>
            </motion.div>
          ))}
        </motion.div>
      )}

      {/* Empty State */}
      {steps.length === 0 && !running && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="rounded-2xl p-12 text-center"
          style={{
            background: "rgba(8,20,32,0.4)",
            border: "2px dashed rgba(0,229,255,0.1)",
          }}
        >
          <FlaskConical className="w-12 h-12 mx-auto mb-4" style={{ color: "var(--text-muted)" }} />
          <p className="font-mono text-sm" style={{ color: "var(--text-secondary)" }}>
            No simulation executed
          </p>
          <p className="font-mono text-xs mt-2" style={{ color: "var(--text-muted)" }}>
            Create a sequence and run your first simulation
          </p>
        </motion.div>
      )}

      {/* Simulation History */}
      {simHistory.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
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
            <Clock className="w-4 h-4" style={{ color: "var(--accent-cyan)" }} />
            <h3 className="text-[11px] font-bold tracking-[0.12em] uppercase" style={{ color: "var(--text-secondary)" }}>
              Simulation History
            </h3>
          </div>
          <div className="p-2 space-y-1">
            {simHistory.map((sim) => (
              <div
                key={sim.id}
                className="flex items-center gap-4 px-4 py-3 rounded-xl"
                style={{ background: "rgba(255,255,255,0.01)" }}
              >
                <span className="text-[10px] font-mono shrink-0" style={{ color: "var(--text-muted)" }}>
                  {new Date(sim.startedAt).toLocaleTimeString("en-US", { hour12: false })}
                </span>
                <span className="text-xs font-mono font-bold shrink-0" style={{ color: "var(--text-primary)" }}>
                  {sim.name}
                </span>
                <span className="text-[10px] font-mono shrink-0" style={{ color: "var(--text-muted)" }}>
                  {sim.totalSteps} steps
                </span>
                <span className="text-[10px] font-mono shrink-0" style={{ color: "var(--accent-cyan)" }}>
                  {(sim.averageConfidence * 100).toFixed(1)}%
                </span>
                <span
                  className="text-[10px] font-mono px-2 py-0.5 rounded shrink-0"
                  style={{
                    background: sim.status === "completed" ? "rgba(0,255,136,0.1)" : "rgba(255,77,109,0.1)",
                    color: sim.status === "completed" ? "var(--accent-green)" : "var(--accent-red)",
                  }}
                >
                  {sim.status.toUpperCase()}
                </span>
                <span className="text-[10px] font-mono shrink-0 ml-auto" style={{ color: "var(--text-muted)" }}>
                  {sim.executionTimeMs}ms
                </span>
              </div>
            ))}
          </div>
        </motion.div>
      )}
    </div>
  );
}
