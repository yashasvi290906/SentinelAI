"use client";

import { motion } from "framer-motion";
import { Bot, Sparkles, Shield, Brain } from "lucide-react";
import { usePredictionStore } from "@/stores/predictionStore";
import { ATTACK_COLORS } from "@/lib/config";

export default function Copilot() {
  const lastPrediction = usePredictionStore((s) => s.lastPrediction);

  return (
    <div className="h-full p-6 lg:p-8 flex flex-col gap-6 overflow-y-auto">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <p className="text-[10px] font-mono tracking-[0.3em] uppercase mb-2" style={{ color: "var(--accent-cyan)" }}>
          SOC Analyst Assistant
        </p>
        <h1 className="text-3xl font-display font-bold" style={{ color: "var(--text-primary)" }}>
          AI Copilot
        </h1>
        <p className="text-sm mt-2" style={{ color: "var(--text-secondary)" }}>
          Ask questions about attacks, predictions, and get expert recommendations. Use the chat widget (bottom-right) for interactive assistance.
        </p>
      </motion.div>

      {/* Overview cards */}
      <div className="grid grid-cols-3 gap-4">
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="rounded-2xl p-5"
          style={{
            background: "rgba(8,20,32,0.7)",
            backdropFilter: "blur(24px)",
            border: "1px solid rgba(0,229,255,0.08)",
          }}
        >
          <div className="flex items-center gap-3 mb-3">
            <div className="w-10 h-10 rounded-xl flex items-center justify-center" style={{ background: "rgba(0,229,255,0.1)", border: "1px solid rgba(0,229,255,0.2)" }}>
              <Bot className="w-5 h-5" style={{ color: "var(--accent-cyan)" }} />
            </div>
            <div>
              <p className="text-sm font-bold" style={{ color: "var(--text-primary)" }}>Conversational AI</p>
              <p className="text-[10px] font-mono" style={{ color: "var(--text-muted)" }}>Natural language interface</p>
            </div>
          </div>
          <p className="text-xs" style={{ color: "var(--text-secondary)" }}>
            Ask questions in plain English. Get expert-level answers about attack patterns, threat intelligence, and incident response.
          </p>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.15 }}
          className="rounded-2xl p-5"
          style={{
            background: "rgba(8,20,32,0.7)",
            backdropFilter: "blur(24px)",
            border: "1px solid rgba(0,229,255,0.08)",
          }}
        >
          <div className="flex items-center gap-3 mb-3">
            <div className="w-10 h-10 rounded-xl flex items-center justify-center" style={{ background: "rgba(255,176,32,0.1)", border: "1px solid rgba(255,176,32,0.2)" }}>
              <Shield className="w-5 h-5" style={{ color: "var(--accent-amber)" }} />
            </div>
            <div>
              <p className="text-sm font-bold" style={{ color: "var(--text-primary)" }}>Expert Knowledge</p>
              <p className="text-[10px] font-mono" style={{ color: "var(--text-muted)" }}>7 attack types covered</p>
            </div>
          </div>
          <p className="text-xs" style={{ color: "var(--text-secondary)" }}>
            Built-in expertise for DDoS, DoS, PortScan, Bot, WebAttack, BruteForce, and Infiltration attack patterns.
          </p>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="rounded-2xl p-5"
          style={{
            background: "rgba(8,20,32,0.7)",
            backdropFilter: "blur(24px)",
            border: "1px solid rgba(0,229,255,0.08)",
          }}
        >
          <div className="flex items-center gap-3 mb-3">
            <div className="w-10 h-10 rounded-xl flex items-center justify-center" style={{ background: "rgba(124,77,255,0.1)", border: "1px solid rgba(124,77,255,0.2)" }}>
              <Sparkles className="w-5 h-5" style={{ color: "var(--accent-purple)" }} />
            </div>
            <div>
              <p className="text-sm font-bold" style={{ color: "var(--text-primary)" }}>Actionable Advice</p>
              <p className="text-[10px] font-mono" style={{ color: "var(--text-muted)" }}>Step-by-step recommendations</p>
            </div>
          </div>
          <p className="text-xs" style={{ color: "var(--text-secondary)" }}>
            Get specific, actionable incident response recommendations tailored to the predicted threat.
          </p>
        </motion.div>
      </div>

      {/* Last prediction context */}
      {lastPrediction && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.25 }}
          className="rounded-2xl p-5"
          style={{
            background: "rgba(8,20,32,0.7)",
            backdropFilter: "blur(24px)",
            border: "1px solid rgba(0,229,255,0.08)",
          }}
        >
          <div className="flex items-center gap-2.5 mb-4">
            <Brain className="w-4 h-4" style={{ color: "var(--accent-cyan)" }} />
            <h3 className="text-[11px] font-bold tracking-[0.12em] uppercase" style={{ color: "var(--text-secondary)" }}>
              Latest Prediction Context
            </h3>
          </div>
          <div className="flex items-center gap-4">
            <div>
              <p className="text-2xl font-display font-bold" style={{ color: ATTACK_COLORS[lastPrediction.predictedAttack] || "var(--text-primary)" }}>
                {lastPrediction.predictedAttack}
              </p>
              <p className="text-xs font-mono mt-1" style={{ color: "var(--text-muted)" }}>
                Confidence: {(lastPrediction.confidence * 100).toFixed(1)}% — {lastPrediction.riskLevel}
              </p>
            </div>
            <div className="flex-1 h-px" style={{ background: "rgba(0,229,255,0.1)" }} />
            <p className="text-xs" style={{ color: "var(--text-secondary)" }}>
              Ask the copilot about this prediction using the chat widget →
            </p>
          </div>
        </motion.div>
      )}

      {/* Usage tips */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
        className="rounded-2xl p-5"
        style={{
          background: "rgba(0,229,255,0.03)",
          border: "1px solid rgba(0,229,255,0.06)",
        }}
      >
        <p className="text-[10px] font-mono tracking-widest uppercase mb-3" style={{ color: "var(--text-muted)" }}>
          Example Questions
        </p>
        <div className="grid grid-cols-2 gap-2">
          {[
            "Why was this predicted as DDoS?",
            "What does BruteForce mean?",
            "What should I do next?",
            "Show me recent attack patterns.",
            "How do I handle an Infiltration alert?",
            "What indicators should I look for?",
          ].map((q) => (
            <div
              key={q}
              className="px-3 py-2 rounded-lg text-xs font-mono"
              style={{
                background: "rgba(8,20,32,0.5)",
                border: "1px solid rgba(0,229,255,0.06)",
                color: "var(--text-secondary)",
              }}
            >
              &quot;{q}&quot;
            </div>
          ))}
        </div>
      </motion.div>
    </div>
  );
}
