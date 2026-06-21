"use client";

import { motion } from "framer-motion";
import GlassPanel from "@/components/ui/GlassPanel";
import {
  Shield, Cpu, Globe, Lock, Radar, GitBranch, Zap, BarChart3,
  Activity, Database, Server, Code2,
} from "lucide-react";

const BUILD_DATE = "2026-06-20";

const container = {
  hidden: { opacity: 0 },
  show: { opacity: 1, transition: { staggerChildren: 0.06 } },
};
const item = {
  hidden: { opacity: 0, y: 10 },
  show: { opacity: 1, y: 0 },
};

const FEATURES = [
  {
    icon: <Zap className="w-5 h-5" />,
    title: "Real-Time Prediction",
    description: "ML-powered attack classification and forecasting from network traffic data",
    color: "var(--accent-cyan)",
  },
  {
    icon: <BarChart3 className="w-5 h-5" />,
    title: "Model Comparison",
    description: "Side-by-side evaluation of ML and Markov chain model outputs",
    color: "var(--accent-green)",
  },
  {
    icon: <Activity className="w-5 h-5" />,
    title: "Drift Detection",
    description: "Continuous monitoring of data distribution changes with automatic alerts",
    color: "var(--accent-amber)",
  },
  {
    icon: <Radar className="w-5 h-5" />,
    title: "Attack Chain Analysis",
    description: "Multi-step attack sequence prediction using ensemble methods",
    color: "var(--accent-purple)",
  },
  {
    icon: <Lock className="w-5 h-5" />,
    title: "Threat Intelligence",
    description: "Encyclopedia of attack types with MITRE ATT&CK technique mapping",
    color: "var(--accent-red)",
  },
  {
    icon: <Globe className="w-5 h-5" />,
    title: "Live Event Feed",
    description: "Real-time stream of predictions, comparisons, and system events",
    color: "var(--accent-cyan)",
  },
];

const FRONTEND_STACK = [
  { name: "Next.js", desc: "React Framework" },
  { name: "React", desc: "UI Library" },
  { name: "TypeScript", desc: "Type Safety" },
  { name: "Zustand", desc: "State Management" },
  { name: "Recharts", desc: "Data Visualization" },
  { name: "Framer Motion", desc: "Animations" },
  { name: "Tailwind CSS", desc: "Styling" },
];

const BACKEND_STACK = [
  { name: "FastAPI", desc: "Python API" },
  { name: "Scikit-learn", desc: "ML Models" },
  { name: "Pandas", desc: "Data Processing" },
  { name: "NumPy", desc: "Numerical Computing" },
  { name: "Pydantic", desc: "Data Validation" },
  { name: "Uvicorn", desc: "ASGI Server" },
];

const ARCHITECTURE_STEPS = [
  { label: "Network Traffic", icon: "📡" },
  { label: "Feature Extraction", icon: "⚙️" },
  { label: "ML Models", icon: "🤖" },
  { label: "Predictions", icon: "🎯" },
];

export default function About() {
  return (
    <div className="h-full p-6 flex flex-col gap-6 overflow-y-auto">
      <div>
        <p className="text-xs font-mono tracking-[0.2em] uppercase mb-2" style={{ color: "var(--accent-cyan)" }}>
          System Information
        </p>
        <h1 className="text-2xl font-display font-semibold" style={{ color: "var(--text-primary)" }}>
          About SentinelAI
        </h1>
        <p className="text-sm mt-1" style={{ color: "var(--text-secondary)" }}>
          AI-Powered Cybersecurity Prediction Platform
        </p>
      </div>

      <motion.div variants={container} initial="hidden" animate="show" className="space-y-6">
        <motion.div variants={item}>
          <GlassPanel title="Project Description" icon={<Shield className="w-4 h-4" />}>
            <div className="space-y-4">
              <p className="text-sm leading-relaxed" style={{ color: "var(--text-secondary)" }}>
                SentinelAI is a production-grade cyber threat intelligence and forecasting platform that leverages
                machine learning to detect, classify, and predict network attack patterns in real-time. The system
                combines multiple ML models with statistical analysis to provide accurate threat assessment and
                early warning capabilities.
              </p>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-4 rounded-xl border" style={{ borderColor: "rgba(255,255,255,0.06)", background: "rgba(255,255,255,0.03)" }}>
                  <div className="flex items-center gap-2 mb-2">
                    <Cpu className="w-4 h-4" style={{ color: "var(--accent-cyan)" }} />
                    <p className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>Architecture</p>
                  </div>
                  <p className="text-xs" style={{ color: "var(--text-secondary)" }}>
                    Next.js frontend + FastAPI backend with ML models. The frontend communicates with the
                    backend via REST API for predictions, comparisons, and drift detection.
                  </p>
                </div>
                <div className="p-4 rounded-xl border" style={{ borderColor: "rgba(255,255,255,0.06)", background: "rgba(255,255,255,0.03)" }}>
                  <div className="flex items-center gap-2 mb-2">
                    <Database className="w-4 h-4" style={{ color: "var(--accent-green)" }} />
                    <p className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>Dataset</p>
                  </div>
                  <p className="text-xs" style={{ color: "var(--text-secondary)" }}>
                    Trained on the CICIDS2017 dataset containing 2.8M+ network flow records with labeled attack types
                    including DDoS, DoS, PortScan, Botnet, Web Attacks, and more.
                  </p>
                </div>
              </div>
            </div>
          </GlassPanel>
        </motion.div>

        <motion.div variants={item}>
          <GlassPanel title="Data Flow" icon={<GitBranch className="w-4 h-4" />}>
            <div className="flex items-center justify-between text-xs overflow-x-auto pb-2">
              {ARCHITECTURE_STEPS.map((step, i) => (
                <div key={step.label} className="flex items-center">
                  <div className="text-center min-w-[80px]">
                    <div
                      className="w-16 h-16 rounded-lg flex items-center justify-center mx-auto mb-2"
                      style={{ background: "rgba(0,229,255,0.05)", border: "1px solid rgba(0,229,255,0.15)" }}
                    >
                      <span className="text-2xl">{step.icon}</span>
                    </div>
                    <p style={{ color: "var(--text-secondary)" }}>{step.label}</p>
                  </div>
                  {i < ARCHITECTURE_STEPS.length - 1 && (
                    <div
                      className="flex-1 h-px mx-4 min-w-[40px]"
                      style={{ background: "linear-gradient(90deg, rgba(0,229,255,0.3), rgba(0,229,255,0.1))" }}
                    />
                  )}
                </div>
              ))}
            </div>
          </GlassPanel>
        </motion.div>

        <motion.div variants={item}>
          <GlassPanel title="Features" icon={<Radar className="w-4 h-4" />}>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {FEATURES.map((feature) => (
                <div
                  key={feature.title}
                  className="p-4 rounded-xl border transition-all duration-300 hover:scale-[1.02]"
                  style={{ borderColor: "rgba(255,255,255,0.06)", background: "rgba(255,255,255,0.03)" }}
                >
                  <div className="mb-3" style={{ color: feature.color }}>{feature.icon}</div>
                  <h3 className="text-sm font-semibold mb-1" style={{ color: "var(--text-primary)" }}>{feature.title}</h3>
                  <p className="text-xs" style={{ color: "var(--text-muted)" }}>{feature.description}</p>
                </div>
              ))}
            </div>
          </GlassPanel>
        </motion.div>

        <motion.div variants={item}>
          <GlassPanel title="Technology Stack" icon={<Code2 className="w-4 h-4" />}>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <h3 className="text-sm font-semibold mb-3" style={{ color: "var(--accent-cyan)" }}>Frontend</h3>
                <ul className="space-y-2">
                  {FRONTEND_STACK.map((tech) => (
                    <li key={tech.name} className="flex items-center gap-2 text-xs" style={{ color: "var(--text-secondary)" }}>
                      <span style={{ color: "var(--accent-cyan)" }}>•</span>
                      <span className="font-medium">{tech.name}</span>
                      <span style={{ color: "var(--text-muted)" }}>— {tech.desc}</span>
                    </li>
                  ))}
                </ul>
              </div>
              <div>
                <h3 className="text-sm font-semibold mb-3" style={{ color: "var(--accent-green)" }}>Backend</h3>
                <ul className="space-y-2">
                  {BACKEND_STACK.map((tech) => (
                    <li key={tech.name} className="flex items-center gap-2 text-xs" style={{ color: "var(--text-secondary)" }}>
                      <span style={{ color: "var(--accent-green)" }}>•</span>
                      <span className="font-medium">{tech.name}</span>
                      <span style={{ color: "var(--text-muted)" }}>— {tech.desc}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </GlassPanel>
        </motion.div>

        <motion.div variants={item}>
          <GlassPanel title="Version Information" icon={<Server className="w-4 h-4" />}>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
              <div className="p-3 rounded-lg border" style={{ borderColor: "rgba(255,255,255,0.06)", background: "rgba(255,255,255,0.03)" }}>
                <p className="mb-1" style={{ color: "var(--text-muted)" }}>Frontend Version</p>
                <p className="font-mono" style={{ color: "var(--text-primary)" }}>v1.0.0</p>
              </div>
              <div className="p-3 rounded-lg border" style={{ borderColor: "rgba(255,255,255,0.06)", background: "rgba(255,255,255,0.03)" }}>
                <p className="mb-1" style={{ color: "var(--text-muted)" }}>Backend Version</p>
                <p className="font-mono" style={{ color: "var(--text-primary)" }}>v1.0.0</p>
              </div>
              <div className="p-3 rounded-lg border" style={{ borderColor: "rgba(255,255,255,0.06)", background: "rgba(255,255,255,0.03)" }}>
                <p className="mb-1" style={{ color: "var(--text-muted)" }}>Build Date</p>
                <p className="font-mono" style={{ color: "var(--text-primary)" }}>{BUILD_DATE}</p>
              </div>
            </div>
          </GlassPanel>
        </motion.div>
      </motion.div>
    </div>
  );
}
