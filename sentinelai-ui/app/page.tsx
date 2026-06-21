"use client";

import { AnimatePresence, motion } from "framer-motion";
import dynamic from "next/dynamic";
import DashboardShell from "@/components/layout/DashboardShell";
import { useGlobalStore } from "@/stores/globalStore";
import { ErrorBoundary } from "@/components/ui/ErrorBoundary";

import { DashboardSkeleton } from '@/components/ui/DashboardSkeleton';

function LoadingSkeleton() {
  return <DashboardSkeleton />;
}

const Dashboard = dynamic(() => import("@/modules/dashboard"), { loading: () => <LoadingSkeleton /> });
const Predictions = dynamic(() => import("@/modules/predictions"), { loading: () => <LoadingSkeleton /> });
const LiveFeed = dynamic(() => import("@/modules/livefeed"), { loading: () => <LoadingSkeleton /> });
const Analytics = dynamic(() => import("@/modules/analytics"), { loading: () => <LoadingSkeleton /> });
const Compare = dynamic(() => import("@/modules/compare"), { loading: () => <LoadingSkeleton /> });
const Timeline = dynamic(() => import("@/modules/timeline"), { loading: () => <LoadingSkeleton /> });
const ThreatIntelligence = dynamic(() => import("@/modules/threat-intelligence"), { loading: () => <LoadingSkeleton /> });
const Reports = dynamic(() => import("@/modules/reports"), { loading: () => <LoadingSkeleton /> });
const Settings = dynamic(() => import("@/modules/settings"), { loading: () => <LoadingSkeleton /> });
const About = dynamic(() => import("@/modules/about"), { loading: () => <LoadingSkeleton /> });
const Simulation = dynamic(() => import("@/modules/simulation"), { loading: () => <LoadingSkeleton /> });
const SystemHealth = dynamic(() => import("@/modules/system-health"), { loading: () => <LoadingSkeleton /> });
const Copilot = dynamic(() => import("@/modules/copilot"), { loading: () => <LoadingSkeleton /> });
const Explainability = dynamic(() => import("@/modules/explainability"), { loading: () => <LoadingSkeleton /> });
const NetworkGraph = dynamic(() => import("@/modules/network-graph"), { loading: () => <LoadingSkeleton /> });
const KillChain = dynamic(() => import("@/modules/killchain"), { loading: () => <LoadingSkeleton /> });
const DriftAnalytics = dynamic(() => import("@/modules/drift-analytics"), { loading: () => <LoadingSkeleton /> });
const AttackJourney = dynamic(() => import("@/modules/attack-journey"), { loading: () => <LoadingSkeleton /> });
const Devices = dynamic(() => import("@/modules/devices"), { loading: () => <LoadingSkeleton /> });
const SystemArchitecture = dynamic(() => import("@/modules/system-architecture"), { loading: () => <LoadingSkeleton /> });
const LogUpload = dynamic(() => import("@/modules/log-upload"), { loading: () => <LoadingSkeleton /> });
const ThreatDetection = dynamic(() => import("@/modules/threat-detection"), { loading: () => <LoadingSkeleton /> });
const MitreMatrix = dynamic(() => import("@/modules/mitre-matrix"), { loading: () => <LoadingSkeleton /> });
const Investigation = dynamic(() => import("@/modules/investigation"), { loading: () => <LoadingSkeleton /> });

const MODULE_MAP: Record<string, { component: React.ComponentType; label: string }> = {
  dashboard: { component: Dashboard, label: "Dashboard" },
  predictions: { component: Predictions, label: "Predictions" },
  compare: { component: Compare, label: "Compare" },
  "live-feed": { component: LiveFeed, label: "Live Feed" },
  timeline: { component: Timeline, label: "Timeline" },
  analytics: { component: Analytics, label: "Analytics" },
  simulation: { component: Simulation, label: "Simulation Lab" },
  "threat-intel": { component: ThreatIntelligence, label: "Threat Intel" },
  reports: { component: Reports, label: "Reports" },
  settings: { component: Settings, label: "Settings" },
  "system-health": { component: SystemHealth, label: "System Health" },
  copilot: { component: Copilot, label: "AI Copilot" },
  explainability: { component: Explainability, label: "Explainability" },
  "network-graph": { component: NetworkGraph, label: "Network Graph" },
  killchain: { component: KillChain, label: "Kill Chain" },
  "drift-analytics": { component: DriftAnalytics, label: "Drift Analytics" },
  "attack-journey": { component: AttackJourney, label: "Attack Journey" },
  "system-architecture": { component: SystemArchitecture, label: "Architecture" },
  "log-upload": { component: LogUpload, label: "Log Upload" },
  "threat-detection": { component: ThreatDetection, label: "Threat Detection" },
  "mitre-matrix": { component: MitreMatrix, label: "MITRE Matrix" },
  "investigation": { component: Investigation, label: "Investigation" },
  devices: { component: Devices, label: "Devices" },
  about: { component: About, label: "About" },
};

export default function Page() {
  const activeModule = useGlobalStore((s) => s.activeModule);
  const entry = MODULE_MAP[activeModule];
  const ModuleComponent = entry?.component ?? Dashboard;
  const label = entry?.label ?? "Dashboard";

  return (
    <DashboardShell>
      <a 
        href="#main-content" 
        className="sr-only focus:not-sr-only focus:fixed focus:top-4 focus:left-4 focus:z-[100] focus:px-4 focus:py-2 focus:bg-cyan-500 focus:text-black focus:rounded-lg focus:outline-none focus:ring-2 focus:ring-cyan-400/50"
      >
        Skip to main content
      </a>
      <AnimatePresence mode="wait">
        <motion.div
          key={activeModule}
          id="main-content"
          tabIndex={-1}
          initial={{ opacity: 0, y: 20, scale: 0.98 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={{ opacity: 0, y: -15, scale: 0.98 }}
          transition={{ duration: 0.35, ease: [0.22, 1, 0.36, 1] }}
          className="h-full"
          style={{ outline: 'none' }}
        >
          <ErrorBoundary moduleName={label} key={activeModule}>
            <ModuleComponent />
          </ErrorBoundary>
        </motion.div>
      </AnimatePresence>
    </DashboardShell>
  );
}
