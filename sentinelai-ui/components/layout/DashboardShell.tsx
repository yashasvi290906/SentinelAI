"use client";

import { ReactNode } from "react";
import CollapsibleSidebar from "@/components/layout/CollapsibleSidebar";
import CommandBar from "@/components/layout/CommandBar";
import CyberBackground from "@/components/layout/CyberBackground";
import LiveActivityTicker from "@/components/layout/LiveActivityTicker";
import ToastContainer from "@/components/ui/Toast";
import CopilotWidget from "@/components/copilot/CopilotWidget";
import { useHealthPolling } from "@/hooks/useHealthPolling";
import { useWebSocket } from "@/hooks/useWebSocket";

interface DashboardShellProps {
  children: ReactNode;
}

export default function DashboardShell({ children }: DashboardShellProps) {
  useHealthPolling();
  useWebSocket();

  return (
    <div
      className="relative h-screen flex flex-col overflow-hidden"
      style={{ background: "var(--bg-deep)" }}
    >
      <CyberBackground />

      {/* Command Bar - top */}
      <CommandBar />

      {/* Live Activity Ticker */}
      <LiveActivityTicker />

      {/* Body: sidebar + main */}
      <div className="relative z-[3] flex flex-1 overflow-hidden">
        <CollapsibleSidebar />
        <main className="flex-1 overflow-y-auto overflow-x-hidden">
          {children}
        </main>
      </div>

      <ToastContainer />
      <CopilotWidget />
    </div>
  );
}
