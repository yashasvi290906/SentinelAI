"use client";
import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import { getAgentsAPI } from "@/lib/api";
import GlassCard from "@/components/ui/GlassCard";
import { Server, Wifi, WifiOff, Clock, Activity, RefreshCw } from "lucide-react";

export default function AgentHealth() {
  const [agents, setAgents] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    try {
      const data = await getAgentsAPI();
      const agentList = data.agents || [];
      const now = Date.now();
      const enriched = agentList.map((a: any) => {
        let isOnline = false;
        let lastSeenText = "Never";
        if (a.last_heartbeat) {
          try {
            const hb = new Date(a.last_heartbeat).getTime();
            const diff = (now - hb) / 1000;
            isOnline = diff < 120;
            lastSeenText = diff < 5 ? "Just now" : diff < 60 ? `${Math.floor(diff)}s ago` : diff < 3600 ? `${Math.floor(diff / 60)}m ago` : `${Math.floor(diff / 3600)}h ago`;
          } catch { }
        }
        return { ...a, is_online: isOnline, lastSeenText };
      });
      setAgents(enriched);
    } catch {
      setAgents([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchData(); const i = setInterval(fetchData, 10000); return () => clearInterval(i); }, [fetchData]);

  const online = agents.filter(a => a.is_online).length;
  const offline = agents.length - online;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-[var(--text-primary)] flex items-center gap-2">
            <Server className="w-6 h-6 text-[var(--accent-cyan)]" />
            Agent Health
          </h1>
          <p className="text-sm text-[var(--text-muted)] mt-1">Sentinel Agent heartbeat monitoring</p>
        </div>
        <button onClick={fetchData} className="flex items-center gap-2 px-3 py-1.5 text-xs bg-[var(--bg-deep)]/50 border border-[var(--accent-cyan)]/10 rounded-lg text-[var(--text-muted)] hover:text-[var(--text-primary)]">
          <RefreshCw className="w-3 h-3" /> Refresh
        </button>
      </div>

      <div className="grid grid-cols-3 gap-4">
        <GlassCard className="p-4">
          <p className="text-xs text-[var(--text-muted)]">Total Agents</p>
          <p className="text-2xl font-bold text-[var(--text-primary)]">{agents.length}</p>
        </GlassCard>
        <GlassCard className="p-4">
          <p className="text-xs text-[var(--text-muted)]">Online</p>
          <p className="text-2xl font-bold text-green-400">{online}</p>
        </GlassCard>
        <GlassCard className="p-4">
          <p className="text-xs text-[var(--text-muted)]">Offline</p>
          <p className="text-2xl font-bold text-red-400">{offline}</p>
        </GlassCard>
      </div>

      {loading ? (
        <GlassCard className="p-8 text-center text-[var(--text-muted)]">Loading agents...</GlassCard>
      ) : agents.length === 0 ? (
        <GlassCard className="p-12 text-center">
          <Server className="w-10 h-10 text-[var(--accent-cyan)]/30 mx-auto mb-3" />
          <p className="text-[var(--text-muted)]">No agents registered yet.</p>
          <p className="text-xs text-[var(--text-muted)] mt-1">Deploy Sentinel Agents to start collecting telemetry.</p>
        </GlassCard>
      ) : (
        <div className="grid grid-cols-2 gap-4">
          {agents.map((agent, i) => (
            <motion.div key={agent.agent_id || i} initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: i * 0.05 }}>
              <GlassCard className="p-5">
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-3">
                    <div className={`p-2 rounded-lg ${agent.is_online ? "bg-green-500/10" : "bg-red-500/10"}`}>
                      {agent.is_online ? <Wifi className="w-5 h-5 text-green-400" /> : <WifiOff className="w-5 h-5 text-red-400" />}
                    </div>
                    <div>
                      <p className="text-sm font-medium text-[var(--text-primary)]">{agent.hostname || agent.agent_id}</p>
                      <p className="text-xs text-[var(--text-muted)]">{agent.os_type || "Unknown OS"}</p>
                    </div>
                  </div>
                  <span className={`px-2 py-0.5 text-xs rounded-full ${agent.is_online ? "bg-green-500/10 text-green-400 border border-green-500/20" : "bg-red-500/10 text-red-400 border border-red-500/20"}`}>
                    {agent.is_online ? "Online" : "Offline"}
                  </span>
                </div>
                <div className="grid grid-cols-3 gap-3 mt-4 text-xs">
                  <div>
                    <p className="text-[var(--text-muted)]">Last Heartbeat</p>
                    <p className="text-[var(--text-primary)] flex items-center gap-1"><Clock className="w-3 h-3" /> {agent.lastSeenText}</p>
                  </div>
                  <div>
                    <p className="text-[var(--text-muted)]">Events Processed</p>
                    <p className="text-[var(--text-primary)]">{(agent.events_processed || 0).toLocaleString()}</p>
                  </div>
                  <div>
                    <p className="text-[var(--text-muted)]">Alerts Generated</p>
                    <p className="text-[var(--text-primary)]">{agent.alerts_generated || 0}</p>
                  </div>
                </div>
                {agent.ip_address && <p className="text-xs text-[var(--text-muted)] mt-2">IP: {agent.ip_address}</p>}
              </GlassCard>
            </motion.div>
          ))}
        </div>
      )}
    </div>
  );
}
