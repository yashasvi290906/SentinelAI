import { create } from "zustand";
import { healthCheck } from "@/lib/api";
import { useEventStore } from "./eventStore";
import { useNotificationStore } from "./notificationStore";
import { audioManager } from "@/services/audioManager";
import { systemMonitor } from "@/services/systemMonitor";

interface SystemState {
  backendStatus: "online" | "offline" | "connecting";
  lastHealthCheck: string | null;
  apiLatency: number;
  uptime: number;
  connectionErrors: number;
  startTime: number;
  systemMetrics: {
    backendHealth: "online" | "offline" | "connecting";
    apiLatency: number;
    predictionThroughput: number;
    avgResponseTime: number;
    memoryUsage: number | null;
    systemUptime: number;
    lastApiCall: string | null;
    predictionQueueSize: number;
    timestamp: string;
  };
  updateSystemMetrics: () => void;
  checkHealth: () => Promise<void>;
}

export const useSystemStore = create<SystemState>((set, get) => ({
  backendStatus: "connecting",
  lastHealthCheck: null,
  apiLatency: 0,
  uptime: 0,
  connectionErrors: 0,
  startTime: Date.now(),
  systemMetrics: { backendHealth: "connecting", apiLatency: 0, predictionThroughput: 0, avgResponseTime: 0, memoryUsage: null, systemUptime: 0, lastApiCall: null, predictionQueueSize: 0, timestamp: new Date().toISOString() },
  updateSystemMetrics: () => {
    if (typeof window !== "undefined") {
      set({ systemMetrics: systemMonitor.getMetrics() });
    }
  },

  checkHealth: async () => {
    const start = Date.now();
    const prev = get();
    try {
      const isOnline = await healthCheck();
      const latency = Date.now() - start;
      const newStatus = isOnline ? "online" : "offline";
      if (prev.backendStatus !== newStatus) {
        set({
          backendStatus: newStatus,
          lastHealthCheck: new Date().toISOString(),
          apiLatency: latency,
          uptime: Date.now() - prev.startTime,
        });
        if (!isOnline) {
          useEventStore.getState().addEvent("error", "Backend health check failed");
          if (prev.backendStatus === "online") {
            if (typeof window !== "undefined") audioManager.play("backendOffline");
            useNotificationStore.getState().addNotification({
              type: "error",
              title: "Backend Offline",
              message: "Lost connection to FastAPI backend",
            });
          }
        } else {
          if (typeof window !== "undefined") audioManager.play("backendReconnected");
          useNotificationStore.getState().addNotification({
            type: "success",
            title: "Backend Online",
            message: `Connected to FastAPI (latency: ${latency}ms)`,
          });
        }
      }
    } catch {
      if (prev.backendStatus !== "offline") {
        set({
          backendStatus: "offline",
          lastHealthCheck: new Date().toISOString(),
          connectionErrors: prev.connectionErrors + 1,
        });
        useEventStore.getState().addEvent("error", "Backend connection error");
        if (prev.backendStatus === "online") {
          if (typeof window !== "undefined") audioManager.play("backendOffline");
          useNotificationStore.getState().addNotification({
            type: "error",
            title: "Backend Offline",
            message: "Connection to FastAPI backend failed",
          });
        }
      }
    }
  },
}));

if (typeof window !== "undefined") {
  systemMonitor.startMonitoring(5000);
  systemMonitor.onMetricsUpdate((metrics) => {
    useSystemStore.setState((prev) => {
      if (
        prev.systemMetrics.backendHealth === metrics.backendHealth &&
        prev.systemMetrics.predictionThroughput === metrics.predictionThroughput
      ) {
        return prev;
      }
      return { systemMetrics: metrics };
    });
  });
}
