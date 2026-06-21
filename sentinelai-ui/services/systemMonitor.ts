"use client";

import { usePredictionStore } from "@/stores/predictionStore";
import { useSystemStore } from "@/stores/systemStore";

export interface SystemMetrics {
  backendHealth: "online" | "offline" | "connecting";
  apiLatency: number;
  predictionThroughput: number;
  avgResponseTime: number;
  memoryUsage: number | null;
  systemUptime: number;
  lastApiCall: string | null;
  predictionQueueSize: number;
  timestamp: string;
}

type MetricsCallback = (metrics: SystemMetrics) => void;

class SystemMonitor {
  private static instance: SystemMonitor;
  private intervalId: ReturnType<typeof setInterval> | null = null;
  private callbacks: MetricsCallback[] = [];
  private pageLoadTime: number = Date.now();
  private lastApiCallTimestamp: string | null = null;

  private constructor() {
    this.pageLoadTime = Date.now();
  }

  static getInstance(): SystemMonitor {
    if (!SystemMonitor.instance) {
      SystemMonitor.instance = new SystemMonitor();
    }
    return SystemMonitor.instance;
  }

  getMetrics(): SystemMetrics {
    const predictionStore = usePredictionStore.getState();
    const systemStore = useSystemStore.getState();

    const predictionHistory = predictionStore.predictionHistory;
    const latencyHistory = predictionStore.latencyHistory;
    const now = Date.now();
    const oneMinuteAgo = now - 60000;

    const recentPredictions = predictionHistory.filter(
      (p) => new Date(p.timestamp).getTime() > oneMinuteAgo
    );
    const predictionThroughput = recentPredictions.length;

    const avgResponseTime =
      latencyHistory.length > 0
        ? latencyHistory.reduce((sum, entry) => sum + entry.latency, 0) / latencyHistory.length
        : 0;

    let memoryUsage: number | null = null;
    if (typeof performance !== "undefined" && "memory" in performance) {
      memoryUsage = (performance as { memory: { usedJSHeapSize: number } }).memory.usedJSHeapSize / 1024 / 1024;
    }

    const systemUptime = (now - this.pageLoadTime) / 1000;

    return {
      backendHealth: systemStore.backendStatus,
      apiLatency: systemStore.apiLatency,
      predictionThroughput,
      avgResponseTime,
      memoryUsage,
      systemUptime,
      lastApiCall: this.lastApiCallTimestamp,
      predictionQueueSize: predictionHistory.length,
      timestamp: new Date().toISOString(),
    };
  }

  startMonitoring(intervalMs: number = 2000): void {
    this.stopMonitoring();
    this.intervalId = setInterval(() => {
      this.notifyCallbacks();
    }, intervalMs);
  }

  stopMonitoring(): void {
    if (this.intervalId !== null) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
  }

  onMetricsUpdate(callback: MetricsCallback): () => void {
    this.callbacks.push(callback);
    return () => {
      this.callbacks = this.callbacks.filter((cb) => cb !== callback);
    };
  }

  updateLastApiCall(timestamp?: string): void {
    this.lastApiCallTimestamp = timestamp || new Date().toISOString();
  }

  private notifyCallbacks(): void {
    const metrics = this.getMetrics();
    this.callbacks.forEach((callback) => callback(metrics));
  }
}

export const systemMonitor = SystemMonitor.getInstance();
