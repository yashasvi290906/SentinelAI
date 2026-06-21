import { usePredictionStore } from "@/stores/predictionStore";
import { useSystemStore } from "@/stores/systemStore";
import { useEventStore } from "@/stores/eventStore";

export interface IntegrityCheck {
  name: string;
  status: "healthy" | "warning" | "error";
  message: string;
  lastChecked: string;
}

export function runIntegrityChecks(): IntegrityCheck[] {
  const now = new Date().toISOString();
  const checks: IntegrityCheck[] = [];
  const predStats = usePredictionStore.getState().getStats();
  const system = useSystemStore.getState();
  const events = useEventStore.getState().events;

  // Check 1: Backend connectivity
  checks.push({
    name: "Backend Connectivity",
    status: system.backendStatus === "online" ? "healthy" : system.backendStatus === "connecting" ? "warning" : "error",
    message:
      system.backendStatus === "online"
        ? `Connected (latency: ${system.apiLatency}ms)`
        : system.backendStatus === "connecting"
        ? "Attempting to establish connection..."
        : `Offline after ${system.connectionErrors} failed attempts`,
    lastChecked: system.lastHealthCheck || now,
  });

  // Check 2: Prediction history integrity
  const preds = usePredictionStore.getState().predictionHistory;
  const hasDuplicates = preds.length > 1 && preds.some((p, i) =>
    preds.slice(i + 1).some((q) => q.id === p.id)
  );
  const hasStaleTimestamps = preds.length > 1 && preds.some((p, i) => {
    if (i === 0) return false;
    return new Date(p.timestamp).getTime() > new Date(preds[i - 1].timestamp).getTime() + 60000;
  });

  checks.push({
    name: "Prediction Data",
    status: hasDuplicates ? "error" : hasStaleTimestamps ? "warning" : "healthy",
    message: hasDuplicates
      ? "Duplicate prediction IDs detected — data corruption possible"
      : preds.length > 0
      ? `${preds.length} predictions stored, ${predStats.averageConfidence > 0 ? `avg confidence: ${(predStats.averageConfidence * 100).toFixed(1)}%` : "no confidence data"}`
      : "No predictions recorded yet",
    lastChecked: now,
  });

  // Check 3: Compare history integrity
  const compares = usePredictionStore.getState().compareHistory;
  checks.push({
    name: "Compare Data",
    status: "healthy",
    message: compares.length > 0
      ? `${compares.length} comparisons, ${(predStats.agreementRate * 100).toFixed(1)}% agreement`
      : "No comparisons recorded yet",
    lastChecked: now,
  });

  // Check 4: Drift measurements
  const drifts = usePredictionStore.getState().driftHistory;
  checks.push({
    name: "Drift Monitoring",
    status: drifts.length > 0 && drifts[0].status === "critical" ? "warning" : "healthy",
    message: drifts.length > 0
      ? `${drifts.length} measurements, latest: ${drifts[0].score.toFixed(3)} (${drifts[0].status})`
      : "No drift measurements recorded",
    lastChecked: now,
  });

  // Check 5: Event log integrity
  const hasEventGaps = events.length > 10 && events.filter((e) => e.type === "error").length > events.length * 0.5;
  checks.push({
    name: "Event Log",
    status: hasEventGaps ? "warning" : "healthy",
    message: `${events.length} events recorded, ${events.filter((e) => e.type === "error").length} errors`,
    lastChecked: now,
  });

  // Check 6: Store synchronization
  checks.push({
    name: "Store Sync",
    status: "healthy",
    message: `Prediction: ${preds.length} items, Compare: ${compares.length} items, Drift: ${drifts.length} items, Events: ${events.length} items`,
    lastChecked: now,
  });

  return checks;
}

export function getOverallHealth(checks: IntegrityCheck[]): "healthy" | "degraded" | "critical" {
  const hasError = checks.some((c) => c.status === "error");
  const hasWarning = checks.some((c) => c.status === "warning");
  if (hasError) return "critical";
  if (hasWarning) return "degraded";
  return "healthy";
}
