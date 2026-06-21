export type AttackType = "DDoS" | "DoS" | "PortScan" | "Bot" | "WebAttack" | "BruteForce" | "Infiltration";

export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface TopPrediction {
  attack: string;
  probability: number;
}

export interface PredictionExplanation {
  reasoning: string[];
  pattern_match: string;
  similar_sequences: number;
  input_pattern: string;
}

export interface PredictResponse {
  model: string;
  prediction: string;
  confidence: number;
  top_predictions: TopPrediction[];
  severity_score: number;
  explanation: PredictionExplanation;
  latency_ms: number;
  sequence?: number[];
}

export interface CompareResponse {
  ml_prediction: string;
  markov_prediction: string;
  ml_confidence: number;
  markov_confidence: number;
  agreement: boolean;
  agreement_score: number;
  ml_top_predictions: TopPrediction[];
  latency_ms: number;
}

export interface DriftResponse {
  drift_score: number;
  status?: string;
}

export interface PredictionRecord {
  id: string;
  timestamp: string;
  sequence: AttackType[];
  predictedAttack: string;
  confidence: number;
  riskLevel: RiskLevel;
  severityScore: number;
  model: string;
  latencyMs: number;
  topPredictions: TopPrediction[];
  explanation: PredictionExplanation;
  rawResponse: unknown;
}

export interface CompareRecord {
  id: string;
  timestamp: string;
  sequence: AttackType[];
  mlPrediction: string;
  markovPrediction: string;
  mlConfidence: number;
  markovConfidence: number;
  modelsAgree: boolean;
  agreementScore: number;
  mlTopPredictions: TopPrediction[];
  latencyMs: number;
  rawResponse: unknown;
}

export interface DriftRecord {
  id: string;
  timestamp: string;
  score: number;
  status: "stable" | "warning" | "critical";
}

export interface SimulationStep {
  index: number;
  inputSequence: AttackType[];
  predictedAttack: string;
  confidence: number;
  severityScore: number;
  riskLevel: RiskLevel;
  model: string;
  timestamp: string;
}

export interface SimulationRecord {
  id: string;
  name: string;
  startedAt: string;
  completedAt: string | null;
  steps: SimulationStep[];
  totalSteps: number;
  averageConfidence: number;
  averageSeverityScore: number;
  executionTimeMs: number;
  attackFlow: string[];
  status: "running" | "completed" | "error";
  error: string | null;
}

export interface Notification {
  id: string;
  timestamp: string;
  type: "info" | "success" | "warning" | "error";
  title: string;
  message: string;
  read: boolean;
}

export interface ReportData {
  id: string;
  title: string;
  generatedAt: string;
  type: string;
  summary: string;
  metrics: {
    totalPredictions: number;
    averageConfidence: number;
    averageLatency: number;
    criticalAlerts: number;
    highAlerts: number;
    totalCompares: number;
    agreementRate: number;
    driftTrend: Array<{ time: string; score: number; status: string }>;
    attackDistribution: Record<string, number>;
    topAttack: string;
    executionTimeMs: number;
  };
  predictions: Array<{
    timestamp: string;
    predictedAttack: string;
    confidence: number;
    severityScore: number;
    riskLevel: string;
    latencyMs: number;
    model: string;
  }>;
}
