import axios from "axios";
import { API_BASE_URL } from "./config";
import type { PredictResponse, CompareResponse } from "./types";

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: { "Content-Type": "application/json" },
});

api.interceptors.request.use((config) => {
  if (typeof window !== "undefined") {
    const token = localStorage.getItem("sentinelai_access_token");
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
  }
  return config;
});

api.interceptors.response.use(
  (res) => res,
  async (error) => {
    if (error.response?.status === 401 && typeof window !== "undefined") {
      const refreshToken = localStorage.getItem("sentinelai_refresh_token");
      if (refreshToken && !error.config._retry) {
        error.config._retry = true;
        try {
          const { data } = await axios.post(`${API_BASE_URL}/auth/refresh`, { refresh_token: refreshToken });
          if (data.access_token) {
            localStorage.setItem("sentinelai_access_token", data.access_token);
            localStorage.setItem("sentinelai_refresh_token", data.refresh_token);
            error.config.headers.Authorization = `Bearer ${data.access_token}`;
            return api(error.config);
          }
        } catch {
          localStorage.removeItem("sentinelai_access_token");
          localStorage.removeItem("sentinelai_refresh_token");
          localStorage.removeItem("sentinelai_user");
          window.location.href = "/login";
        }
      } else {
        localStorage.removeItem("sentinelai_access_token");
        localStorage.removeItem("sentinelai_refresh_token");
        localStorage.removeItem("sentinelai_user");
        window.location.href = "/login";
      }
    }
    return Promise.reject(error);
  }
);

export async function loginAPI(email: string, password: string) {
  const { data } = await api.post("/auth/login", { email, password });
  return data;
}

export async function registerAPI(name: string, email: string, password: string) {
  const { data } = await api.post("/auth/register", { name, email, password });
  return data;
}

export async function generateOtpAPI(email: string) {
  const { data } = await api.post("/auth/otp/generate", { email });
  return data;
}

export async function verifyOtpAPI(email: string, otp: string) {
  const { data } = await api.post("/auth/otp/verify", { email, otp });
  return data;
}

export async function resetPasswordAPI(email: string, otp: string, newPassword: string) {
  const { data } = await api.post("/auth/otp/reset-password", { email, otp, new_password: newPassword });
  return data;
}

export async function predictAPI(sequence: number[]): Promise<PredictResponse> {
  const res = await api.post<PredictResponse>("/predict", { sequence });
  return res.data;
}

export async function compareAPI(sequence: number[]): Promise<CompareResponse> {
  const res = await api.post<CompareResponse>("/compare", { sequence });
  return res.data;
}

export interface SystemStats {
  total_predictions: number;
  total_comparisons: number;
  total_simulations: number;
  attack_distribution: Record<string, number>;
  most_frequent_attack: string;
  average_confidence: number;
  average_latency: number;
  average_severity: number;
  agreement_rate: number;
  critical_alerts: number;
  high_alerts: number;
  threat_score: {
    score: number;
    breakdown: {
      confidence_contribution: number;
      critical_alerts: number;
      model_conflict: number;
      drift_impact: number;
    };
    factors: {
      avg_confidence: number;
      critical_count: number;
      disagreement_rate: number;
      drift_score: number;
    };
  };
  recent_predictions: Array<{
    timestamp: string;
    sequence: number[];
    prediction: string;
    confidence: number;
    severity_score: number;
    severity: string;
    latency_ms: number;
    model: string;
  }>;
  recent_comparisons: Array<{
    timestamp: string;
    ml_prediction: string;
    markov_prediction: string;
    agreement: boolean;
    latency_ms: number;
  }>;
}

export async function statsAPI(): Promise<SystemStats> {
  const res = await api.get<SystemStats>("/stats");
  return res.data;
}

export async function healthCheck(): Promise<boolean> {
  try {
    const res = await api.get("/", { timeout: 3000 });
    return res.status === 200;
  } catch {
    return false;
  }
}

export interface CopilotResponse {
  prediction: string;
  confidence: number;
  explanation: string;
  indicators: string[];
  recommendations: string[];
  kill_chain_stage: string;
  severity_weight: number;
}

export async function copilotAPI(sequence: number[], prediction: string, question: string = ""): Promise<CopilotResponse> {
  const res = await api.post<CopilotResponse>("/copilot", { sequence, prediction, question });
  return res.data;
}

export async function explainAPI(sequence: number[]) {
  const res = await api.post("/explain", { sequence });
  return res.data as {
    prediction: string;
    confidence: number;
    importance: Array<{ token: string; position: number; weight: number; label: string }>;
    top_predictions: Array<{ attack: string; probability: number }>;
    explanation: { reasoning: string[]; pattern_match: string; similar_sequences: number; input_pattern: string };
  };
}

export interface GraphNode {
  id: string;
  type: string;
  label: string;
  confidence: number;
  severity_score: number;
  timestamp?: string;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: string;
}

export async function graphAPI() {
  const res = await api.get("/graph");
  return res.data as { nodes: GraphNode[]; edges: GraphEdge[] };
}

export interface KillChainStage {
  id: string;
  name: string;
  description: string;
  icon: string;
  status: "completed" | "active" | "pending";
}

export async function killchainAPI(prediction: string) {
  const res = await api.get(`/killchain/${prediction}`);
  return res.data as { attack: string; current_stage: string; progress: number; stages: KillChainStage[] };
}

export interface DriftAnalyticsResponse {
  drift_score: number;
  accuracy: number;
  confidence: number;
  status: string;
  history: Array<{ timestamp: string; confidence: number; prediction: string; latency_ms: number }>;
  distribution: Record<string, number>;
  total_predictions: number;
}

export async function driftAnalyticsAPI(): Promise<DriftAnalyticsResponse> {
  const res = await api.get<DriftAnalyticsResponse>("/analytics/drift");
  return res.data;
}

export interface Recommendation {
  text: string;
  priority: "critical" | "high" | "medium";
  category: string;
}

export async function recommendationsAPI(): Promise<{ recommendations: Recommendation[]; attack: string; severity: string; confidence: number }> {
  const res = await api.get("/api/recommendations");
  return res.data;
}
