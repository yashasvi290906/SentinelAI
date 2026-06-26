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
    const user = localStorage.getItem("sentinelai_user");
    if (user) {
      try {
        const parsed = JSON.parse(user);
        if (parsed.organization_id) {
          config.headers["X-Organization-Id"] = parsed.organization_id;
        }
      } catch { /* ignore */ }
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
            const newApi = axios.create({
              baseURL: API_BASE_URL,
              timeout: 10000,
              headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${data.access_token}`,
              },
            });
            const { method, url, data: body } = error.config;
            const retryRes = await newApi.request({ method, url, data: body });
            return retryRes;
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
  response: string;
  explanation?: string;
  source: string;
  indicators: string[];
  recommendations: string[];
  kill_chain_stage: string;
  severity_weight: number;
  detection_summary?: { total: number; by_type: Record<string, number> };
  alerts_count?: number;
  incidents_count?: number;
  devices_count?: number;
}

export async function copilotAPI(
  sequence: number[],
  prediction: string,
  question: string = "",
  conversationHistory: Array<{ role: string; content: string }> = []
): Promise<CopilotResponse> {
  const res = await api.post<CopilotResponse>("/copilot", {
    sequence,
    prediction,
    question,
    conversation_history: conversationHistory,
  });
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

// ── Log Management ──
export async function uploadLogAPI(file: File) {
  const formData = new FormData();
  formData.append('file', file);
  const res = await api.post('/api/logs/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
  return res.data;
}

export async function getLogsAPI() {
  const res = await api.get('/api/logs');
  return res.data;
}

export async function getLogEventsAPI(logId: string, limit = 1000) {
  const res = await api.get(`/api/logs/${logId}/events?limit=${limit}`);
  return res.data;
}

// ── Threat Detection ──
export async function getThreatsAPI(params?: { severity?: string; threat_type?: string; source_ip?: string; limit?: number }) {
  const queryParams = new URLSearchParams();
  if (params?.severity) queryParams.set('severity', params.severity);
  if (params?.threat_type) queryParams.set('threat_type', params.threat_type);
  if (params?.source_ip) queryParams.set('source_ip', params.source_ip);
  if (params?.limit) queryParams.set('limit', String(params.limit));
  const res = await api.get(`/api/threats?${queryParams.toString()}`);
  return res.data;
}

export async function getThreatSummaryAPI() {
  const res = await api.get('/api/threats/summary');
  return res.data;
}

// ── Anomaly Detection ──
export async function analyzeAnomalyAPI(logId: string) {
  const res = await api.post('/api/anomaly/analyze', { log_id: logId });
  return res.data;
}

// ── MITRE ──
export async function getMitreAPI() {
  const res = await api.get('/api/mitre');
  return res.data;
}

// ── Investigation ──
export async function investigateIPAPI(ip: string) {
  const res = await api.get(`/api/investigate/${ip}`);
  return res.data;
}

// ── Reports ──
export async function generateReportAPI(reportType: string, logId?: string) {
  const res = await api.post('/api/reports/generate', { report_type: reportType, log_id: logId });
  return res.data;
}

export async function downloadReportAPI(reportId: string, format: string = 'json') {
  const res = await api.get(`/api/reports/${reportId}/download?format=${format}`, { responseType: 'blob' });
  return res.data;
}

// ── Threat Intelligence ──
export async function lookupIntelAPI(query: string, type: string = 'ip') {
  const res = await api.post('/api/intel/lookup', { query, type });
  return res.data;
}

// ── Dashboard Stats ──
export async function getDashboardStatsAPI() {
  const res = await api.get('/api/dashboard/stats');
  return res.data;
}

// ── Alerts ──
export async function getAlertsAPI(params?: { severity?: string; status?: string; limit?: number }) {
  const queryParams = new URLSearchParams();
  if (params?.severity) queryParams.set('severity', params.severity);
  if (params?.status) queryParams.set('status', params.status);
  if (params?.limit) queryParams.set('limit', String(params.limit));
  const res = await api.get(`/api/alerts?${queryParams.toString()}`);
  return res.data;
}

export async function getAlertStatsAPI() {
  const res = await api.get('/api/alerts/stats');
  return res.data;
}

export async function updateAlertStatusAPI(alertId: string, status: string, assignedTo?: string) {
  const res = await api.post(`/api/alerts/${alertId}/status`, { status, assigned_to: assignedTo });
  return res.data;
}

// ── Incidents ──
export async function getIncidentsAPI(params?: { severity?: string; status?: string; limit?: number }) {
  const queryParams = new URLSearchParams();
  if (params?.severity) queryParams.set('severity', params.severity);
  if (params?.status) queryParams.set('status', params.status);
  if (params?.limit) queryParams.set('limit', String(params.limit));
  const res = await api.get(`/api/incidents?${queryParams.toString()}`);
  return res.data;
}

export async function getIncidentStatsAPI() {
  const res = await api.get('/api/incidents/stats');
  return res.data;
}

export async function getIncidentAPI(incidentId: string) {
  const res = await api.get(`/api/incidents/${incidentId}`);
  return res.data;
}

export async function updateIncidentStatusAPI(incidentId: string, status: string, assignedTo?: string) {
  const res = await api.post(`/api/incidents/${incidentId}/status`, { status, assigned_to: assignedTo });
  return res.data;
}

export async function correlateAlertsAPI() {
  const res = await api.post('/api/incidents/correlate');
  return res.data;
}

// ── GeoIP ──
export async function geoipLookupAPI(ip: string) {
  const res = await api.get(`/api/geoip/${ip}`);
  return res.data;
}

export async function geoipAttackMapAPI() {
  const res = await api.get('/api/geoip/attacks');
  return res.data;
}

// ── APS Metrics ──
export async function getApsAPI() {
  const res = await api.get('/api/metrics/aps');
  return res.data;
}

// ── MITRE Matrix ──
export async function getMitreMatrixAPI() {
  const res = await api.get('/api/mitre/matrix');
  return res.data;
}

// ── Threat Hunting ──
export async function threatHuntSearchAPI(params: {
  q?: string; severity?: string; attack_type?: string;
  source_ip?: string; hostname?: string; date_from?: string;
  date_to?: string; limit?: number;
}) {
  const queryParams = new URLSearchParams();
  if (params.q) queryParams.set('q', params.q);
  if (params.severity) queryParams.set('severity', params.severity);
  if (params.attack_type) queryParams.set('attack_type', params.attack_type);
  if (params.source_ip) queryParams.set('source_ip', params.source_ip);
  if (params.hostname) queryParams.set('hostname', params.hostname);
  if (params.date_from) queryParams.set('date_from', params.date_from);
  if (params.date_to) queryParams.set('date_to', params.date_to);
  if (params.limit) queryParams.set('limit', String(params.limit));
  const res = await api.get(`/api/hunt/search?${queryParams.toString()}`);
  return res.data;
}

// ── Security Metrics ──
export async function getSecurityMetricsAPI() {
  const res = await api.get('/api/metrics/security');
  return res.data;
}

// ── Pipeline Metrics ──
export async function getPipelineMetricsAPI() {
  const res = await api.get('/api/metrics/pipeline');
  return res.data;
}

// ── Attack Heatmap ──
export async function getAttackHeatmapAPI() {
  const res = await api.get('/api/metrics/heatmap');
  return res.data;
}

// ── Asset Risk ──
export async function getAssetRiskAPI(assetId: string) {
  const res = await api.get(`/api/assets/${assetId}/risk`);
  return res.data;
}

// ── Assets ──
export async function getAssetsAPI() {
  const res = await api.get('/api/assets');
  return res.data;
}

export async function createAssetAPI(asset: {
  hostname: string; ip_address: string; os_type?: string;
  asset_type?: string; criticality?: string; owner?: string;
}) {
  const res = await api.post('/api/assets', asset);
  return res.data;
}

export async function deleteAssetAPI(assetId: string) {
  const res = await api.delete(`/api/assets/${assetId}`);
  return res.data;
}

// ── IOC ──
export async function getIocsAPI(indicatorType?: string) {
  const queryParams = indicatorType ? `?indicator_type=${indicatorType}` : '';
  const res = await api.get(`/api/ioc${queryParams}`);
  return res.data;
}

export async function createIocAPI(ioc: {
  indicator_type: string; indicator_value: string;
  threat_type?: string; severity?: string; confidence?: number;
  source?: string; description?: string;
}) {
  const res = await api.post('/api/ioc', ioc);
  return res.data;
}

export async function checkIocAPI(indicator: string) {
  const res = await api.get(`/api/ioc/check/${indicator}`);
  return res.data;
}

// ── Detection Rules ──
export async function getDetectionRulesAPI() {
  const res = await api.get('/api/rules');
  return res.data;
}

export async function createDetectionRuleAPI(rule: {
  title: string; description?: string; condition: string;
  window_seconds?: number; threshold?: number; severity?: string;
  mitre_technique?: string; mitre_tactic?: string;
}) {
  const res = await api.post('/api/rules', rule);
  return res.data;
}

export async function deleteDetectionRuleAPI(ruleId: string) {
  const res = await api.delete(`/api/rules/${ruleId}`);
  return res.data;
}

// ── Agents ──
export async function getAgentsAPI() {
  const res = await api.get('/api/agents');
  return res.data;
}

// ── Vulnerabilities ──
export async function searchVulnerabilitiesAPI(keyword: string = "", cvssMin: number = 0, limit: number = 20) {
  const params = new URLSearchParams();
  if (keyword) params.set('keyword', keyword);
  if (cvssMin > 0) params.set('cvss_min', String(cvssMin));
  params.set('limit', String(limit));
  const res = await api.get(`/api/vulnerabilities/search?${params.toString()}`);
  return res.data;
}

export async function getCveAPI(cveId: string) {
  const res = await api.get(`/api/vulnerabilities/${cveId}`);
  return res.data;
}

// ── Agent Health ──
export async function getAgentHealthAPI() {
  const res = await api.get('/api/agents/health');
  return res.data;
}
