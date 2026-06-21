'use client';
import { create } from 'zustand';

export interface UploadedLog {
  id: string;
  filename: string;
  file_size: number;
  source_type: string;
  event_count: number;
  upload_time: string;
  status: string;
}

export interface LogEvent {
  id: string;
  log_id: string;
  timestamp: string;
  source_ip: string;
  dest_ip: string;
  source_port: number;
  dest_port: number;
  protocol: string;
  event_type: string;
  severity: string;
  user_name: string;
  url: string;
  method: string;
  status_code: number;
  message: string;
  source_format: string;
}

export interface ThreatDetection {
  id: string;
  log_id: string;
  detection_time: string;
  threat_type: string;
  severity: string;
  confidence: number;
  source_ip: string;
  dest_ip: string;
  dest_port: number;
  description: string;
  evidence: string[];
  mitre_technique: string;
  mitre_tactic: string;
  first_seen: string;
  last_seen: string;
  event_count: number;
  recommendations: string[];
  status: string;
}

export interface ThreatSummary {
  total: number;
  by_severity: Record<string, number>;
  by_type: Record<string, number>;
  by_status: Record<string, number>;
}

export interface DashboardStats {
  total_logs: number;
  total_events: number;
  total_threats: number;
  critical_threats: number;
  unique_source_ips: number;
  avg_anomaly_score: number;
}

export interface Alert {
  id: string;
  organization_id: string;
  log_id: string;
  device_id: string;
  alert_type: string;
  severity: string;
  title: string;
  description: string;
  source_ip: string;
  destination_ip: string;
  source_port: number;
  destination_port: number;
  protocol: string;
  mitre_technique: string;
  mitre_tactic: string;
  evidence: string[];
  recommendations: string[];
  status: string;
  assigned_to: string;
  created_at: string;
  updated_at: string;
}

interface LogState {
  logs: UploadedLog[];
  currentLogId: string | null;
  events: LogEvent[];
  threats: ThreatDetection[];
  threatSummary: ThreatSummary | null;
  dashboardStats: DashboardStats | null;
  isUploading: boolean;
  isAnalyzing: boolean;
  alerts: Alert[];
  alertStats: any;
  
  setLogs: (logs: UploadedLog[]) => void;
  addLog: (log: UploadedLog) => void;
  setCurrentLogId: (id: string | null) => void;
  setEvents: (events: LogEvent[]) => void;
  setThreats: (threats: ThreatDetection[]) => void;
  setThreatSummary: (summary: ThreatSummary) => void;
  setDashboardStats: (stats: DashboardStats) => void;
  setIsUploading: (v: boolean) => void;
  setIsAnalyzing: (v: boolean) => void;
  setAlerts: (alerts: Alert[]) => void;
  setAlertStats: (stats: any) => void;
}

export const useLogStore = create<LogState>((set) => ({
  logs: [],
  currentLogId: null,
  events: [],
  threats: [],
  threatSummary: null,
  dashboardStats: null,
  isUploading: false,
  isAnalyzing: false,
  alerts: [],
  alertStats: null,
  
  setLogs: (logs) => set({ logs }),
  addLog: (log) => set((s) => ({ logs: [log, ...s.logs] })),
  setCurrentLogId: (id) => set({ currentLogId: id }),
  setEvents: (events) => set({ events }),
  setThreats: (threats) => set({ threats }),
  setThreatSummary: (summary) => set({ threatSummary: summary }),
  setDashboardStats: (stats) => set({ dashboardStats: stats }),
  setIsUploading: (v) => set({ isUploading: v }),
  setIsAnalyzing: (v) => set({ isAnalyzing: v }),
  setAlerts: (alerts) => set({ alerts }),
  setAlertStats: (stats) => set({ alertStats: stats }),
}));
