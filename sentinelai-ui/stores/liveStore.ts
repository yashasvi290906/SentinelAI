import { create } from "zustand";

export interface LiveAlert {
  id: string;
  title: string;
  severity: string;
  source_ip: string;
  dest_ip: string;
  attack_type: string;
  confidence: number;
  status: string;
  created_at: string;
  mitre_technique?: string;
}

export interface LiveIncident {
  id: string;
  title: string;
  severity: string;
  status: string;
  affected_ips: string[];
  created_at: string;
  description?: string;
}

export interface LiveDetection {
  id: string;
  attack_type: string;
  severity: string;
  source_ip: string;
  dest_ip: string;
  confidence: number;
  timestamp: string;
  description?: string;
}

interface LiveState {
  alerts: LiveAlert[];
  incidents: LiveIncident[];
  detections: LiveDetection[];
  aps: number;
  totalAlerts: number;
  totalIncidents: number;
  totalDetections: number;
  lastUpdate: string;
  addAlert: (alert: LiveAlert) => void;
  addIncident: (incident: LiveIncident) => void;
  addDetection: (detection: LiveDetection) => void;
  setMetrics: (metrics: { aps: number; totalAlerts: number; totalIncidents: number; totalDetections: number }) => void;
  clearOld: () => void;
}

export const useLiveStore = create<LiveState>((set) => ({
  alerts: [],
  incidents: [],
  detections: [],
  aps: 0,
  totalAlerts: 0,
  totalIncidents: 0,
  totalDetections: 0,
  lastUpdate: "",

  addAlert: (alert) =>
    set((state) => ({
      alerts: [alert, ...state.alerts].slice(0, 200),
      totalAlerts: state.totalAlerts + 1,
      lastUpdate: new Date().toISOString(),
    })),

  addIncident: (incident) =>
    set((state) => ({
      incidents: [incident, ...state.incidents].slice(0, 100),
      totalIncidents: state.totalIncidents + 1,
      lastUpdate: new Date().toISOString(),
    })),

  addDetection: (detection) =>
    set((state) => ({
      detections: [detection, ...state.detections].slice(0, 500),
      totalDetections: state.totalDetections + 1,
      lastUpdate: new Date().toISOString(),
    })),

  setMetrics: (metrics) =>
    set({
      aps: metrics.aps,
      totalAlerts: metrics.totalAlerts,
      totalIncidents: metrics.totalIncidents,
      totalDetections: metrics.totalDetections,
    }),

  clearOld: () =>
    set((state) => ({
      alerts: state.alerts.slice(0, 100),
      incidents: state.incidents.slice(0, 50),
      detections: state.detections.slice(0, 200),
    })),
}));
