"use client";

import { useEffect, useRef, useCallback } from "react";
import { API_BASE_URL } from "@/lib/config";
import { useEventStore, type EventType } from "@/stores/eventStore";

export type WsChannel = "dashboard" | "alerts" | "incidents" | "analytics" | "all";

interface WsEvent {
  id?: string;
  timestamp?: string;
  type?: string;
  attack_type?: string;
  source_ip?: string;
  dest_ip?: string;
  severity?: string;
  status?: string;
  confidence?: number;
  severity_score?: number;
  title?: string;
  incident_id?: string;
  channel?: string;
}

function severityToType(severity: string): EventType {
  switch (severity) {
    case "CRITICAL": return "error";
    case "HIGH": return "compare";
    case "MEDIUM": return "prediction";
    default: return "system";
  }
}

// Global WebSocket singleton
let globalWs: WebSocket | null = null;
let globalReconnectTimer: ReturnType<typeof setTimeout> | null = null;
let globalBackoff = 1000;
let globalMounted = false;
let globalSubscribers: Set<(event: WsEvent) => void> = new Set();
let globalChannels: Set<WsChannel> = new Set(["all"]);

function connectWs() {
  if (globalMounted && globalWs && globalWs.readyState === WebSocket.OPEN) return;

  let token = "";
  if (typeof window !== "undefined") {
    token = localStorage.getItem("sentinelai_access_token") || "";
  }

  const wsUrl = API_BASE_URL.replace("http", "ws") + `/ws/events${token ? `?token=${token}` : ""}`;

  try {
    const ws = new WebSocket(wsUrl);
    globalWs = ws;

    ws.onopen = () => {
      globalBackoff = 1000;
      // Subscribe to all channels
      globalChannels.forEach((ch) => {
        ws.send(JSON.stringify({ action: "subscribe", channel: ch }));
      });
    };

    ws.onmessage = (msg) => {
      if (!globalMounted) return;
      try {
        const event: WsEvent = JSON.parse(msg.data);
        if (event.type === "subscribed" || event.type === "unsubscribed") return;
        globalSubscribers.forEach((cb) => cb(event));
      } catch {}
    };

    ws.onerror = () => {};

    ws.onclose = () => {
      if (globalMounted) {
        const delay = Math.min(globalBackoff, 30000);
        globalBackoff = delay * 2;
        globalReconnectTimer = setTimeout(connectWs, delay);
      }
    };
  } catch {
    if (globalMounted) {
      const delay = Math.min(globalBackoff, 30000);
      globalBackoff = delay * 2;
      globalReconnectTimer = setTimeout(connectWs, delay);
    }
  }
}

export function useWebSocket(channels?: WsChannel[]) {
  const addEvent = useEventStore((s) => s.addEvent);

  useEffect(() => {
    globalMounted = true;

    const handler = (event: WsEvent) => {
      const eventType = severityToType(event.severity || "INFO");
      const attackType = event.attack_type || "Unknown";
      const sourceIp = event.source_ip || "";
      const destIp = event.dest_ip || "";

      if (event.type === "incident") {
        addEvent("error", `Incident: ${event.title || attackType}`, {
          channel: "incidents",
          incident_id: event.incident_id,
          severity: event.severity,
        });
      } else if (event.type === "detection" || event.type === "rule_alert") {
        const message = event.type === "rule_alert"
          ? `Rule Alert: ${event.title || "Rule matched"}`
          : `${attackType} from ${sourceIp} → ${destIp} [${event.severity}]`;
        addEvent(eventType, message, {
          id: event.id,
          attack_type: attackType,
          source_ip: sourceIp,
          dest_ip: destIp,
          severity: event.severity,
          status: event.status,
          confidence: event.confidence,
          severity_score: event.severity_score,
          channel: "alerts",
        });
      } else if (event.type === "prediction") {
        addEvent(eventType, `Prediction: ${attackType} (${event.severity})`, {
          attack_type: attackType,
          severity: event.severity,
          confidence: event.confidence,
          channel: "dashboard",
        });
      }
    };

    globalSubscribers.add(handler);
    connectWs();

    return () => {
      globalSubscribers.delete(handler);
    };
  }, [addEvent]);
}

export function sendWsMessage(message: object) {
  if (globalWs && globalWs.readyState === WebSocket.OPEN) {
    globalWs.send(JSON.stringify(message));
  }
}

export function subscribeChannel(channel: WsChannel) {
  globalChannels.add(channel);
  sendWsMessage({ action: "subscribe", channel });
}

export function unsubscribeChannel(channel: WsChannel) {
  globalChannels.delete(channel);
  sendWsMessage({ action: "unsubscribe", channel });
}
