"use client";

import { useEffect, useRef } from "react";
import { API_BASE_URL } from "@/lib/config";
import { useEventStore, type EventType } from "@/stores/eventStore";

interface WsEvent {
  id: number;
  timestamp: string;
  attack_type: string;
  source_ip: string;
  dest_ip: string;
  severity: string;
  status: string;
  confidence: number;
  severity_score: number;
  geo: {
    src_country: string;
    src_lat: number;
    src_lng: number;
  };
  dest_geo?: {
    dest_country: string;
    dest_lat: number;
    dest_lng: number;
  };
}

function severityToType(severity: string): EventType {
  switch (severity) {
    case "CRITICAL":
      return "error";
    case "HIGH":
      return "compare";
    case "MEDIUM":
      return "prediction";
    default:
      return "system";
  }
}

export function useWebSocket() {
  const addEvent = useEventStore((s) => s.addEvent);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const mountedRef = useRef(true);
  const backoffRef = useRef(1000);

  useEffect(() => {
    mountedRef.current = true;
    backoffRef.current = 1000;

    function connect() {
      if (!mountedRef.current) return;

      const wsUrl = API_BASE_URL.replace("http", "ws") + "/ws/events";
      try {
        const ws = new WebSocket(wsUrl);
        wsRef.current = ws;

        ws.onopen = () => {
          backoffRef.current = 1000;
          addEvent("system", "WebSocket connected to backend", {
            source: "websocket",
          });
        };

        ws.onmessage = (msg) => {
          if (!mountedRef.current) return;
          try {
            const event: WsEvent = JSON.parse(msg.data);
            const eventType = severityToType(event.severity);
            const message = `${event.attack_type} from ${event.source_ip} → ${event.dest_ip} [${event.severity}] ${event.status}`;

            addEvent(eventType, message, {
              id: event.id,
              attack_type: event.attack_type,
              source_ip: event.source_ip,
              dest_ip: event.dest_ip,
              severity: event.severity,
              status: event.status,
              confidence: event.confidence,
              severity_score: event.severity_score,
              country: event.geo?.src_country,
              lat: event.geo?.src_lat,
              lng: event.geo?.src_lng,
              geo: event.geo,
              dest_geo: event.dest_geo,
            });
          } catch {
            // ignore malformed events
          }
        };

        ws.onerror = () => {};

        ws.onclose = () => {
          if (mountedRef.current) {
            const delay = Math.min(backoffRef.current, 30000);
            backoffRef.current = delay * 2;
            reconnectTimer.current = setTimeout(connect, delay);
          }
        };
      } catch {
        if (mountedRef.current) {
          const delay = Math.min(backoffRef.current, 30000);
          backoffRef.current = delay * 2;
          reconnectTimer.current = setTimeout(connect, delay);
        }
      }
    }

    connect();

    return () => {
      mountedRef.current = false;
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [addEvent]);
}
