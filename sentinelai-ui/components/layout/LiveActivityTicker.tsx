"use client";

import { useEffect, useRef, useState, useMemo } from "react";
import { useEventStore } from "@/stores/eventStore";
import { Zap } from "lucide-react";

const severityColor: Record<string, string> = {
  CRITICAL: "#ff4d6d",
  HIGH: "#ff9500",
  MEDIUM: "#00e5ff",
  LOW: "#00ff88",
};

interface TickerItem {
  id: string;
  time: string;
  message: string;
  color: string;
}

export default function LiveActivityTicker() {
  const events = useEventStore((s) => s.events);
  const scrollRef = useRef<HTMLDivElement>(null);
  const [paused, setPaused] = useState(false);

  const items: TickerItem[] = useMemo(() => {
    return events.slice(0, 20).map((e) => {
      const d = e.details as Record<string, unknown> | undefined;
      const sev = (d?.severity as string) || "MEDIUM";
      return {
        id: e.id,
        time: new Date(e.timestamp).toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" }),
        message: e.message,
        color: severityColor[sev] || severityColor.MEDIUM,
      };
    });
  }, [events]);

  useEffect(() => {
    if (paused || !scrollRef.current) return;
    const el = scrollRef.current;
    let raf: number;
    const scroll = () => {
      if (el.scrollLeft >= el.scrollWidth - el.clientWidth) {
        el.scrollLeft = 0;
      } else {
        el.scrollLeft += 1;
      }
      raf = requestAnimationFrame(scroll);
    };
    raf = requestAnimationFrame(scroll);
    return () => cancelAnimationFrame(raf);
  }, [paused, items]);

  if (items.length === 0) return null;

  return (
    <div
      className="w-full overflow-hidden border-b"
      style={{
        background: "rgba(0,8,20,0.6)",
        borderColor: "rgba(0,229,255,0.06)",
        backdropFilter: "blur(12px)",
      }}
      onMouseEnter={() => setPaused(true)}
      onMouseLeave={() => setPaused(false)}
    >
      <div className="flex items-center h-8 px-4 gap-4">
        <div className="flex items-center gap-1.5 shrink-0">
          <Zap className="w-3 h-3" style={{ color: "var(--accent-cyan)" }} />
          <span className="text-[9px] font-mono font-bold tracking-wider" style={{ color: "var(--accent-cyan)" }}>
            LIVE
          </span>
        </div>
        <div className="w-px h-4 shrink-0" style={{ background: "rgba(0,229,255,0.15)" }} />
        <div ref={scrollRef} className="flex-1 overflow-hidden whitespace-nowrap">
          {items.map((item) => (
            <span
              key={item.id}
              className="inline-flex items-center gap-2 mr-8"
            >
              <span className="text-[9px] font-mono" style={{ color: "var(--text-muted)" }}>
                {item.time}
              </span>
              <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: item.color }} />
              <span className="text-[9px] font-mono" style={{ color: item.color }}>
                {item.message}
              </span>
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}
