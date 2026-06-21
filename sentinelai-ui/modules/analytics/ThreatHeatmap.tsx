"use client";

import { useMemo, useState, useEffect } from "react";
import { motion } from "framer-motion";
import { usePredictionStore } from "@/stores/predictionStore";
import { useEventStore } from "@/stores/eventStore";

const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const HOURS = Array.from({ length: 24 }, (_, i) => `${i.toString().padStart(2, "0")}:00`);

const sevToVal = (s: string) => {
  switch (s) {
    case "CRITICAL": return 4;
    case "HIGH": return 3;
    case "MEDIUM": return 2;
    case "LOW": return 1;
    default: return 0;
  }
};

const cellColor = (v: number) => {
  if (v === 0) return "rgba(0,229,255,0.03)";
  if (v <= 1) return "rgba(0,255,136,0.15)";
  if (v <= 2) return "rgba(0,229,255,0.25)";
  if (v <= 3) return "rgba(255,149,0,0.35)";
  return "rgba(255,77,109,0.5)";
};

interface Cell {
  day: number;
  hour: number;
  count: number;
  maxSev: number;
  topAttack: string;
}

export default function ThreatHeatmap() {
  const predictionHistory = usePredictionStore((s) => s.predictionHistory);
  const events = useEventStore((s) => s.events);
  const [filter, setFilter] = useState<"24h" | "7d" | "30d">("7d");
  const [tip, setTip] = useState<Cell | null>(null);
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 5000);
    return () => clearInterval(id);
  }, []);

  const grid = useMemo(() => {
    const cells: Cell[][] = DAYS.map(() =>
      HOURS.map(() => ({ count: 0, maxSev: 0, topAttack: "", day: 0, hour: 0 }))
    );

    const cutoff = filter === "24h" ? now - 86400000 : filter === "7d" ? now - 604800000 : now - 2592000000;

    const attacks: Record<string, number> = {};

    predictionHistory.forEach((p) => {
      const t = new Date(p.timestamp).getTime();
      if (t < cutoff) return;
      const d = new Date(p.timestamp);
      const dayIdx = (d.getDay() + 6) % 7;
      const hour = d.getHours();
      cells[dayIdx][hour].count++;
      const sv = sevToVal(p.riskLevel);
      if (sv > cells[dayIdx][hour].maxSev) cells[dayIdx][hour].maxSev = sv;
      attacks[p.predictedAttack] = (attacks[p.predictedAttack] || 0) + 1;
    });

    events.forEach((e) => {
      if (!e.details) return;
      const t = new Date(e.timestamp).getTime();
      if (t < cutoff) return;
      const d = new Date(e.timestamp);
      const dayIdx = (d.getDay() + 6) % 7;
      const hour = d.getHours();
      const det = e.details as Record<string, unknown>;
      const sev = (det.severity as string) || "LOW";
      const atk = (det.attack_type as string) || "";
      cells[dayIdx][hour].count++;
      const sv = sevToVal(sev);
      if (sv > cells[dayIdx][hour].maxSev) cells[dayIdx][hour].maxSev = sv;
      if (atk) attacks[atk] = (attacks[atk] || 0) + 1;
    });

    const topAttack = Object.entries(attacks).sort(([, a], [, b]) => b - a)[0]?.[0] || "";
    cells.forEach((row, di) =>
      row.forEach((cell, hi) => {
        cell.day = di;
        cell.hour = hi;
        if (!cell.topAttack) cell.topAttack = topAttack;
      })
    );

    return cells;
  }, [predictionHistory, events, filter, now]);

  const maxCount = useMemo(() => {
    let m = 0;
    grid.forEach((row) => row.forEach((c) => { if (c.count > m) m = c.count; }));
    return m || 1;
  }, [grid]);

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        {(["24h", "7d", "30d"] as const).map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className="px-3 py-1 rounded-lg text-[10px] font-mono font-bold tracking-wider transition-colors"
            style={{
              background: filter === f ? "rgba(0,229,255,0.12)" : "transparent",
              color: filter === f ? "var(--accent-cyan)" : "var(--text-muted)",
              border: `1px solid ${filter === f ? "rgba(0,229,255,0.25)" : "rgba(0,229,255,0.06)"}`,
            }}
          >
            {f}
          </button>
        ))}
      </div>

      <div className="overflow-x-auto">
        <div className="inline-flex flex-col gap-1">
          <div className="flex gap-1 ml-10">
            {HOURS.filter((_, i) => i % 3 === 0).map((h) => (
              <span key={h} className="text-[7px] font-mono w-[72px] text-center" style={{ color: "var(--text-muted)" }}>
                {h}
              </span>
            ))}
          </div>
          {grid.map((row, di) => (
            <div key={di} className="flex items-center gap-1">
              <span className="text-[8px] font-mono w-8 text-right shrink-0" style={{ color: "var(--text-muted)" }}>
                {DAYS[di]}
              </span>
              <div className="flex gap-[2px]">
                {row.map((cell, hi) => (
                  <motion.div
                    key={`${di}-${hi}`}
                    className="rounded-[2px] cursor-pointer"
                    style={{
                      width: 14,
                      height: 14,
                      background: cellColor(cell.maxSev),
                      opacity: cell.count > 0 ? 0.5 + (cell.count / maxCount) * 0.5 : 0.3,
                    }}
                    whileHover={{ scale: 1.6, zIndex: 10 }}
                    onMouseEnter={() => setTip(cell)}
                    onMouseLeave={() => setTip(null)}
                  />
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      {tip && (
        <div className="rounded-xl px-3 py-2 text-[9px] font-mono space-y-1"
          style={{
            background: "rgba(0,8,20,0.9)",
            border: "1px solid rgba(0,229,255,0.15)",
          }}
        >
          <p style={{ color: "var(--text-primary)" }}>
            {DAYS[tip.day]} {HOURS[tip.hour]}
          </p>
          <p style={{ color: "var(--text-muted)" }}>
            {tip.count} events · Max severity: {["—", "LOW", "MEDIUM", "HIGH", "CRITICAL"][tip.maxSev]}
          </p>
          {tip.topAttack && (
            <p style={{ color: "var(--accent-cyan)" }}>
              Top: {tip.topAttack}
            </p>
          )}
        </div>
      )}

      <div className="flex items-center gap-2 pt-2">
        <span className="text-[8px] font-mono" style={{ color: "var(--text-muted)" }}>Less</span>
        {[0, 1, 2, 3, 4].map((v) => (
          <div key={v} className="w-3 h-3 rounded-[2px]" style={{ background: cellColor(v) }} />
        ))}
        <span className="text-[8px] font-mono" style={{ color: "var(--text-muted)" }}>More</span>
      </div>
    </div>
  );
}
