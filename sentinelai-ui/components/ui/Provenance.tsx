"use client";

import { formatTime } from "@/lib/utils";

interface ProvenanceProps {
  source?: string;
  lastUpdated?: string | null;
  className?: string;
}

export default function Provenance({
  source = "FastAPI Backend",
  lastUpdated,
  className = "",
}: ProvenanceProps) {
  const timeText = lastUpdated ? formatTime(new Date(lastUpdated)) : formatTime(new Date());

  return (
    <div
      className={`flex items-center gap-3 text-[9px] font-mono tracking-wider ${className}`}
      style={{ color: "var(--text-muted)" }}
    >
      <span className="flex items-center gap-1">
        <span style={{ color: "var(--accent-cyan)" }}>Source:</span> {source}
      </span>
      <span style={{ opacity: 0.3 }}>|</span>
      <span className="flex items-center gap-1" suppressHydrationWarning>
        <span style={{ color: "var(--accent-cyan)" }}>Updated:</span> {timeText}
      </span>
    </div>
  );
}
