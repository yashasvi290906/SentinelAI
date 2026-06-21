"use client";

import { Info } from "lucide-react";

interface ExplanationProps {
  text: string;
  className?: string;
}

export default function Explanation({ text, className = "" }: ExplanationProps) {
  return (
    <div
      className={`flex items-start gap-2 px-3 py-2 rounded-lg ${className}`}
      style={{
        background: "rgba(0,229,255,0.03)",
        border: "1px solid rgba(0,229,255,0.06)",
      }}
    >
      <Info
        className="w-3.5 h-3.5 mt-0.5 shrink-0"
        style={{ color: "var(--accent-cyan)", opacity: 0.6 }}
      />
      <p className="text-[11px] leading-relaxed" style={{ color: "var(--text-muted)" }}>
        {text}
      </p>
    </div>
  );
}
