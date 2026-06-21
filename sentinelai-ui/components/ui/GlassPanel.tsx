"use client";

import React from "react";

interface GlassPanelProps {
  title?: string;
  icon?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}

export default function GlassPanel({ title, icon, children, className = "" }: GlassPanelProps) {
  return (
    <div
      className={`rounded-2xl overflow-hidden ${className}`}
      style={{
        background: "rgba(8,20,32,0.7)",
        backdropFilter: "blur(24px)",
        border: "1px solid rgba(0,229,255,0.08)",
      }}
    >
      {(title || icon) && (
        <div
          className="flex items-center gap-2 px-5 py-3"
          style={{ borderBottom: "1px solid rgba(0,229,255,0.06)" }}
        >
          {icon && (
            <span style={{ color: "var(--accent-cyan)" }}>{icon}</span>
          )}
          {title && (
            <span
              className="text-[11px] font-mono tracking-widest uppercase"
              style={{ color: "var(--text-muted)" }}
            >
              {title}
            </span>
          )}
        </div>
      )}
      <div className="p-5">{children}</div>
    </div>
  );
}
