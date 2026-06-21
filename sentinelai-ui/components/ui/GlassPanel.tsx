"use client";

import React from "react";
import { motion } from "framer-motion";

interface GlassPanelProps {
  title?: string;
  icon?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}

export default function GlassPanel({ title, icon, children, className = "" }: GlassPanelProps) {
  return (
    <motion.div
      whileHover={{ y: -2, boxShadow: "0 0 15px rgba(0,255,255,0.2)" }}
      transition={{ duration: 0.2 }}
      className={`rounded-2xl overflow-hidden ${className}`}
      style={{
        background: "var(--glass-bg)",
        backdropFilter: "var(--glass-blur)",
        border: "var(--glass-border)",
        boxShadow: "var(--glass-shadow)",
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
    </motion.div>
  );
}
