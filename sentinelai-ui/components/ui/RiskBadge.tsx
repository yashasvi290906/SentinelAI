"use client";

interface RiskBadgeProps {
  level: string;
}

const riskStyles: Record<string, { bg: string; border: string; text: string }> = {
  CRITICAL: { bg: "rgba(255,77,109,0.1)", border: "rgba(255,77,109,0.3)", text: "var(--accent-red)" },
  HIGH: { bg: "rgba(255,176,32,0.1)", border: "rgba(255,176,32,0.3)", text: "var(--accent-amber)" },
  MEDIUM: { bg: "rgba(0,229,255,0.1)", border: "rgba(0,229,255,0.3)", text: "var(--accent-cyan)" },
  LOW: { bg: "rgba(0,255,136,0.1)", border: "rgba(0,255,136,0.3)", text: "var(--accent-green)" },
};

export function RiskBadge({ level }: RiskBadgeProps) {
  const style = riskStyles[level] || riskStyles.MEDIUM;
  return (
    <span
      className="px-2 py-0.5 rounded text-[10px] font-mono font-bold"
      style={{ background: style.bg, border: `1px solid ${style.border}`, color: style.text }}
    >
      {level}
    </span>
  );
}
