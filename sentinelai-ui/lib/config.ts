export const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

export const ATTACK_TYPES = [
  "DDoS",
  "DoS",
  "PortScan",
  "Bot",
  "WebAttack",
  "BruteForce",
  "Infiltration",
] as const;

export const ATTACK_COLORS: Record<string, string> = {
  DDoS: "#FF3B3B",
  DoS: "#FF6B35",
  PortScan: "#F59E0B",
  Bot: "#A855F7",
  WebAttack: "#EC4899",
  BruteForce: "#EF4444",
  Infiltration: "#EF4444",
};

export const ATTACK_SEVERITY: Record<string, "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"> = {
  DDoS: "CRITICAL",
  DoS: "HIGH",
  PortScan: "MEDIUM",
  Bot: "HIGH",
  WebAttack: "HIGH",
  BruteForce: "HIGH",
  Infiltration: "CRITICAL",
};

export const ATTACK_TO_NUMERIC: Record<string, number> = {
  DDoS: 0,
  DoS: 1,
  PortScan: 2,
  Bot: 3,
  WebAttack: 4,
  BruteForce: 5,
  Infiltration: 6,
};

export const HEALTH_POLL_INTERVAL = 10000;
