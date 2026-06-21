"use client";

import { motion } from "framer-motion";

const fadeUp = {
  hidden: { opacity: 0, y: 18 },
  show: { opacity: 1, y: 0, transition: { duration: 0.45, ease: [0.22, 1, 0.36, 1] as const } },
};

export default function GlassCard({
  children,
  className = "",
  hoverGlow = true,
}: {
  children: React.ReactNode;
  className?: string;
  hoverGlow?: boolean;
}) {
  return (
    <motion.div
      variants={fadeUp}
      whileHover={{ y: -2, boxShadow: "0 0 15px rgba(0,255,255,0.2)" }}
      transition={{ duration: 0.2 }}
      className={`rounded-2xl p-5 relative overflow-hidden ${hoverGlow ? "hover:shadow-[0_0_28px_rgba(0,229,255,0.06)]" : ""} ${className}`}
      style={{
        background: "var(--glass-bg)",
        backdropFilter: "var(--glass-blur)",
        border: "var(--glass-border)",
        boxShadow: "var(--glass-shadow)",
      }}
    >
      {children}
    </motion.div>
  );
}
