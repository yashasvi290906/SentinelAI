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
      className={`rounded-2xl p-5 relative overflow-hidden transition-shadow duration-300 ${hoverGlow ? "hover:shadow-[0_0_28px_rgba(0,229,255,0.06)]" : ""} ${className}`}
      style={{
        background: "rgba(8,20,32,0.7)",
        backdropFilter: "blur(24px)",
        border: "1px solid rgba(0,229,255,0.08)",
      }}
    >
      {children}
    </motion.div>
  );
}
