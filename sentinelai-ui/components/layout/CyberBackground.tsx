"use client";

import { motion } from "framer-motion";

export default function CyberBackground() {
  return (
    <div className="fixed inset-0 z-0 pointer-events-none overflow-hidden">
      {/* Layer 1: Deep space gradient */}
      <div
        className="absolute inset-0"
        style={{
          background:
            "radial-gradient(ellipse 80% 60% at 50% 0%, rgba(0,229,255,0.04) 0%, transparent 60%), " +
            "radial-gradient(ellipse 60% 50% at 80% 100%, rgba(128,0,255,0.03) 0%, transparent 50%), " +
            "radial-gradient(ellipse 40% 30% at 10% 90%, rgba(0,255,136,0.02) 0%, transparent 50%), " +
            "linear-gradient(180deg, #050d18 0%, #0a1929 40%, #081420 100%)",
        }}
      />

      {/* Layer 1b: Hacker background image (masked) */}
      <div
        className="absolute inset-0"
        style={{
          backgroundImage: "url('/hacker-bg.jpg')",
          backgroundSize: "cover",
          backgroundPosition: "center 30%",
          opacity: 0.12,
          mixBlendMode: "screen",
        }}
      />

      {/* Layer 2: Moving cyber grid */}
      <div
        className="absolute inset-0"
        style={{
          backgroundImage:
            "linear-gradient(rgba(0,229,255,0.03) 1px, transparent 1px), " +
            "linear-gradient(90deg, rgba(0,229,255,0.03) 1px, transparent 1px)",
          backgroundSize: "48px 48px",
          opacity: 0.5,
          animation: "gridScroll 60s linear infinite",
        }}
      />

      {/* Layer 3: Animated neural network connections */}
      <svg className="absolute inset-0 w-full h-full" style={{ opacity: 0.15 }}>
        <defs>
          <linearGradient id="neuralGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="var(--accent-cyan)" stopOpacity="0.4" />
            <stop offset="100%" stopColor="var(--accent-purple)" stopOpacity="0.1" />
          </linearGradient>
        </defs>
        {/* Neural lines */}
        {[
          { x1: "10%", y1: "20%", x2: "30%", y2: "40%", delay: 0 },
          { x1: "70%", y1: "15%", x2: "85%", y2: "35%", delay: 1 },
          { x1: "20%", y1: "70%", x2: "45%", y2: "85%", delay: 2 },
          { x1: "60%", y1: "60%", x2: "80%", y2: "80%", delay: 0.5 },
          { x1: "40%", y1: "30%", x2: "65%", y2: "50%", delay: 1.5 },
          { x1: "15%", y1: "45%", x2: "35%", y2: "65%", delay: 2.5 },
          { x1: "55%", y1: "10%", x2: "75%", y2: "25%", delay: 3 },
          { x1: "5%", y1: "85%", x2: "25%", y2: "95%", delay: 0.8 },
        ].map((line, i) => (
          <motion.line
            key={i}
            x1={line.x1}
            y1={line.y1}
            x2={line.x2}
            y2={line.y2}
            stroke="url(#neuralGrad)"
            strokeWidth="1"
            initial={{ pathLength: 0, opacity: 0 }}
            animate={{ pathLength: 1, opacity: [0, 0.6, 0] }}
            transition={{
              duration: 4,
              delay: line.delay,
              repeat: Infinity,
              repeatDelay: 6,
              ease: "easeInOut",
            }}
          />
        ))}
        {/* Neural nodes */}
        {[
          { cx: "10%", cy: "20%", delay: 0 },
          { cx: "30%", cy: "40%", delay: 0.5 },
          { cx: "70%", cy: "15%", delay: 1 },
          { cx: "85%", cy: "35%", delay: 1.5 },
          { cx: "20%", cy: "70%", delay: 2 },
          { cx: "60%", cy: "60%", delay: 2.5 },
          { cx: "40%", cy: "30%", delay: 3 },
          { cx: "75%", cy: "25%", delay: 3.5 },
        ].map((node, i) => (
          <motion.circle
            key={i}
            cx={node.cx}
            cy={node.cy}
            r="2"
            fill="var(--accent-cyan)"
            initial={{ opacity: 0, scale: 0 }}
            animate={{ opacity: [0, 0.8, 0], scale: [0, 1, 0] }}
            transition={{
              duration: 3,
              delay: node.delay,
              repeat: Infinity,
              repeatDelay: 7,
            }}
          />
        ))}
      </svg>

      {/* Layer 4: Slow parallax particles */}
      <div className="absolute inset-0">
        {Array.from({ length: 20 }).map((_, i) => (
          <motion.div
            key={i}
            className="absolute w-0.5 h-0.5 rounded-full"
            style={{
              background: i % 3 === 0 ? "var(--accent-cyan)" : i % 3 === 1 ? "var(--accent-purple)" : "var(--accent-green)",
              left: `${(i * 5.3 + 2) % 100}%`,
              top: `${(i * 7.1 + 5) % 100}%`,
            }}
            animate={{
              y: [0, -30, 0],
              opacity: [0, 0.4, 0],
            }}
            transition={{
              duration: 8 + (i % 4) * 2,
              delay: i * 0.7,
              repeat: Infinity,
              ease: "easeInOut",
            }}
          />
        ))}
      </div>

      {/* Layer 5: Radar scanning rings */}
      <div className="absolute inset-0 flex items-center justify-center">
        {[200, 350, 500].map((size, i) => (
          <motion.div
            key={i}
            className="absolute rounded-full"
            style={{
              width: size,
              height: size,
              border: "1px solid rgba(0,229,255,0.06)",
            }}
            animate={{ rotate: 360 }}
            transition={{
              duration: 20 + i * 10,
              repeat: Infinity,
              ease: "linear",
            }}
          />
        ))}
        {/* Radar sweep */}
        <motion.div
          className="absolute w-[500px] h-[500px]"
          style={{
            background: "conic-gradient(from 0deg, transparent 0%, rgba(0,229,255,0.04) 10%, transparent 20%)",
            borderRadius: "50%",
          }}
          animate={{ rotate: 360 }}
          transition={{ duration: 12, repeat: Infinity, ease: "linear" }}
        />
      </div>

      {/* Layer 6: Glowing data streams */}
      <div className="absolute inset-0">
        {[15, 35, 55, 75, 90].map((left, i) => (
          <motion.div
            key={i}
            className="absolute w-px"
            style={{
              left: `${left}%`,
              height: "100%",
              background: `linear-gradient(180deg, transparent 0%, rgba(0,229,255,${0.03 + (i % 3) * 0.01}) 50%, transparent 100%)`,
            }}
            animate={{ opacity: [0, 0.5, 0] }}
            transition={{
              duration: 4 + i,
              delay: i * 1.2,
              repeat: Infinity,
              ease: "easeInOut",
            }}
          />
        ))}
      </div>

      {/* Vignette overlay */}
      <div
        className="absolute inset-0"
        style={{
          background: "radial-gradient(ellipse at center, transparent 40%, rgba(5,13,24,0.8) 100%)",
        }}
      />

      {/* Scanline effect */}
      <motion.div
        className="absolute left-0 right-0 h-px"
        style={{
          background: "linear-gradient(90deg, transparent 0%, rgba(0,229,255,0.1) 50%, transparent 100%)",
        }}
        animate={{ top: ["0%", "100%"] }}
        transition={{ duration: 8, repeat: Infinity, ease: "linear" }}
      />
    </div>
  );
}
