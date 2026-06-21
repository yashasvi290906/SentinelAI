"use client";

import { motion, AnimatePresence } from "framer-motion";
import { useNotificationStore } from "@/stores/notificationStore";
import {
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Info,
  X,
} from "lucide-react";

const ICONS = {
  success: CheckCircle2,
  warning: AlertTriangle,
  error: XCircle,
  info: Info,
};

const COLORS = {
  success: { bg: "rgba(0,255,136,0.08)", border: "rgba(0,255,136,0.2)", text: "var(--accent-green)" },
  warning: { bg: "rgba(255,176,32,0.08)", border: "rgba(255,176,32,0.2)", text: "var(--accent-amber)" },
  error: { bg: "rgba(255,77,109,0.08)", border: "rgba(255,77,109,0.2)", text: "var(--accent-red)" },
  info: { bg: "rgba(0,229,255,0.08)", border: "rgba(0,229,255,0.2)", text: "var(--accent-cyan)" },
};

export default function ToastContainer() {
  const notifications = useNotificationStore((s) => s.notifications);
  const markRead = useNotificationStore((s) => s.markRead);

  const visible = notifications.filter((n) => !n.read).slice(0, 3);

  return (
    <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 pointer-events-none">
      <AnimatePresence>
        {visible.map((n) => {
          const Icon = ICONS[n.type];
          const colors = COLORS[n.type];
          return (
            <motion.div
              key={n.id}
              initial={{ opacity: 0, x: 80, scale: 0.9 }}
              animate={{ opacity: 1, x: 0, scale: 1 }}
              exit={{ opacity: 0, x: 80, scale: 0.9 }}
              transition={{ duration: 0.3, ease: [0.22, 1, 0.36, 1] }}
              className="pointer-events-auto flex items-start gap-3 px-4 py-3 rounded-xl max-w-sm"
              style={{
                background: "rgba(8,20,32,0.9)",
                backdropFilter: "blur(24px)",
                border: `1px solid ${colors.border}`,
                boxShadow: `0 8px 32px rgba(0,0,0,0.4), 0 0 20px ${colors.border}`,
              }}
            >
              <Icon className="w-4 h-4 mt-0.5 shrink-0" style={{ color: colors.text }} />
              <div className="flex-1 min-w-0">
                <p className="text-xs font-bold" style={{ color: colors.text }}>
                  {n.title}
                </p>
                <p className="text-[11px] mt-0.5" style={{ color: "var(--text-muted)" }}>
                  {n.message}
                </p>
              </div>
              <button
                onClick={() => markRead(n.id)}
                className="shrink-0 p-0.5 rounded transition-colors hover:bg-white/10"
              >
                <X className="w-3 h-3" style={{ color: "var(--text-muted)" }} />
              </button>
            </motion.div>
          );
        })}
      </AnimatePresence>
    </div>
  );
}
