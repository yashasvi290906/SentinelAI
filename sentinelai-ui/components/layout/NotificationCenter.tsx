"use client";

import { useState, useCallback, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Bell, Check, Trash2, Filter, X } from "lucide-react";
import { useNotificationStore } from "@/stores/notificationStore";

type FilterType = "all" | "info" | "success" | "warning" | "error";

const FILTER_OPTIONS: { key: FilterType; label: string; color: string }[] = [
  { key: "all", label: "All", color: "var(--text-muted)" },
  { key: "error", label: "Error", color: "var(--accent-red)" },
  { key: "warning", label: "Warn", color: "var(--accent-amber)" },
  { key: "success", label: "OK", color: "var(--accent-green)" },
  { key: "info", label: "Info", color: "var(--accent-cyan)" },
];

export default function NotificationCenter() {
  const [open, setOpen] = useState(false);
  const [filter, setFilter] = useState<FilterType>("all");
  const notifications = useNotificationStore((s) => s.notifications);
  const markRead = useNotificationStore((s) => s.markRead);
  const markAllRead = useNotificationStore((s) => s.markAllRead);
  const clearAll = useNotificationStore((s) => s.clearAll);
  const unread = notifications.filter((n) => !n.read).length;

  const filtered = useMemo(() => {
    if (filter === "all") return notifications;
    return notifications.filter((n) => n.type === filter);
  }, [notifications, filter]);

  const toggle = useCallback(() => setOpen((p) => !p), []);

  return (
    <div className="relative">
      <button
        onClick={toggle}
        className="relative p-1.5 rounded-lg transition-all duration-300 hover:bg-white/[0.04]"
        style={{
          border: "1px solid rgba(0,229,255,0.08)",
        }}
      >
        <Bell className="w-4 h-4" style={{ color: "var(--text-muted)" }} />
        {unread > 0 && (
          <motion.div
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            className="absolute -top-1 -right-1 w-4 h-4 rounded-full flex items-center justify-center text-[8px] font-bold"
            suppressHydrationWarning
            style={{
              background: "var(--accent-red)",
              color: "#fff",
              boxShadow: "0 0 8px rgba(255,77,109,0.5)",
            }}
          >
            {unread > 9 ? "9+" : unread}
          </motion.div>
        )}
      </button>

      <AnimatePresence>
        {open && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 z-40"
              onClick={() => setOpen(false)}
            />
            <motion.div
              initial={{ opacity: 0, y: -8, scale: 0.96 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: -8, scale: 0.96 }}
              transition={{ duration: 0.2 }}
              className="absolute top-full right-0 mt-2 w-96 max-h-[32rem] overflow-hidden z-50 rounded-xl"
              style={{
                background: "rgba(8,20,32,0.95)",
                backdropFilter: "blur(24px)",
                border: "1px solid rgba(0,229,255,0.12)",
                boxShadow: "0 20px 50px rgba(0,0,0,0.5)",
              }}
            >
              <div
                className="flex items-center justify-between px-4 py-3 border-b"
                style={{ borderColor: "rgba(0,229,255,0.06)" }}
              >
                <div className="flex items-center gap-2">
                  <p className="text-xs font-bold tracking-wider uppercase" style={{ color: "var(--text-secondary)" }}>
                    Notifications
                  </p>
                  {unread > 0 && (
                    <span
                      className="px-1.5 py-0.5 rounded text-[8px] font-bold"
                      style={{ background: "rgba(255,77,109,0.15)", color: "var(--accent-red)" }}
                    >
                      {unread}
                    </span>
                  )}
                </div>
                <div className="flex gap-1">
                  {unread > 0 && (
                    <button
                      onClick={markAllRead}
                      className="p-1 rounded hover:bg-white/5"
                      title="Mark all read"
                    >
                      <Check className="w-3 h-3" style={{ color: "var(--accent-green)" }} />
                    </button>
                  )}
                  <button
                    onClick={clearAll}
                    className="p-1 rounded hover:bg-white/5"
                    title="Clear all"
                  >
                    <Trash2 className="w-3 h-3" style={{ color: "var(--text-muted)" }} />
                  </button>
                </div>
              </div>

              {/* Filter bar */}
              <div className="flex items-center gap-1 px-3 py-2 border-b" style={{ borderColor: "rgba(0,229,255,0.04)" }}>
                <Filter className="w-3 h-3 mr-1" style={{ color: "var(--text-muted)" }} />
                {FILTER_OPTIONS.map((opt) => (
                  <button
                    key={opt.key}
                    onClick={() => setFilter(opt.key)}
                    className="px-2 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider transition-all"
                    style={{
                      background: filter === opt.key ? `${opt.color}15` : "transparent",
                      color: filter === opt.key ? opt.color : "var(--text-muted)",
                      border: `1px solid ${filter === opt.key ? `${opt.color}30` : "transparent"}`,
                    }}
                  >
                    {opt.label}
                  </button>
                ))}
                {filter !== "all" && (
                  <button onClick={() => setFilter("all")} className="ml-auto p-0.5 rounded hover:bg-white/5">
                    <X className="w-2.5 h-2.5" style={{ color: "var(--text-muted)" }} />
                  </button>
                )}
              </div>

              <div className="overflow-y-auto max-h-72">
                {filtered.length === 0 ? (
                  <div className="p-8 text-center">
                    <Bell className="w-8 h-8 mx-auto mb-2" style={{ color: "var(--text-muted)", opacity: 0.3 }} />
                    <p className="text-xs" style={{ color: "var(--text-muted)" }}>
                      {notifications.length === 0 ? "No notifications yet" : "No matching notifications"}
                    </p>
                  </div>
                ) : (
                  filtered.slice(0, 30).map((n) => (
                    <button
                      key={n.id}
                      onClick={() => markRead(n.id)}
                      className="w-full text-left px-4 py-3 border-b transition-colors hover:bg-white/[0.02]"
                      style={{
                        borderColor: "rgba(0,229,255,0.04)",
                        opacity: n.read ? 0.5 : 1,
                      }}
                    >
                      <div className="flex items-start gap-2">
                        <div
                          className="w-1.5 h-1.5 rounded-full mt-1.5 shrink-0"
                          style={{
                            background: n.type === "error" ? "var(--accent-red)"
                              : n.type === "warning" ? "var(--accent-amber)"
                              : n.type === "success" ? "var(--accent-green)"
                              : "var(--accent-cyan)",
                          }}
                        />
                        <div className="flex-1 min-w-0">
                          <p className="text-[11px] font-bold" style={{ color: "var(--text-primary)" }}>
                            {n.title}
                          </p>
                          <p className="text-[10px] mt-0.5" style={{ color: "var(--text-muted)" }}>
                            {n.message}
                          </p>
                          <p className="text-[9px] mt-1 font-mono" style={{ color: "var(--text-muted)", opacity: 0.6 }}>
                            {new Date(n.timestamp).toLocaleTimeString("en-US", { hour12: false })}
                          </p>
                        </div>
                      </div>
                    </button>
                  ))
                )}
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </div>
  );
}
