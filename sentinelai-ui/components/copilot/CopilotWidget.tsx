"use client";

import { useState, useRef, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { MessageCircle, X, Send, Bot, User, Sparkles, Shield, AlertTriangle } from "lucide-react";
import { copilotAPI, type CopilotResponse } from "@/lib/api";
import { usePredictionStore } from "@/stores/predictionStore";
import { ATTACK_COLORS } from "@/lib/config";

interface Message {
  id: string;
  role: "user" | "assistant";
  content: string;
  data?: CopilotResponse;
  timestamp: string;
}

export default function CopilotWidget() {
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState<Message[]>([
    {
      id: "welcome",
      role: "assistant",
      content: "I'm SentinelAI Copilot. I can explain predictions, recommend actions, and help you understand attack patterns. Try asking:\n\n• \"Why was this predicted as DDoS?\"\n• \"What should I do next?\"\n• \"Show me recent patterns.\"",
      timestamp: new Date().toISOString(),
    },
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const lastPrediction = usePredictionStore((s) => s.lastPrediction);

  const scrollToBottom = useCallback(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, []);

  useEffect(() => {
    scrollToBottom();
  }, [messages, scrollToBottom]);

  const sendMessage = async () => {
    if (!input.trim() || loading) return;

    const userMsg: Message = {
      id: `user-${Date.now()}`,
      role: "user",
      content: input.trim(),
      timestamp: new Date().toISOString(),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInput("");
    setLoading(true);

    try {
      const sequence = lastPrediction?.sequence?.map((a) => {
        const map: Record<string, number> = { DDoS: 0, DoS: 1, PortScan: 2, Bot: 3, WebAttack: 4, BruteForce: 5, Infiltration: 6 };
        return map[a] ?? 0;
      }) ?? [2, 2, 3];

      const prediction = lastPrediction?.predictedAttack || "DDoS";
      const response = await copilotAPI(sequence, prediction, input.trim());

      const assistantMsg: Message = {
        id: `assistant-${Date.now()}`,
        role: "assistant",
        content: response.explanation,
        data: response,
        timestamp: new Date().toISOString(),
      };

      setMessages((prev) => [...prev, assistantMsg]);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "";
      const content = msg.includes("401")
        ? "Authentication required. Please log in first."
        : msg.includes("500")
        ? "Copilot encountered an error. Please try again."
        : "I couldn't reach the backend. Make sure the SentinelAI server is running on port 8000.";
      setMessages((prev) => [
        ...prev,
        {
          id: `error-${Date.now()}`,
          role: "assistant",
          content,
          timestamp: new Date().toISOString(),
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      {/* Floating button */}
      <motion.button
        onClick={() => setIsOpen(!isOpen)}
        className="fixed bottom-6 right-6 z-50 w-14 h-14 rounded-full flex items-center justify-center shadow-lg focus:outline-none focus:ring-2 focus:ring-cyan-400/50 focus:ring-offset-2 focus:ring-offset-transparent"
        aria-label="AI Copilot"
        style={{
          background: "linear-gradient(135deg, var(--accent-cyan), #00B8D4)",
          boxShadow: "0 0 30px rgba(0,229,255,0.3)",
        }}
        whileHover={{ scale: 1.1 }}
        whileTap={{ scale: 0.95 }}
      >
        {isOpen ? (
          <X className="w-6 h-6" style={{ color: "var(--bg-deep)" }} />
        ) : (
          <MessageCircle className="w-6 h-6" style={{ color: "var(--bg-deep)" }} />
        )}
      </motion.button>

      {/* Chat panel */}
      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ opacity: 0, y: 20, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 20, scale: 0.95 }}
            transition={{ duration: 0.3, ease: [0.22, 1, 0.36, 1] }}
            className="fixed bottom-24 right-6 z-50 w-[420px] h-[560px] rounded-2xl overflow-hidden flex flex-col"
            role="dialog"
            aria-label="AI Copilot"
            style={{
              background: "rgba(8,20,32,0.95)",
              backdropFilter: "blur(24px)",
              border: "1px solid rgba(0,229,255,0.15)",
              boxShadow: "0 0 60px rgba(0,229,255,0.1), 0 20px 60px rgba(0,0,0,0.5)",
            }}
          >
            {/* Header */}
            <div
              className="flex items-center gap-3 px-5 py-4 border-b"
              style={{ borderColor: "rgba(0,229,255,0.1)" }}
            >
              <div
                className="w-9 h-9 rounded-xl flex items-center justify-center"
                style={{
                  background: "rgba(0,229,255,0.1)",
                  border: "1px solid rgba(0,229,255,0.2)",
                }}
              >
                <Bot className="w-5 h-5" style={{ color: "var(--accent-cyan)" }} />
              </div>
              <div>
                <p className="text-sm font-bold" style={{ color: "var(--text-primary)" }}>
                  SentinelAI Copilot
                </p>
                <p className="text-[10px] font-mono" style={{ color: "var(--accent-green)" }}>
                  Online — SOC Analyst Assistant
                </p>
              </div>
              <Sparkles className="w-4 h-4 ml-auto" style={{ color: "var(--accent-amber)" }} />
            </div>

            {/* Messages */}
            <div className="flex-1 overflow-y-auto p-4 space-y-4">
              {messages.map((msg) => (
                <motion.div
                  key={msg.id}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  className={`flex gap-3 ${msg.role === "user" ? "justify-end" : ""}`}
                >
                  {msg.role === "assistant" && (
                    <div
                      className="w-7 h-7 rounded-lg flex items-center justify-center shrink-0 mt-0.5"
                      style={{
                        background: "rgba(0,229,255,0.1)",
                        border: "1px solid rgba(0,229,255,0.2)",
                      }}
                    >
                      <Bot className="w-3.5 h-3.5" style={{ color: "var(--accent-cyan)" }} />
                    </div>
                  )}
                  <div
                    className={`max-w-[85%] rounded-xl px-4 py-3 ${
                      msg.role === "user" ? "rounded-br-sm" : "rounded-bl-sm"
                    }`}
                    style={{
                      background: msg.role === "user"
                        ? "rgba(0,229,255,0.12)"
                        : "rgba(255,255,255,0.03)",
                      border: `1px solid ${msg.role === "user" ? "rgba(0,229,255,0.2)" : "rgba(0,229,255,0.06)"}`,
                    }}
                  >
                    <p
                      className="text-xs leading-relaxed whitespace-pre-line"
                      style={{ color: "var(--text-secondary)" }}
                    >
                      {msg.content}
                    </p>

                    {/* Recommendation cards */}
                    {msg.data?.recommendations && msg.data.recommendations.length > 0 && (
                      <div className="mt-3 space-y-1.5">
                        <p className="text-[10px] font-mono font-bold" style={{ color: "var(--accent-cyan)" }}>
                          RECOMMENDATIONS
                        </p>
                        {msg.data.recommendations.slice(0, 5).map((rec, i) => (
                          <div
                            key={i}
                            className="flex items-start gap-2 text-[11px] font-mono p-2 rounded-lg"
                            style={{
                              background: "rgba(0,229,255,0.03)",
                              border: "1px solid rgba(0,229,255,0.06)",
                            }}
                          >
                            <span style={{ color: "var(--accent-cyan)" }}>{i + 1}.</span>
                            <span style={{ color: "var(--text-secondary)" }}>{rec}</span>
                          </div>
                        ))}
                      </div>
                    )}

                    {/* Indicators */}
                    {msg.data?.indicators && msg.data.indicators.length > 0 && (
                      <div className="mt-3">
                        <p className="text-[10px] font-mono font-bold mb-1.5" style={{ color: "var(--accent-amber)" }}>
                          INDICATORS
                        </p>
                        {msg.data.indicators.map((ind, i) => (
                          <div key={i} className="flex items-start gap-2 text-[11px] font-mono mb-1">
                            <AlertTriangle className="w-3 h-3 mt-0.5 shrink-0" style={{ color: "var(--accent-amber)" }} />
                            <span style={{ color: "var(--text-muted)" }}>{ind}</span>
                          </div>
                        ))}
                      </div>
                    )}

                    {/* Confidence badge */}
                    {msg.data?.confidence !== undefined && (
                      <div className="mt-2 flex items-center gap-2">
                        <Shield className="w-3 h-3" style={{ color: "var(--accent-green)" }} />
                        <span className="text-[10px] font-mono" style={{ color: "var(--text-muted)" }}>
                          Confidence: {(msg.data.confidence * 100).toFixed(1)}%
                        </span>
                        {msg.data.prediction && (
                          <span
                            className="text-[10px] font-mono font-bold px-2 py-0.5 rounded"
                            style={{
                              background: `${ATTACK_COLORS[msg.data.prediction] || "var(--accent-cyan)"}15`,
                              color: ATTACK_COLORS[msg.data.prediction] || "var(--accent-cyan)",
                            }}
                          >
                            {msg.data.prediction}
                          </span>
                        )}
                      </div>
                    )}
                  </div>
                  {msg.role === "user" && (
                    <div
                      className="w-7 h-7 rounded-lg flex items-center justify-center shrink-0 mt-0.5"
                      style={{
                        background: "rgba(124,77,255,0.1)",
                        border: "1px solid rgba(124,77,255,0.2)",
                      }}
                    >
                      <User className="w-3.5 h-3.5" style={{ color: "var(--accent-purple)" }} />
                    </div>
                  )}
                </motion.div>
              ))}

              {loading && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="flex gap-3"
                >
                  <div
                    className="w-7 h-7 rounded-lg flex items-center justify-center shrink-0"
                    style={{
                      background: "rgba(0,229,255,0.1)",
                      border: "1px solid rgba(0,229,255,0.2)",
                    }}
                  >
                    <Bot className="w-3.5 h-3.5" style={{ color: "var(--accent-cyan)" }} />
                  </div>
                  <div
                    className="rounded-xl px-4 py-3 rounded-bl-sm"
                    style={{
                      background: "rgba(255,255,255,0.03)",
                      border: "1px solid rgba(0,229,255,0.06)",
                    }}
                  >
                    <div className="flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 rounded-full animate-bounce" style={{ background: "var(--accent-cyan)", animationDelay: "0ms" }} />
                      <span className="w-1.5 h-1.5 rounded-full animate-bounce" style={{ background: "var(--accent-cyan)", animationDelay: "150ms" }} />
                      <span className="w-1.5 h-1.5 rounded-full animate-bounce" style={{ background: "var(--accent-cyan)", animationDelay: "300ms" }} />
                    </div>
                  </div>
                </motion.div>
              )}
              <div ref={messagesEndRef} />
            </div>

            {/* Input */}
            <div
              className="px-4 py-3 border-t"
              style={{ borderColor: "rgba(0,229,255,0.1)" }}
            >
              <div className="flex items-center gap-2">
                <input
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && sendMessage()}
                  placeholder="Ask about attacks, predictions, or actions..."
                  aria-label="Message input"
                  className="flex-1 px-4 py-2.5 rounded-xl text-xs font-mono outline-none focus:ring-2 focus:ring-cyan-400/50 focus:ring-offset-2 focus:ring-offset-transparent"
                  style={{
                    background: "rgba(0,229,255,0.03)",
                    border: "1px solid rgba(0,229,255,0.1)",
                    color: "var(--text-primary)",
                  }}
                />
                <button
                  onClick={sendMessage}
                  disabled={!input.trim() || loading}
                  className="w-9 h-9 rounded-xl flex items-center justify-center transition-all disabled:opacity-30"
                  style={{
                    background: "rgba(0,229,255,0.1)",
                    border: "1px solid rgba(0,229,255,0.2)",
                  }}
                >
                  <Send className="w-4 h-4" style={{ color: "var(--accent-cyan)" }} />
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}
