"use client";

import { Suspense, useState } from "react";
import { motion } from "framer-motion";
import { useRouter, useSearchParams } from "next/navigation";
import { Shield, Eye, EyeOff, Loader2 } from "lucide-react";
import { loginAPI } from "@/lib/api";

function LoginForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const redirect = searchParams.get("redirect") || "/";

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError("");

    try {
      const data = await loginAPI(email, password);

      if (data.error) {
        setError(data.error);
        setLoading(false);
        return;
      }

      if (data.access_token) {
        localStorage.setItem("sentinelai_access_token", data.access_token);
        localStorage.setItem("sentinelai_refresh_token", data.refresh_token);
        localStorage.setItem("sentinelai_user", JSON.stringify(data.user));
        router.push(redirect);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Unable to connect to server.";
      setError(msg.includes("timeout") ? "Connection timeout. Please try again." : msg.includes("401") ? "Invalid credentials." : "Unable to connect to server.");
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4" style={{ background: "linear-gradient(180deg, #050d18 0%, #0a1929 40%, #081420 100%)" }}>
      <div className="fixed inset-0 pointer-events-none" style={{
        backgroundImage: "linear-gradient(rgba(0,229,255,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(0,229,255,0.03) 1px, transparent 1px)",
        backgroundSize: "48px 48px",
        opacity: 0.5,
      }} />

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="w-full max-w-lg relative z-10"
      >
        <div className="rounded-2xl p-10" style={{
          background: "rgba(8,20,32,0.8)",
          backdropFilter: "blur(24px)",
          border: "1px solid rgba(0,229,255,0.1)",
        }}>
          <div className="flex items-center justify-center gap-3 mb-8">
            <div className="w-14 h-14 rounded-xl flex items-center justify-center" style={{
              background: "rgba(0,229,255,0.1)",
              border: "1px solid rgba(0,229,255,0.2)",
            }}>
              <Shield className="w-7 h-7" style={{ color: "var(--accent-cyan)" }} />
            </div>
            <div>
              <h1 className="text-2xl font-display font-bold" style={{ color: "var(--text-primary)" }}>
                SENTINEL<span style={{ color: "var(--accent-cyan)" }}>AI</span>
              </h1>
              <p className="text-[10px] font-mono tracking-[0.3em] uppercase" style={{ color: "var(--text-muted)" }}>
                Cyber Command
              </p>
            </div>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            {error && (
              <div className="rounded-xl px-4 py-3 text-xs font-mono" style={{
                background: "rgba(255,77,109,0.08)",
                border: "1px solid rgba(255,77,109,0.2)",
                color: "#ff4d6d",
              }}>
                {error}
              </div>
            )}

            <div>
              <label className="text-xs font-mono tracking-wider uppercase mb-2 block" style={{ color: "var(--text-muted)" }}>
                Email
              </label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                className="w-full px-5 py-3.5 rounded-xl text-base font-mono outline-none transition-colors"
                style={{
                  background: "rgba(0,229,255,0.04)",
                  border: "1px solid rgba(0,229,255,0.1)",
                  color: "var(--text-primary)",
                }}
                onFocus={(e) => (e.currentTarget.style.borderColor = "rgba(0,229,255,0.3)")}
                onBlur={(e) => (e.currentTarget.style.borderColor = "rgba(0,229,255,0.1)")}
                placeholder="analyst@sentinelai.com"
              />
            </div>

            <div>
              <label className="text-xs font-mono tracking-wider uppercase mb-2 block" style={{ color: "var(--text-muted)" }}>
                Password
              </label>
              <div className="relative">
                <input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  className="w-full px-5 py-3.5 pr-12 rounded-xl text-base font-mono outline-none transition-colors"
                  style={{
                    background: "rgba(0,229,255,0.04)",
                    border: "1px solid rgba(0,229,255,0.1)",
                    color: "var(--text-primary)",
                  }}
                  onFocus={(e) => (e.currentTarget.style.borderColor = "rgba(0,229,255,0.3)")}
                  onBlur={(e) => (e.currentTarget.style.borderColor = "rgba(0,229,255,0.1)")}
                  placeholder="••••••••"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2"
                >
                  {showPassword ? (
                    <EyeOff className="w-4 h-4" style={{ color: "var(--text-muted)" }} />
                  ) : (
                    <Eye className="w-4 h-4" style={{ color: "var(--text-muted)" }} />
                  )}
                </button>
              </div>
            </div>

            <div className="flex items-center justify-between">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={rememberMe}
                  onChange={(e) => setRememberMe(e.target.checked)}
                  className="w-4 h-4 rounded"
                  style={{ accentColor: "var(--accent-cyan)" }}
                />
                <span className="text-xs font-mono" style={{ color: "var(--text-muted)" }}>Remember me</span>
              </label>
              <a href="/forgot-password" className="text-xs font-mono" style={{ color: "var(--accent-cyan)" }}>
                Forgot password?
              </a>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-3.5 rounded-xl text-xs font-mono font-bold tracking-wider transition-all flex items-center justify-center gap-2"
              style={{
                background: loading ? "rgba(0,229,255,0.05)" : "rgba(0,229,255,0.12)",
                border: "1px solid rgba(0,229,255,0.25)",
                color: loading ? "var(--text-muted)" : "var(--accent-cyan)",
                cursor: loading ? "not-allowed" : "pointer",
              }}
            >
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
              {loading ? "Signing in..." : "Sign In"}
            </button>
          </form>

          <div className="mt-8 text-center">
            <span className="text-xs font-mono" style={{ color: "var(--text-muted)" }}>
              Don&apos;t have an account?{" "}
              <a href="/signup" className="font-bold" style={{ color: "var(--accent-cyan)" }}>
                Create Account
              </a>
            </span>
          </div>
        </div>
      </motion.div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen flex items-center justify-center" style={{ background: "linear-gradient(180deg, #050d18 0%, #0a1929 40%, #081420 100%)" }}>
        <Loader2 className="w-6 h-6 animate-spin" style={{ color: "var(--accent-cyan)" }} />
      </div>
    }>
      <LoginForm />
    </Suspense>
  );
}
