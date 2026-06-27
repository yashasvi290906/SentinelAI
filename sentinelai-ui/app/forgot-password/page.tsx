"use client";

import { Suspense, useState, useEffect } from "react";
import { motion } from "framer-motion";
import { useRouter, useSearchParams } from "next/navigation";
import { Shield, Eye, EyeOff, Loader2, Mail, KeyRound, Lock, CheckCircle2 } from "lucide-react";
import { generateOtpAPI, verifyOtpAPI, resetPasswordAPI } from "@/lib/api";

type Step = "email" | "otp" | "new-password";

function ForgotPasswordForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const flowParam = searchParams.get("flow");

  const [step, setStep] = useState<Step>(flowParam === "verify-otp" ? "otp" : "email");
  const [email, setEmail] = useState(() => typeof window !== 'undefined' ? sessionStorage.getItem("sentinelai_signup_email") || "" : "");
  const [otp, setOtp] = useState(["", "", "", "", "", ""]);
  const [verifiedOtp, setVerifiedOtp] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [resendTimer, setResendTimer] = useState(0);

  useEffect(() => {
    if (resendTimer > 0) {
      const t = setTimeout(() => setResendTimer(resendTimer - 1), 1000);
      return () => clearTimeout(t);
    }
  }, [resendTimer]);

  const handleSendOTP = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError("");

    try {
      const data = await generateOtpAPI(email);

      if (data.error) {
        setError(data.error);
        setLoading(false);
        return;
      }

      setSuccess("OTP sent to your email address.");
      setStep("otp");
      setResendTimer(60);
      setLoading(false);
    } catch (err) {
      const message = err instanceof Error ? err.message : "Unable to connect to server.";
      setError(message);
      setLoading(false);
    }
  };

  const handleVerifyOTP = async (e: React.FormEvent) => {
    e.preventDefault();
    const otpCode = otp.join("");
    if (otpCode.length !== 6) {
      setError("Please enter the complete 6-digit OTP.");
      return;
    }

    setLoading(true);
    setError("");

    try {
      const data = await verifyOtpAPI(email, otpCode);

      if (data.error) {
        setError(data.error);
        setLoading(false);
        return;
      }

      setVerifiedOtp(otpCode);
      setStep("new-password");
      setLoading(false);
    } catch (err) {
      const message = err instanceof Error ? err.message : "Unable to connect to server.";
      setError(message);
      setLoading(false);
    }
  };

  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault();

    if (newPassword.length < 8) {
      setError("Password must be at least 8 characters.");
      return;
    }
    if (newPassword !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    setLoading(true);
    setError("");

    try {
      const data = await resetPasswordAPI(email, verifiedOtp, newPassword);

      if (data.error) {
        setError(data.error);
        setLoading(false);
        return;
      }

      sessionStorage.removeItem("sentinelai_signup_email");
      setSuccess("Password reset successfully. Redirecting to login...");
      setTimeout(() => router.push("/login"), 2000);
    } catch (err) {
      const message = err instanceof Error ? err.message : "Unable to connect to server.";
      setError(message);
      setLoading(false);
    }
  };

  const handleOtpChange = (index: number, value: string) => {
    if (value.length > 1) return;
    const newOtp = [...otp];
    newOtp[index] = value;
    setOtp(newOtp);

    if (value && index < 5) {
      const next = document.querySelector(`input[name="otp-${index + 1}"]`) as HTMLInputElement;
      next?.focus();
    }
  };

  const handleOtpKeyDown = (index: number, e: React.KeyboardEvent) => {
    if (e.key === "Backspace" && !otp[index] && index > 0) {
      const prev = document.querySelector(`input[name="otp-${index - 1}"]`) as HTMLInputElement;
      prev?.focus();
    }
  };

  const handleResend = async () => {
    if (resendTimer > 0) return;
    setLoading(true);
    setError("");

    try {
      await generateOtpAPI(email);
      setSuccess("OTP resent to your email address.");
      setResendTimer(60);
      setLoading(false);
    } catch {
      setLoading(false);
    }
  };

  const inputStyle = {
    background: "rgba(0,229,255,0.04)",
    border: "1px solid rgba(0,229,255,0.1)",
    color: "var(--text-primary)",
  };

  const stepIcons: Record<Step, React.ReactNode> = {
    email: <Mail className="w-5 h-5" style={{ color: "var(--accent-cyan)" }} />,
    otp: <KeyRound className="w-5 h-5" style={{ color: "var(--accent-cyan)" }} />,
    "new-password": <Lock className="w-5 h-5" style={{ color: "var(--accent-cyan)" }} />,
  };

  const stepLabels: Record<Step, string> = {
    email: "Reset Password",
    otp: "Verify OTP",
    "new-password": "New Password",
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
        className="w-full max-w-md relative z-10"
      >
        <div className="rounded-2xl p-8" style={{
          background: "rgba(8,20,32,0.8)",
          backdropFilter: "blur(24px)",
          border: "1px solid rgba(0,229,255,0.1)",
        }}>
          <div className="flex items-center justify-center gap-3 mb-8">
            <div className="w-12 h-12 rounded-xl flex items-center justify-center" style={{
              background: "rgba(0,229,255,0.1)",
              border: "1px solid rgba(0,229,255,0.2)",
            }}>
              <Shield className="w-6 h-6" style={{ color: "var(--accent-cyan)" }} />
            </div>
            <div>
              <h1 className="text-xl font-display font-bold" style={{ color: "var(--text-primary)" }}>
                SENTINEL<span style={{ color: "var(--accent-cyan)" }}>AI</span>
              </h1>
              <p className="text-[9px] font-mono tracking-[0.3em] uppercase" style={{ color: "var(--text-muted)" }}>
                Cyber Command
              </p>
            </div>
          </div>

          <div className="flex items-center justify-center gap-2 mb-6">
            {stepIcons[step]}
            <span className="text-sm font-mono font-bold" style={{ color: "var(--text-primary)" }}>
              {stepLabels[step]}
            </span>
          </div>

          {/* Step indicator */}
          <div className="flex items-center justify-center gap-2 mb-6">
            {(["email", "otp", "new-password"] as Step[]).map((s, i) => (
              <div key={s} className="flex items-center gap-2">
                <div
                  className="w-6 h-6 rounded-full flex items-center justify-center text-[9px] font-mono font-bold"
                  style={{
                    background: step === s ? "rgba(0,229,255,0.15)" : "rgba(0,229,255,0.05)",
                    border: `1px solid ${step === s ? "rgba(0,229,255,0.3)" : "rgba(0,229,255,0.1)"}`,
                    color: step === s ? "var(--accent-cyan)" : "var(--text-muted)",
                  }}
                >
                  {i + 1}
                </div>
                {i < 2 && (
                  <div className="w-8 h-px" style={{
                    background: (["email", "otp", "new-password"].indexOf(step) > i)
                      ? "rgba(0,229,255,0.3)"
                      : "rgba(0,229,255,0.08)",
                  }} />
                )}
              </div>
            ))}
          </div>

          {error && (
            <div className="rounded-xl px-4 py-3 text-[11px] font-mono mb-4" style={{
              background: "rgba(255,77,109,0.08)",
              border: "1px solid rgba(255,77,109,0.2)",
              color: "#ff4d6d",
            }}>
              {error}
            </div>
          )}

          {success && (
            <div className="rounded-xl px-4 py-3 text-[11px] font-mono mb-4" style={{
              background: "rgba(0,255,136,0.08)",
              border: "1px solid rgba(0,255,136,0.2)",
              color: "var(--accent-green)",
            }}>
              {success}
            </div>
          )}

          {/* Step 1: Email */}
          {step === "email" && (
            <form onSubmit={handleSendOTP} className="space-y-4">
              <p className="text-[10px] font-mono text-center" style={{ color: "var(--text-muted)" }}>
                Enter your registered email address and we&apos;ll send you a verification code.
              </p>
              <div>
                <label className="text-[10px] font-mono tracking-wider uppercase mb-1.5 block" style={{ color: "var(--text-muted)" }}>
                  Email
                </label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  className="w-full px-4 py-3 rounded-xl text-sm font-mono outline-none transition-colors"
                  style={inputStyle}
                  onFocus={(e) => (e.currentTarget.style.borderColor = "rgba(0,229,255,0.3)")}
                  onBlur={(e) => (e.currentTarget.style.borderColor = "rgba(0,229,255,0.1)")}
                  placeholder="analyst@sentinelai.com"
                />
              </div>
              <button
                type="submit"
                disabled={loading}
                className="w-full py-3 rounded-xl text-[11px] font-mono font-bold tracking-wider transition-all flex items-center justify-center gap-2"
                style={{
                  background: loading ? "rgba(0,229,255,0.05)" : "rgba(0,229,255,0.12)",
                  border: "1px solid rgba(0,229,255,0.25)",
                  color: loading ? "var(--text-muted)" : "var(--accent-cyan)",
                  cursor: loading ? "not-allowed" : "pointer",
                }}
              >
                {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
                {loading ? "Sending..." : "Send OTP"}
              </button>
            </form>
          )}

          {/* Step 2: OTP */}
          {step === "otp" && (
            <form onSubmit={handleVerifyOTP} className="space-y-4">
              <p className="text-[10px] font-mono text-center" style={{ color: "var(--text-muted)" }}>
                Enter the 6-digit code sent to <span style={{ color: "var(--accent-cyan)" }}>{email}</span>
              </p>
              <div className="flex justify-center gap-2">
                {otp.map((digit, i) => (
                  <input
                    key={i}
                    name={`otp-${i}`}
                    type="text"
                    inputMode="numeric"
                    maxLength={1}
                    value={digit}
                    onChange={(e) => handleOtpChange(i, e.target.value)}
                    onKeyDown={(e) => handleOtpKeyDown(i, e)}
                    className="w-10 h-12 rounded-lg text-center text-lg font-mono font-bold outline-none transition-colors"
                    style={inputStyle}
                    onFocus={(e) => (e.currentTarget.style.borderColor = "rgba(0,229,255,0.3)")}
                    onBlur={(e) => (e.currentTarget.style.borderColor = "rgba(0,229,255,0.1)")}
                  />
                ))}
              </div>
              <div className="text-center">
                <button
                  type="button"
                  onClick={handleResend}
                  disabled={resendTimer > 0}
                  className="text-[10px] font-mono"
                  style={{
                    color: resendTimer > 0 ? "var(--text-muted)" : "var(--accent-cyan)",
                    cursor: resendTimer > 0 ? "not-allowed" : "pointer",
                  }}
                >
                  {resendTimer > 0 ? `Resend in ${resendTimer}s` : "Resend OTP"}
                </button>
              </div>
              <button
                type="submit"
                disabled={loading}
                className="w-full py-3 rounded-xl text-[11px] font-mono font-bold tracking-wider transition-all flex items-center justify-center gap-2"
                style={{
                  background: loading ? "rgba(0,229,255,0.05)" : "rgba(0,229,255,0.12)",
                  border: "1px solid rgba(0,229,255,0.25)",
                  color: loading ? "var(--text-muted)" : "var(--accent-cyan)",
                  cursor: loading ? "not-allowed" : "pointer",
                }}
              >
                {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
                {loading ? "Verifying..." : "Verify OTP"}
              </button>
            </form>
          )}

          {/* Step 3: New Password */}
          {step === "new-password" && (
            <form onSubmit={handleResetPassword} className="space-y-4">
              <p className="text-[10px] font-mono text-center" style={{ color: "var(--text-muted)" }}>
                Create a new password for your account.
              </p>
              <div>
                <label className="text-[10px] font-mono tracking-wider uppercase mb-1.5 block" style={{ color: "var(--text-muted)" }}>
                  New Password
                </label>
                <div className="relative">
                  <input
                    type={showPassword ? "text" : "password"}
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    required
                    className="w-full px-4 py-3 pr-12 rounded-xl text-sm font-mono outline-none transition-colors"
                    style={inputStyle}
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
                {newPassword.length > 0 && (
                  <div className="mt-2 grid grid-cols-2 gap-1">
                    {[
                      { label: "At least 8 characters", valid: newPassword.length >= 8 },
                      { label: "Contains uppercase", valid: /[A-Z]/.test(newPassword) },
                      { label: "Contains lowercase", valid: /[a-z]/.test(newPassword) },
                      { label: "Contains a number", valid: /\d/.test(newPassword) },
                    ].map((check) => (
                      <div key={check.label} className="flex items-center gap-1.5">
                        <CheckCircle2
                          className="w-3 h-3"
                          style={{ color: check.valid ? "var(--accent-green)" : "var(--text-muted)" }}
                        />
                        <span className="text-[9px] font-mono" style={{ color: check.valid ? "var(--accent-green)" : "var(--text-muted)" }}>
                          {check.label}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
              <div>
                <label className="text-[10px] font-mono tracking-wider uppercase mb-1.5 block" style={{ color: "var(--text-muted)" }}>
                  Confirm Password
                </label>
                <div className="relative">
                  <input
                    type={showPassword ? "text" : "password"}
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    required
                    className="w-full px-4 py-3 pr-12 rounded-xl text-sm font-mono outline-none transition-colors"
                    style={{
                      ...inputStyle,
                      borderColor: confirmPassword
                        ? (newPassword === confirmPassword ? "rgba(0,255,136,0.3)" : "rgba(255,77,109,0.3)")
                        : undefined,
                    }}
                    onFocus={(e) => (e.currentTarget.style.borderColor = "rgba(0,229,255,0.3)")}
                    onBlur={(e) => {
                      if (confirmPassword) {
                        e.currentTarget.style.borderColor = newPassword === confirmPassword ? "rgba(0,255,136,0.3)" : "rgba(255,77,109,0.3)";
                      } else {
                        e.currentTarget.style.borderColor = "rgba(0,229,255,0.1)";
                      }
                    }}
                    placeholder="••••••••"
                  />
                </div>
              </div>
              <button
                type="submit"
                disabled={loading}
                className="w-full py-3 rounded-xl text-[11px] font-mono font-bold tracking-wider transition-all flex items-center justify-center gap-2"
                style={{
                  background: loading ? "rgba(0,229,255,0.05)" : "rgba(0,229,255,0.12)",
                  border: "1px solid rgba(0,229,255,0.25)",
                  color: loading ? "var(--text-muted)" : "var(--accent-cyan)",
                  cursor: loading ? "not-allowed" : "pointer",
                }}
              >
                {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
                {loading ? "Resetting..." : "Reset Password"}
              </button>
            </form>
          )}

          <div className="mt-6 text-center">
            <a href="/login" className="text-[10px] font-mono" style={{ color: "var(--accent-cyan)" }}>
              Back to Sign In
            </a>
          </div>
        </div>
      </motion.div>
    </div>
  );
}

export default function ForgotPasswordPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen flex items-center justify-center" style={{ background: "linear-gradient(180deg, #050d18 0%, #0a1929 40%, #081420 100%)" }}>
        <Loader2 className="w-6 h-6 animate-spin" style={{ color: "var(--accent-cyan)" }} />
      </div>
    }>
      <ForgotPasswordForm />
    </Suspense>
  );
}
