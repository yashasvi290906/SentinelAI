"use client";

import React from "react";
import { AlertTriangle, RefreshCw } from "lucide-react";

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

interface ErrorBoundaryProps {
  children: React.ReactNode;
  fallback?: React.ReactNode;
  moduleName?: string;
}

export class ErrorBoundary extends React.Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error(`[SentinelAI] Error in ${this.props.moduleName || "module"}:`, error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) return this.props.fallback;

      return (
        <div className="flex items-center justify-center h-full p-8">
          <div
            className="max-w-md w-full rounded-2xl p-8 text-center"
            style={{
              background: "rgba(8,20,32,0.7)",
              border: "1px solid rgba(255,77,109,0.2)",
            }}
          >
            <AlertTriangle className="w-12 h-12 mx-auto mb-4" style={{ color: "var(--accent-red)" }} />
            <p className="text-sm font-bold mb-2" style={{ color: "var(--text-primary)" }}>
              Module Error
            </p>
            <p className="text-xs mb-4" style={{ color: "var(--text-muted)" }}>
              {this.props.moduleName
                ? `The ${this.props.moduleName} module encountered an error.`
                : "A module encountered an unexpected error."}
            </p>
            <p className="text-[10px] font-mono mb-4 p-2 rounded" style={{ color: "var(--accent-red)", background: "rgba(255,77,109,0.05)" }}>
              {this.state.error?.message || "Unknown error"}
            </p>
            <button
              onClick={() => this.setState({ hasError: false, error: null })}
              className="flex items-center gap-2 mx-auto px-4 py-2 text-xs font-mono font-bold rounded-xl transition-all"
              style={{
                background: "rgba(0,229,255,0.1)",
                border: "1px solid rgba(0,229,255,0.2)",
                color: "var(--accent-cyan)",
              }}
            >
              <RefreshCw className="w-3.5 h-3.5" />
              Retry
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
