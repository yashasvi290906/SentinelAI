"use client";

type LogLevel = "info" | "warn" | "error" | "debug";
type LogCategory = "prediction" | "report" | "auth" | "api" | "system" | "audio" | "security";

interface LogEntry {
  timestamp: string;
  level: LogLevel;
  category: LogCategory;
  message: string;
  metadata?: Record<string, unknown>;
}

interface LogFilter {
  level?: LogLevel;
  category?: LogCategory;
  limit?: number;
}

const MAX_LOGS = 500;
const STORAGE_KEY = "sentinelai_logs";

const LEVEL_COLORS: Record<LogLevel, string> = {
  info: "\x1b[36m",
  warn: "\x1b[33m",
  error: "\x1b[31m",
  debug: "\x1b[90m",
};

const RESET_COLOR = "\x1b[0m";

class Logger {
  private static instance: Logger;
  private logs: LogEntry[] = [];

  private constructor() {
    this.loadFromStorage();
  }

  static getInstance(): Logger {
    if (!Logger.instance) {
      Logger.instance = new Logger();
    }
    return Logger.instance;
  }

  info(category: LogCategory, message: string, metadata?: Record<string, unknown>): void {
    this.log("info", category, message, metadata);
  }

  warn(category: LogCategory, message: string, metadata?: Record<string, unknown>): void {
    this.log("warn", category, message, metadata);
  }

  error(category: LogCategory, message: string, metadata?: Record<string, unknown>): void {
    this.log("error", category, message, metadata);
  }

  debug(category: LogCategory, message: string, metadata?: Record<string, unknown>): void {
    this.log("debug", category, message, metadata);
  }

  getLogs(filter?: LogFilter): LogEntry[] {
    let filtered = [...this.logs];

    if (filter?.level) {
      filtered = filtered.filter((l) => l.level === filter.level);
    }

    if (filter?.category) {
      filtered = filtered.filter((l) => l.category === filter.category);
    }

    if (filter?.limit && filter.limit > 0) {
      filtered = filtered.slice(-filter.limit);
    }

    return filtered;
  }

  exportLogs(): string {
    return JSON.stringify(this.logs, null, 2);
  }

  clearLogs(): void {
    this.logs = [];
    this.saveToStorage();
  }

  getLogCount(): number {
    return this.logs.length;
  }

  private log(level: LogLevel, category: LogCategory, message: string, metadata?: Record<string, unknown>): void {
    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      category,
      message,
      metadata,
    };

    this.logs.push(entry);

    if (this.logs.length > MAX_LOGS) {
      this.logs = this.logs.slice(-MAX_LOGS);
    }

    this.saveToStorage();

    if (process.env.NODE_ENV === "development") {
      this.consoleLog(entry);
    }
  }

  private consoleLog(entry: LogEntry): void {
    const color = LEVEL_COLORS[entry.level];
    const prefix = `${color}[${entry.timestamp}] [${entry.level.toUpperCase()}] [${entry.category}]${RESET_COLOR}`;
    const msg = `${prefix} ${entry.message}`;

    switch (entry.level) {
      case "error":
        console.error(msg, entry.metadata ?? "");
        break;
      case "warn":
        console.warn(msg, entry.metadata ?? "");
        break;
      default:
        console.log(msg, entry.metadata ?? "");
    }
  }

  private saveToStorage(): void {
    try {
      if (typeof window !== "undefined" && window.localStorage) {
        window.localStorage.setItem(STORAGE_KEY, JSON.stringify(this.logs));
      }
    } catch {
      // localStorage may be full or unavailable
    }
  }

  private loadFromStorage(): void {
    try {
      if (typeof window !== "undefined" && window.localStorage) {
        const stored = window.localStorage.getItem(STORAGE_KEY);
        if (stored) {
          this.logs = JSON.parse(stored);
          if (this.logs.length > MAX_LOGS) {
            this.logs = this.logs.slice(-MAX_LOGS);
          }
        }
      }
    } catch {
      this.logs = [];
    }
  }
}

export const logger = Logger.getInstance();
