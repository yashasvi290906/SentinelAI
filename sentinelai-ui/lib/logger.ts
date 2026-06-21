const isDev = process.env.NODE_ENV === 'development';

function sanitizeMetadata(metadata?: Record<string, unknown>): Record<string, unknown> | undefined {
  if (!metadata) return undefined;
  const sensitive = ['password', 'token', 'otp', 'api_key', 'apiKey', 'secret', 'email'];
  const sanitized: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(metadata)) {
    if (sensitive.some(s => key.toLowerCase().includes(s))) {
      sanitized[key] = '[REDACTED]';
    } else {
      sanitized[key] = value;
    }
  }
  return sanitized;
}

function formatTimestamp(): string {
  return new Date().toISOString();
}

export const logger = {
  info(message: string, metadata?: Record<string, unknown>) {
    const sanitized = sanitizeMetadata(metadata);
    if (isDev) {
      console.log(`\x1b[36m[INFO]\x1b[0m ${formatTimestamp()} ${message}`, sanitized ?? '');
    } else {
      console.log(`[INFO] ${message}`, sanitized ? JSON.stringify(sanitized) : '');
    }
  },

  warn(message: string, metadata?: Record<string, unknown>) {
    const sanitized = sanitizeMetadata(metadata);
    if (isDev) {
      console.warn(`\x1b[33m[WARN]\x1b[0m ${formatTimestamp()} ${message}`, sanitized ?? '');
    } else {
      console.warn(`[WARN] ${message}`, sanitized ? JSON.stringify(sanitized) : '');
    }
  },

  error(message: string, metadata?: Record<string, unknown>) {
    const sanitized = sanitizeMetadata(metadata);
    if (isDev) {
      console.error(`\x1b[31m[ERROR]\x1b[0m ${formatTimestamp()} ${message}`, sanitized ?? '');
    } else {
      console.error(`[ERROR] ${message}`, sanitized ? JSON.stringify(sanitized) : '');
    }
  },

  debug(message: string, metadata?: Record<string, unknown>) {
    if (!isDev) return;
    const sanitized = sanitizeMetadata(metadata);
    console.debug(`\x1b[90m[DEBUG]\x1b[0m ${formatTimestamp()} ${message}`, sanitized ?? '');
  },
};
