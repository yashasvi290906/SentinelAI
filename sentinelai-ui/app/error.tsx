'use client';
import { motion } from 'framer-motion';

export default function Error({ error: _error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <div className="min-h-screen bg-[var(--bg-deep)] flex items-center justify-center">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="text-center max-w-md"
      >
        <h1 className="text-6xl font-bold text-red-400/20">500</h1>
        <h2 className="text-2xl font-semibold text-white mt-4">System Error</h2>
        <p className="text-white/50 mt-2">An unexpected error occurred. Our team has been notified.</p>
        <button
          onClick={reset}
          className="mt-8 px-6 py-3 bg-cyan-500/20 border border-cyan-400/30 rounded-lg text-cyan-400 hover:bg-cyan-500/30 transition-colors"
        >
          Try Again
        </button>
      </motion.div>
    </div>
  );
}
