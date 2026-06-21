'use client';
import { motion } from 'framer-motion';
import Link from 'next/link';

export default function NotFound() {
  return (
    <div className="min-h-screen bg-[var(--bg-deep)] flex items-center justify-center">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="text-center"
      >
        <h1 className="text-8xl font-bold text-cyan-400/20">404</h1>
        <h2 className="text-2xl font-semibold text-white mt-4">Page Not Found</h2>
        <p className="text-white/50 mt-2">The requested resource does not exist.</p>
        <Link
          href="/"
          className="mt-8 inline-block px-6 py-3 bg-cyan-500/20 border border-cyan-400/30 rounded-lg text-cyan-400 hover:bg-cyan-500/30 transition-colors"
        >
          Return to Dashboard
        </Link>
      </motion.div>
    </div>
  );
}
