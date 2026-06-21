'use client';
import { motion } from 'framer-motion';

interface SkeletonProps {
  className?: string;
  count?: number;
  height?: number | string;
  width?: number | string;
  rounded?: boolean;
}

export function Skeleton({ className = '', count = 1, height = 20, width = '100%', rounded = false }: SkeletonProps) {
  return (
    <div className={`space-y-3 ${className}`}>
      {Array.from({ length: count }).map((_, i) => (
        <motion.div
          key={i}
          className={`bg-gradient-to-r from-white/5 via-white/10 to-white/5 ${rounded ? 'rounded-full' : 'rounded-lg'}`}
          style={{ height, width }}
          animate={{ opacity: [0.3, 0.6, 0.3] }}
          transition={{ duration: 1.5, repeat: Infinity, ease: 'easeInOut', delay: i * 0.1 }}
        />
      ))}
    </div>
  );
}
