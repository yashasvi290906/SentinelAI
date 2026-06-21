'use client';
import { useAnimatedCounter } from '@/hooks/useAnimatedCounter';
import { motion } from 'framer-motion';

interface AnimatedCounterProps {
  value: number;
  prefix?: string;
  suffix?: string;
  className?: string;
}

export function AnimatedCounter({ value, prefix = '', suffix = '', className }: AnimatedCounterProps) {
  const animated = useAnimatedCounter(value);
  return (
    <motion.span className={className} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
      {prefix}{animated.toLocaleString()}{suffix}
    </motion.span>
  );
}
