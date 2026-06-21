'use client';
import { useEffect, useState, useRef } from 'react';

export function useAnimatedCounter(target: number, duration = 1200) {
  const [value, setValue] = useState(0);
  const prevTargetRef = useRef(0);
  const rafRef = useRef<number | null>(null);

  useEffect(() => {
    const start = prevTargetRef.current;
    const diff = target - start;
    if (diff === 0) return;
    
    const startTime = performance.now();
    
    const animate = (now: number) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3); // easeOutCubic
      setValue(Math.round(start + diff * eased));
      
      if (progress < 1) {
        rafRef.current = requestAnimationFrame(animate);
      } else {
        prevTargetRef.current = target;
      }
    };
    
    rafRef.current = requestAnimationFrame(animate);
    return () => { if (rafRef.current) cancelAnimationFrame(rafRef.current); };
  }, [target, duration]);

  return value;
}
