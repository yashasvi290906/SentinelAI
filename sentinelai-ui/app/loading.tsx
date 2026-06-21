'use client';
import { DashboardSkeleton } from '@/components/ui/DashboardSkeleton';

export default function Loading() {
  return (
    <div className="min-h-screen bg-[var(--bg-deep)] p-6">
      <DashboardSkeleton />
    </div>
  );
}
