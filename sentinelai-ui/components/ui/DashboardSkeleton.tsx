'use client';
import { Skeleton } from './Skeleton';

export function DashboardSkeleton() {
  return (
    <div className="space-y-6">
      {/* Top row: 5 metric cards */}
      <div className="grid grid-cols-5 gap-4">
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="rounded-xl border border-white/10 p-4 bg-white/5">
            <Skeleton height={16} width="40%" />
            <Skeleton height={32} width="60%" className="mt-3" />
            <Skeleton height={12} width="30%" className="mt-2" />
          </div>
        ))}
      </div>
      {/* Middle: 2 large chart areas */}
      <div className="grid grid-cols-2 gap-4">
        <div className="rounded-xl border border-white/10 p-4 bg-white/5 h-64">
          <Skeleton height={16} width="30%" />
          <Skeleton height="100%" className="mt-4" />
        </div>
        <div className="rounded-xl border border-white/10 p-4 bg-white/5 h-64">
          <Skeleton height={16} width="30%" />
          <Skeleton height="100%" className="mt-4" />
        </div>
      </div>
      {/* Bottom: recent activity list */}
      <div className="rounded-xl border border-white/10 p-4 bg-white/5">
        <Skeleton height={16} width="25%" />
        <Skeleton count={4} height={40} className="mt-4" />
      </div>
    </div>
  );
}
