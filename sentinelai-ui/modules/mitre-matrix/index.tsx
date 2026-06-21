'use client';
import { useState, useEffect, useCallback } from 'react';
import { motion } from 'framer-motion';
import { Target, ExternalLink } from 'lucide-react';
import { getMitreAPI } from '@/lib/api';
import GlassCard from '@/components/ui/GlassCard';

const TACTICS = [
  { id: 'TA0043', name: 'Reconnaissance', color: '#00e5ff' },
  { id: 'TA0001', name: 'Initial Access', color: '#ff9500' },
  { id: 'TA0002', name: 'Execution', color: '#ff4d6d' },
  { id: 'TA0005', name: 'Persistence', color: '#ff6b35' },
  { id: 'TA0006', name: 'Credential Access', color: '#ffd93d' },
  { id: 'TA0008', name: 'Lateral Movement', color: '#c084fc' },
  { id: 'TA0010', name: 'Exfiltration', color: '#f43f5e' },
  { id: 'TA0040', name: 'Impact', color: '#ef4444' },
  { id: 'TA0011', name: 'Command and Control', color: '#8b5cf6' },
];

interface MitreEntry {
  technique_id: string;
  technique_name: string;
  tactic: string;
  detection_count: number;
}

export default function MitreMatrixModule() {
  const [coverage, setCoverage] = useState<MitreEntry[]>([]);
  const [loading, setLoading] = useState(false);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const data = await getMitreAPI();
      setCoverage(data.coverage || []);
    } catch (e) {
      console.error('Failed to fetch MITRE data');
    }
    setLoading(false);
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const getTechniquesForTactic = (tacticName: string) => {
    return coverage.filter(c => c.tactic === tacticName);
  };

  const maxCount = Math.max(...coverage.map(c => c.detection_count), 1);

  return (
    <div className="space-y-6">
      <GlassCard className="p-6">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h2 className="text-xl font-semibold text-white flex items-center gap-2">
              <Target className="w-5 h-5 text-cyan-400" />
              MITRE ATT&CK Matrix
            </h2>
            <p className="text-white/40 text-sm mt-1">
              Threat detection coverage mapped to the MITRE ATT&CK framework
            </p>
          </div>
          <button onClick={fetchData} className="text-sm text-cyan-400 hover:text-cyan-300">
            {loading ? 'Loading...' : 'Refresh'}
          </button>
        </div>

        {coverage.length === 0 ? (
          <div className="text-center py-12">
            <Target className="w-16 h-16 text-white/10 mx-auto mb-4" />
            <p className="text-white/40">No MITRE mappings available yet.</p>
            <p className="text-white/30 text-sm mt-1">Upload logs and detect threats to see MITRE coverage.</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-3">
            {TACTICS.map((tactic) => {
              const techniques = getTechniquesForTactic(tactic.name);
              return (
                <div key={tactic.id} className="space-y-2">
                  <div className="p-3 rounded-lg border" style={{ borderColor: `${tactic.color}30`, background: `${tactic.color}08` }}>
                    <p className="text-xs font-mono" style={{ color: tactic.color }}>{tactic.id}</p>
                    <p className="text-sm font-medium text-white mt-0.5">{tactic.name}</p>
                    <p className="text-xs text-white/40 mt-1">{techniques.length} technique{techniques.length !== 1 ? 's' : ''}</p>
                  </div>
                  
                  <div className="space-y-1 min-h-[60px]">
                    {techniques.map((tech, i) => (
                      <motion.div
                        key={tech.technique_id}
                        initial={{ opacity: 0, x: -10 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: i * 0.05 }}
                        className="p-2 rounded bg-white/[0.03] border border-white/5 hover:border-white/10 transition-colors"
                      >
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-mono text-white/60">{tech.technique_id}</span>
                          <span className="text-xs font-medium" style={{ color: tactic.color }}>
                            {tech.detection_count}
                          </span>
                        </div>
                        <p className="text-xs text-white/50 mt-0.5">{tech.technique_name}</p>
                      </motion.div>
                    ))}
                    
                    {techniques.length === 0 && (
                      <p className="text-xs text-white/20 text-center py-4">No detections</p>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </GlassCard>

      {/* Coverage Stats */}
      {coverage.length > 0 && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <GlassCard className="p-4 text-center">
            <p className="text-3xl font-bold text-cyan-400">{coverage.length}</p>
            <p className="text-xs text-white/40 mt-1">Unique Techniques</p>
          </GlassCard>
          <GlassCard className="p-4 text-center">
            <p className="text-3xl font-bold text-orange-400">
              {new Set(coverage.map(c => c.tactic)).size}
            </p>
            <p className="text-xs text-white/40 mt-1">Tactics Covered</p>
          </GlassCard>
          <GlassCard className="p-4 text-center">
            <p className="text-3xl font-bold text-emerald-400">
              {coverage.reduce((sum, c) => sum + c.detection_count, 0)}
            </p>
            <p className="text-xs text-white/40 mt-1">Total Detections</p>
          </GlassCard>
          <GlassCard className="p-4 text-center">
            <p className="text-3xl font-bold text-red-400">
              {coverage.filter(c => c.detection_count >= 3).length}
            </p>
            <p className="text-xs text-white/40 mt-1">High-Frequency</p>
          </GlassCard>
        </div>
      )}
    </div>
  );
}
