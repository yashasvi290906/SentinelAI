'use client';
import { useState, useEffect, useCallback } from 'react';
import { motion } from 'framer-motion';
import { Server, Shield, AlertTriangle, Wifi, WifiOff, Clock, Activity } from 'lucide-react';
import GlassCard from '@/components/ui/GlassCard';
import { fetchWithAuth } from "@/lib/api";

interface Device {
  id: string;
  hostname: string;
  ip_address: string;
  os_type: string;
  status: string;
  risk_score: number;
  last_seen: string;
  created_at: string;
}

export default function DevicesModule() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(false);

  const fetchDevices = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetchWithAuth('/api/devices');
      const data = await res.json();
      setDevices(data.devices || []);
    } catch (e) {
      console.error('Failed to fetch devices');
    }
    setLoading(false);
  }, []);

  useEffect(() => { fetchDevices(); }, [fetchDevices]);

  const getRiskColor = (score: number) => {
    if (score >= 0.8) return 'text-red-400';
    if (score >= 0.5) return 'text-orange-400';
    if (score >= 0.3) return 'text-yellow-400';
    return 'text-emerald-400';
  };

  const getOsIcon = (os: string) => {
    if (os.toLowerCase().includes('windows')) return '🪟';
    if (os.toLowerCase().includes('linux')) return '🐧';
    if (os.toLowerCase().includes('mac')) return '🍎';
    return '💻';
  };

  return (
    <div className="space-y-6">
      <GlassCard className="p-6">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h2 className="text-xl font-semibold text-white flex items-center gap-2">
              <Server className="w-5 h-5 text-cyan-400" />
              Device Management
            </h2>
            <p className="text-white/40 text-sm mt-1">
              Monitor all devices sending security events to SentinelAI
            </p>
          </div>
          <button onClick={fetchDevices} className="text-sm text-cyan-400 hover:text-cyan-300">
            {loading ? 'Loading...' : 'Refresh'}
          </button>
        </div>

        {devices.length === 0 ? (
          <div className="text-center py-16">
            <Server className="w-20 h-20 text-white/10 mx-auto mb-4" />
            <p className="text-white/40 text-lg">No devices registered yet</p>
            <p className="text-white/30 text-sm mt-2">
              Install the Sentinel Agent on your servers to start sending events
            </p>
            <div className="mt-6 p-4 rounded-lg bg-white/[0.03] border border-white/5 max-w-md mx-auto text-left">
              <p className="text-cyan-400 text-xs font-mono mb-2">Quick Start:</p>
              <code className="text-white/60 text-xs block">
                pip install sentinel-agent<br/>
                sentinel-agent register --server http://your-sentinelai:8000<br/>
                sentinel-agent start
              </code>
            </div>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {devices.map((device, i) => (
              <motion.div
                key={device.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.05 }}
              >
                <GlassCard className="p-5 hover:border-white/10 transition-colors">
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <span className="text-2xl">{getOsIcon(device.os_type)}</span>
                      <div>
                        <p className="text-white font-medium">{device.hostname}</p>
                        <p className="text-white/40 text-xs font-mono">{device.ip_address}</p>
                      </div>
                    </div>
                    <span className={`flex items-center gap-1 px-2 py-0.5 rounded text-xs ${
                      device.status === 'active' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-white/5 text-white/40'
                    }`}>
                      {device.status === 'active' ? <Wifi className="w-3 h-3" /> : <WifiOff className="w-3 h-3" />}
                      {device.status}
                    </span>
                  </div>
                  
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-white/40">OS</span>
                      <span className="text-white/70 capitalize">{device.os_type}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-white/40">Risk Score</span>
                      <span className={`font-bold ${getRiskColor(device.risk_score)}`}>
                        {(device.risk_score * 100).toFixed(0)}%
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-white/40">Last Seen</span>
                      <span className="text-white/50 text-xs">
                        {device.last_seen ? new Date(device.last_seen).toLocaleString() : 'Never'}
                      </span>
                    </div>
                  </div>
                  
                  {/* Risk bar */}
                  <div className="mt-3 h-1.5 bg-white/5 rounded-full overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${device.risk_score * 100}%` }}
                      className={`h-full rounded-full ${
                        device.risk_score >= 0.8 ? 'bg-red-500' :
                        device.risk_score >= 0.5 ? 'bg-orange-500' :
                        device.risk_score >= 0.3 ? 'bg-yellow-500' : 'bg-emerald-500'
                      }`}
                    />
                  </div>
                </GlassCard>
              </motion.div>
            ))}
          </div>
        )}
      </GlassCard>
    </div>
  );
}
