'use client';
import { useState, useCallback, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Upload, FileText, AlertTriangle, CheckCircle, Loader2, X, ChevronDown } from 'lucide-react';
import { useLogStore } from '@/stores/logStore';
import { uploadLogAPI, getLogsAPI, getLogEventsAPI, getThreatsAPI, getThreatSummaryAPI } from '@/lib/api';
import GlassCard from '@/components/ui/GlassCard';

const ACCEPTED_TYPES = '.log,.csv,.json,.txt,.evtx,.syslog';
const MAX_SIZE = 50 * 1024 * 1024; // 50MB

export default function LogUploadModule() {
  const { logs, setLogs, addLog, isUploading, setIsUploading } = useLogStore();
  const [isDragging, setIsDragging] = useState(false);
  const [uploadResult, setUploadResult] = useState<any>(null);
  const [selectedLog, setSelectedLog] = useState<string | null>(null);
  const [events, setEvents] = useState<any[]>([]);
  const [loadingLogs, setLoadingLogs] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const fetchLogs = useCallback(async () => {
    setLoadingLogs(true);
    try {
      const data = await getLogsAPI();
      setLogs(data.logs || []);
    } catch (e) {
      console.error('Failed to fetch logs');
    }
    setLoadingLogs(false);
  }, [setLogs]);

  const handleUpload = async (file: File) => {
    if (file.size > MAX_SIZE) {
      alert('File too large. Maximum size is 50MB.');
      return;
    }
    
    setIsUploading(true);
    setUploadResult(null);
    
    try {
      const result = await uploadLogAPI(file);
      setUploadResult(result);
      addLog({
        id: result.log_id,
        filename: file.name,
        file_size: file.size,
        source_type: result.source_type,
        event_count: result.event_count,
        upload_time: new Date().toISOString(),
        status: 'completed',
      });
    } catch (e: any) {
      setUploadResult({ error: e.response?.data?.detail || 'Upload failed' });
    }
    setIsUploading(false);
  };

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) handleUpload(file);
  }, []);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback(() => setIsDragging(false), []);

  const viewEvents = async (logId: string) => {
    setSelectedLog(logId);
    try {
      const data = await getLogEventsAPI(logId);
      setEvents(data.events || []);
    } catch (e) {
      setEvents([]);
    }
  };

  return (
    <div className="space-y-6">
      {/* Upload Area */}
      <GlassCard className="p-8">
        <h2 className="text-xl font-semibold text-white mb-4">Upload Security Logs</h2>
        <p className="text-white/50 mb-6">Upload firewall logs, Apache/Nginx access logs, syslog, CSV exports, or JSON logs for analysis.</p>
        
        <div
          onDrop={handleDrop}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onClick={() => fileInputRef.current?.click()}
          className={`border-2 border-dashed rounded-xl p-12 text-center cursor-pointer transition-all duration-300 ${
            isDragging 
              ? 'border-cyan-400 bg-cyan-400/5 scale-[1.02]' 
              : 'border-white/10 hover:border-cyan-400/30 hover:bg-white/[0.02]'
          }`}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept={ACCEPTED_TYPES}
            onChange={(e) => e.target.files?.[0] && handleUpload(e.target.files[0])}
            className="hidden"
          />
          
          {isUploading ? (
            <div className="flex flex-col items-center gap-4">
              <Loader2 className="w-12 h-12 text-cyan-400 animate-spin" />
              <p className="text-white/70">Parsing and analyzing log file...</p>
            </div>
          ) : (
            <div className="flex flex-col items-center gap-4">
              <Upload className="w-12 h-12 text-white/30" />
              <div>
                <p className="text-white/70 text-lg">Drag and drop your log file here</p>
                <p className="text-white/40 text-sm mt-1">or click to browse</p>
              </div>
              <p className="text-white/30 text-xs">Supports: .log, .csv, .json, .txt, .syslog (max 50MB)</p>
            </div>
          )}
        </div>

        {/* Upload Result */}
        <AnimatePresence>
          {uploadResult && !uploadResult.error && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              className="mt-6 p-4 rounded-lg bg-emerald-500/10 border border-emerald-500/20"
            >
              <div className="flex items-start gap-3">
                <CheckCircle className="w-5 h-5 text-emerald-400 mt-0.5" />
                <div className="flex-1">
                  <p className="text-emerald-400 font-medium">Analysis Complete</p>
                  <div className="mt-2 grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
                    <div>
                      <span className="text-white/40">Events Parsed</span>
                      <p className="text-white font-medium">{uploadResult.event_count}</p>
                    </div>
                    <div>
                      <span className="text-white/40">Source Type</span>
                      <p className="text-white font-medium capitalize">{uploadResult.source_type}</p>
                    </div>
                    <div>
                      <span className="text-white/40">Threats Found</span>
                      <p className={`font-medium ${uploadResult.threats?.length > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                        {uploadResult.threats?.length || 0}
                      </p>
                    </div>
                    <div>
                      <span className="text-white/40">Anomaly Score</span>
                      <p className={`font-medium ${
                        (uploadResult.anomaly?.anomaly_score || 0) > 0.6 ? 'text-red-400' : 'text-emerald-400'
                      }`}>
                        {(uploadResult.anomaly?.anomaly_score || 0).toFixed(3)}
                      </p>
                    </div>
                  </div>
                  
                  {/* Threats */}
                  {uploadResult.threats?.length > 0 && (
                    <div className="mt-4 space-y-2">
                      <p className="text-white/60 text-sm font-medium">Detected Threats:</p>
                      {uploadResult.threats.map((t: any, i: number) => (
                        <div key={i} className="flex items-center gap-2 text-sm">
                          <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                            t.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400' :
                            t.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400' :
                            'bg-yellow-500/20 text-yellow-400'
                          }`}>{t.severity}</span>
                          <span className="text-white/70">{t.threat_type?.replace(/_/g, ' ')}</span>
                          <span className="text-white/40">from {t.source_ip}</span>
                          <span className="text-white/30 ml-auto">{t.mitre_technique}</span>
                        </div>
                      ))}
                    </div>
                  )}
                  
                  <button onClick={() => setUploadResult(null)} className="mt-3 text-white/40 hover:text-white/60 text-sm">
                    Dismiss
                  </button>
                </div>
              </div>
            </motion.div>
          )}
          
          {uploadResult?.error && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              className="mt-6 p-4 rounded-lg bg-red-500/10 border border-red-500/20"
            >
              <div className="flex items-center gap-3">
                <AlertTriangle className="w-5 h-5 text-red-400" />
                <p className="text-red-400">{uploadResult.error}</p>
                <button onClick={() => setUploadResult(null)} className="ml-auto text-white/40 hover:text-white/60">
                  <X className="w-4 h-4" />
                </button>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </GlassCard>

      {/* Uploaded Logs List */}
      <GlassCard className="p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-white">Uploaded Logs</h3>
          <button onClick={fetchLogs} className="text-sm text-cyan-400 hover:text-cyan-300">
            {loadingLogs ? 'Loading...' : 'Refresh'}
          </button>
        </div>
        
        {logs.length === 0 ? (
          <p className="text-white/40 text-sm">No logs uploaded yet. Upload a log file above to get started.</p>
        ) : (
          <div className="space-y-2">
            {logs.map((log) => (
              <motion.div
                key={log.id}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className={`flex items-center gap-4 p-3 rounded-lg border transition-colors cursor-pointer ${
                  selectedLog === log.id 
                    ? 'border-cyan-400/30 bg-cyan-400/5' 
                    : 'border-white/5 hover:border-white/10'
                }`}
                onClick={() => viewEvents(log.id)}
              >
                <FileText className="w-5 h-5 text-white/40" />
                <div className="flex-1 min-w-0">
                  <p className="text-white text-sm font-medium truncate">{log.filename}</p>
                  <p className="text-white/40 text-xs">
                    {log.source_type} • {log.event_count} events • {(log.file_size / 1024).toFixed(1)}KB
                  </p>
                </div>
                <span className={`px-2 py-0.5 rounded text-xs ${
                  log.status === 'completed' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-yellow-500/20 text-yellow-400'
                }`}>{log.status}</span>
              </motion.div>
            ))}
          </div>
        )}
      </GlassCard>

      {/* Events Viewer */}
      {selectedLog && events.length > 0 && (
        <GlassCard className="p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-white">Parsed Events ({events.length})</h3>
            <button onClick={() => { setSelectedLog(null); setEvents([]); }} className="text-white/40 hover:text-white/60">
              <X className="w-4 h-4" />
            </button>
          </div>
          
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-white/40 border-b border-white/5">
                  <th className="text-left py-2 px-3">Timestamp</th>
                  <th className="text-left py-2 px-3">Source IP</th>
                  <th className="text-left py-2 px-3">Dest IP:Port</th>
                  <th className="text-left py-2 px-3">Event Type</th>
                  <th className="text-left py-2 px-3">Severity</th>
                  <th className="text-left py-2 px-3">Message</th>
                </tr>
              </thead>
              <tbody>
                {events.slice(0, 100).map((event, i) => (
                  <tr key={i} className="border-b border-white/5 hover:bg-white/[0.02]">
                    <td className="py-2 px-3 text-white/60 font-mono text-xs">{event.timestamp?.slice(0, 19)}</td>
                    <td className="py-2 px-3 text-cyan-400 font-mono text-xs">{event.source_ip || '-'}</td>
                    <td className="py-2 px-3 text-white/60 font-mono text-xs">{event.dest_ip || '-'}:{event.dest_port || ''}</td>
                    <td className="py-2 px-3">
                      <span className="px-2 py-0.5 rounded text-xs bg-white/5 text-white/70">
                        {event.event_type?.replace(/_/g, ' ')}
                      </span>
                    </td>
                    <td className="py-2 px-3">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                        event.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400' :
                        event.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400' :
                        event.severity === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-400' :
                        'bg-white/5 text-white/50'
                      }`}>{event.severity}</span>
                    </td>
                    <td className="py-2 px-3 text-white/50 text-xs max-w-[300px] truncate">{event.message}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {events.length > 100 && (
            <p className="text-white/30 text-xs mt-3 text-center">Showing 100 of {events.length} events</p>
          )}
        </GlassCard>
      )}
    </div>
  );
}
