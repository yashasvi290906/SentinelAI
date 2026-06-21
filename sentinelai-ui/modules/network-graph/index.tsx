"use client";

import { useState, useEffect, useCallback } from "react";
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  Handle,
  useNodesState,
  useEdgesState,
  type Node,
  type Edge,
  Position,
} from "reactflow";
import "reactflow/dist/style.css";
import { motion } from "framer-motion";
import { graphAPI, type GraphNode, type GraphEdge } from "@/lib/api";
import { Network } from "lucide-react";
import "./styles.css";

function getSeverityColor(score: number): string {
  if (score < 30) return "#22c55e";
  if (score <= 60) return "#f59e0b";
  return "#ef4444";
}

function getSeverityBorder(score: number): string {
  if (score < 30) return "rgba(34,197,94,0.5)";
  if (score <= 60) return "rgba(245,158,11,0.5)";
  return "rgba(239,68,68,0.5)";
}

function getSeverityGlow(score: number): string {
  if (score < 30) return "0 0 12px rgba(34,197,94,0.25)";
  if (score <= 60) return "0 0 12px rgba(245,158,11,0.25)";
  return "0 0 12px rgba(239,68,68,0.25)";
}

function CustomNode({ data }: { data: { label: string; confidence: number; severityScore: number } }) {
  const borderColor = getSeverityBorder(data.severityScore);
  const glowColor = getSeverityGlow(data.severityScore);

  return (
    <div
      className="custom-graph-node"
      style={{
        background: "rgba(8,20,32,0.85)",
        backdropFilter: "blur(12px)",
        border: `1.5px solid ${borderColor}`,
        borderRadius: "12px",
        padding: "12px 16px",
        minWidth: "120px",
        boxShadow: glowColor,
      }}
    >
      <Handle type="target" position={Position.Top} id="target" style={{ background: borderColor, width: 8, height: 8 }} />
      <p
        className="text-[11px] font-mono font-bold uppercase tracking-wider text-center mb-1"
        style={{ color: getSeverityColor(data.severityScore) }}
      >
        {data.label}
      </p>
      <p
        className="text-[10px] font-mono text-center"
        style={{ color: "var(--text-muted)" }}
      >
        {data.confidence.toFixed(1)}% confidence
      </p>
      <Handle type="source" position={Position.Bottom} id="source" style={{ background: borderColor, width: 8, height: 8 }} />
    </div>
  );
}

const nodeTypes = { customNode: CustomNode };

export default function NetworkGraph() {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [loading, setLoading] = useState(true);
  const [hasData, setHasData] = useState(false);

  const fetchData = useCallback(async () => {
    try {
      setLoading(true);
      const data = await graphAPI();

      if (!data.nodes || data.nodes.length === 0) {
        setHasData(false);
        return;
      }

      setHasData(true);

      const rfNodes: Node[] = data.nodes.map((node: GraphNode, i: number) => ({
        id: node.id,
        type: "customNode",
        position: {
          x: 250 + Math.cos((2 * Math.PI * i) / data.nodes.length) * 200,
          y: 200 + Math.sin((2 * Math.PI * i) / data.nodes.length) * 200,
        },
        data: {
          label: node.label,
          confidence: node.confidence,
          severityScore: node.severity_score,
        },
      }));

      const nodeIds = new Set(data.nodes.map((n) => n.id));
      const rfEdges: Edge[] = data.edges
        .filter((edge: GraphEdge) => nodeIds.has(edge.source) && nodeIds.has(edge.target))
        .map((edge: GraphEdge) => ({
          id: edge.id,
          source: edge.source,
          sourceHandle: "source",
          target: edge.target,
          targetHandle: "target",
          label: edge.type,
          animated: true,
          style: { stroke: "rgba(0,229,255,0.3)", strokeWidth: 2 },
          labelStyle: { fill: "var(--text-muted)", fontSize: 9, fontFamily: "monospace" },
          labelBgStyle: { fill: "rgba(8,20,32,0.9)", stroke: "rgba(0,229,255,0.1)" },
        }));

      setNodes(rfNodes);
      setEdges(rfEdges);
    } catch {
      setHasData(false);
    } finally {
      setLoading(false);
    }
  }, [setNodes, setEdges]);

  useEffect(() => {
    const timer = setTimeout(fetchData, 0);
    return () => clearTimeout(timer);
  }, [fetchData]);

  if (loading) {
    return (
      <div className="h-full p-6 lg:p-8 flex flex-col gap-6 overflow-y-auto">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
        >
          <p
            className="text-[10px] font-mono tracking-[0.3em] uppercase mb-2"
            style={{ color: "var(--accent-cyan)" }}
          >
            Attack Topology
          </p>
          <h1
            className="text-3xl font-display font-bold"
            style={{ color: "var(--text-primary)" }}
          >
            Network Graph
          </h1>
        </motion.div>

        <div
          className="flex-1 rounded-2xl flex items-center justify-center min-h-[400px]"
          style={{
            background: "rgba(8,20,32,0.7)",
            border: "1px solid rgba(0,229,255,0.08)",
          }}
        >
          <div className="flex flex-col items-center gap-3">
            <div
              className="w-8 h-8 rounded-full border-2 border-t-transparent animate-spin"
              style={{ borderColor: "rgba(0,229,255,0.3)", borderTopColor: "transparent" }}
            />
            <p className="text-xs font-mono" style={{ color: "var(--text-muted)" }}>
              Loading graph data...
            </p>
          </div>
        </div>
      </div>
    );
  }

  if (!hasData) {
    return (
      <div className="h-full p-6 lg:p-8 flex flex-col gap-6 overflow-y-auto">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
        >
          <p
            className="text-[10px] font-mono tracking-[0.3em] uppercase mb-2"
            style={{ color: "var(--accent-cyan)" }}
          >
            Attack Topology
          </p>
          <h1
            className="text-3xl font-display font-bold"
            style={{ color: "var(--text-primary)" }}
          >
            Network Graph
          </h1>
          <p
            className="text-sm mt-2"
            style={{ color: "var(--text-secondary)" }}
          >
            Interactive visualization of attack relationships and threat propagation
          </p>
        </motion.div>

        <div
          className="flex-1 rounded-2xl flex items-center justify-center min-h-[400px]"
          style={{
            background: "rgba(8,20,32,0.7)",
            border: "1px solid rgba(0,229,255,0.08)",
          }}
        >
          <div className="flex flex-col items-center gap-3">
            <Network
              className="w-10 h-10"
              style={{ color: "var(--text-muted)", opacity: 0.3 }}
            />
            <p className="text-sm font-medium" style={{ color: "var(--text-secondary)" }}>
              No graph data
            </p>
            <p className="text-xs" style={{ color: "var(--text-muted)" }}>
              Run predictions to generate attack relationship graphs
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full p-6 lg:p-8 flex flex-col gap-6 overflow-hidden">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <p
          className="text-[10px] font-mono tracking-[0.3em] uppercase mb-2"
          style={{ color: "var(--accent-cyan)" }}
        >
          Attack Topology
        </p>
        <h1
          className="text-3xl font-display font-bold"
          style={{ color: "var(--text-primary)" }}
        >
          Network Graph
        </h1>
        <p
          className="text-sm mt-2"
          style={{ color: "var(--text-secondary)" }}
        >
          Interactive visualization of attack relationships and threat propagation
        </p>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.1 }}
        className="flex-1 rounded-2xl overflow-hidden min-h-0"
        style={{
          background: "rgba(8,20,32,0.7)",
          backdropFilter: "blur(24px)",
          border: "1px solid rgba(0,229,255,0.08)",
        }}
      >
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          nodeTypes={nodeTypes}
          fitView
          proOptions={{ hideAttribution: true }}
        >
          <Background color="rgba(0,229,255,0.04)" gap={24} size={1} />
          <Controls position="bottom-left" />
          <MiniMap
            position="bottom-right"
            nodeColor={(node) => {
              const score = (node.data as Record<string, unknown>)?.severityScore as number;
              return getSeverityColor(score ?? 50);
            }}
            maskColor="rgba(8,20,32,0.75)"
            style={{ width: 140, height: 100 }}
          />
        </ReactFlow>
      </motion.div>
    </div>
  );
}
