"use client";

import React, { useMemo, useState } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  Handle,
  Position,
  NodeProps,
  Edge,
  Node
} from "@xyflow/react";
import { Shield, Globe, Server, AlertTriangle, Flame, Network, X } from "lucide-react";
import { GraphNodeData, GraphEdgeData } from "@/lib/types";

// Custom Target Node
const TargetNodeComponent = ({ data }: NodeProps) => (
  <div className="px-4 py-3 bg-[#0B0F19] border-2 border-emerald-500 rounded-xl shadow-lg glow-emerald text-center min-w-[160px]">
    <Handle type="source" position={Position.Bottom} className="w-2.5 h-2.5 !bg-emerald-400" />
    <div className="flex items-center justify-center gap-1.5 text-emerald-400 mb-1 font-bold text-xs uppercase tracking-wider font-mono">
      <Globe className="w-3.5 h-3.5" />
      <span>TARGET HOST</span>
    </div>
    <div className="font-mono text-sm font-semibold text-white truncate">{data.label as string}</div>
  </div>
);

// Custom Service Node
const ServiceNodeComponent = ({ data }: NodeProps) => (
  <div className="px-3.5 py-2.5 bg-[#111827] border border-sky-500/80 rounded-lg shadow-md min-w-[140px] text-center">
    <Handle type="target" position={Position.Top} className="w-2 h-2 !bg-sky-400" />
    <Handle type="source" position={Position.Bottom} className="w-2 h-2 !bg-sky-400" />
    <div className="flex items-center justify-center gap-1 text-sky-400 text-[10px] font-mono font-semibold uppercase">
      <Network className="w-3 h-3" />
      <span>SURFACE</span>
    </div>
    <div className="font-mono text-xs text-gray-200 mt-0.5 truncate">{data.label as string}</div>
  </div>
);

// Custom Port Node
const PortNodeComponent = ({ data }: NodeProps) => (
  <div className="px-3 py-2 bg-[#161B22] border border-gray-700 hover:border-gray-500 rounded-lg shadow min-w-[110px] text-center">
    <Handle type="target" position={Position.Top} className="w-2 h-2 !bg-gray-400" />
    <Handle type="source" position={Position.Bottom} className="w-2 h-2 !bg-gray-400" />
    <div className="flex items-center justify-center gap-1 text-teal-400 text-[10px] font-mono font-bold">
      <Server className="w-3 h-3" />
      <span>OPEN PORT</span>
    </div>
    <div className="font-mono text-xs text-teal-200 mt-0.5 font-medium">{data.label as string}</div>
  </div>
);

// Custom Vulnerability Node
const VulnNodeComponent = ({ data }: NodeProps) => {
  const sev = (data.severity as string) || "MEDIUM";
  const borderCol =
    sev === "CRITICAL"
      ? "border-red-500 glow-crimson bg-red-950/40 text-red-200"
      : sev === "HIGH"
      ? "border-amber-500 bg-amber-950/40 text-amber-200"
      : "border-yellow-500 bg-yellow-950/30 text-yellow-200";

  return (
    <div className={`px-3.5 py-2.5 border rounded-xl shadow-xl min-w-[170px] max-w-[240px] ${borderCol}`}>
      <Handle type="target" position={Position.Top} className="w-2 h-2" />
      <Handle type="source" position={Position.Bottom} className="w-2 h-2" />
      <div className="flex items-center justify-between text-[10px] font-mono font-black mb-1">
        <span className="flex items-center gap-1">
          <AlertTriangle className="w-3 h-3" />
          {sev} VULN
        </span>
        {data.node_metadata?.cvss && (
          <span className="px-1.5 py-0.2 rounded bg-black/50 text-[10px]">
            CVSS {data.node_metadata.cvss}
          </span>
        )}
      </div>
      <div className="font-sans text-xs font-semibold line-clamp-2 leading-tight">{data.label as string}</div>
    </div>
  );
};

// Custom Chained Impact Node
const ImpactNodeComponent = ({ data }: NodeProps) => (
  <div className="px-4 py-3 bg-purple-950/60 border-2 border-purple-500 rounded-xl shadow-2xl text-center min-w-[190px] max-w-[260px] animate-pulse">
    <Handle type="target" position={Position.Top} className="w-2.5 h-2.5 !bg-purple-400" />
    <div className="flex items-center justify-center gap-1 text-purple-400 font-mono font-extrabold text-xs mb-1">
      <Flame className="w-3.5 h-3.5 text-purple-400" />
      <span>EXPLOIT CHAIN IMPACT</span>
    </div>
    <div className="font-sans text-xs font-bold text-white leading-snug">{data.label as string}</div>
  </div>
);

const nodeTypes = {
  target: TargetNodeComponent,
  service: ServiceNodeComponent,
  port: PortNodeComponent,
  vulnerability: VulnNodeComponent,
  impact: ImpactNodeComponent,
};

interface AttackGraphProps {
  nodes: GraphNodeData[];
  edges: GraphEdgeData[];
}

export const AttackGraph: React.FC<AttackGraphProps> = ({ nodes: rawNodes, edges: rawEdges }) => {
  const [selectedNode, setSelectedNode] = useState<GraphNodeData | null>(null);

  // Auto-layout algorithm: place nodes in tiered vertical hierarchies
  const layoutedNodes: Node[] = useMemo(() => {
    if (!rawNodes || rawNodes.length === 0) return [];

    const nodeLevels: Record<string, number> = {
      target: 0,
      service: 1,
      port: 2,
      vulnerability: 3,
      impact: 4,
    };

    // Group by level
    const groups: Record<number, GraphNodeData[]> = {};
    rawNodes.forEach((node) => {
      const lvl = nodeLevels[node.node_type] ?? 2;
      if (!groups[lvl]) groups[lvl] = [];
      groups[lvl].push(node);
    });

    const result: Node[] = [];
    const levelYSpacing = 160;

    Object.entries(groups).forEach(([lvlStr, groupNodes]) => {
      const lvl = parseInt(lvlStr);
      const totalInGroup = groupNodes.length;
      const xSpacing = 220;
      const startX = -((totalInGroup - 1) * xSpacing) / 2 + 350;

      groupNodes.forEach((n, idx) => {
        result.push({
          id: n.id,
          type: n.node_type,
          position: {
            x: startX + idx * xSpacing,
            y: 50 + lvl * levelYSpacing,
          },
          data: {
            label: n.label,
            severity: n.severity,
            node_metadata: n.node_metadata,
            rawNode: n,
          },
        });
      });
    });

    return result;
  }, [rawNodes]);

  const flowEdges: Edge[] = useMemo(() => {
    return rawEdges.map((e) => ({
      id: e.id,
      source: e.source_id,
      target: e.target_id,
      animated: e.animated ?? true,
      label: e.label,
      style: { stroke: "#10B981", strokeWidth: 2 },
      labelStyle: { fill: "#9CA3AF", fontSize: 10, fontFamily: "monospace" },
      labelBgStyle: { fill: "#111827", fillOpacity: 0.8 },
    }));
  }, [rawEdges]);

  return (
    <div className="relative w-full h-full min-h-[460px] bg-[#0A0D14] border border-[#1F2937] rounded-xl overflow-hidden shadow-2xl flex flex-col">
      {/* Top Header of Graph */}
      <div className="flex items-center justify-between px-4 py-2.5 bg-[#111827] border-b border-[#1F2937] z-10">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-emerald-400" />
          <span className="text-xs font-mono font-bold tracking-wider text-gray-200 uppercase">
            Live Attack-Path Reasoning Graph
          </span>
          <span className="text-xs font-mono text-gray-500">
            ({rawNodes.length} nodes • {rawEdges.length} vectors)
          </span>
        </div>

        {/* Legend */}
        <div className="hidden lg:flex items-center gap-3 text-[11px] font-mono text-gray-400">
          <span className="flex items-center gap-1">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500"></span> Target
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2.5 h-2.5 rounded-full bg-sky-400"></span> Surface
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2.5 h-2.5 rounded-full bg-red-500"></span> Vuln
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2.5 h-2.5 rounded-full bg-purple-500"></span> Exploit Chain
          </span>
        </div>
      </div>

      {/* Main Flow Canvas */}
      <div className="flex-1 w-full h-full">
        {rawNodes.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-gray-500 space-y-2 py-20">
            <Network className="w-10 h-10 opacity-30 text-emerald-400 animate-pulse" />
            <p className="text-sm font-mono">No active scan attack graph.</p>
            <p className="text-xs text-gray-600">Nodes and attack chains will materialize here in real-time.</p>
          </div>
        ) : (
          <ReactFlow
            nodes={layoutedNodes}
            edges={flowEdges}
            nodeTypes={nodeTypes}
            fitView
            attributionPosition="bottom-left"
            onNodeClick={(_, node) => setSelectedNode(node.data.rawNode as GraphNodeData)}
          >
            <Background color="#1F2937" gap={20} size={1} />
            <Controls />
            <MiniMap
              nodeColor={(n) => {
                if (n.type === "target") return "#10B981";
                if (n.type === "vulnerability") return "#EF4444";
                if (n.type === "impact") return "#A855F7";
                return "#38BDF8";
              }}
              maskColor="rgba(11, 15, 25, 0.75)"
              style={{ background: "#0B0F19", border: "1px solid #1F2937" }}
            />
          </ReactFlow>
        )}
      </div>

      {/* Node Details Inspection Drawer / Modal */}
      {selectedNode && (
        <div className="absolute top-12 right-4 w-80 bg-[#111827] border border-[#1F2937] rounded-xl p-4 shadow-2xl z-20 font-mono text-xs">
          <div className="flex items-center justify-between border-b border-gray-800 pb-2 mb-2">
            <span className="text-emerald-400 font-bold uppercase tracking-wider">
              {selectedNode.node_type} Details
            </span>
            <button
              onClick={() => setSelectedNode(null)}
              className="text-gray-400 hover:text-white"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
          <div className="space-y-2">
            <div>
              <span className="text-gray-500 block text-[10px]">LABEL</span>
              <span className="text-gray-200 font-semibold">{selectedNode.label}</span>
            </div>
            {selectedNode.severity && (
              <div>
                <span className="text-gray-500 block text-[10px]">SEVERITY</span>
                <span
                  className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                    selectedNode.severity === "CRITICAL"
                      ? "bg-red-950 text-red-300 border border-red-800"
                      : "bg-amber-950 text-amber-300 border border-amber-800"
                  }`}
                >
                  {selectedNode.severity}
                </span>
              </div>
            )}
            {selectedNode.node_metadata && (
              <div>
                <span className="text-gray-500 block text-[10px] mb-1">METADATA</span>
                <pre className="bg-[#0B0F19] p-2 rounded text-[11px] text-gray-300 overflow-x-auto max-h-40">
                  {JSON.stringify(selectedNode.node_metadata, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
