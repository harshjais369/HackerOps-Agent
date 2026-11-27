"use client";

import React, { useMemo, useState } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  Handle,
  Position,
  NodeProps,
  Edge,
  Node,
  MarkerType,
} from "@xyflow/react";
import { Shield, Globe, Server, AlertTriangle, Flame, Network, X } from "lucide-react";
import { GraphNodeData, GraphEdgeData } from "@/lib/types";

// Custom Target Node
const TargetNodeComponent = ({ data }: NodeProps) => (
  <div className="px-4 py-2.5 bg-[#0B0F19] border-2 border-emerald-500 rounded-xl shadow-lg glow-emerald text-center w-[190px]">
    <Handle type="source" position={Position.Bottom} className="w-2.5 h-2.5 !bg-emerald-400" />
    <div className="flex items-center justify-center gap-1.5 text-emerald-400 mb-0.5 font-bold text-[10px] uppercase tracking-wider font-mono">
      <Globe className="w-3.5 h-3.5" />
      <span>TARGET HOST</span>
    </div>
    <div className="font-mono text-xs font-bold text-white truncate" title={data.label as string}>
      {data.label as string}
    </div>
  </div>
);

// Custom Service Node
const ServiceNodeComponent = ({ data }: NodeProps) => (
  <div className="px-3 py-2 bg-[#111827] border border-sky-500/80 rounded-lg shadow-md w-[160px] text-center">
    <Handle type="target" position={Position.Top} className="w-2 h-2 !bg-sky-400" />
    <Handle type="source" position={Position.Bottom} className="w-2 h-2 !bg-sky-400" />
    <div className="flex items-center justify-center gap-1 text-sky-400 text-[10px] font-mono font-semibold uppercase">
      <Network className="w-3 h-3" />
      <span>SURFACE</span>
    </div>
    <div className="font-mono text-xs text-gray-200 mt-0.5 truncate" title={data.label as string}>
      {data.label as string}
    </div>
  </div>
);

// Custom Port Node
const PortNodeComponent = ({ data }: NodeProps) => (
  <div className="px-3 py-2 bg-[#161B22] border border-teal-500/80 hover:border-teal-400 rounded-lg shadow w-[130px] text-center">
    <Handle type="target" position={Position.Top} className="w-2 h-2 !bg-teal-400" />
    <Handle type="source" position={Position.Bottom} className="w-2 h-2 !bg-teal-400" />
    <div className="flex items-center justify-center gap-1 text-teal-400 text-[10px] font-mono font-bold">
      <Server className="w-3 h-3" />
      <span>OPEN PORT</span>
    </div>
    <div className="font-mono text-xs text-teal-200 mt-0.5 font-medium truncate" title={data.label as string}>
      {data.label as string}
    </div>
  </div>
);

// Custom Vulnerability Node (Fixed width, clean typography, non-overlapping)
const VulnNodeComponent = ({ data }: NodeProps) => {
  const sev = (data.severity as string) || "MEDIUM";
  const borderCol =
    sev === "CRITICAL"
      ? "border-red-500 glow-crimson bg-red-950/60 text-red-100"
      : sev === "HIGH"
      ? "border-amber-500 bg-amber-950/60 text-amber-100"
      : sev === "MEDIUM"
      ? "border-yellow-500/80 bg-yellow-950/40 text-yellow-100"
      : "border-blue-500/80 bg-blue-950/40 text-blue-100";

  const handleColor =
    sev === "CRITICAL"
      ? "!bg-red-400"
      : sev === "HIGH"
      ? "!bg-amber-400"
      : sev === "MEDIUM"
      ? "!bg-yellow-400"
      : "!bg-blue-400";

  return (
    <div className={`px-3 py-2 border rounded-xl shadow-xl w-[230px] ${borderCol}`}>
      <Handle type="target" position={Position.Top} className={`w-2 h-2 ${handleColor}`} />
      <Handle type="source" position={Position.Bottom} className="w-2 h-2 !bg-purple-400" />
      <div className="flex items-center justify-between text-[10px] font-mono font-black mb-1">
        <span className="flex items-center gap-1">
          <AlertTriangle className="w-3 h-3 shrink-0" />
          <span>{sev} VULN</span>
        </span>
        {data.node_metadata?.cvss && (
          <span className="px-1.5 py-0.2 rounded bg-black/60 font-mono text-[9px] border border-white/10">
            CVSS {data.node_metadata.cvss}
          </span>
        )}
      </div>
      <div className="font-sans text-[11px] font-medium line-clamp-2 leading-snug" title={data.label as string}>
        {data.label as string}
      </div>
    </div>
  );
};

// Custom Chained Impact Node
const ImpactNodeComponent = ({ data }: NodeProps) => (
  <div className="px-4 py-2.5 bg-purple-950/60 border-2 border-purple-500 rounded-xl shadow-2xl text-center w-[250px] animate-pulse">
    <Handle type="target" position={Position.Top} className="w-2.5 h-2.5 !bg-purple-400" />
    <div className="flex items-center justify-center gap-1 text-purple-400 font-mono font-extrabold text-[11px] mb-0.5">
      <Flame className="w-3.5 h-3.5 text-purple-400" />
      <span>EXPLOIT CHAIN IMPACT</span>
    </div>
    <div className="font-sans text-xs font-bold text-white leading-snug line-clamp-2" title={data.label as string}>
      {data.label as string}
    </div>
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

  // Structured multi-tier layout: Target (Tier 0) -> Infrastructure & Ports (Tier 1) -> Vulnerabilities (Tier 2 Multi-Row) -> Impact (Tier 3)
  const layoutedNodes: Node[] = useMemo(() => {
    if (!rawNodes || rawNodes.length === 0) return [];

    const result: Node[] = [];

    const targetNodes = rawNodes.filter((n) => n.node_type === "target");
    const serviceNodes = rawNodes.filter((n) => n.node_type === "service");
    const portNodes = rawNodes.filter((n) => n.node_type === "port");
    const vulnNodes = rawNodes.filter((n) => n.node_type === "vulnerability");
    const impactNodes = rawNodes.filter((n) => n.node_type === "impact");

    const centerX = 500;

    // 1. Target Node (Tier 0)
    targetNodes.forEach((n) => {
      result.push({
        id: n.id,
        type: n.node_type,
        position: { x: centerX - 95, y: 30 },
        data: { label: n.label, severity: n.severity, node_metadata: n.node_metadata, rawNode: n },
      });
    });

    // 2. Infrastructure: Services + Ports in a single horizontal tier (Tier 1)
    const infraNodes = [...serviceNodes, ...portNodes];
    const totalInfra = infraNodes.length;
    const infraSpacing = 180;
    const infraStartX = centerX - ((totalInfra - 1) * infraSpacing) / 2 - 80;

    infraNodes.forEach((n, idx) => {
      result.push({
        id: n.id,
        type: n.node_type,
        position: {
          x: infraStartX + idx * infraSpacing,
          y: 140,
        },
        data: { label: n.label, severity: n.severity, node_metadata: n.node_metadata, rawNode: n },
      });
    });

    // 3. Vulnerability Findings in structured rows (Tier 2 - Max 3 per row to prevent overlaps)
    const totalVulns = vulnNodes.length;
    const maxPerRow = totalVulns > 4 ? 3 : totalVulns;
    const vulnSpacingX = 260; // 230px card + 30px gap
    const vulnSpacingY = 100;

    vulnNodes.forEach((n, idx) => {
      const row = Math.floor(idx / maxPerRow);
      const col = idx % maxPerRow;
      const countInThisRow = Math.min(maxPerRow, totalVulns - row * maxPerRow);
      const rowStartX = centerX - ((countInThisRow - 1) * vulnSpacingX) / 2 - 115;

      result.push({
        id: n.id,
        type: n.node_type,
        position: {
          x: rowStartX + col * vulnSpacingX,
          y: 260 + row * vulnSpacingY,
        },
        data: { label: n.label, severity: n.severity, node_metadata: n.node_metadata, rawNode: n },
      });
    });

    // 4. Impact Nodes (Tier 3)
    const vulnRows = Math.ceil(totalVulns / maxPerRow) || 1;
    const impactY = 260 + vulnRows * vulnSpacingY + 20;
    const totalImpact = impactNodes.length;
    const impactSpacing = 280;
    const impactStartX = centerX - ((totalImpact - 1) * impactSpacing) / 2 - 125;

    impactNodes.forEach((n, idx) => {
      result.push({
        id: n.id,
        type: n.node_type,
        position: {
          x: impactStartX + idx * impactSpacing,
          y: impactY,
        },
        data: { label: n.label, severity: n.severity, node_metadata: n.node_metadata, rawNode: n },
      });
    });

    return result;
  }, [rawNodes]);

  // Color-coded, arrow-directed, smoothstep edges to clearly distinguish connections
  const flowEdges: Edge[] = useMemo(() => {
    const nodeMap = new Map<string, GraphNodeData>();
    rawNodes.forEach((n) => nodeMap.set(n.id, n));

    return rawEdges.map((e) => {
      const targetNode = nodeMap.get(e.target_id);
      const sourceNode = nodeMap.get(e.source_id);
      const targetType = targetNode?.node_type || "vulnerability";
      const targetSev = targetNode?.severity || "MEDIUM";

      let strokeColor = "#10B981"; // default emerald
      let strokeWidth = 2;
      let isAnimated = true;

      if (sourceNode?.node_type === "target") {
        // Target -> Infrastructure (Sky Blue)
        strokeColor = "#38BDF8";
        strokeWidth = 1.75;
      } else if (targetType === "impact") {
        // Escalation to Exploit Chain (Royal Purple)
        strokeColor = "#A855F7";
        strokeWidth = 2.5;
      } else if (targetType === "vulnerability") {
        // Exposes Flaw -> Severity color
        switch (targetSev) {
          case "CRITICAL":
            strokeColor = "#EF4444";
            strokeWidth = 2.5;
            break;
          case "HIGH":
            strokeColor = "#F97316";
            strokeWidth = 2;
            break;
          case "MEDIUM":
            strokeColor = "#EAB308";
            strokeWidth = 2;
            break;
          case "LOW":
          default:
            strokeColor = "#3B82F6";
            strokeWidth = 1.5;
            break;
        }
      }

      return {
        id: e.id,
        source: e.source_id,
        target: e.target_id,
        type: "smoothstep",
        animated: isAnimated,
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: strokeColor,
          width: 14,
          height: 14,
        },
        style: {
          stroke: strokeColor,
          strokeWidth,
          strokeDasharray: isAnimated ? "5 4" : undefined,
        },
        label: e.label,
        labelStyle: {
          fill: strokeColor,
          fontSize: 10,
          fontFamily: "monospace",
          fontWeight: 600,
        },
        labelBgStyle: {
          fill: "#0B0F19",
          fillOpacity: 0.9,
          stroke: strokeColor,
          strokeWidth: 0.5,
          rx: 4,
          ry: 4,
        },
        labelBgPadding: [4, 2] as [number, number],
      };
    });
  }, [rawNodes, rawEdges]);

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

        {/* Color-Coded Legend */}
        <div className="hidden lg:flex items-center gap-3 text-[11px] font-mono text-gray-400">
          <span className="flex items-center gap-1">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500"></span> Target
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2.5 h-2.5 rounded-full bg-sky-400"></span> Surface/Port
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2.5 h-2.5 rounded-full bg-red-500"></span> Crit/High
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2.5 h-2.5 rounded-full bg-yellow-400"></span> Med/Low
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2.5 h-2.5 rounded-full bg-purple-500"></span> Impact
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
            fitViewOptions={{ padding: 0.15 }}
            minZoom={0.2}
            maxZoom={1.5}
            attributionPosition="bottom-left"
            onNodeClick={(_, node) => setSelectedNode(node.data.rawNode as GraphNodeData)}
          >
            <Background color="#1F2937" gap={20} size={1} />
            <Controls />
            {/* Note: MiniMap removed to eliminate the empty black box artifact */}
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
