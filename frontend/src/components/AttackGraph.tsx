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

// 1. Target Node (Level 0)
const TargetNodeComponent = ({ data }: NodeProps) => (
  <div className="px-4 py-2.5 bg-[#0B0F19] border-2 border-emerald-500 rounded-xl shadow-lg glow-emerald text-center w-[180px]">
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

// 2. Service Node (Level 1)
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

// 3. Port Node (Level 2)
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

// 4. Vulnerability Node (Level 3 - Fixed width, guaranteed zero overlapping)
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
    <div className={`px-3 py-2 border rounded-xl shadow-xl w-[210px] ${borderCol}`}>
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

// 5. Exploit Chain Impact Node (Level 4)
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

  // Pure hierarchical top-to-bottom Tree Layout: Target -> Services -> Ports -> Vulnerabilities -> Impact
  const layoutedNodes: Node[] = useMemo(() => {
    if (!rawNodes || rawNodes.length === 0) return [];

    const nodeLevels: Record<string, number> = {
      target: 0,
      service: 1,
      port: 2,
      vulnerability: 3,
      impact: 4,
    };

    // Separate spacing per tier so nodes never collide
    const tierSpacingX: Record<number, number> = {
      0: 220,
      1: 220, // Services
      2: 180, // Ports
      3: 260, // Vulnerabilities: 210px width + 50px generous gap!
      4: 280, // Impact
    };

    const tierY: Record<number, number> = {
      0: 40,  // Target
      1: 160, // Services (DNS, TLS, Surface)
      2: 275, // Ports (Port 80, Port 443)
      3: 410, // Vulnerability findings row
      4: 550, // Impact
    };

    // Group by level
    const groups: Record<number, GraphNodeData[]> = {};
    rawNodes.forEach((node) => {
      const lvl = nodeLevels[node.node_type] ?? 2;
      if (!groups[lvl]) groups[lvl] = [];
      groups[lvl].push(node);
    });

    const result: Node[] = [];
    const centerX = 550;

    Object.entries(groups).forEach(([lvlStr, groupNodes]) => {
      const lvl = parseInt(lvlStr);
      const totalInGroup = groupNodes.length;
      const xSpacing = tierSpacingX[lvl] || 240;
      const startX = centerX - ((totalInGroup - 1) * xSpacing) / 2;

      groupNodes.forEach((n, idx) => {
        // Half-width offset so the box is centered around the coordinate
        const nodeWidth = lvl === 0 ? 180 : lvl === 1 ? 160 : lvl === 2 ? 130 : lvl === 3 ? 210 : 250;
        result.push({
          id: n.id,
          type: n.node_type,
          position: {
            x: startX + idx * xSpacing - nodeWidth / 2,
            y: tierY[lvl] ?? (40 + lvl * 130),
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

  // Clean, natural curved tree branches with directional arrowheads
  const flowEdges: Edge[] = useMemo(() => {
    const nodeMap = new Map<string, GraphNodeData>();
    rawNodes.forEach((n) => nodeMap.set(n.id, n));

    return rawEdges.map((e) => {
      const targetNode = nodeMap.get(e.target_id);
      const sourceNode = nodeMap.get(e.source_id);
      const targetType = targetNode?.node_type || "vulnerability";
      const targetSev = targetNode?.severity || "MEDIUM";

      let strokeColor = "#10B981"; // Default emerald
      let strokeWidth = 1.75;
      let isAnimated = true;

      // Color-code lines so relationships are instantly identifiable
      if (sourceNode?.node_type === "target") {
        strokeColor = "#38BDF8"; // Sky blue for Target -> Infra
        strokeWidth = 1.75;
      } else if (targetType === "impact") {
        strokeColor = "#A855F7"; // Purple for Exploit Chain
        strokeWidth = 2.5;
      } else if (targetType === "vulnerability") {
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
            strokeWidth = 1.75;
            break;
          case "LOW":
          default:
            strokeColor = "#3B82F6";
            strokeWidth = 1.5;
            break;
        }
      }

      // Hide repetitive "Exposes Flaw" text pills that clutter lines; keep key structural labels
      const shouldShowLabel = e.label && e.label !== "Exposes Flaw" && e.label !== "Exposes";

      return {
        id: e.id,
        source: e.source_id,
        target: e.target_id,
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
        label: shouldShowLabel ? e.label : undefined,
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
            {/* Note: MiniMap removed to eliminate empty black box */}
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
