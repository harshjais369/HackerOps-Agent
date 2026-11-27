"use client";

import React, { useState, useEffect, useRef } from "react";
import {
  Shield,
  Radio,
  FileDown,
  Terminal as TerminalIcon,
  Layers,
  Code2,
  Bug,
  RefreshCw,
  Zap,
} from "lucide-react";
import { ScanForm } from "@/components/ScanForm";
import { AttackGraph } from "@/components/AttackGraph";
import { LiveTerminal } from "@/components/LiveTerminal";
import { RiskMetrics } from "@/components/RiskMetrics";
import { PatchViewer } from "@/components/PatchViewer";
import { FindingsTable } from "@/components/FindingsTable";
import {
  ScanState,
  Finding,
  GraphNodeData,
  GraphEdgeData,
  Patch,
  TerminalLog,
} from "@/lib/types";
import { createScan, fetchScanDetail, getReportDownloadUrl } from "@/lib/api";

export default function Dashboard() {
  const [scanState, setScanState] = useState<ScanState>({
    id: "",
    target_url: "",
    target_host: "",
    status: "pending",
    risk_score: 0.0,
    compliance_grade: "A+",
    findings: [],
    nodes: [],
    edges: [],
    patches: [],
    logs: [],
    progress: 0,
    currentState: "IDLE",
  });

  const [isLoading, setIsLoading] = useState(false);
  const [bottomTab, setBottomTab] = useState<"findings" | "patches">("findings");
  const wsRef = useRef<WebSocket | null>(null);

  // Clean up WebSocket on unmount
  useEffect(() => {
    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  const startScan = async (target: string, depth: string) => {
    setIsLoading(true);

    // Reset local state
    setScanState({
      id: "",
      target_url: target,
      target_host: target.replace(/^https?:\/\//, "").split("/")[0],
      status: "running",
      risk_score: 0.0,
      compliance_grade: "A",
      findings: [],
      nodes: [],
      edges: [],
      patches: [],
      logs: [
        {
          id: `log-0`,
          message: `[AGENT] Dispatching autonomous security assessment for target: ${target}`,
          level: "AGENT",
          time: new Date().toLocaleTimeString(),
        },
      ],
      progress: 5,
      currentState: "INIT",
    });

    try {
      const scanData = await createScan(target, depth);
      const scanId = scanData.id;

      setScanState((prev) => ({
        ...prev,
        id: scanId,
        target_url: scanData.target_url,
        target_host: scanData.target_host,
        resolved_ip: scanData.resolved_ip,
      }));

      // Connect to WebSocket for live event streaming
      const wsProtocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      const wsHost = process.env.NEXT_PUBLIC_WS_HOST || `${window.location.hostname}:8080`;
      const wsUrl =
        process.env.NEXT_PUBLIC_WS_URL ||
        `${wsProtocol}//${wsHost}/ws/scans/${scanId}`;
      
      if (wsRef.current) {
        wsRef.current.close();
      }

      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        // Ping periodically to keep alive
        const pingInterval = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send("ping");
          } else {
            clearInterval(pingInterval);
          }
        }, 10000);
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          handleWebSocketEvent(msg);
        } catch (e) {
          // Plaintext ping/pong or raw message
        }
      };

      ws.onerror = (err) => {
        console.warn("WebSocket stream error, fallback polling active:", err);
      };

      ws.onclose = () => {
        setIsLoading(false);
      };
    } catch (err: any) {
      setIsLoading(false);
      setScanState((prev) => ({
        ...prev,
        status: "failed",
        error_message: err.message,
        logs: [
          ...prev.logs,
          {
            id: `err-${Date.now()}`,
            message: `[ERROR] Scan initiation failed: ${err.message}`,
            level: "ERROR",
            time: new Date().toLocaleTimeString(),
          },
        ],
      }));
      throw err;
    }
  };

  const handleWebSocketEvent = (event: any) => {
    const type = event.type;
    const data = event.data;

    if (type === "log") {
      setScanState((prev) => ({
        ...prev,
        logs: [
          ...prev.logs,
          {
            id: `log-${Date.now()}-${Math.random()}`,
            message: data.message,
            level: data.level || "INFO",
            time: data.time || new Date().toLocaleTimeString(),
          },
        ],
      }));
    } else if (type === "graph_node") {
      setScanState((prev) => {
        if (prev.nodes.some((n) => n.id === data.id)) return prev;
        return { ...prev, nodes: [...prev.nodes, data] };
      });
    } else if (type === "graph_edge") {
      setScanState((prev) => {
        if (prev.edges.some((e) => e.id === data.id)) return prev;
        return { ...prev, edges: [...prev.edges, data] };
      });
    } else if (type === "finding") {
      setScanState((prev) => ({
        ...prev,
        findings: [...prev.findings, data],
      }));
    } else if (type === "patch") {
      setScanState((prev) => ({
        ...prev,
        patches: [...prev.patches, data],
      }));
    } else if (type === "status") {
      setScanState((prev) => ({
        ...prev,
        currentState: data.state,
        progress: data.progress,
      }));
    } else if (type === "complete") {
      setIsLoading(false);
      setScanState((prev) => ({
        ...prev,
        status: "completed",
        risk_score: data.risk_score,
        compliance_grade: data.compliance_grade,
        progress: 100,
        currentState: "COMPLETE",
      }));
    } else if (type === "error") {
      setIsLoading(false);
      setScanState((prev) => ({
        ...prev,
        status: "failed",
        error_message: data.message,
      }));
    }
  };

  return (
    <main className="min-h-screen bg-[#0B0F19] flex flex-col">
      {/* Top Navigation Bar */}
      <header className="border-b border-[#1F2937] bg-[#111827]/80 backdrop-blur-md sticky top-0 z-30 px-6 py-3.5">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center glow-emerald">
              <Shield className="w-5 h-5 text-emerald-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-base font-black tracking-wider text-white">
                  HACKER<span className="text-emerald-400">OPS</span> AGENT
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">
                  v1.0 DEFENSE
                </span>
              </div>
              <p className="text-[11px] text-gray-400">
                Autonomous Web Vulnerability Assessment &amp; Auto-Remediation System
              </p>
            </div>
          </div>

          {/* Right Status Badge & Report Downloads */}
          <div className="flex items-center gap-3">
            {scanState.status === "running" ? (
              <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-emerald-950/80 border border-emerald-800 text-emerald-400 font-mono text-xs font-semibold animate-pulse">
                <Radio className="w-3.5 h-3.5" />
                <span>{scanState.currentState} ({scanState.progress}%)</span>
              </div>
            ) : scanState.status === "completed" ? (
              <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-blue-950/80 border border-blue-800 text-blue-300 font-mono text-xs font-semibold">
                <span>ASSESSMENT COMPLETE</span>
              </div>
            ) : null}

            {scanState.id && (
              <div className="flex items-center gap-1.5">
                <a
                  href={getReportDownloadUrl(scanState.id, "html")}
                  target="_blank"
                  rel="noreferrer"
                  className="px-2.5 py-1.5 bg-[#1F2937] hover:bg-emerald-950 hover:text-emerald-300 text-gray-300 text-xs font-mono rounded-lg transition-colors flex items-center gap-1.5 border border-gray-700"
                  title="View HTML Report"
                >
                  <FileDown className="w-3.5 h-3.5" />
                  <span>HTML</span>
                </a>
                <a
                  href={getReportDownloadUrl(scanState.id, "markdown")}
                  target="_blank"
                  rel="noreferrer"
                  className="px-2.5 py-1.5 bg-[#1F2937] hover:bg-emerald-950 hover:text-emerald-300 text-gray-300 text-xs font-mono rounded-lg transition-colors flex items-center gap-1.5 border border-gray-700"
                  title="Download Markdown Report"
                >
                  <FileDown className="w-3.5 h-3.5" />
                  <span>MD</span>
                </a>
                <a
                  href={getReportDownloadUrl(scanState.id, "json")}
                  target="_blank"
                  rel="noreferrer"
                  className="px-2.5 py-1.5 bg-[#1F2937] hover:bg-emerald-950 hover:text-emerald-300 text-gray-300 text-xs font-mono rounded-lg transition-colors flex items-center gap-1.5 border border-gray-700"
                  title="Export JSON Telemetry"
                >
                  <FileDown className="w-3.5 h-3.5" />
                  <span>JSON</span>
                </a>
              </div>
            )}
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <div className="flex-1 max-w-7xl mx-auto w-full px-4 sm:px-6 py-6 space-y-6">
        {/* 1. Target URL Input Form */}
        <ScanForm onStartScan={startScan} isLoading={isLoading} />

        {/* 2. Middle Section: Attack Graph (60%) & Live Terminal + Risk Metrics (40%) */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Main Left: Interactive Attack Graph (60%) */}
          <div className="lg:col-span-7 flex flex-col h-[560px]">
            <AttackGraph nodes={scanState.nodes} edges={scanState.edges} />
          </div>

          {/* Main Right: Metrics (Top) & Terminal (Bottom) (40%) */}
          <div className="lg:col-span-5 flex flex-col h-[560px] gap-4">
            <RiskMetrics
              riskScore={scanState.risk_score}
              complianceGrade={scanState.compliance_grade}
              findings={scanState.findings}
            />

            <div className="flex-1 min-h-[300px]">
              <LiveTerminal
                logs={scanState.logs}
                status={scanState.status}
                onClear={() => setScanState((prev) => ({ ...prev, logs: [] }))}
              />
            </div>
          </div>
        </div>

        {/* 3. Bottom Section: Findings Table & PatchGen Auto-Remediation */}
        <div className="space-y-3">
          <div className="flex items-center justify-between border-b border-[#1F2937] pb-2">
            <div className="flex items-center gap-2">
              <button
                onClick={() => setBottomTab("findings")}
                className={`px-4 py-2 rounded-lg font-mono text-xs font-bold flex items-center gap-2 transition-all ${
                  bottomTab === "findings"
                    ? "bg-emerald-500 text-black shadow-lg shadow-emerald-500/20"
                    : "bg-[#111827] text-gray-400 hover:text-gray-200 border border-[#1F2937]"
                }`}
              >
                <Bug className="w-4 h-4" />
                <span>Vulnerability Findings ({scanState.findings.length})</span>
              </button>

              <button
                onClick={() => setBottomTab("patches")}
                className={`px-4 py-2 rounded-lg font-mono text-xs font-bold flex items-center gap-2 transition-all ${
                  bottomTab === "patches"
                    ? "bg-emerald-500 text-black shadow-lg shadow-emerald-500/20"
                    : "bg-[#111827] text-gray-400 hover:text-gray-200 border border-[#1F2937]"
                }`}
              >
                <Code2 className="w-4 h-4" />
                <span>PatchGen Defensive Fixes ({scanState.patches.length})</span>
              </button>
            </div>

            <div className="hidden sm:flex items-center gap-2 text-xs font-mono text-gray-500">
              <Zap className="w-3.5 h-3.5 text-emerald-400" />
              <span>Closed-Loop Vulnerability Mitigation</span>
            </div>
          </div>

          {bottomTab === "findings" ? (
            <FindingsTable findings={scanState.findings} />
          ) : (
            <PatchViewer
              patches={scanState.patches}
              targetHost={scanState.target_host}
            />
          )}
        </div>
      </div>

      {/* Footer */}
      <footer className="mt-auto border-t border-[#1F2937] py-4 px-6 text-center text-xs font-mono text-gray-500 bg-[#0B0F19]">
        <span>HackerOps Agent • Built with Next.js 14, React Flow, FastAPI, and Docker Sandbox • Strictly Read-Only Probes</span>
      </footer>
    </main>
  );
}
