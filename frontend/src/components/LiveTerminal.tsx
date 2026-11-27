"use client";

import React, { useEffect, useRef, useState } from "react";
import { Terminal, Trash2, ArrowDownCircle, CheckCircle2 } from "lucide-react";
import { TerminalLog } from "@/lib/types";

interface LiveTerminalProps {
  logs: TerminalLog[];
  status: string;
  onClear?: () => void;
}

export const LiveTerminal: React.FC<LiveTerminalProps> = ({ logs, status, onClear }) => {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);

  useEffect(() => {
    if (autoScroll && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs, autoScroll]);

  const getTagColor = (message: string, level: string) => {
    if (message.includes("[AGENT]")) return "text-purple-400 font-bold";
    if (message.includes("[OSINT]")) return "text-sky-400 font-semibold";
    if (message.includes("[AUDIT]")) return "text-yellow-400 font-semibold";
    if (message.includes("[RECON]")) return "text-cyan-400 font-semibold";
    if (message.includes("[PROBE]")) return "text-teal-400 font-semibold";
    if (message.includes("[PATCHGEN]")) return "text-emerald-400 font-bold";
    if (message.includes("[COMPLETE]")) return "text-emerald-300 font-bold";
    if (message.includes("[ERROR]") || level === "ERROR" || level === "VULN") return "text-red-400 font-bold";
    return "text-gray-300";
  };

  return (
    <div className="flex flex-col h-full bg-[#0D1117] border border-[#1F2937] rounded-xl overflow-hidden shadow-2xl">
      {/* Terminal Title Bar */}
      <div className="flex items-center justify-between px-4 py-2.5 bg-[#161B22] border-b border-[#21262D]">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-emerald-400" />
          <span className="text-xs font-mono font-semibold tracking-wider text-gray-200 uppercase">
            Agent Reasoning &amp; Execution Stream
          </span>
          {status === "running" ? (
            <span className="flex items-center gap-1.5 ml-2 px-2 py-0.5 rounded-full text-[10px] font-mono bg-emerald-950 text-emerald-400 border border-emerald-800 animate-pulse">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
              LIVE EXECUTION
            </span>
          ) : status === "completed" ? (
            <span className="flex items-center gap-1 ml-2 px-2 py-0.5 rounded-full text-[10px] font-mono bg-blue-950 text-blue-300 border border-blue-800">
              <CheckCircle2 className="w-3 h-3 text-blue-400" />
              COMPLETE
            </span>
          ) : null}
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setAutoScroll(!autoScroll)}
            className={`text-xs px-2 py-1 rounded transition-colors flex items-center gap-1 font-mono ${
              autoScroll ? "bg-emerald-950 text-emerald-400" : "bg-[#21262D] text-gray-400"
            }`}
            title="Toggle Auto-Scroll"
          >
            <ArrowDownCircle className="w-3 h-3" />
            <span className="text-[10px]">Scroll</span>
          </button>
          {onClear && (
            <button
              onClick={onClear}
              className="p-1 rounded text-gray-400 hover:text-gray-200 hover:bg-[#21262D] transition-colors"
              title="Clear Terminal"
            >
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Terminal Scroll Area */}
      <div
        ref={scrollRef}
        className="flex-1 p-4 font-mono text-xs overflow-y-auto space-y-2 select-text selection:bg-emerald-900 selection:text-white"
      >
        {logs.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full min-h-[220px] text-gray-500 space-y-2">
            <Terminal className="w-8 h-8 opacity-40 text-emerald-500" />
            <p className="text-xs">Awaiting autonomous scan target initialization...</p>
            <p className="text-[11px] text-gray-600">Enter a target URL above to observe real-time agent thoughts.</p>
          </div>
        ) : (
          logs.map((log) => (
            <div key={log.id} className="leading-relaxed flex items-start gap-2.5 hover:bg-[#161B22]/50 px-1.5 py-1 rounded transition-colors">
              <span className="text-gray-500 select-none text-[11px] shrink-0 font-mono">[{log.time}]</span>
              <span className={`break-words whitespace-pre-wrap ${getTagColor(log.message, log.level)}`}>
                {log.message}
              </span>
            </div>
          ))
        )}
      </div>

      {/* Terminal Footer Bar */}
      <div className="px-4 py-1.5 bg-[#161B22] border-t border-[#21262D] text-[11px] text-gray-500 flex justify-between items-center font-mono">
        <span>Output Lines: {logs.length}</span>
        <span className="text-emerald-500">Isolated Docker Sandbox • Read-Only Mode</span>
      </div>
    </div>
  );
};
