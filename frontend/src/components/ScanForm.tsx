"use client";

import React, { useState } from "react";
import { Shield, Play, Loader2, Sparkles, AlertTriangle } from "lucide-react";

interface ScanFormProps {
  onStartScan: (target: string, depth: string) => Promise<void>;
  isLoading: boolean;
}

export const ScanForm: React.FC<ScanFormProps> = ({ onStartScan, isLoading }) => {
  const [target, setTarget] = useState("");
  const [depth, setDepth] = useState("standard");
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!target.trim()) {
      setError("Please enter a target URL or domain.");
      return;
    }
    try {
      await onStartScan(target.trim(), depth);
    } catch (err: any) {
      setError(err.message || "Failed to start scan");
    }
  };

  const setPreset = (url: string) => {
    setTarget(url);
    setError(null);
  };

  return (
    <div className="w-full bg-[#111827] border border-[#1F2937] rounded-xl p-4 shadow-xl">
      <form onSubmit={handleSubmit} className="flex flex-col md:flex-row items-center gap-3">
        <div className="relative flex-1 w-full">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-emerald-500">
            <Shield className="w-5 h-5" />
          </div>
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            disabled={isLoading}
            placeholder="Enter target URL (e.g. https://example.com)..."
            className="w-full pl-10 pr-4 py-2.5 bg-[#0B0F19] border border-[#1F2937] rounded-lg text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 transition-all font-mono"
          />
        </div>

        <select
          value={depth}
          onChange={(e) => setDepth(e.target.value)}
          disabled={isLoading}
          aria-label="Scan Depth"
          className="bg-[#0B0F19] border border-[#1F2937] text-gray-300 text-sm rounded-lg px-3 py-2.5 focus:outline-none focus:border-emerald-500 font-mono"
        >
          <option value="quick">Quick Audit (DNS + Headers)</option>
          <option value="standard">Standard Recon (Full Modular)</option>
          <option value="deep">Deep Recon + Exploit Chaining</option>
          <option value="compliance">PCI-DSS / OWASP Compliance</option>
        </select>

        <button
          type="submit"
          disabled={isLoading}
          className="w-full md:w-auto px-5 py-2.5 bg-emerald-500 hover:bg-emerald-400 text-black font-semibold text-sm rounded-lg flex items-center justify-center gap-2 transition-all shadow-lg shadow-emerald-500/20 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
        >
          {isLoading ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              <span>Scanning...</span>
            </>
          ) : (
            <>
              <Play className="w-4 h-4 fill-black" />
              <span>Start Autonomous Scan</span>
            </>
          )}
        </button>
      </form>

      {/* Preset target buttons & error alerts */}
      <div className="mt-3 flex flex-wrap items-center justify-between text-xs text-gray-400 gap-2">
        <div className="flex items-center gap-2">
          <span className="flex items-center gap-1 text-gray-500 font-medium">
            <Sparkles className="w-3.5 h-3.5 text-emerald-400" />
            Safe Test Targets:
          </span>
          <button
            type="button"
            onClick={() => setPreset("https://example.com")}
            className="px-2 py-0.5 rounded bg-[#1F2937] hover:bg-emerald-950 hover:text-emerald-300 transition-colors font-mono"
          >
            example.com
          </button>
          <button
            type="button"
            onClick={() => setPreset("https://google.com")}
            className="px-2 py-0.5 rounded bg-[#1F2937] hover:bg-emerald-950 hover:text-emerald-300 transition-colors font-mono"
          >
            google.com
          </button>
        </div>

        <span className="text-[11px] text-gray-500">
          Strictly Non-Destructive Probes • RFC1918 Private IP Guardrail Active
        </span>
      </div>

      {error && (
        <div className="mt-3 p-3 bg-red-950/50 border border-red-800/80 rounded-lg text-red-200 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0 text-red-400" />
          <span>{error}</span>
        </div>
      )}
    </div>
  );
};
