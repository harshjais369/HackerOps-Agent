"use client";

import React, { useState } from "react";
import { Code2, Copy, Check, Download, FileCode, ShieldCheck } from "lucide-react";
import { Patch } from "@/lib/types";

interface PatchViewerProps {
  patches: Patch[];
  targetHost?: string;
}

export const PatchViewer: React.FC<PatchViewerProps> = ({ patches, targetHost = "target" }) => {
  const [activeTab, setActiveTab] = useState(0);
  const [copied, setCopied] = useState(false);

  if (!patches || patches.length === 0) {
    return (
      <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-8 text-center text-gray-500 font-mono text-xs">
        <ShieldCheck className="w-8 h-8 mx-auto mb-2 text-emerald-500 opacity-40" />
        <p className="font-semibold text-gray-400">No Auto-Remediation Patches Generated Yet.</p>
        <p className="text-[11px] text-gray-600 mt-1">
          When high or medium severity risks are correlated, HackerOps synthesizes copy-paste configurations here.
        </p>
      </div>
    );
  }

  const currentPatch = patches[activeTab] || patches[0];

  const handleCopy = () => {
    if (!currentPatch) return;
    navigator.clipboard.writeText(currentPatch.diff_content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    if (!currentPatch) return;
    const blob = new Blob([currentPatch.diff_content], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    const filename = currentPatch.file_target.split("/").pop() || `${currentPatch.patch_type}-security.conf`;
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="bg-[#111827] border border-[#1F2937] rounded-xl overflow-hidden shadow-2xl flex flex-col font-mono text-xs">
      {/* Header with Tabs */}
      <div className="flex flex-wrap items-center justify-between px-4 py-2.5 bg-[#161B22] border-b border-[#21262D] gap-2">
        <div className="flex items-center gap-1.5 overflow-x-auto">
          <Code2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span className="font-bold text-gray-200 tracking-wider uppercase mr-2 shrink-0">
            PatchGen Auto-Remediation:
          </span>
          {patches.map((p, idx) => (
            <button
              key={idx}
              onClick={() => setActiveTab(idx)}
              className={`px-3 py-1 rounded-md transition-all font-semibold uppercase text-[10px] shrink-0 ${
                activeTab === idx
                  ? "bg-emerald-500 text-black shadow-md shadow-emerald-500/20"
                  : "bg-[#21262D] text-gray-400 hover:text-gray-200"
              }`}
            >
              {p.patch_type}
            </button>
          ))}
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-2">
          <button
            onClick={handleCopy}
            className="px-3 py-1 bg-[#21262D] hover:bg-emerald-950 hover:text-emerald-300 text-gray-200 rounded flex items-center gap-1.5 transition-colors border border-gray-700 hover:border-emerald-700"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? "Copied!" : "Copy Patch"}</span>
          </button>
          <button
            onClick={handleDownload}
            className="px-3 py-1 bg-emerald-600 hover:bg-emerald-500 text-black font-semibold rounded flex items-center gap-1.5 transition-colors shadow-sm"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download</span>
          </button>
        </div>
      </div>

      {/* Target Path & Explanation Banner */}
      <div className="px-4 py-2.5 bg-[#0D1117] border-b border-[#1F2937] flex flex-col md:flex-row md:items-center justify-between gap-1 text-[11px] text-gray-400">
        <div className="flex items-center gap-2">
          <FileCode className="w-4 h-4 text-sky-400" />
          <span>Target File:</span>
          <span className="text-emerald-400 font-semibold">{currentPatch.file_target}</span>
        </div>
        <div className="text-gray-400 italic">{currentPatch.explanation}</div>
      </div>

      {/* Code Viewer Body */}
      <div className="p-4 bg-[#0B0F19] overflow-x-auto max-h-[340px] text-gray-200 leading-relaxed selection:bg-emerald-800">
        <pre className="text-xs font-mono">{currentPatch.diff_content}</pre>
      </div>

      {/* Footer */}
      <div className="px-4 py-2 bg-[#161B22] border-t border-[#21262D] text-[10px] text-gray-500 flex justify-between items-center">
        <span>Verified Production Syntax • Drop-in Defensive Configuration</span>
        <span className="text-emerald-500">Zero Target Modifications Required</span>
      </div>
    </div>
  );
};
