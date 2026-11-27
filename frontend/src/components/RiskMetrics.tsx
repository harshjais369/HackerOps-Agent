"use client";

import React from "react";
import { ShieldAlert, Award, FileCheck2, AlertCircle } from "lucide-react";
import { Finding } from "@/lib/types";

interface RiskMetricsProps {
  riskScore: number;
  complianceGrade: string;
  findings: Finding[];
}

export const RiskMetrics: React.FC<RiskMetricsProps> = ({
  riskScore,
  complianceGrade,
  findings,
}) => {
  // Count by severity
  const criticals = findings.filter((f) => f.severity === "CRITICAL").length;
  const highs = findings.filter((f) => f.severity === "HIGH").length;
  const mediums = findings.filter((f) => f.severity === "MEDIUM").length;
  const lows = findings.filter((f) => f.severity === "LOW").length;

  const getScoreColor = (score: number) => {
    if (score <= 20) return { text: "text-emerald-400", bg: "bg-emerald-500", border: "border-emerald-500" };
    if (score <= 50) return { text: "text-amber-400", bg: "bg-amber-500", border: "border-amber-500" };
    return { text: "text-red-500", bg: "bg-red-500", border: "border-red-500" };
  };

  const scoreTheme = getScoreColor(riskScore);

  return (
    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
      {/* 1. Compromise Risk Gauge */}
      <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4 flex flex-col justify-between shadow-lg">
        <div className="flex items-center justify-between text-xs font-mono text-gray-400">
          <span className="flex items-center gap-1.5 uppercase font-semibold">
            <ShieldAlert className={`w-4 h-4 ${scoreTheme.text}`} />
            Risk Score
          </span>
          <span className="text-[10px] text-gray-500">CVSS v3.1</span>
        </div>

        <div className="my-2 flex items-baseline gap-2">
          <div className={`text-3xl font-black font-mono tracking-tight ${scoreTheme.text}`}>
            {riskScore.toFixed(1)}
          </div>
          <span className="text-gray-500 text-xs font-mono">/ 100</span>
        </div>

        {/* Progress bar */}
        <div className="w-full bg-[#1F2937] h-2 rounded-full overflow-hidden">
          <div
            className={`h-full ${scoreTheme.bg} transition-all duration-500 rounded-full`}
            style={{ width: `${Math.min(100, Math.max(5, riskScore))}%` }}
          />
        </div>
      </div>

      {/* 2. Compliance Grade */}
      <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4 flex flex-col justify-between shadow-lg">
        <div className="flex items-center justify-between text-xs font-mono text-gray-400">
          <span className="flex items-center gap-1.5 uppercase font-semibold">
            <Award className="w-4 h-4 text-emerald-400" />
            Compliance Grade
          </span>
          <span className="text-[10px] text-gray-500">OWASP / PCI</span>
        </div>

        <div className="my-2 flex items-center gap-3">
          <div
            className={`w-10 h-10 shrink-0 rounded-lg border-2 flex items-center justify-center font-mono font-black text-xl shadow-inner ${
              complianceGrade.startsWith("A")
                ? "border-emerald-500 text-emerald-400 bg-emerald-950/40"
                : complianceGrade.startsWith("B")
                ? "border-cyan-500 text-cyan-400 bg-cyan-950/40"
                : complianceGrade.startsWith("C")
                ? "border-yellow-500 text-yellow-400 bg-yellow-950/40"
                : "border-red-500 text-red-500 bg-red-950/40"
            }`}
          >
            {complianceGrade || "A"}
          </div>
          <div className="text-[11px] text-gray-300 leading-snug">
            {complianceGrade.startsWith("A")
              ? "Defensive baseline meets enterprise hygiene standards."
              : "Security misconfigurations detected; patch recommended."}
          </div>
        </div>

        <div className="text-[10px] font-mono text-gray-500 flex justify-between">
          <span>PCI-DSS v4.0</span>
          <span className={criticals === 0 ? "text-emerald-400 font-bold" : "text-red-400 font-bold"}>
            {criticals === 0 ? "PASSED" : "FAILED REQS"}
          </span>
        </div>
      </div>

      {/* 3. Severity Breakdown Stats */}
      <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4 flex flex-col justify-between shadow-lg font-mono">
        <div className="flex items-center justify-between text-xs text-gray-400">
          <span className="flex items-center gap-1.5 uppercase font-semibold">
            <FileCheck2 className="w-4 h-4 text-sky-400" />
            Findings ({findings.length})
          </span>
        </div>

        <div className="grid grid-cols-4 gap-1.5 my-2 text-center">
          <div className="bg-red-950/40 border border-red-900/60 rounded p-1.5">
            <div className="text-[10px] text-red-400 font-bold">CRIT</div>
            <div className="text-sm font-black text-red-200">{criticals}</div>
          </div>
          <div className="bg-amber-950/40 border border-amber-900/60 rounded p-1.5">
            <div className="text-[10px] text-amber-400 font-bold">HIGH</div>
            <div className="text-sm font-black text-amber-200">{highs}</div>
          </div>
          <div className="bg-yellow-950/40 border border-yellow-900/60 rounded p-1.5">
            <div className="text-[10px] text-yellow-400 font-bold">MED</div>
            <div className="text-sm font-black text-yellow-200">{mediums}</div>
          </div>
          <div className="bg-blue-950/40 border border-blue-900/60 rounded p-1.5">
            <div className="text-[10px] text-blue-400 font-bold">LOW</div>
            <div className="text-sm font-black text-blue-200">{lows}</div>
          </div>
        </div>

        <div className="text-[10px] text-gray-500 flex justify-between">
          <span>OWASP Top 10</span>
          <span className="text-gray-300">{findings.length > 0 ? "Flagged" : "Clear"}</span>
        </div>
      </div>
    </div>
  );
};
