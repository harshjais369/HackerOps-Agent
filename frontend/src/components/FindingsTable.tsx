"use client";

import React, { useState } from "react";
import { AlertCircle, ChevronDown, ChevronUp, Search, ExternalLink, ShieldCheck } from "lucide-react";
import { Finding, Severity } from "@/lib/types";

interface FindingsTableProps {
  findings: Finding[];
}

export const FindingsTable: React.FC<FindingsTableProps> = ({ findings }) => {
  const [filterSeverity, setFilterSeverity] = useState<string>("ALL");
  const [searchTerm, setSearchTerm] = useState("");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const filtered = findings.filter((f) => {
    const matchesSev = filterSeverity === "ALL" || f.severity === filterSeverity;
    const matchesSearch =
      searchTerm === "" ||
      f.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      f.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (f.owasp_category && f.owasp_category.toLowerCase().includes(searchTerm.toLowerCase()));
    return matchesSev && matchesSearch;
  });

  const getSeverityBadge = (sev: Severity) => {
    switch (sev) {
      case "CRITICAL":
        return "bg-red-950 text-red-300 border-red-800";
      case "HIGH":
        return "bg-amber-950 text-amber-300 border-amber-800";
      case "MEDIUM":
        return "bg-yellow-950 text-yellow-300 border-yellow-800";
      case "LOW":
        return "bg-blue-950 text-blue-300 border-blue-800";
      default:
        return "bg-gray-800 text-gray-300 border-gray-700";
    }
  };

  if (findings.length === 0) {
    return (
      <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-8 text-center text-gray-500 font-mono text-xs">
        <ShieldCheck className="w-8 h-8 mx-auto mb-2 text-emerald-500 opacity-40" />
        <p className="font-semibold text-gray-400">Zero Active Findings Discovered.</p>
        <p className="text-[11px] text-gray-600 mt-1">Initiate a security assessment to populate vulnerability telemetry.</p>
      </div>
    );
  }

  return (
    <div className="bg-[#111827] border border-[#1F2937] rounded-xl overflow-hidden shadow-2xl flex flex-col font-mono text-xs">
      {/* Search & Filter Toolbar */}
      <div className="p-3 bg-[#161B22] border-b border-[#21262D] flex flex-wrap items-center justify-between gap-3">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
          <input
            type="text"
            placeholder="Filter findings by keyword, OWASP, or category..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 bg-[#0B0F19] border border-[#21262D] rounded-lg text-xs text-gray-200 placeholder-gray-500 focus:outline-none focus:border-emerald-500"
          />
        </div>

        <div className="flex items-center gap-1">
          {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
            <button
              key={sev}
              onClick={() => setFilterSeverity(sev)}
              className={`px-2.5 py-1 rounded text-[10px] font-bold transition-all ${
                filterSeverity === sev
                  ? "bg-emerald-500 text-black shadow-sm"
                  : "bg-[#21262D] text-gray-400 hover:text-gray-200"
              }`}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {/* Table Body */}
      <div className="overflow-x-auto max-h-[380px]">
        <table className="w-full text-left border-collapse">
          <thead className="bg-[#0B0F19] text-gray-400 text-[10px] uppercase border-b border-[#1F2937] sticky top-0 z-10">
            <tr>
              <th className="py-2.5 px-4">Severity</th>
              <th className="py-2.5 px-4">Vulnerability Title</th>
              <th className="py-2.5 px-4">CVSS</th>
              <th className="py-2.5 px-4">Category</th>
              <th className="py-2.5 px-4">OWASP Top 10</th>
              <th className="py-2.5 px-4 text-right">Details</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#1F2937] text-gray-300">
            {filtered.map((f, idx) => {
              const rowId = f.id || `f-${idx}`;
              const isExpanded = expandedId === rowId;
              return (
                <React.Fragment key={rowId}>
                  <tr
                    onClick={() => setExpandedId(isExpanded ? null : rowId)}
                    className="hover:bg-[#161B22]/70 cursor-pointer transition-colors"
                  >
                    <td className="py-2.5 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-black border ${getSeverityBadge(f.severity)}`}>
                        {f.severity}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 font-semibold text-gray-100 font-sans text-xs">
                      {f.title}
                    </td>
                    <td className="py-2.5 px-4 font-mono font-bold text-gray-200">
                      {f.cvss_score.toFixed(1)}
                    </td>
                    <td className="py-2.5 px-4 text-gray-400 uppercase text-[10px]">
                      {f.category}
                    </td>
                    <td className="py-2.5 px-4 text-gray-400 text-[11px] truncate max-w-[180px]">
                      {f.owasp_category || "-"}
                    </td>
                    <td className="py-2.5 px-4 text-right">
                      {isExpanded ? (
                        <ChevronUp className="w-4 h-4 text-emerald-400 ml-auto" />
                      ) : (
                        <ChevronDown className="w-4 h-4 text-gray-500 ml-auto" />
                      )}
                    </td>
                  </tr>

                  {isExpanded && (
                    <tr className="bg-[#0B0F19]/90 border-b border-[#1F2937]">
                      <td colSpan={6} className="p-4 space-y-2">
                        <div className="text-gray-300 font-sans text-xs leading-relaxed">
                          {f.description}
                        </div>
                        {f.evidence && (
                          <div className="bg-[#111827] p-2.5 rounded border border-gray-800 text-[11px]">
                            <span className="text-gray-500 font-bold block mb-1">AUDIT EVIDENCE:</span>
                            <code className="text-red-300 font-mono break-all">{f.evidence}</code>
                          </div>
                        )}
                        {f.remediation_hint && (
                          <div className="bg-emerald-950/30 p-2.5 rounded border border-emerald-900/50 text-[11px] text-emerald-300">
                            <span className="font-bold block mb-0.5 text-emerald-400">DEFENSIVE REMEDIATION:</span>
                            <span>{f.remediation_hint}</span>
                          </div>
                        )}
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};
