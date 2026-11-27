export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface Finding {
  id?: string;
  title: string;
  description: string;
  severity: Severity;
  cvss_score: number;
  owasp_category?: string;
  pci_dss_ref?: string;
  category: string;
  evidence?: string;
  remediation_hint?: string;
  created_at?: string;
}

export interface Patch {
  id?: string;
  patch_type: "nginx" | "fastapi" | "express" | "dns" | "docker" | string;
  title: string;
  file_target: string;
  diff_content: string;
  explanation: string;
}

export interface GraphNodeData {
  id: string;
  scan_id?: string;
  node_type: "target" | "service" | "port" | "vulnerability" | "impact";
  label: string;
  severity?: Severity;
  node_metadata?: Record<string, any>;
}

export interface GraphEdgeData {
  id: string;
  source_id: string;
  target_id: string;
  label?: string;
  animated?: boolean;
}

export interface TerminalLog {
  id: string;
  message: string;
  level: "INFO" | "AGENT" | "WARN" | "VULN" | "ERROR";
  time: string;
}

export interface ScanState {
  id: string;
  target_url: string;
  target_host: string;
  resolved_ip?: string;
  status: "pending" | "running" | "completed" | "failed";
  risk_score: number;
  compliance_grade: string;
  error_message?: string;
  findings: Finding[];
  nodes: GraphNodeData[];
  edges: GraphEdgeData[];
  patches: Patch[];
  logs: TerminalLog[];
  progress: number;
  currentState: string;
}
