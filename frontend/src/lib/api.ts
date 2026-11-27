const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export async function createScan(target: string, scan_depth: string = "standard") {
  const res = await fetch(`${API_BASE}/api/scans`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target, scan_depth }),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({ detail: "Request failed" }));
    throw new Error(errorData.detail || `Scan creation failed with status ${res.status}`);
  }
  return res.json();
}

export async function fetchScanDetail(scanId: string) {
  const res = await fetch(`${API_BASE}/api/scans/${scanId}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch scan detail (${res.status})`);
  }
  return res.json();
}

export async function fetchRecentScans() {
  const res = await fetch(`${API_BASE}/api/scans?limit=10`);
  if (!res.ok) return [];
  return res.json();
}

export function getReportDownloadUrl(scanId: string, format: "markdown" | "html" | "json") {
  return `${API_BASE}/api/scans/${scanId}/report?format=${format}`;
}
