export function getApiBaseUrl(): string {
  if (typeof window !== "undefined") {
    // In the browser, use relative path so Next.js rewrites proxy to backend cleanly
    return "";
  }
  return process.env.BACKEND_INTERNAL_URL || "http://127.0.0.1:8000";
}

export async function createScan(target: string, scan_depth: string = "standard") {
  const baseUrl = getApiBaseUrl();
  const res = await fetch(`${baseUrl}/api/scans`, {
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
  const baseUrl = getApiBaseUrl();
  const res = await fetch(`${baseUrl}/api/scans/${scanId}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch scan detail (${res.status})`);
  }
  return res.json();
}

export async function fetchRecentScans() {
  const baseUrl = getApiBaseUrl();
  const res = await fetch(`${baseUrl}/api/scans?limit=10`);
  if (!res.ok) return [];
  return res.json();
}

export function getReportDownloadUrl(scanId: string, format: "markdown" | "html" | "json") {
  const baseUrl = getApiBaseUrl();
  return `${baseUrl}/api/scans/${scanId}/report?format=${format}`;
}
