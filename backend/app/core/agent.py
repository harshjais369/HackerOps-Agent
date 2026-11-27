import asyncio
import logging
import uuid
from datetime import datetime
from typing import Dict, Any, List, Callable, Awaitable, Optional

from sqlalchemy.ext.asyncio import AsyncSession
from app.models.scan import Scan
from app.models.finding import Finding
from app.models.graph import GraphNode, GraphEdge
from app.models.patch import Patch
from app.core.scanners import (
    scan_osint_dns,
    scan_headers_and_tls,
    scan_cors,
    scan_sensitive_paths,
    scan_ports_and_services
)
from app.core.patchgen import PatchGenerator
from app.config import settings

logger = logging.getLogger("hackerops.agent")

class ConnectionManager:
    """Manages active WebSockets for real-time live streaming."""
    def __init__(self):
        # scan_id -> set of websocket instances
        self.active_connections: Dict[str, set] = {}

    async def connect(self, scan_id: str, websocket):
        await websocket.accept()
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = set()
        self.active_connections[scan_id].add(websocket)

    def disconnect(self, scan_id: str, websocket):
        if scan_id in self.active_connections:
            self.active_connections[scan_id].discard(websocket)
            if not self.active_connections[scan_id]:
                del self.active_connections[scan_id]

    async def broadcast(self, scan_id: str, message: Dict[str, Any]):
        if scan_id in self.active_connections:
            dead_sockets = set()
            for ws in self.active_connections[scan_id]:
                try:
                    await ws.send_json(message)
                except Exception:
                    dead_sockets.add(ws)
            for ws in dead_sockets:
                self.active_connections[scan_id].discard(ws)

manager = ConnectionManager()


class SecurityAgent:
    """
    Autonomous multi-step cybersecurity agent.
    Executes non-destructive state machine:
    INIT -> PASSIVE_OSINT -> HEADER_TLS_AUDIT -> PORT_RECON -> SURFACE_MAPPING -> CORRELATE_CHAINS -> PATCH_GEN -> COMPLETE
    """
    def __init__(self, scan: Scan, db: AsyncSession):
        self.scan = scan
        self.db = db
        self.scan_id = scan.id
        self.target_url = scan.target_url
        self.target_host = scan.target_host
        self.findings: List[Dict[str, Any]] = []
        self.nodes: List[Dict[str, Any]] = []
        self.edges: List[Dict[str, Any]] = []
        self.patches: List[Dict[str, Any]] = []

    async def emit_event(self, event_type: str, data: Dict[str, Any]):
        """Broadcasts event to WebSocket and records agent progress."""
        payload = {
            "type": event_type,
            "scan_id": self.scan_id,
            "timestamp": datetime.utcnow().isoformat(),
            "data": data
        }
        await manager.broadcast(self.scan_id, payload)

    async def emit_log(self, message: str, level: str = "INFO"):
        await self.emit_event("log", {
            "message": message,
            "level": level,
            "time": datetime.utcnow().strftime("%H:%M:%S")
        })

    async def emit_node(self, node_id: str, node_type: str, label: str, severity: str = None, metadata: dict = None):
        if any(n["id"] == node_id for n in self.nodes):
            return
        node_data = {
            "id": node_id,
            "scan_id": self.scan_id,
            "node_type": node_type,
            "label": label,
            "severity": severity,
            "node_metadata": metadata or {}
        }
        self.nodes.append(node_data)
        # Save to DB
        db_node = GraphNode(
            id=node_id,
            scan_id=self.scan_id,
            node_type=node_type,
            label=label,
            severity=severity,
            node_metadata=metadata or {}
        )
        self.db.add(db_node)
        await self.db.commit()
        await self.emit_event("graph_node", node_data)

    async def emit_edge(self, edge_id: str, source: str, target: str, label: str = None):
        unique_edge_id = f"edge-{uuid.uuid4().hex[:12]}"
        edge_data = {
            "id": unique_edge_id,
            "scan_id": self.scan_id,
            "source_id": source,
            "target_id": target,
            "label": label,
            "animated": True
        }
        self.edges.append(edge_data)
        db_edge = GraphEdge(
            id=unique_edge_id,
            scan_id=self.scan_id,
            source_id=source,
            target_id=target,
            label=label,
            animated=True
        )
        self.db.add(db_edge)
        await self.db.commit()
        await self.emit_event("graph_edge", edge_data)

    async def run(self):
        try:
            self.scan.status = "running"
            await self.db.commit()

            # --- STEP 1: INIT ---
            await self.emit_log(f"[AGENT] Initializing autonomous assessment for target: {self.target_url}", "AGENT")
            await self.emit_event("status", {"state": "INIT", "progress": 5})
            
            # Root Node in Attack Graph
            root_node_id = f"target-{self.scan_id[:8]}"
            await self.emit_node(root_node_id, "target", f"Target: {self.target_host}", "INFO", {"url": self.target_url, "ip": self.scan.resolved_ip})
            await asyncio.sleep(0.5)

            # --- STEP 2: PASSIVE_OSINT ---
            await self.emit_log(f"[OSINT] Querying DNS zone records, SPF, DMARC, and checking CNAME dangling takeover indicators...", "INFO")
            await self.emit_event("status", {"state": "PASSIVE_OSINT", "progress": 20})
            osint_res = await scan_osint_dns(self.target_host)
            
            # Add DNS Node
            dns_node_id = f"dns-{self.scan_id[:8]}"
            await self.emit_node(dns_node_id, "service", f"DNS Zone ({len(osint_res['metadata'].get('a_records', []))} IPs)", "INFO", osint_res["metadata"])
            await self.emit_edge(f"e-target-dns", root_node_id, dns_node_id, "Resolves via")

            await self._process_findings(osint_res["findings"], dns_node_id)
            await asyncio.sleep(0.4)

            # --- STEP 3: HEADER_TLS_AUDIT ---
            await self.emit_log(f"[AUDIT] Probing HTTP response headers, CSP directives, HSTS, and SSL/TLS certificate...", "INFO")
            await self.emit_event("status", {"state": "HEADER_TLS_AUDIT", "progress": 40})
            headers_res = await scan_headers_and_tls(self.target_url, self.target_host)

            tls_node_id = f"tls-{self.scan_id[:8]}"
            tls_ver = headers_res["metadata"].get("tls_version") or "TLS Active"
            await self.emit_node(tls_node_id, "service", f"Web Security ({tls_ver})", "INFO", headers_res["metadata"])
            await self.emit_edge(f"e-target-tls", root_node_id, tls_node_id, "Serves HTTPS")

            await self._process_findings(headers_res["findings"], tls_node_id)
            await asyncio.sleep(0.4)

            # --- STEP 4: PORT_RECON ---
            await self.emit_log(f"[RECON] Executing non-destructive port recon inside isolated sandbox...", "INFO")
            await self.emit_event("status", {"state": "PORT_RECON", "progress": 60})
            ports_res = await scan_ports_and_services(self.target_host)
            
            for p in ports_res["metadata"].get("ports", []):
                port_id = f"port-{p['port']}-{self.scan_id[:6]}"
                await self.emit_node(port_id, "port", f"Port {p['port']} ({p['service']})", "LOW", p)
                await self.emit_edge(f"e-target-{port_id}", root_node_id, port_id, "Exposes")

            await self._process_findings(ports_res["findings"], root_node_id)
            await asyncio.sleep(0.4)

            # --- STEP 5: SURFACE_MAPPING (CORS & Sensitive Paths) ---
            await self.emit_log(f"[PROBE] Testing CORS preflight origins and auditing safe read-only sensitive paths...", "INFO")
            await self.emit_event("status", {"state": "SURFACE_MAPPING", "progress": 75})
            cors_res = await scan_cors(self.target_url)
            paths_res = await scan_sensitive_paths(self.target_url)

            surface_node_id = f"surface-{self.scan_id[:8]}"
            await self.emit_node(surface_node_id, "service", "API & Web Surface", "INFO")
            await self.emit_edge(f"e-target-surface", root_node_id, surface_node_id, "Maps")

            await self._process_findings(cors_res["findings"], surface_node_id)
            await self._process_findings(paths_res["findings"], surface_node_id)
            await asyncio.sleep(0.4)

            # --- STEP 6: CORRELATE_CHAINS (Exploit-Chain Synthesis) ---
            await self.emit_log(f"[AGENT] Correlating findings into plausible attack paths and calculating threat impact...", "AGENT")
            await self.emit_event("status", {"state": "CORRELATE_CHAINS", "progress": 85})
            await self._correlate_attack_chains()
            await asyncio.sleep(0.4)

            # --- STEP 7: PATCH_GEN ---
            await self.emit_log(f"[PATCHGEN] Synthesizing copy-paste defensive patches for discovered vulnerabilities...", "AGENT")
            await self.emit_event("status", {"state": "PATCH_GEN", "progress": 92})
            raw_patches = await PatchGenerator.synthesize_all_patches(self.findings, self.target_host)
            for p in raw_patches:
                db_patch = Patch(
                    scan_id=self.scan_id,
                    patch_type=p["patch_type"],
                    title=p["title"],
                    file_target=p["file_target"],
                    diff_content=p["diff_content"],
                    explanation=p["explanation"]
                )
                self.db.add(db_patch)
                self.patches.append(p)
                await self.emit_event("patch", p)

            # --- STEP 8: COMPLETE & SCORING ---
            risk_score, grade = self._calculate_scores()
            self.scan.risk_score = risk_score
            self.scan.compliance_grade = grade
            self.scan.status = "completed"
            self.scan.completed_at = datetime.utcnow()
            await self.db.commit()

            await self.emit_log(f"[COMPLETE] Assessment finished! Compromise Risk Score: {risk_score}/100 (Grade: {grade})", "AGENT")
            await self.emit_event("status", {"state": "COMPLETE", "progress": 100})
            await self.emit_event("complete", {
                "risk_score": risk_score,
                "compliance_grade": grade,
                "total_findings": len(self.findings),
                "total_patches": len(self.patches)
            })

        except Exception as e:
            logger.exception(f"Error during scan {self.scan_id}: {e}")
            try:
                await self.db.rollback()
            except Exception:
                pass
            self.scan.status = "failed"
            self.scan.error_message = str(e)
            try:
                await self.db.commit()
            except Exception:
                pass
            await self.emit_log(f"[ERROR] Scan failed: {str(e)}", "WARN")
            await self.emit_event("error", {"message": str(e)})

    async def _process_findings(self, raw_findings: List[Dict[str, Any]], parent_node_id: str):
        for f in raw_findings:
            self.findings.append(f)
            # Create DB Finding
            db_finding = Finding(
                scan_id=self.scan_id,
                title=f["title"],
                description=f["description"],
                severity=f["severity"],
                cvss_score=f["cvss_score"],
                owasp_category=f.get("owasp_category"),
                pci_dss_ref=f.get("pci_dss_ref"),
                category=f["category"],
                evidence=f.get("evidence"),
                remediation_hint=f.get("remediation_hint")
            )
            self.db.add(db_finding)
            await self.db.commit()
            await self.emit_event("finding", f)

            # Add Vulnerability Node to Graph
            vuln_node_id = f"vuln-{uuid.uuid4().hex[:8]}"
            await self.emit_node(vuln_node_id, "vulnerability", f["title"], f["severity"], {
                "cvss": f["cvss_score"],
                "owasp": f.get("owasp_category"),
                "category": f["category"]
            })
            await self.emit_edge(f"e-{parent_node_id}-{vuln_node_id}", parent_node_id, vuln_node_id, "Exposes Flaw")

    async def _correlate_attack_chains(self):
        """Identifies synergistic vulnerabilities and synthesizes an Impact node."""
        categories = {f["category"] for f in self.findings}
        severities = {f["severity"] for f in self.findings}

        # Chain 1: Missing CSP + Permissive CORS
        if "cors" in categories and "headers" in categories:
            chain_id = f"impact-xss-{self.scan_id[:6]}"
            await self.emit_node(
                chain_id,
                "impact",
                "Chained Exploit: Cross-Origin Data Exfiltration",
                "HIGH",
                {"detail": "Permissive CORS combined with missing CSP allows injected or third-party scripts to exfiltrate authenticated session state."}
            )
            # Connect to related vuln nodes
            for n in [nd for nd in self.nodes if nd["node_type"] == "vulnerability" and nd.get("node_metadata", {}).get("category") in ("cors", "headers")][:2]:
                await self.emit_edge(f"e-{n['id']}-{chain_id}", n["id"], chain_id, "Enables Attack Path")

        # Chain 2: Exposed database or sensitive files
        if "CRITICAL" in severities or "HIGH" in severities:
            takeover_id = f"impact-breach-{self.scan_id[:6]}"
            await self.emit_node(
                takeover_id,
                "impact",
                "Direct Infrastructure Compromise Risk",
                "CRITICAL",
                {"detail": "Critical exposure (e.g. database port or .env secrets) enables potential remote data extraction or backend compromise."}
            )
            for n in [nd for nd in self.nodes if nd["node_type"] == "vulnerability" and nd["severity"] in ("CRITICAL", "HIGH")][:2]:
                await self.emit_edge(f"e-{n['id']}-{takeover_id}", n["id"], takeover_id, "Escalates to")

    def _calculate_scores(self) -> (float, str):
        if not self.findings:
            return 0.0, "A+"

        # Weighted calculation based on CVSS scores
        weights = {"CRITICAL": 30, "HIGH": 18, "MEDIUM": 8, "LOW": 3, "INFO": 0}
        total_risk = 0.0
        for f in self.findings:
            sev = f.get("severity", "LOW")
            cvss = f.get("cvss_score", 3.0)
            total_risk += weights.get(sev, 5) * (cvss / 10.0)

        # Cap at 100.0
        risk_score = round(min(100.0, total_risk), 1)

        # Grade calculation
        if risk_score <= 10.0:
            grade = "A"
        elif risk_score <= 25.0:
            grade = "B"
        elif risk_score <= 50.0:
            grade = "C"
        elif risk_score <= 75.0:
            grade = "D"
        else:
            grade = "F"

        return risk_score, grade
