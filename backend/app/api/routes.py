from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Response
from fastapi.responses import HTMLResponse, PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from typing import List, Optional
import asyncio
import json

from app.database import get_db, AsyncSessionLocal
from app.models.scan import Scan
from app.models.finding import Finding
from app.models.graph import GraphNode, GraphEdge
from app.models.patch import Patch
from app.schemas.scan import ScanCreate, ScanSummary, ScanDetail
from app.core.validator import validate_and_normalize_target, TargetValidationError
from app.core.agent import SecurityAgent
from app.core.sandbox import sandbox_runner

router = APIRouter(prefix="/api", tags=["Scans"])

async def execute_agent_scan(scan_id: str):
    """Background task orchestrating autonomous scan execution."""
    try:
        async with AsyncSessionLocal() as db:
            res = await db.execute(
                select(Scan)
                .options(
                    selectinload(Scan.findings),
                    selectinload(Scan.nodes),
                    selectinload(Scan.edges),
                    selectinload(Scan.patches)
                )
                .where(Scan.id == scan_id)
            )
            scan = res.scalar_one_or_none()
            if not scan:
                return
            agent = SecurityAgent(scan, db)
            await agent.run()
    except Exception as e:
        import logging
        logging.getLogger("hackerops.routes").exception(f"Fatal error in execute_agent_scan {scan_id}: {e}")

@router.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "HackerOps Agent API",
        "docker_sandbox_active": sandbox_runner.docker_available,
        "mode": "production" if sandbox_runner.docker_available else "native_sandboxed"
    }

@router.post("/scans", response_model=ScanSummary)
async def create_scan(payload: ScanCreate, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    try:
        norm_url, hostname, resolved_ip = validate_and_normalize_target(payload.target)
    except TargetValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Target validation failed: {str(e)}")

    scan = Scan(
        target_url=norm_url,
        target_host=hostname,
        resolved_ip=resolved_ip,
        scan_depth=payload.scan_depth,
        status="pending"
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Launch autonomous agent as an asynchronous background task
    asyncio.create_task(execute_agent_scan(scan.id))

    return scan

@router.get("/scans", response_model=List[ScanSummary])
async def list_scans(limit: int = 20, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Scan).order_by(Scan.created_at.desc()).limit(limit)
    )
    return result.scalars().all()

@router.get("/scans/{scan_id}", response_model=ScanDetail)
async def get_scan_detail(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Scan)
        .options(
            selectinload(Scan.findings),
            selectinload(Scan.nodes),
            selectinload(Scan.edges),
            selectinload(Scan.patches)
        )
        .where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@router.get("/scans/{scan_id}/report")
async def generate_audit_report(scan_id: str, format: str = "markdown", db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Scan)
        .options(
            selectinload(Scan.findings),
            selectinload(Scan.patches)
        )
        .where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = scan.findings
    patches = scan.patches

    if format == "json":
        data = {
            "scan_id": scan.id,
            "target_url": scan.target_url,
            "target_host": scan.target_host,
            "resolved_ip": scan.resolved_ip,
            "risk_score": scan.risk_score,
            "compliance_grade": scan.compliance_grade,
            "status": scan.status,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity,
                    "cvss_score": f.cvss_score,
                    "owasp_category": f.owasp_category,
                    "pci_dss_ref": f.pci_dss_ref,
                    "description": f.description,
                    "evidence": f.evidence,
                    "remediation_hint": f.remediation_hint
                }
                for f in findings
            ],
            "patches": [
                {
                    "patch_type": p.patch_type,
                    "title": p.title,
                    "file_target": p.file_target,
                    "diff_content": p.diff_content,
                    "explanation": p.explanation
                }
                for p in patches
            ]
        }
        return Response(content=json.dumps(data, indent=2), media_type="application/json")

    elif format == "html":
        rows = "".join([
            f"""<tr class="border-b border-gray-800">
                <td class="p-3"><span class="px-2 py-1 rounded text-xs font-bold {'bg-red-900 text-red-200' if f.severity in ('CRITICAL', 'HIGH') else 'bg-yellow-900 text-yellow-200'}">{f.severity}</span></td>
                <td class="p-3 font-semibold">{f.title}</td>
                <td class="p-3 font-mono text-sm">{f.cvss_score}</td>
                <td class="p-3 text-xs text-gray-400">{f.owasp_category or '-'}</td>
                <td class="p-3 text-sm">{f.description}</td>
            </tr>"""
            for f in findings
        ])
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>HackerOps Security Audit Report - {scan.target_host}</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-950 text-gray-100 p-8 font-sans">
    <div class="max-w-5xl mx-auto space-y-6">
        <header class="border-b border-gray-800 pb-6 flex justify-between items-center">
            <div>
                <h1 class="text-3xl font-extrabold text-emerald-400">HackerOps Security Audit</h1>
                <p class="text-gray-400 mt-1">Target: <span class="font-mono text-emerald-300">{scan.target_url}</span></p>
            </div>
            <div class="text-right">
                <div class="text-4xl font-black {'text-emerald-400' if scan.compliance_grade in ('A+', 'A') else 'text-red-500'}">Grade {scan.compliance_grade}</div>
                <div class="text-sm text-gray-400">Risk Score: {scan.risk_score}/100</div>
            </div>
        </header>

        <section class="bg-gray-900 rounded-lg p-5 border border-gray-800">
            <h2 class="text-xl font-bold text-gray-200 mb-4">Vulnerability Findings ({len(findings)})</h2>
            <div class="overflow-x-auto">
                <table class="w-full text-left">
                    <thead class="bg-gray-800 text-gray-400 text-xs uppercase">
                        <tr>
                            <th class="p-3">Severity</th>
                            <th class="p-3">Title</th>
                            <th class="p-3">CVSS</th>
                            <th class="p-3">OWASP</th>
                            <th class="p-3">Description</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows}
                    </tbody>
                </table>
            </div>
        </section>

        <section class="bg-gray-900 rounded-lg p-5 border border-gray-800">
            <h2 class="text-xl font-bold text-gray-200 mb-4">Auto-Remediation Patches ({len(patches)})</h2>
            {"".join([f'''<div class="mb-4">
                <h3 class="text-sm font-mono text-emerald-400">{p.title} ({p.file_target})</h3>
                <pre class="bg-black text-gray-300 p-4 rounded text-xs overflow-x-auto mt-2 font-mono">{p.diff_content}</pre>
            </div>''' for p in patches])}
        </section>
    </div>
</body>
</html>"""
        return HTMLResponse(content=html)

    else:
        # Default Markdown
        md = f"""# HackerOps Autonomous Security Assessment Report
**Target URL:** {scan.target_url}  
**Resolved IP:** {scan.resolved_ip}  
**Compromise Risk Score:** {scan.risk_score}/100  
**Compliance Grade:** {scan.compliance_grade}  
**Scan Status:** {scan.status}  

---

## 1. Discovered Vulnerabilities ({len(findings)})

"""
        for f in findings:
            md += f"""### [{f.severity}] {f.title} (CVSS: {f.cvss_score})
- **OWASP Category:** {f.owasp_category or 'N/A'}
- **PCI-DSS Ref:** {f.pci_dss_ref or 'N/A'}
- **Description:** {f.description}
- **Evidence:** `{f.evidence}`
- **Remediation Hint:** {f.remediation_hint}

"""

        md += f"""---

## 2. Defensive Patches ({len(patches)})

"""
        for p in patches:
            md += f"""### {p.title} (`{p.file_target}`)
*{p.explanation}*

```{p.patch_type}
{p.diff_content}
```

"""
        return PlainTextResponse(content=md, media_type="text/markdown")
