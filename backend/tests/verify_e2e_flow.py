import asyncio
import json
import httpx
import websockets
import sys

API_BASE = "http://127.0.0.1:8000"
WS_BASE = "ws://127.0.0.1:8000"
FRONTEND_URL = "http://127.0.0.1:3000"

async def run_e2e_verification():
    print("=== [1] Verifying Frontend and Backend Health ===")
    async with httpx.AsyncClient(timeout=10.0) as client:
        # Check backend
        resp = await client.get(f"{API_BASE}/api/health")
        assert resp.status_code == 200, f"Backend health failed: {resp.text}"
        health_data = resp.json()
        print(f"Backend Health: OK ({health_data['service']} - {health_data['mode']})")

        # Check frontend
        resp_fe = await client.get(FRONTEND_URL)
        assert resp_fe.status_code == 200, f"Frontend check failed: {resp_fe.status_code}"
        print(f"Frontend HTTP: OK (Status 200)")

    print("\n=== [2] Triggering Autonomous Scan for https://example.com ===")
    scan_id = None
    async with httpx.AsyncClient(timeout=10.0) as client:
        scan_resp = await client.post(
            f"{API_BASE}/api/scans",
            json={"target": "https://example.com", "scan_depth": "quick"}
        )
        assert scan_resp.status_code == 200, f"Scan creation failed: {scan_resp.text}"
        scan_json = scan_resp.json()
        scan_id = scan_json["id"]
        print(f"Scan Created: ID={scan_id}, Target={scan_json['target_url']}, Status={scan_json['status']}")

    print(f"\n=== [3] Connecting to WebSocket: {WS_BASE}/ws/scans/{scan_id} ===")
    logs_received = []
    nodes_received = []
    findings_received = []
    patches_received = []

    try:
        async with websockets.connect(f"{WS_BASE}/ws/scans/{scan_id}") as ws:
            print("WebSocket Connected! Streaming live agent events...")
            while True:
                try:
                    raw_msg = await asyncio.wait_for(ws.recv(), timeout=15.0)
                    event = json.loads(raw_msg)
                    ev_type = event.get("type")
                    data = event.get("data", {})

                    if ev_type == "log":
                        logs_received.append(data)
                        print(f"  [STREAM LOG] {data.get('message')}")
                    elif ev_type == "graph_node":
                        nodes_received.append(data)
                        print(f"  [GRAPH NODE] +{data.get('node_type', '').upper()}: {data.get('label')}")
                    elif ev_type == "finding":
                        findings_received.append(data)
                        print(f"  [VULNERABILITY] [{data.get('severity')}] {data.get('title')} (CVSS {data.get('cvss_score')})")
                    elif ev_type == "patch":
                        patches_received.append(data)
                        print(f"  [PATCHGEN] Synthesized: {data.get('title')} ({data.get('patch_type')})")
                    elif ev_type == "complete":
                        print(f"\n=== [4] Scan Completed Event Received! ===")
                        print(f"Risk Score: {data.get('risk_score')}/100 | Grade: {data.get('compliance_grade')}")
                        break
                    elif ev_type == "error":
                        print(f"ERROR Event: {data}")
                        break
                except asyncio.TimeoutError:
                    print("WebSocket idle, checking database for completed status...")
                    break
    except Exception as e:
        print(f"WebSocket Notice: {e}")

    print("\n=== [5] Polling Database for Completion & Final Telemetry ===")
    detail = None
    async with httpx.AsyncClient(timeout=15.0) as client:
        for _ in range(30):
            detail_resp = await client.get(f"{API_BASE}/api/scans/{scan_id}")
            if detail_resp.status_code == 200:
                detail = detail_resp.json()
                if detail["status"] in ("completed", "failed"):
                    break
            await asyncio.sleep(1)

        print(f"DB Record Status: {detail['status']}")
        print(f"Final Risk Score: {detail['risk_score']}/100")
        print(f"Compliance Grade: {detail['compliance_grade']}")
        print(f"Persisted Findings: {len(detail['findings'])}")
        print(f"Persisted Nodes: {len(detail['nodes'])}")
        print(f"Persisted Edges: {len(detail['edges'])}")
        print(f"Persisted Patches: {len(detail['patches'])}")

        assert detail["status"] == "completed", f"Scan not completed: {detail.get('error_message')}"
        assert len(detail["findings"]) > 0, "Expected findings to be saved in DB"
        assert len(detail["patches"]) > 0, "Expected patches to be saved in DB"
        assert len(detail["nodes"]) > 0, "Expected graph nodes to be saved in DB"

        # Check Report endpoints
        md_resp = await client.get(f"{API_BASE}/api/scans/{scan_id}/report?format=markdown")
        assert md_resp.status_code == 200
        assert "HackerOps Autonomous Security Assessment Report" in md_resp.text
        print("Markdown Report Endpoint: Verified OK")

        html_resp = await client.get(f"{API_BASE}/api/scans/{scan_id}/report?format=html")
        assert html_resp.status_code == 200
        assert "HackerOps Security Audit" in html_resp.text
        print("HTML Report Endpoint: Verified OK")

        json_resp = await client.get(f"{API_BASE}/api/scans/{scan_id}/report?format=json")
        assert json_resp.status_code == 200
        print("JSON Telemetry Endpoint: Verified OK")

    print("\n=======================================================")
    print("SUCCESS: Full End-to-End Autonomous Lifecycle Verified!")
    print(f"Total Logs Streamed: {len(logs_received)}")
    print(f"Total Graph Nodes Generated: {len(nodes_received)}")
    print(f"Total Vulnerabilities Discovered: {len(findings_received)}")
    print(f"Total Defensive Patches Synthesized: {len(patches_received)}")
    print("=======================================================")

if __name__ == "__main__":
    asyncio.run(run_e2e_verification())
