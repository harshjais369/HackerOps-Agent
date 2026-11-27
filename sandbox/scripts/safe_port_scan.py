#!/usr/bin/env python3
"""
Safe Read-Only Nmap Top-Ports Scanner Wrapper.
Runs restricted, non-intrusive banner checks and outputs normalized JSON.
Strictly read-only: no aggressive scripts, no brute force, no exploit payloads.
"""
import sys
import json
import subprocess
import xml.etree.ElementTree as ET

def scan_ports(target_host: str, top_ports: int = 50):
    cmd = [
        "nmap",
        "-sV",
        "--version-light",
        "-Pn",
        "-T4",
        "--max-retries", "1",
        "--host-timeout", "10s",
        f"--top-ports={top_ports}",
        "--open",
        "-oX", "-",
        target_host
    ]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, text=True)
        if proc.returncode != 0 and not proc.stdout:
            return {"status": "error", "message": proc.stderr.strip(), "ports": []}
        
        # Parse XML
        root = ET.fromstring(proc.stdout)
        open_ports = []
        for host in root.findall("host"):
            ports_elem = host.find("ports")
            if ports_elem is not None:
                for port in ports_elem.findall("port"):
                    port_id = port.get("portid")
                    proto = port.get("protocol")
                    state = port.find("state")
                    service = port.find("service")
                    if state is not None and state.get("state") == "open":
                        service_name = service.get("name", "unknown") if service is not None else "unknown"
                        product = service.get("product", "") if service is not None else ""
                        version = service.get("version", "") if service is not None else ""
                        open_ports.append({
                            "port": int(port_id),
                            "protocol": proto,
                            "service": service_name,
                            "banner": f"{product} {version}".strip()
                        })
        return {"status": "success", "target": target_host, "ports": open_ports}
    except Exception as e:
        return {"status": "error", "message": str(e), "ports": []}

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"status": "error", "message": "Missing target argument", "ports": []}))
        sys.exit(1)
    target = sys.argv[1]
    res = scan_ports(target)
    print(json.dumps(res))
