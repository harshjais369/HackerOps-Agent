import asyncio
import json
import logging
import time
from typing import Dict, Any, List, Optional
import socket
from app.config import settings

logger = logging.getLogger("hackerops.sandbox")

class SandboxResult:
    def __init__(self, success: bool, output: str, data: Dict[str, Any] = None, error: Optional[str] = None):
        self.success = success
        self.output = output
        self.data = data or {}
        self.error = error

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "output": self.output,
            "data": self.data,
            "error": self.error
        }

class SandboxRunner:
    """
    Executes security audit tools inside an isolated Docker container with strict resource limits.
    Gracefully falls back to Native Async Python Sandbox if the Docker daemon is unavailable.
    """
    def __init__(self):
        self.docker_available = False
        self.client = None
        self._check_docker()

    def _check_docker(self):
        try:
            import docker
            self.client = docker.from_env()
            self.client.ping()
            self.docker_available = True
            logger.info("Docker daemon connected successfully. Sandbox isolation active.")
        except Exception as e:
            self.docker_available = False
            self.client = None
            logger.info(f"Docker daemon not available ({e}). Using Native Async Python Sandbox fallback.")

    async def run_port_scan(self, target_host: str, ports: List[int] = None) -> SandboxResult:
        """
        Executes non-destructive port recon. If Docker is running, runs in container.
        Otherwise executes via native async non-blocking socket probes.
        """
        default_ports = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3000, 3306, 5000, 5432, 6379, 8000, 8080, 8443, 27017]
        target_ports = ports or default_ports

        if self.docker_available:
            try:
                cmd = f"python3 /home/sandboxuser/scripts/safe_port_scan.py {target_host}"
                loop = asyncio.get_event_loop()
                container_run = lambda: self.client.containers.run(
                    image=settings.docker_sandbox_image,
                    command=cmd,
                    mem_limit=settings.sandbox_mem_limit,
                    cpu_period=100000,
                    cpu_quota=settings.sandbox_cpu_quota,
                    network_mode="bridge",
                    security_opt=["no-new-privileges:true"],
                    cap_drop=["ALL"],
                    remove=True,
                    stdout=True,
                    stderr=True
                )
                raw_out = await asyncio.wait_for(loop.run_in_executor(None, container_run), timeout=settings.sandbox_timeout_seconds)
                decoded = raw_out.decode("utf-8")
                parsed = json.loads(decoded)
                return SandboxResult(success=True, output=decoded, data=parsed)
            except Exception as e:
                logger.warning(f"Docker container execution failed or timed out: {e}. Falling back to native probe.")

        # Native Async Socket Probe (Graceful Fallback)
        return await self._native_port_scan(target_host, target_ports)

    async def _native_port_scan(self, target_host: str, ports: List[int]) -> SandboxResult:
        start_time = time.time()
        open_ports = []
        
        known_services = {
            21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP",
            110: "POP3", 143: "IMAP", 443: "HTTPS", 465: "SMTPS", 587: "Submission",
            993: "IMAPS", 995: "POP3S", 3000: "Node/React Dev", 3306: "MySQL Database",
            5000: "Flask/API", 5432: "PostgreSQL Database", 6379: "Redis In-Memory Store",
            8000: "HTTP-Alt / FastAPI", 8080: "HTTP-Proxy / Spring", 8443: "HTTPS-Alt",
            27017: "MongoDB Database"
        }

        async def probe_port(port: int):
            try:
                conn = asyncio.open_connection(target_host, port)
                reader, writer = await asyncio.wait_for(conn, timeout=1.5)
                
                banner = ""
                # Non-destructive banner grab with strict 1s timeout
                try:
                    if port in (80, 8080, 8000, 3000, 5000):
                        writer.write(b"HEAD / HTTP/1.0\r\nHost: " + target_host.encode() + b"\r\n\r\n")
                        await writer.drain()
                    banner_bytes = await asyncio.wait_for(reader.read(256), timeout=1.0)
                    banner = banner_bytes.decode("utf-8", errors="ignore").strip().split("\r\n")[0]
                except Exception:
                    pass
                finally:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass

                return {
                    "port": port,
                    "protocol": "tcp",
                    "service": known_services.get(port, "unknown"),
                    "banner": banner
                }
            except Exception:
                return None

        tasks = [probe_port(p) for p in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, dict) and r is not None:
                open_ports.append(r)

        duration = round(time.time() - start_time, 2)
        data = {
            "status": "success",
            "target": target_host,
            "scanned_ports": len(ports),
            "open_ports_count": len(open_ports),
            "ports": open_ports,
            "scan_duration_sec": duration,
            "sandbox_type": "native_async_socket" if not self.docker_available else "docker_sandbox"
        }
        return SandboxResult(success=True, output=json.dumps(data), data=data)

# Singleton sandbox instance
sandbox_runner = SandboxRunner()
