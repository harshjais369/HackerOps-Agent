import asyncio
import ssl
import socket
import datetime
import httpx
import dns.resolver
from typing import Dict, Any, List
import logging
from app.core.sandbox import sandbox_runner

logger = logging.getLogger("hackerops.scanners")

# -------------------------------------------------------------
# 1. Passive OSINT & DNS Hygiene Scanner
# -------------------------------------------------------------
async def scan_osint_dns(domain: str) -> Dict[str, Any]:
    findings = []
    metadata = {
        "domain": domain,
        "a_records": [],
        "mx_records": [],
        "cname_records": [],
        "spf": None,
        "dmarc": None,
        "dangling_cname": False
    }

    resolver = dns.resolver.Resolver()
    resolver.timeout = 4.0
    resolver.lifetime = 4.0

    # A Records
    try:
        answers = resolver.resolve(domain, "A")
        metadata["a_records"] = [r.to_text() for r in answers]
    except Exception:
        pass

    # MX Records
    try:
        answers = resolver.resolve(domain, "MX")
        metadata["mx_records"] = [f"{r.preference} {r.exchange.to_text()}" for r in answers]
    except Exception:
        pass

    # CNAME Records & Dangling CNAME Check
    try:
        answers = resolver.resolve(domain, "CNAME")
        metadata["cname_records"] = [r.to_text() for r in answers]
        for cname in metadata["cname_records"]:
            target_host = cname.rstrip(".")
            try:
                resolver.resolve(target_host, "A")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                metadata["dangling_cname"] = True
                findings.append({
                    "title": "Dangling CNAME / Potential Subdomain Takeover Risk",
                    "description": f"Domain CNAME '{cname}' points to an unresolvable or de-provisioned host, exposing it to hijacking by third parties.",
                    "severity": "HIGH",
                    "cvss_score": 7.5,
                    "owasp_category": "A05:2021-Security Misconfiguration",
                    "pci_dss_ref": "PCI-DSS v4.0 Req 6.4.1",
                    "category": "dns",
                    "evidence": f"CNAME {domain} -> {cname} (NXDOMAIN)",
                    "remediation_hint": "Remove stale CNAME records immediately or reclaim the target resource on the cloud provider."
                })
    except Exception:
        pass

    # SPF Record Check
    try:
        answers = resolver.resolve(domain, "TXT")
        for r in answers:
            txt = b"".join(r.strings).decode("utf-8", errors="ignore")
            if txt.startswith("v=spf1"):
                metadata["spf"] = txt
                if "+all" in txt:
                    findings.append({
                        "title": "Permissive SPF Record (+all)",
                        "description": "The SPF record includes '+all', allowing any sender IP on the Internet to spoof emails from this domain.",
                        "severity": "HIGH",
                        "cvss_score": 7.3,
                        "owasp_category": "A05:2021-Security Misconfiguration",
                        "pci_dss_ref": "PCI-DSS v4.0 Req 5.2.1",
                        "category": "dns",
                        "evidence": f"SPF TXT: {txt}",
                        "remediation_hint": "Change '+all' to '~all' (SoftFail) or '-all' (HardFail) in the SPF record."
                    })
                elif "?all" in txt:
                    findings.append({
                        "title": "Neutral SPF Record (?all)",
                        "description": "The SPF record uses '?all', offering zero spam/spoofing protection policy enforcement.",
                        "severity": "LOW",
                        "cvss_score": 3.7,
                        "owasp_category": "A05:2021-Security Misconfiguration",
                        "pci_dss_ref": "PCI-DSS v4.0 Req 5.2.1",
                        "category": "dns",
                        "evidence": f"SPF TXT: {txt}",
                        "remediation_hint": "Update SPF qualifier to '-all' to reject unauthorized mail servers."
                    })
    except Exception:
        pass

    if not metadata["spf"]:
        findings.append({
            "title": "Missing SPF (Sender Policy Framework) Record",
            "description": "No SPF TXT record was found. Adversaries can forge emails using this domain name in phishing campaigns.",
            "severity": "MEDIUM",
            "cvss_score": 5.3,
            "owasp_category": "A05:2021-Security Misconfiguration",
            "pci_dss_ref": "PCI-DSS v4.0 Req 5.2.1",
            "category": "dns",
            "evidence": f"No v=spf1 TXT record for {domain}",
            "remediation_hint": "Publish a valid SPF record: 'v=spf1 mx -all' or include authorized sending providers."
        })

    # DMARC Record Check
    try:
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for r in answers:
            txt = b"".join(r.strings).decode("utf-8", errors="ignore")
            if txt.startswith("v=DMARC1"):
                metadata["dmarc"] = txt
                if "p=none" in txt:
                    findings.append({
                        "title": "DMARC Policy Set to 'none' (Monitoring Only)",
                        "description": "DMARC record policy is set to 'p=none', meaning unauthorized spoofed emails are delivered to recipients rather than rejected.",
                        "severity": "LOW",
                        "cvss_score": 3.5,
                        "owasp_category": "A05:2021-Security Misconfiguration",
                        "pci_dss_ref": "PCI-DSS v4.0 Req 5.2.1",
                        "category": "dns",
                        "evidence": f"DMARC TXT: {txt}",
                        "remediation_hint": "Upgrade DMARC policy from 'p=none' to 'p=quarantine' or 'p=reject'."
                    })
    except Exception:
        pass

    if not metadata["dmarc"]:
        findings.append({
            "title": "Missing DMARC Record",
            "description": f"Domain lacks a DMARC policy at _dmarc.{domain}, preventing email receivers from rejecting spoofed domain mail.",
            "severity": "MEDIUM",
            "cvss_score": 5.8,
            "owasp_category": "A05:2021-Security Misconfiguration",
            "pci_dss_ref": "PCI-DSS v4.0 Req 5.2.1",
            "category": "dns",
            "evidence": f"DNS query for _dmarc.{domain} returned no record",
            "remediation_hint": "Create a TXT record for '_dmarc' with 'v=DMARC1; p=reject; rua=mailto:dmarc-reports@domain.com'."
        })

    return {
        "tool": "Passive OSINT & DNS Hygiene",
        "status": "success",
        "metadata": metadata,
        "findings": findings
    }


# -------------------------------------------------------------
# 2. HTTP Security Headers & TLS Auditor
# -------------------------------------------------------------
async def scan_headers_and_tls(target_url: str, hostname: str) -> Dict[str, Any]:
    findings = []
    metadata = {
        "headers_inspected": {},
        "tls_version": None,
        "tls_cipher": None,
        "cert_expiry_days": None,
        "cert_subject": None,
        "cookies": []
    }

    # TLS Inspection
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        with socket.create_connection((hostname, 443), timeout=4.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                metadata["tls_version"] = ssock.version()
                metadata["tls_cipher"] = ssock.cipher()
                
                # Check cert expiration
                exp_date_str = cert.get("notAfter")
                if exp_date_str:
                    exp_date = datetime.datetime.strptime(exp_date_str, "%b %d %H:%M:%S %Y %Z")
                    days_left = (exp_date - datetime.datetime.utcnow()).days
                    metadata["cert_expiry_days"] = days_left
                    if days_left < 14:
                        findings.append({
                            "title": "TLS Certificate Expiring Soon",
                            "description": f"The SSL/TLS certificate expires in {days_left} days ({exp_date_str}). Service outage risk.",
                            "severity": "HIGH" if days_left < 7 else "MEDIUM",
                            "cvss_score": 6.5 if days_left < 7 else 4.5,
                            "owasp_category": "A02:2021-Cryptographic Failures",
                            "pci_dss_ref": "PCI-DSS v4.0 Req 4.1.1",
                            "category": "tls",
                            "evidence": f"notAfter: {exp_date_str} ({days_left} days remaining)",
                            "remediation_hint": "Renew the SSL/TLS certificate immediately using Let's Encrypt or your certificate authority."
                        })
    except ssl.SSLCertVerificationError as e:
        findings.append({
            "title": "Invalid or Untrusted TLS/SSL Certificate",
            "description": f"The SSL certificate verification failed: {e.verify_message}",
            "severity": "HIGH",
            "cvss_score": 7.4,
            "owasp_category": "A02:2021-Cryptographic Failures",
            "pci_dss_ref": "PCI-DSS v4.0 Req 4.1.1",
            "category": "tls",
            "evidence": str(e),
            "remediation_hint": "Install a valid, publicly-trusted CA certificate and verify intermediate chain bundles."
        })
    except Exception as e:
        logger.debug(f"TLS audit connection skipped or non-TLS port: {e}")

    # HTTP Headers & Cookies
    try:
        async with httpx.AsyncClient(timeout=6.0, follow_redirects=True, verify=False) as client:
            resp = await client.get(target_url)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            metadata["headers_inspected"] = dict(headers)
            metadata["status_code"] = resp.status_code

            # Check Strict-Transport-Security (HSTS)
            if "strict-transport-security" not in headers:
                findings.append({
                    "title": "Missing HTTP Strict-Transport-Security (HSTS) Header",
                    "description": "Without HSTS, browsers may initially communicate over plaintext HTTP, opening users to SSL-stripping and Man-in-the-Middle (MitM) attacks.",
                    "severity": "MEDIUM",
                    "cvss_score": 5.4,
                    "owasp_category": "A05:2021-Security Misconfiguration",
                    "pci_dss_ref": "PCI-DSS v4.0 Req 4.2.1",
                    "category": "headers",
                    "evidence": "Strict-Transport-Security header absent",
                    "remediation_hint": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses."
                })

            # Check Content-Security-Policy (CSP)
            if "content-security-policy" not in headers:
                findings.append({
                    "title": "Missing Content-Security-Policy (CSP) Header",
                    "description": "Absence of a Content-Security-Policy allows unauthorized script execution, increasing vulnerability to Cross-Site Scripting (XSS) and data injection.",
                    "severity": "MEDIUM",
                    "cvss_score": 6.1,
                    "owasp_category": "A05:2021-Security Misconfiguration",
                    "pci_dss_ref": "PCI-DSS v4.0 Req 6.4.3",
                    "category": "headers",
                    "evidence": "Content-Security-Policy header absent",
                    "remediation_hint": "Define a robust CSP such as 'default-src \\'self\\'; script-src \\'self\\'; object-src \\'none\\';'."
                })
            elif "unsafe-inline" in headers["content-security-policy"] and "nonce" not in headers["content-security-policy"]:
                findings.append({
                    "title": "Weak Content-Security-Policy ('unsafe-inline' enabled)",
                    "description": "CSP allows 'unsafe-inline' scripts without nonce or hash validation, degrading XSS defenses.",
                    "severity": "LOW",
                    "cvss_score": 4.3,
                    "owasp_category": "A03:2021-Injection",
                    "pci_dss_ref": "PCI-DSS v4.0 Req 6.4.3",
                    "category": "headers",
                    "evidence": f"CSP: {headers['content-security-policy']}",
                    "remediation_hint": "Migrate inline scripts to external bundles or adopt cryptographic nonces ('nonce-<random>')."
                })

            # Check X-Frame-Options / Clickjacking
            if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", ""):
                findings.append({
                    "title": "Missing Clickjacking Defense (X-Frame-Options / frame-ancestors)",
                    "description": "The site does not restrict framing via X-Frame-Options or CSP frame-ancestors, permitting UI redress / clickjacking attacks.",
                    "severity": "MEDIUM",
                    "cvss_score": 5.0,
                    "owasp_category": "A05:2021-Security Misconfiguration",
                    "pci_dss_ref": "PCI-DSS v4.0 Req 6.4.1",
                    "category": "headers",
                    "evidence": "X-Frame-Options header absent",
                    "remediation_hint": "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'."
                })

            # Check X-Content-Type-Options
            if headers.get("x-content-type-options") != "nosniff":
                findings.append({
                    "title": "Missing X-Content-Type-Options: nosniff Header",
                    "description": "Missing 'nosniff' enables MIME-type sniffing in browsers, allowing untrusted files (e.g. image uploads) to be interpreted as executable HTML/JS.",
                    "severity": "LOW",
                    "cvss_score": 3.7,
                    "owasp_category": "A05:2021-Security Misconfiguration",
                    "pci_dss_ref": "PCI-DSS v4.0 Req 6.4.1",
                    "category": "headers",
                    "evidence": f"X-Content-Type-Options: {headers.get('x-content-type-options')}",
                    "remediation_hint": "Set 'X-Content-Type-Options: nosniff' header."
                })

            # Check Referrer-Policy
            if "referrer-policy" not in headers:
                findings.append({
                    "title": "Missing Referrer-Policy Header",
                    "description": "Without an explicit Referrer-Policy, sensitive URLs containing query parameters or authentication tokens may leak to external third parties.",
                    "severity": "LOW",
                    "cvss_score": 3.1,
                    "owasp_category": "A05:2021-Security Misconfiguration",
                    "pci_dss_ref": "PCI-DSS v4.0 Req 6.4.1",
                    "category": "headers",
                    "evidence": "Referrer-Policy header absent",
                    "remediation_hint": "Set 'Referrer-Policy: strict-origin-when-cross-origin'."
                })

            # Check Cookie security flags
            cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else [resp.headers.get("set-cookie", "")]
            for cookie in cookies:
                if not cookie:
                    continue
                cookie_lower = cookie.lower()
                c_name = cookie.split("=")[0].strip()
                if "httponly" not in cookie_lower:
                    findings.append({
                        "title": f"Cookie '{c_name}' Missing HttpOnly Flag",
                        "description": f"Session cookie '{c_name}' is accessible via JavaScript document.cookie, making it vulnerable to theft via XSS.",
                        "severity": "MEDIUM",
                        "cvss_score": 5.0,
                        "owasp_category": "A05:2021-Security Misconfiguration",
                        "pci_dss_ref": "PCI-DSS v4.0 Req 6.4.3",
                        "category": "headers",
                        "evidence": f"Set-Cookie: {cookie}",
                        "remediation_hint": f"Append '; HttpOnly' to the '{c_name}' cookie attribute."
                    })
                if "secure" not in cookie_lower:
                    findings.append({
                        "title": f"Cookie '{c_name}' Missing Secure Flag",
                        "description": f"Cookie '{c_name}' can be transmitted in unencrypted plaintext over HTTP connections.",
                        "severity": "MEDIUM",
                        "cvss_score": 4.8,
                        "owasp_category": "A05:2021-Security Misconfiguration",
                        "pci_dss_ref": "PCI-DSS v4.0 Req 4.1.1",
                        "category": "headers",
                        "evidence": f"Set-Cookie: {cookie}",
                        "remediation_hint": f"Append '; Secure' to the '{c_name}' cookie attribute."
                    })
    except Exception as e:
        logger.warning(f"HTTP header inspection failed for {target_url}: {e}")

    return {
        "tool": "HTTP Security Headers & TLS Auditor",
        "status": "success",
        "metadata": metadata,
        "findings": findings
    }


# -------------------------------------------------------------
# 3. CORS & API Surface Probe
# -------------------------------------------------------------
async def scan_cors(target_url: str) -> Dict[str, Any]:
    findings = []
    metadata = {"probed_origins": [], "responses": {}}

    test_origins = [
        "https://evil-attacker.com",
        "null"
    ]

    async def probe_origin(test_origin: str):
        try:
            async with httpx.AsyncClient(timeout=3.0, verify=False) as client:
                headers = {
                    "Origin": test_origin,
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "Authorization, Content-Type"
                }
                resp = await client.options(target_url, headers=headers)
                acao = resp.headers.get("access-control-allow-origin")
                acac = resp.headers.get("access-control-allow-credentials", "").lower()

                return {
                    "origin": test_origin,
                    "acao": acao,
                    "acac": acac,
                    "status_code": resp.status_code
                }
        except Exception:
            return None

    probed_results = await asyncio.gather(*[probe_origin(o) for o in test_origins], return_exceptions=True)

    for item in probed_results:
        if not isinstance(item, dict) or not item:
            continue
        test_origin = item["origin"]
        acao = item["acao"]
        acac = item["acac"]
        metadata["probed_origins"].append(item)

        if acao == "*":
            if acac == "true":
                findings.append({
                    "title": "Critical CORS Misconfiguration: Wildcard Origin with Credentials",
                    "description": "Server config reflects wildcard '*' origin alongside 'Access-Control-Allow-Credentials: true', enabling cross-origin authentication theft.",
                    "severity": "CRITICAL",
                    "cvss_score": 9.1,
                    "owasp_category": "A01:2021-Broken Access Control",
                    "pci_dss_ref": "PCI-DSS v4.0 Req 6.4.1",
                    "category": "cors",
                    "evidence": f"ACAO: {acao}, ACAC: {acac}",
                    "remediation_hint": "Disable wildcard reflection and specify explicit whitelisted trusted domain origins."
                })
            else:
                findings.append({
                    "title": "Permissive CORS Wildcard (Access-Control-Allow-Origin: *)",
                    "description": "The API allows any third-party website to make cross-origin requests to this endpoint.",
                    "severity": "LOW",
                    "cvss_score": 3.7,
                    "owasp_category": "A01:2021-Broken Access Control",
                    "pci_dss_ref": "PCI-DSS v4.0 Req 6.4.1",
                    "category": "cors",
                    "evidence": f"Origin: {test_origin} -> ACAO: {acao}",
                    "remediation_hint": "Restrict Access-Control-Allow-Origin to authorized frontend domains."
                })
        elif acao == test_origin:
            if acac == "true":
                findings.append({
                    "title": "Exploitable CORS Misconfiguration: Origin Reflection with Credentials",
                    "description": f"Server dynamically reflects arbitrary attacker origin '{test_origin}' and sets Access-Control-Allow-Credentials to true. Attackers can execute authenticated data exfiltration via malicious websites.",
                    "severity": "CRITICAL",
                    "cvss_score": 8.8,
                    "owasp_category": "A01:2021-Broken Access Control",
                    "pci_dss_ref": "PCI-DSS v4.0 Req 6.4.1",
                    "category": "cors",
                    "evidence": f"Reflected Origin: {test_origin} | ACAC: true",
                    "remediation_hint": "Do not dynamically reflect the incoming Origin header. Implement strict origin whitelist checks."
                })
            else:
                findings.append({
                    "title": "Arbitrary CORS Origin Reflection",
                    "description": f"Server blindly reflects untrusted origin '{test_origin}' in the ACAO header without validation.",
                    "severity": "MEDIUM",
                    "cvss_score": 5.3,
                    "owasp_category": "A01:2021-Broken Access Control",
                    "pci_dss_ref": "PCI-DSS v4.0 Req 6.4.1",
                    "category": "cors",
                    "evidence": f"Reflected Origin: {test_origin}",
                    "remediation_hint": "Validate origin against a strict whitelist array before returning ACAO header."
                })

    return {
        "tool": "CORS & API Surface Probe",
        "status": "success",
        "metadata": metadata,
        "findings": findings
    }


# -------------------------------------------------------------
# 4. Sensitive Path & Exposure Discovery Scanner
# -------------------------------------------------------------
async def scan_sensitive_paths(base_url: str) -> Dict[str, Any]:
    findings = []
    metadata = {"checked_paths": [], "exposed_paths": []}

    target_clean = base_url.rstrip("/")

    high_risk_paths = [
        {"path": "/.env", "severity": "CRITICAL", "cvss": 9.3, "indicators": ["DB_", "API_KEY", "SECRET", "PASSWORD", "="]},
        {"path": "/.git/HEAD", "severity": "HIGH", "cvss": 8.5, "indicators": ["ref: refs/heads/"]},
        {"path": "/robots.txt", "severity": "INFO", "cvss": 0.0, "indicators": ["User-agent", "Disallow"]},
        {"path": "/swagger.json", "severity": "LOW", "cvss": 3.5, "indicators": ["swagger", "paths"]},
        {"path": "/openapi.json", "severity": "LOW", "cvss": 3.5, "indicators": ["openapi", "paths"]},
        {"path": "/actuator/health", "severity": "LOW", "cvss": 3.0, "indicators": ["status", "UP"]},
        {"path": "/.DS_Store", "severity": "LOW", "cvss": 3.0, "indicators": ["Bud1"]}
    ]

    async def check_single_path(item: dict):
        probe_url = f"{target_clean}{item['path']}"
        try:
            async with httpx.AsyncClient(timeout=2.0, verify=False, follow_redirects=False) as client:
                resp = await client.get(probe_url, headers={"User-Agent": "HackerOps-Audit/1.0"})
                body_sample = resp.text[:512]
                return {"item": item, "url": probe_url, "status_code": resp.status_code, "body": body_sample}
        except Exception:
            return {"item": item, "url": probe_url, "status_code": 0, "body": ""}

    results = await asyncio.gather(*[check_single_path(p) for p in high_risk_paths], return_exceptions=True)

    for res in results:
        if not isinstance(res, dict):
            continue
        item = res["item"]
        probe_url = res["url"]
        metadata["checked_paths"].append(probe_url)

        if res["status_code"] == 200:
            body_sample = res["body"]
            matched = any(ind in body_sample for ind in item["indicators"])
            if matched or item["path"] in ("/swagger.json", "/openapi.json"):
                metadata["exposed_paths"].append(probe_url)
                if item["severity"] != "INFO":
                    findings.append({
                        "title": f"Sensitive File Exposed: {item['path']}",
                        "description": f"Accessible public file found at '{probe_url}'. May reveal credentials, private Git commit trees, or internal architecture details.",
                        "severity": item["severity"],
                        "cvss_score": item["cvss"],
                        "owasp_category": "A05:2021-Security Misconfiguration",
                        "pci_dss_ref": "PCI-DSS v4.0 Req 6.4.1",
                        "category": "paths",
                        "evidence": f"HTTP 200 OK at {probe_url} (Body snippet: {body_sample[:80]}...)",
                        "remediation_hint": f"Block access to '{item['path']}' in your reverse proxy (nginx.conf) or web server configuration."
                    })

    return {
        "tool": "Sensitive Path & Exposure Discovery",
        "status": "success",
        "metadata": metadata,
        "findings": findings
    }


# -------------------------------------------------------------
# 5. Scoped Port & Service Recon (Sandbox Runner)
# -------------------------------------------------------------
async def scan_ports_and_services(target_host: str) -> Dict[str, Any]:
    findings = []
    sandbox_res = await sandbox_runner.run_port_scan(target_host)
    data = sandbox_res.data
    ports = data.get("ports", [])

    db_ports = {3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch"}
    unencrypted_ports = {21: "FTP", 23: "Telnet", 80: "HTTP"}

    for p in ports:
        port_num = p.get("port")
        banner = p.get("banner", "")

        # Check exposed database services
        if port_num in db_ports:
            db_name = db_ports[port_num]
            findings.append({
                "title": f"Exposed Database Service: {db_name} (Port {port_num})",
                "description": f"Publicly accessible database listener ({db_name}) detected on port {port_num}. Databases should never be exposed to the public Internet without VPN or SSH tunnels.",
                "severity": "HIGH",
                "cvss_score": 8.0,
                "owasp_category": "A05:2021-Security Misconfiguration",
                "pci_dss_ref": "PCI-DSS v4.0 Req 1.3.1",
                "category": "ports",
                "evidence": f"Port {port_num}/tcp OPEN, service: {db_name}, banner: {banner}",
                "remediation_hint": f"Bind {db_name} to 127.0.0.1 or place it behind a private VPC subnet/firewall."
            })
        
        # Check unencrypted protocols
        if port_num in (21, 23):
            proto_name = unencrypted_ports.get(port_num)
            findings.append({
                "title": f"Legacy Plaintext Protocol Exposed: {proto_name} (Port {port_num})",
                "description": f"Port {port_num} runs unencrypted {proto_name}. Credentials and session data are susceptible to network sniffing.",
                "severity": "MEDIUM",
                "cvss_score": 6.2,
                "owasp_category": "A02:2021-Cryptographic Failures",
                "pci_dss_ref": "PCI-DSS v4.0 Req 4.1.1",
                "category": "ports",
                "evidence": f"Port {port_num}/tcp OPEN ({proto_name})",
                "remediation_hint": f"Decommission {proto_name} and replace with SSH or SFTP."
            })

    return {
        "tool": "Scoped Port & Service Recon",
        "status": "success",
        "metadata": data,
        "findings": findings
    }
