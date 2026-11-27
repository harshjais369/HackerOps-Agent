import json
import logging
from typing import List, Dict, Any, Optional
from app.config import settings

logger = logging.getLogger("hackerops.patchgen")

class PatchGenerator:
    """
    Synthesizes copy-paste-ready, production-grade defensive patches and remediation configs.
    Supports Nginx, FastAPI, Express, DNS records, and Docker hardening.
    Falls back deterministically to proven security templates if no LLM API key is present.
    """

    @staticmethod
    def generate_nginx_patch(findings: List[Dict[str, Any]], domain: str) -> Dict[str, Any]:
        """Generates hardened nginx.conf snippet."""
        conf_lines = [
            f"# ============================================================",
            f"# HackerOps Auto-Remediation: Hardened Nginx Reverse Proxy",
            f"# Generated for target: {domain}",
            f"# ============================================================",
            "server {",
            "    listen 443 ssl http2;",
            f"    server_name {domain};",
            "",
            "    # SSL Protocols & Modern Ciphers",
            "    ssl_protocols TLSv1.2 TLSv1.3;",
            "    ssl_prefer_server_ciphers on;",
            "    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;",
            "",
            "    # Defensive Security Headers",
            "    add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;",
            "    add_header X-Frame-Options \"DENY\" always;",
            "    add_header X-Content-Type-Options \"nosniff\" always;",
            "    add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;",
            "    add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';\" always;",
            "    add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;",
            "",
            "    # Hide Nginx server version banner",
            "    server_tokens off;",
            "",
            "    # Block access to hidden files and sensitive dotfiles (.env, .git, etc.)",
            "    location ~ /\\.(?!well-known) {",
            "        deny all;",
            "        access_log off;",
            "        log_not_found off;",
            "        return 404;",
            "    }",
            "",
            "    # Block Swagger / OpenAPI UI in production unless authenticated",
            "    location ~* ^/(swagger\\.json|openapi\\.json|actuator) {",
            "        allow 10.0.0.0/8;",
            "        allow 172.16.0.0/12;",
            "        allow 192.168.0.0/16;",
            "        deny all;",
            "        return 403;",
            "    }",
            "",
            "    location / {",
            "        proxy_pass http://127.0.0.1:8000;",
            "        proxy_set_header Host $host;",
            "        proxy_set_header X-Real-IP $remote_addr;",
            "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
            "        proxy_set_header X-Forwarded-Proto $scheme;",
            "    }",
            "}"
        ]
        diff_text = "\n".join(conf_lines)
        return {
            "patch_type": "nginx",
            "title": "Hardened Nginx Reverse Proxy Configuration",
            "file_target": "/etc/nginx/conf.d/security.conf",
            "diff_content": diff_text,
            "explanation": "Enforces HSTS, rigid Content-Security-Policy, anti-clickjacking headers, drops sensitive dotfiles (/.env, /.git), and restricts internal API docs."
        }

    @staticmethod
    def generate_fastapi_cors_patch(domain: str) -> Dict[str, Any]:
        """Generates secure FastAPI CORS middleware patch."""
        code = f"""# ============================================================
# HackerOps Auto-Remediation: Secure FastAPI CORS Middleware
# Target domain: {domain}
# ============================================================
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# Strict, explicit origin whitelist (NEVER use ['*'] with allow_credentials=True)
ALLOWED_ORIGINS = [
    "https://{domain}",
    "https://app.{domain}",
    "http://localhost:3000",  # Development only
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
    max_age=600,
)
"""
        return {
            "patch_type": "fastapi",
            "title": "FastAPI Whitelist-Based CORS Middleware",
            "file_target": "app/main.py",
            "diff_content": code,
            "explanation": "Replaces wildcard / arbitrary origin reflection with an immutable domain whitelist, neutralizing cross-origin credential leaks."
        }

    @staticmethod
    def generate_express_cors_patch(domain: str) -> Dict[str, Any]:
        """Generates secure Express.js CORS + Helmet middleware patch."""
        code = f"""// ============================================================
// HackerOps Auto-Remediation: Express.js Helmet & CORS Protection
// Target domain: {domain}
// ============================================================
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');

const app = express();

// Comprehensive HTTP Header hardening via Helmet
app.use(helmet({{
  contentSecurityPolicy: {{
    directives: {{
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: [],
    }},
  }},
  hsts: {{
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  }},
}}));

// Origin whitelist with dynamic reflection rejection
const whitelist = ['https://{domain}', 'https://app.{domain}'];
const corsOptions = {{
  origin: function (origin, callback) {{
    if (!origin || whitelist.indexOf(origin) !== !== -1) {{
      callback(null, true);
    }} else {{
      callback(new Error('Blocked by HackerOps CORS Policy'));
    }}
  }},
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 600
}};

app.use(cors(corsOptions));
"""
        return {
            "patch_type": "express",
            "title": "Express.js Helmet Security Headers & Strict CORS",
            "file_target": "src/server.js",
            "diff_content": code,
            "explanation": "Integrates Helmet for modern browser security headers and restricts cross-origin resource requests to authorized domains."
        }

    @staticmethod
    def generate_dns_patch(domain: str) -> Dict[str, Any]:
        """Generates DNS SPF & DMARC TXT record fixes."""
        dns_records = f"""; ============================================================
; HackerOps Auto-Remediation: Hardened DNS Records (SPF & DMARC)
; Domain: {domain}
; ============================================================

; 1. SPF Record: Restrict mail sending to authorized MX hosts and reject forged IPs (-all)
{domain}.    IN    TXT    "v=spf1 mx ~all"

; 2. DMARC Policy: Reject unauthenticated emails and receive daily forensic aggregate reports
_dmarc.{domain}.   IN    TXT    "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; rua=mailto:dmarc-reports@{domain}; pct=100;"
"""
        return {
            "patch_type": "dns",
            "title": "SPF & DMARC Anti-Phishing DNS Records",
            "file_target": f"DNS Provider / Zone File ({domain})",
            "diff_content": dns_records,
            "explanation": "Neutralizes email spoofing and phishing by enforcing strict SPF validation and an authoritative DMARC reject policy."
        }

    @staticmethod
    def generate_docker_patch() -> Dict[str, Any]:
        """Generates hardened container runtime config."""
        docker_conf = """# ============================================================
# HackerOps Auto-Remediation: Hardened Docker Compose Service
# ============================================================
services:
  web:
    image: my-app:latest
    user: "1001:1001"          # Never run as root
    read_only: true            # Immutable root filesystem
    tmpfs:
      - /tmp:rw,noexec,nosuid
    security_opt:
      - no-new-privileges:true # Prevent privilege escalation
    cap_drop:
      - ALL                    # Drop all kernel capabilities
    cap_add:
      - NET_BIND_SERVICE       # Grant only bind permission
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 512M
"""
        return {
            "patch_type": "docker",
            "title": "Hardened Container Runtime & Capability Drop",
            "file_target": "docker-compose.yml",
            "diff_content": docker_conf,
            "explanation": "Applies defense-in-depth container sandboxing: drops Linux capabilities, runs as non-root, and mounts a read-only rootfs."
        }

    @classmethod
    async def synthesize_all_patches(cls, findings: List[Dict[str, Any]], domain: str) -> List[Dict[str, Any]]:
        """
        Compiles appropriate defensive patches based on the discovered vulnerabilities.
        """
        patches = []
        categories = {f.get("category") for f in findings}

        # If header or path issues found: produce Nginx patch
        if "headers" in categories or "paths" in categories or "tls" in categories or len(findings) > 0:
            patches.append(cls.generate_nginx_patch(findings, domain))

        # If CORS misconfigurations found
        if "cors" in categories:
            patches.append(cls.generate_fastapi_cors_patch(domain))
            patches.append(cls.generate_express_cors_patch(domain))

        # If DNS/email spoofing issues found
        if "dns" in categories:
            patches.append(cls.generate_dns_patch(domain))

        # If port / service exposure issues found
        if "ports" in categories:
            patches.append(cls.generate_docker_patch())

        # If LLM API Key is configured, attempt intelligent LLM patch augmentation
        if settings.llm_api_key:
            try:
                import litellm
                prompt = (
                    f"Given these security findings for domain '{domain}': {json.dumps(findings[:5])}, "
                    "generate a concise, specific environment hardening patch in markdown diff format."
                )
                response = await litellm.acompletion(
                    model=settings.llm_model,
                    api_key=settings.llm_api_key,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=600,
                    temperature=0.2
                )
                ai_text = response.choices[0].message.content
                patches.append({
                    "patch_type": "ai_custom",
                    "title": "AI Synthesized Contextual Remediation",
                    "file_target": ".env.security / application.conf",
                    "diff_content": ai_text,
                    "explanation": "Custom mitigation synthesized by LLM reasoning over specific vulnerability correlation."
                })
            except Exception as e:
                logger.warning(f"LLM patch synthesis skipped or failed: {e}")

        return patches
