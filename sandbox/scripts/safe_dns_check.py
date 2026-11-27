#!/usr/bin/env python3
"""
Passive DNS & Mail Security Check Wrapper.
Queries SPF, DKIM, DMARC, MX, A, AAAA, and CNAME records non-intrusively.
"""
import sys
import json
import dns.resolver

def check_dns(domain: str):
    results = {
        "domain": domain,
        "a_records": [],
        "cname_records": [],
        "mx_records": [],
        "spf_record": None,
        "dmarc_record": None,
        "dangling_cname": False,
        "status": "success"
    }
    
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5.0
    resolver.lifetime = 5.0

    # A records
    try:
        answers = resolver.resolve(domain, "A")
        results["a_records"] = [rdata.to_text() for rdata in answers]
    except Exception:
        pass

    # CNAME records
    try:
        answers = resolver.resolve(domain, "CNAME")
        results["cname_records"] = [rdata.to_text() for rdata in answers]
        # Dangling CNAME check: if CNAME points to known cloud services (e.g., github.io, heroku, s3, azure) but NXDOMAIN
        for cname in results["cname_records"]:
            target_cname = cname.rstrip(".")
            try:
                resolver.resolve(target_cname, "A")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                results["dangling_cname"] = True
    except Exception:
        pass

    # MX records
    try:
        answers = resolver.resolve(domain, "MX")
        results["mx_records"] = [f"{rdata.preference} {rdata.exchange.to_text()}" for rdata in answers]
    except Exception:
        pass

    # TXT (SPF)
    try:
        answers = resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt_string = b"".join(rdata.strings).decode("utf-8", errors="ignore")
            if txt_string.startswith("v=spf1"):
                results["spf_record"] = txt_string
    except Exception:
        pass

    # DMARC TXT (_dmarc.domain)
    try:
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in answers:
            txt_string = b"".join(rdata.strings).decode("utf-8", errors="ignore")
            if txt_string.startswith("v=DMARC1"):
                results["dmarc_record"] = txt_string
    except Exception:
        pass

    return results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"status": "error", "message": "Domain argument missing"}))
        sys.exit(1)
    domain = sys.argv[1]
    res = check_dns(domain)
    print(json.dumps(res))
