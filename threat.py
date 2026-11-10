"""Threat Exposure checks - external posture of a public domain or email.

This measures exposure and hygiene. It cannot prove that ransomware is present.
"""
import ipaddress
import re
import urllib.parse

import dns.resolver
import requests

DOMAIN_RE = re.compile(r"^(?=.{3,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def normalise(target):
    t = (target or "").strip().lower()
    email = t if re.fullmatch(r"[^@\s]+@[^@\s]+", t) else None
    host = t.split("@")[-1]
    host = urllib.parse.urlparse("//" + host).hostname or ""
    return (host if DOMAIN_RE.match(host) else None), email


def _txt(name):
    try:
        return ["".join(p.decode() if isinstance(p, bytes) else p for p in r.strings)
                for r in dns.resolver.resolve(name, "TXT", lifetime=4)]
    except Exception:
        return []


def _has(name, rtype):
    try:
        return [r.to_text() for r in dns.resolver.resolve(name, rtype, lifetime=4)]
    except Exception:
        return []


def _public_ips(domain):
    ips = _has(domain, "A") + _has(domain, "AAAA")
    public = []
    for ip in ips:
        try:
            obj = ipaddress.ip_address(ip)
            if obj.is_global:
                public.append(ip)
        except ValueError:
            pass
    return ips, public


def check(domain, email, cfg):
    checks = []

    def add(cid, name, group, status, detail, advice=""):
        checks.append({"id": cid, "name": name, "group": group, "status": status, "detail": detail, "advice": advice})

    ips, public = _public_ips(domain)
    if not ips and not _has(domain, "MX") and not _has(domain, "NS"):
        return {"error": f"{domain} could not be resolved. Check the spelling or try again in a moment."}
    if not ips:
        add("dns", "Domain resolution", "DNS", "info", "No website address (A/AAAA) records, but the domain exists in DNS.")
    elif not public:
        add("dns", "Domain resolution", "DNS", "fail", "The domain resolves only to private or reserved addresses.", "Internal hostnames are not scanned for safety.")
    else:
        add("dns", "Domain resolution", "DNS", "pass", f"Resolves to {len(public)} public address(es).")

    mx = _has(domain, "MX")
    add("mx", "Mail exchanger (MX)", "Email", "pass" if mx else "info",
        f"{len(mx)} mail server record(s) found." if mx else "No MX records - the domain may not receive email.")

    spf = [t for t in _txt(domain) if t.lower().startswith("v=spf1")]
    if not spf:
        add("spf", "SPF sender policy", "Email", "fail", "No SPF record found. Anyone can spoof mail from this domain.", "Publish an SPF record ending in -all or ~all.")
    elif len(spf) > 1:
        add("spf", "SPF sender policy", "Email", "fail", "Multiple SPF records found - receivers will treat SPF as invalid.", "Merge into a single SPF record.")
    else:
        rec = spf[0].lower()
        if "+all" in rec:
            add("spf", "SPF sender policy", "Email", "fail", "SPF ends with +all, allowing any sender.", "Change +all to -all.")
        elif "?all" in rec or "all" not in rec:
            add("spf", "SPF sender policy", "Email", "warn", "SPF exists but its policy is neutral or incomplete.", "End the record with -all or ~all.")
        elif "~all" in rec:
            add("spf", "SPF sender policy", "Email", "pass", "SPF present with soft-fail (~all).", "Consider -all once all senders are listed.")
        else:
            add("spf", "SPF sender policy", "Email", "pass", "SPF present with hard-fail (-all).")

    dmarc = [t for t in _txt("_dmarc." + domain) if t.lower().startswith("v=dmarc1")]
    if not dmarc:
        add("dmarc", "DMARC enforcement", "Email", "fail", "No DMARC record. Spoofed phishing from this domain will not be blocked.", "Publish DMARC, starting at p=none with reporting, then enforce.")
    else:
        m = re.search(r"p=(\w+)", dmarc[0].lower())
        pol = m.group(1) if m else "none"
        if pol in ("reject", "quarantine"):
            add("dmarc", "DMARC enforcement", "Email", "pass", f"DMARC policy is p={pol}.")
        else:
            add("dmarc", "DMARC enforcement", "Email", "warn", "DMARC is in monitor-only mode (p=none).", "Move to p=quarantine, then p=reject.")

    sts = [t for t in _txt("_mta-sts." + domain) if t.lower().startswith("v=stsv1")]
    add("mtasts", "MTA-STS encrypted delivery", "Email", "pass" if sts else "warn",
        "MTA-STS policy published." if sts else "No MTA-STS policy - inbound mail may be downgraded to unencrypted.",
        "" if sts else "Publish an MTA-STS policy to enforce TLS for inbound mail.")

    tlsrpt = [t for t in _txt("_smtp._tls." + domain) if t.lower().startswith("v=tlsrptv1")]
    add("tlsrpt", "TLS reporting", "Email", "pass" if tlsrpt else "info",
        "TLS-RPT reporting enabled." if tlsrpt else "No TLS-RPT record.", "" if tlsrpt else "Add TLS-RPT to receive delivery-encryption failure reports.")

    dnssec = _has(domain, "DNSKEY")
    add("dnssec", "DNSSEC", "DNS", "pass" if dnssec else "warn",
        "DNSSEC keys published." if dnssec else "DNSSEC not detected - DNS answers could be spoofed.",
        "" if dnssec else "Enable DNSSEC at your registrar/DNS host.")

    caa = _has(domain, "CAA")
    add("caa", "Certificate authority control (CAA)", "DNS", "pass" if caa else "warn",
        "CAA restricts which authorities may issue certificates." if caa else "No CAA record - any CA may issue certificates.",
        "" if caa else "Publish CAA records for your approved certificate authorities.")

    if public:
        try:
            r = requests.get(f"https://{domain}", timeout=6, allow_redirects=True,
                             headers={"User-Agent": "RansomwareShield-SA/3.1 exposure-check"})
            hsts = "strict-transport-security" in {k.lower() for k in r.headers}
            add("https", "HTTPS website", "Web", "pass", f"HTTPS responded with status {r.status_code}.")
            add("hsts", "HSTS enforcement", "Web", "pass" if hsts else "warn",
                "HSTS header present." if hsts else "HSTS header missing - browsers may be downgraded to HTTP.",
                "" if hsts else "Add Strict-Transport-Security to HTTPS responses.")
        except requests.exceptions.SSLError:
            add("https", "HTTPS website", "Web", "fail", "TLS certificate error on the website.", "Renew or correct the certificate.")
        except Exception:
            add("https", "HTTPS website", "Web", "info", "No HTTPS website responded within 6 seconds.")

    if cfg.get("VIRUSTOTAL_API_KEY"):
        try:
            r = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}",
                             headers={"x-apikey": cfg["VIRUSTOTAL_API_KEY"]}, timeout=10)
            stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {}) if r.ok else {}
            mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
            status = "fail" if mal else "warn" if sus else "pass"
            add("vt", "Domain reputation", "Intelligence", status, f"{mal} engine(s) flag malicious, {sus} suspicious.",
                "Investigate immediately and review the domain's hosting." if mal else "")
        except Exception:
            add("vt", "Domain reputation", "Intelligence", "info", "Reputation provider unavailable.")
    else:
        add("vt", "Domain reputation", "Intelligence", "info", "Not configured (add VIRUSTOTAL_API_KEY).")

    if email:
        if cfg.get("HIBP_API_KEY"):
            try:
                r = requests.get("https://haveibeenpwned.com/api/v3/breachedaccount/" + urllib.parse.quote(email, safe=""),
                                 headers={"hibp-api-key": cfg["HIBP_API_KEY"], "user-agent": "RansomwareShield-SA/3.1"},
                                 params={"truncateResponse": "true"}, timeout=10)
                count = len(r.json()) if r.status_code == 200 else 0
                add("hibp", "Breach exposure", "Intelligence", "fail" if count >= 3 else "warn" if count else "pass",
                    f"Found in {count} known breach(es)." if count else "Not found in known breaches.",
                    "Reset the password everywhere it was reused and enforce MFA." if count else "")
            except Exception:
                add("hibp", "Breach exposure", "Intelligence", "info", "Breach provider unavailable.")
        else:
            add("hibp", "Breach exposure", "Intelligence", "info", "Not configured (add HIBP_API_KEY).")

    score = 100
    for c in checks:
        score -= {"fail": 18, "warn": 7}.get(c["status"], 0)
    score = max(0, score)
    if any(c["id"] == "vt" and c["status"] == "fail" for c in checks) or score < 35:
        risk = "Critical"
    elif score < 55:
        risk = "High"
    elif score < 80:
        risk = "Medium"
    else:
        risk = "Low"
    counts = {s: sum(1 for c in checks if c["status"] == s) for s in ("pass", "warn", "fail", "info")}
    return {"domain": domain, "email": email, "score": score, "risk": risk, "counts": counts, "checks": checks,
            "summary": f"{domain} has a {risk.lower()} external exposure posture ({score}/100). "
                       "This reflects public hygiene and reputation - it does not prove that ransomware is present."}
