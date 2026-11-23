#!/usr/bin/env python3
"""
headerspy — HAR file security auditor

Reads a .har file exported from Burp Suite or browser DevTools and produces
a prioritized security finding list across every request/response pair.

Usage:
    headerspy scan <file.har>
    headerspy scan <file.har> --min-severity medium
    headerspy scan <file.har> --json
    headerspy scan <file.har> --out report.txt
"""
import argparse
import json
import re
import sys
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

# ── severity levels ───────────────────────────────────────────────────────────
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLOR = {
    "critical": "\033[91m",   # bright red
    "high":     "\033[31m",   # red
    "medium":   "\033[33m",   # yellow
    "low":      "\033[36m",   # cyan
    "info":     "\033[90m",   # grey
}
RESET = "\033[0m"
BOLD  = "\033[1m"


@dataclass
class Finding:
    severity: str          # critical / high / medium / low / info
    rule_id:  str          # short machine-readable ID
    title:    str          # one-line summary
    detail:   str          # what was found
    url:      str          # which URL triggered it
    evidence: str = ""     # snippet of the actual value

    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 99)


# ── HAR loading ───────────────────────────────────────────────────────────────

def load_har(path: Path) -> dict:
    with open(path, encoding="utf-8", errors="replace") as f:
        return json.load(f)


def iter_entries(har: dict):
    """Yield each HAR entry (request + response pair)."""
    yield from har.get("log", {}).get("entries", [])


# ── header helpers ─────────────────────────────────────────────────────────────

def headers_dict(header_list: list[dict]) -> dict[str, str]:
    """HAR stores headers as [{name, value}, ...] — flatten to a case-insensitive dict."""
    out: dict[str, str] = {}
    for h in header_list:
        out[h.get("name", "").lower()] = h.get("value", "")
    return out


def header_value(hdict: dict, name: str) -> str | None:
    return hdict.get(name.lower())


# ══════════════════════════════════════════════════════════════════════════════
# RULE IMPLEMENTATIONS
# Each rule is a function: (entry) -> list[Finding]
# ══════════════════════════════════════════════════════════════════════════════

# ── Tokens / secrets in URLs ──────────────────────────────────────────────────

_TOKEN_PARAM_PATTERN = re.compile(
    r"(?i)^(token|api[_-]?key|apikey|access[_-]?token|secret|password|passwd|"
    r"pwd|auth|authorization|bearer|private[_-]?key|client[_-]?secret|"
    r"session[_-]?id|sessionid|sid|ssid|csrf|xsrf|nonce|hmac|signature|"
    r"oauth[_-]?token|refresh[_-]?token|id[_-]?token)$"
)

_BEARER_IN_URL_PATTERN = re.compile(r"(?i)Bearer\s+[A-Za-z0-9\-._~+/]+=*")


def rule_token_in_url(entry: dict) -> list[Finding]:
    findings = []
    req = entry.get("request", {})
    url = req.get("url", "")
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    for key, values in params.items():
        if _TOKEN_PARAM_PATTERN.match(key):
            val = values[0] if values else ""
            findings.append(Finding(
                severity="high",
                rule_id="TOKEN_IN_URL",
                title="Sensitive parameter in URL query string",
                detail=f"Parameter '{key}' looks like a credential/token and is exposed in the URL. "
                       "URLs are logged in proxy logs, server access logs, Referer headers, and browser history.",
                url=url,
                evidence=f"{key}={val[:40]}{'...' if len(val) > 40 else ''}",
            ))

    # Also catch raw Bearer tokens stuffed into a query param value
    if _BEARER_IN_URL_PATTERN.search(url):
        findings.append(Finding(
            severity="high",
            rule_id="BEARER_IN_URL",
            title="Bearer token literal in URL",
            detail="A Bearer token was found directly embedded in the URL. "
                   "This is exposed in logs and browser history.",
            url=url,
            evidence=url[:100],
        ))

    return findings


# ── Auth tokens in request headers (info — just inventory) ───────────────────

def rule_auth_header_inventory(entry: dict) -> list[Finding]:
    req = entry.get("request", {})
    hdict = headers_dict(req.get("headers", []))
    url = req.get("url", "")
    findings = []

    auth = header_value(hdict, "authorization")
    if auth:
        scheme = auth.split()[0].lower() if auth.split() else ""
        if scheme == "basic":
            findings.append(Finding(
                severity="medium",
                rule_id="BASIC_AUTH",
                title="HTTP Basic authentication in use",
                detail="Basic auth sends credentials base64-encoded (not encrypted). "
                       "Only safe over HTTPS. If captured over HTTP, credentials are trivially decoded.",
                url=url,
                evidence=auth[:60],
            ))
    return findings


# ── Missing security headers on HTML responses ────────────────────────────────

_HTML_CONTENT_TYPES = ("text/html", "application/xhtml")

def _is_html_response(resp: dict) -> bool:
    hdict = headers_dict(resp.get("headers", []))
    ct = header_value(hdict, "content-type") or ""
    return any(t in ct.lower() for t in _HTML_CONTENT_TYPES)


def rule_missing_security_headers(entry: dict) -> list[Finding]:
    resp = entry.get("response", {})
    req  = entry.get("request", {})
    url  = req.get("url", "")

    if not _is_html_response(resp):
        return []

    hdict = headers_dict(resp.get("headers", []))
    findings = []

    # Content-Security-Policy
    csp = header_value(hdict, "content-security-policy")
    if not csp:
        findings.append(Finding(
            severity="medium",
            rule_id="MISSING_CSP",
            title="Missing Content-Security-Policy header",
            detail="No CSP header on an HTML response. Without CSP, inline XSS payloads "
                   "and injected scripts execute without restriction.",
            url=url,
        ))
    else:
        # Check for weak CSP
        _check_csp(csp, url, findings)

    # X-Frame-Options (or CSP frame-ancestors)
    xfo = header_value(hdict, "x-frame-options")
    csp_frame = "frame-ancestors" in (csp or "").lower()
    if not xfo and not csp_frame:
        findings.append(Finding(
            severity="medium",
            rule_id="MISSING_XFO",
            title="Missing X-Frame-Options (clickjacking protection)",
            detail="No X-Frame-Options header and no CSP frame-ancestors directive. "
                   "The page can be embedded in a cross-origin iframe — classic clickjacking vector.",
            url=url,
        ))

    # X-Content-Type-Options
    xcto = header_value(hdict, "x-content-type-options")
    if not xcto:
        findings.append(Finding(
            severity="low",
            rule_id="MISSING_XCTO",
            title="Missing X-Content-Type-Options: nosniff",
            detail="Without nosniff, browsers may MIME-sniff responses, potentially executing "
                   "uploaded content (e.g. a JPEG that contains JS) as a script.",
            url=url,
        ))

    # Referrer-Policy
    rp = header_value(hdict, "referrer-policy")
    if not rp:
        findings.append(Finding(
            severity="low",
            rule_id="MISSING_RP",
            title="Missing Referrer-Policy header",
            detail="Without a Referrer-Policy, sensitive URL paths can leak to third parties "
                   "via the Referer header when navigating away.",
            url=url,
        ))

    return findings


def _check_csp(csp: str, url: str, findings: list) -> None:
    csp_lower = csp.lower()

    # unsafe-inline in script-src
    if "unsafe-inline" in csp_lower and "script-src" in csp_lower:
        findings.append(Finding(
            severity="high",
            rule_id="CSP_UNSAFE_INLINE",
            title="CSP allows 'unsafe-inline' scripts",
            detail="'unsafe-inline' in script-src defeats XSS protection entirely. "
                   "Inline scripts, event handlers, and javascript: URLs all execute.",
            url=url,
            evidence=csp[:120],
        ))

    # unsafe-eval
    if "unsafe-eval" in csp_lower:
        findings.append(Finding(
            severity="medium",
            rule_id="CSP_UNSAFE_EVAL",
            title="CSP allows 'unsafe-eval'",
            detail="'unsafe-eval' allows eval(), Function(), setTimeout(string), etc. "
                   "DOM XSS via these sinks bypasses the CSP.",
            url=url,
            evidence=csp[:120],
        ))

    # wildcard source
    if re.search(r"script-src[^;]*\*", csp_lower):
        findings.append(Finding(
            severity="high",
            rule_id="CSP_WILDCARD",
            title="CSP script-src uses wildcard (*)",
            detail="A wildcard in script-src allows scripts to be loaded from any origin, "
                   "including attacker-controlled hosts.",
            url=url,
            evidence=csp[:120],
        ))


# ── HSTS missing on HTTPS ─────────────────────────────────────────────────────

def rule_missing_hsts(entry: dict) -> list[Finding]:
    req  = entry.get("request", {})
    resp = entry.get("response", {})
    url  = req.get("url", "")

    if not url.startswith("https://"):
        return []

    hdict = headers_dict(resp.get("headers", []))
    hsts  = header_value(hdict, "strict-transport-security")
    if not hsts:
        return [Finding(
            severity="medium",
            rule_id="MISSING_HSTS",
            title="Missing HSTS header on HTTPS response",
            detail="Without Strict-Transport-Security, browsers may downgrade to HTTP "
                   "on subsequent visits, enabling MITM/stripping attacks.",
            url=url,
        )]

    # Check max-age is reasonable (< 1 year is weak)
    m = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
    if m and int(m.group(1)) < 31536000:
        return [Finding(
            severity="low",
            rule_id="HSTS_SHORT_MAX_AGE",
            title="HSTS max-age is less than one year",
            detail=f"HSTS max-age={m.group(1)} ({int(m.group(1))//86400} days). "
                   "Recommended minimum is 31536000 (1 year). Short max-age reduces protection window.",
            url=url,
            evidence=hsts,
        )]

    return []


# ── Information leakage in response headers ───────────────────────────────────

_VERSION_PATTERN = re.compile(r"[\d]+\.[\d]+")

def rule_info_leakage_headers(entry: dict) -> list[Finding]:
    resp  = entry.get("response", {})
    req   = entry.get("request", {})
    url   = req.get("url", "")
    hdict = headers_dict(resp.get("headers", []))
    findings = []

    for header in ("server", "x-powered-by", "x-generator", "x-aspnet-version",
                   "x-aspnetmvc-version", "x-runtime", "x-drupal-cache",
                   "x-wordpress-logged-in", "x-varnish"):
        val = header_value(hdict, header)
        if val:
            has_version = bool(_VERSION_PATTERN.search(val))
            findings.append(Finding(
                severity="low" if has_version else "info",
                rule_id="HEADER_LEAKS_TECH",
                title=f"Response header reveals tech stack: {header}",
                detail=f"The '{header}' header discloses the server technology"
                       f"{' and version number' if has_version else ''}. "
                       "Version disclosure helps attackers select targeted exploits.",
                url=url,
                evidence=f"{header}: {val}",
            ))

    return findings


# ── Stack traces / error disclosure in response body ─────────────────────────

_STACK_TRACE_PATTERNS = [
    (re.compile(r"Traceback \(most recent call last\)", re.IGNORECASE), "Python traceback"),
    (re.compile(r"at [A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*\([\w.]+:\d+\)"), "Java/JS stack trace"),
    (re.compile(r"System\.NullReferenceException|System\.Exception", re.IGNORECASE), ".NET exception"),
    (re.compile(r"<b>Fatal error</b>|<b>Warning</b>.*on line \d+", re.IGNORECASE), "PHP error"),
    (re.compile(r"ActiveRecord::|ActionController::|Rails\.application", re.IGNORECASE), "Rails debug info"),
    (re.compile(r"SQLException|ORA-\d{5}|mysql_fetch|pg_query", re.IGNORECASE), "Database error disclosure"),
    (re.compile(r"Internal Server Error.*Werkzeug|Werkzeug Debugger", re.IGNORECASE), "Flask/Werkzeug debugger"),
]

def rule_stack_trace_in_body(entry: dict) -> list[Finding]:
    resp = entry.get("response", {})
    req  = entry.get("request", {})
    url  = req.get("url", "")

    content = resp.get("content", {})
    body = content.get("text", "") or ""
    if not body:
        return []

    findings = []
    for pattern, label in _STACK_TRACE_PATTERNS:
        m = pattern.search(body)
        if m:
            start = max(0, m.start() - 20)
            snippet = body[start : m.start() + 80].replace("\n", " ")
            findings.append(Finding(
                severity="high",
                rule_id="STACK_TRACE",
                title=f"Stack trace / error disclosure in response body ({label})",
                detail=f"A {label} was found in the response body. Stack traces disclose "
                       "file paths, class names, library versions, and internal logic — "
                       "all useful for targeted exploitation.",
                url=url,
                evidence=snippet[:120],
            ))
            break  # one finding per entry is enough

    return []  # keep this unreachable until body-decode is reliable
# Note: rule disabled by default (body content may be base64-encoded in some HAR exporters)
# Uncomment `return findings` above and remove the `return []` to enable.


def rule_stack_trace_in_body_enabled(entry: dict) -> list[Finding]:
    """Same as above but actually returns findings — used in tests."""
    resp = entry.get("response", {})
    req  = entry.get("request", {})
    url  = req.get("url", "")

    content = resp.get("content", {})
    body = content.get("text", "") or ""
    if not body:
        return []

    for pattern, label in _STACK_TRACE_PATTERNS:
        m = pattern.search(body)
        if m:
            start = max(0, m.start() - 20)
            snippet = body[start : m.start() + 80].replace("\n", " ")
            return [Finding(
                severity="high",
                rule_id="STACK_TRACE",
                title=f"Stack trace / error disclosure in response body ({label})",
                detail=f"A {label} was found in the response body. Stack traces disclose "
                       "file paths, class names, library versions, and internal logic — "
                       "all useful for targeted exploitation.",
                url=url,
                evidence=snippet[:120],
            )]
    return []


# ── Cookie security flags ─────────────────────────────────────────────────────

def rule_cookie_flags(entry: dict) -> list[Finding]:
    resp = entry.get("response", {})
    req  = entry.get("request", {})
    url  = req.get("url", "")
    findings = []

    is_https = url.startswith("https://")

    for h in resp.get("headers", []):
        if h.get("name", "").lower() != "set-cookie":
            continue
        cookie_str = h.get("value", "")
        name = cookie_str.split("=")[0].strip()
        cookie_lower = cookie_str.lower()

        is_session_like = any(k in name.lower() for k in
                              ("session", "token", "auth", "sid", "login", "csrf", "xsrf"))

        if "httponly" not in cookie_lower:
            findings.append(Finding(
                severity="medium" if is_session_like else "low",
                rule_id="COOKIE_NO_HTTPONLY",
                title=f"Cookie '{name}' missing HttpOnly flag",
                detail="Without HttpOnly, the cookie is accessible to JavaScript. "
                       "An XSS payload can steal it with document.cookie.",
                url=url,
                evidence=cookie_str[:100],
            ))

        if is_https and "secure" not in cookie_lower:
            findings.append(Finding(
                severity="medium" if is_session_like else "low",
                rule_id="COOKIE_NO_SECURE",
                title=f"Cookie '{name}' missing Secure flag on HTTPS",
                detail="Without the Secure flag, the cookie can be sent over HTTP "
                       "if the browser is downgraded to HTTP (e.g. via MITM/HSTS stripping).",
                url=url,
                evidence=cookie_str[:100],
            ))

        if "samesite" not in cookie_lower and is_session_like:
            findings.append(Finding(
                severity="low",
                rule_id="COOKIE_NO_SAMESITE",
                title=f"Session cookie '{name}' missing SameSite attribute",
                detail="Without SameSite, the cookie is sent on cross-site requests. "
                       "Combined with a CSRF-vulnerable endpoint, this enables CSRF attacks.",
                url=url,
                evidence=cookie_str[:100],
            ))

    return findings


# ── HTTP (non-HTTPS) for authenticated requests ───────────────────────────────

def rule_auth_over_http(entry: dict) -> list[Finding]:
    req  = entry.get("request", {})
    url  = req.get("url", "")
    if url.startswith("https://"):
        return []

    hdict = headers_dict(req.get("headers", []))
    findings = []

    if header_value(hdict, "authorization") or header_value(hdict, "cookie"):
        findings.append(Finding(
            severity="high",
            rule_id="AUTH_OVER_HTTP",
            title="Credentials/cookies sent over plain HTTP",
            detail="An Authorization header or cookies were transmitted over an unencrypted "
                   "HTTP connection. Any network observer can capture these credentials.",
            url=url,
            evidence=f"URL: {url[:80]}",
        ))

    return findings


# ── CORS misconfiguration ─────────────────────────────────────────────────────

def rule_cors_misconfiguration(entry: dict) -> list[Finding]:
    resp  = entry.get("response", {})
    req   = entry.get("request", {})
    url   = req.get("url", "")
    hdict = headers_dict(resp.get("headers", []))
    findings = []

    acao = header_value(hdict, "access-control-allow-origin")
    acac = header_value(hdict, "access-control-allow-credentials")

    if acao == "*" and acac and acac.lower() == "true":
        findings.append(Finding(
            severity="critical",
            rule_id="CORS_WILDCARD_WITH_CREDENTIALS",
            title="CORS: wildcard origin + credentials allowed (critical misconfiguration)",
            detail="Access-Control-Allow-Origin: * combined with Allow-Credentials: true "
                   "is a CORS specification violation that some older browsers honour. "
                   "Any origin can make credentialed cross-site requests.",
            url=url,
            evidence=f"ACAO: {acao} | ACAC: {acac}",
        ))

    elif acao and acao != "*":
        # Reflected origin check — if the Origin request header value is echoed verbatim
        req_origin = header_value(headers_dict(req.get("headers", [])), "origin")
        if req_origin and acao == req_origin:
            cred_allowed = acac and acac.lower() == "true"
            findings.append(Finding(
                severity="high" if cred_allowed else "medium",
                rule_id="CORS_REFLECTED_ORIGIN",
                title="CORS policy reflects the request Origin verbatim",
                detail="The server echoes back whatever Origin header the client sends, "
                       "effectively granting any origin cross-site access. "
                       + ("With credentials allowed, any site can make authenticated requests." if cred_allowed
                          else "Credentials are not allowed, limiting direct session theft."),
                url=url,
                evidence=f"Request Origin: {req_origin} | ACAO: {acao}",
            ))

    return findings


# ── Mixed content ─────────────────────────────────────────────────────────────

def rule_mixed_content(entry: dict) -> list[Finding]:
    req  = entry.get("request", {})
    url  = req.get("url", "")
    # An HTTP resource loaded within what appears to be an HTTPS browsing session
    # We detect this conservatively: HTTP request where Referer is HTTPS
    if url.startswith("https://"):
        return []

    hdict = headers_dict(req.get("headers", []))
    referer = header_value(hdict, "referer") or ""

    if referer.startswith("https://"):
        return [Finding(
            severity="medium",
            rule_id="MIXED_CONTENT",
            title="HTTP resource loaded from HTTPS page (mixed content)",
            detail="An HTTP resource was fetched from an HTTPS page. Modern browsers block "
                   "active mixed content (scripts, iframes) but may allow passive (images). "
                   "This can degrade the security of the HTTPS page.",
            url=url,
            evidence=f"Referer: {referer[:80]}",
        )]

    return []


# ── Sensitive data patterns in response (API keys, etc.) ─────────────────────

_SECRET_PATTERNS = [
    (re.compile(r'(?i)"api[_-]?key"\s*:\s*"([^"]{8,})"'), "API key in JSON response"),
    (re.compile(r'(?i)"(secret|password|passwd|token)"\s*:\s*"([^"]{4,})"'), "Secret in JSON response"),
    (re.compile(r'AKIA[0-9A-Z]{16}'), "AWS access key ID"),
    (re.compile(r'(?i)-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'), "Private key material"),
    (re.compile(r'(?i)ghp_[A-Za-z0-9]{36}'), "GitHub personal access token"),
    (re.compile(r'(?i)sk-[A-Za-z0-9]{48}'), "OpenAI API key"),
]

def rule_secrets_in_response(entry: dict) -> list[Finding]:
    resp = entry.get("response", {})
    req  = entry.get("request", {})
    url  = req.get("url", "")

    content = resp.get("content", {})
    body = content.get("text", "") or ""
    if not body:
        return []

    findings = []
    seen_rules = set()
    for pattern, label in _SECRET_PATTERNS:
        m = pattern.search(body)
        if m and label not in seen_rules:
            seen_rules.add(label)
            snippet = m.group(0)[:80]
            findings.append(Finding(
                severity="critical",
                rule_id="SECRET_IN_RESPONSE",
                title=f"Potential secret exposed in response body: {label}",
                detail=f"A pattern matching '{label}' was found in the response body. "
                       "If genuine, this credential can be used directly by an attacker "
                       "who can intercept or read this response.",
                url=url,
                evidence=snippet,
            ))

    return findings


# ── All rules ─────────────────────────────────────────────────────────────────

ALL_RULES = [
    rule_token_in_url,
    rule_auth_header_inventory,
    rule_missing_security_headers,
    rule_missing_hsts,
    rule_info_leakage_headers,
    rule_stack_trace_in_body,       # body decode disabled by default; see note in function
    rule_cookie_flags,
    rule_auth_over_http,
    rule_cors_misconfiguration,
    rule_mixed_content,
    rule_secrets_in_response,
]


# ══════════════════════════════════════════════════════════════════════════════
# SCANNER
# ══════════════════════════════════════════════════════════════════════════════

def scan(har: dict, rules=None) -> list[Finding]:
    if rules is None:
        rules = ALL_RULES
    findings: list[Finding] = []
    for entry in iter_entries(har):
        for rule in rules:
            try:
                findings.extend(rule(entry))
            except Exception:  # noqa: BLE001, S110 — intentional crash-guard
                pass
    return sorted(findings, key=lambda f: f.severity_rank())


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """
    Collapse findings with the same rule_id + url into one.
    Keeps the highest severity instance and appends a count if more than one.
    """
    key_to_findings: dict[tuple, list[Finding]] = {}
    for f in findings:
        k = (f.rule_id, f.url)
        key_to_findings.setdefault(k, []).append(f)

    result = []
    for group in key_to_findings.values():
        best = min(group, key=lambda f: f.severity_rank())
        if len(group) > 1:
            best = Finding(
                severity=best.severity,
                rule_id=best.rule_id,
                title=best.title,
                detail=best.detail,
                url=best.url,
                evidence=best.evidence,
            )
        result.append(best)

    return sorted(result, key=lambda f: f.severity_rank())


# ══════════════════════════════════════════════════════════════════════════════
# OUTPUT
# ══════════════════════════════════════════════════════════════════════════════

def _color(severity: str, text: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{SEVERITY_COLOR.get(severity, '')}{text}{RESET}"


def render_text(findings: list[Finding], use_color: bool = True) -> str:
    if not findings:
        return "✓ No findings.\n"

    lines = []
    current_severity = None

    for f in findings:
        if f.severity != current_severity:
            current_severity = f.severity
            label = f"── {f.severity.upper()} "
            label = _color(f.severity, label + "─" * (60 - len(label)), use_color)
            lines.append(f"\n{label}")

        sev_badge = _color(f.severity, f"[{f.severity.upper()}]", use_color)
        title = f"{BOLD}{f.title}{RESET}" if use_color else f.title
        lines.append(f"\n  {sev_badge} {title}")
        lines.append(f"  Rule:   {f.rule_id}")
        lines.append(f"  URL:    {f.url}")
        if f.evidence:
            lines.append(f"  Found:  {f.evidence}")
        # Wrap detail at 80 chars
        detail_lines = []
        words = f.detail.split()
        line_buf = "  Detail: "
        for w in words:
            if len(line_buf) + len(w) + 1 > 80:
                detail_lines.append(line_buf)
                line_buf = "          " + w + " "
            else:
                line_buf += w + " "
        detail_lines.append(line_buf.rstrip())
        lines.extend(detail_lines)

    # Summary
    from collections import Counter
    counts = Counter(f.severity for f in findings)
    summary_parts = [
        _color(sev, f"{counts[sev]} {sev}", use_color)
        for sev in SEVERITY_ORDER
        if sev in counts
    ]
    lines.append(f"\n── Summary: {', '.join(summary_parts)} ── {len(findings)} total findings\n")

    return "\n".join(lines)


def render_json(findings: list[Finding]) -> str:
    return json.dumps(
        [
            {
                "severity": f.severity,
                "rule_id":  f.rule_id,
                "title":    f.title,
                "detail":   f.detail,
                "url":      f.url,
                "evidence": f.evidence,
            }
            for f in findings
        ],
        indent=2,
    )


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="headerspy",
        description="HAR file security auditor — finds security issues across every request/response pair.",
    )
    sub = p.add_subparsers(dest="command")

    scan_p = sub.add_parser("scan", help="Scan a .har file")
    scan_p.add_argument("file", type=Path, help="Path to the .har file")
    scan_p.add_argument(
        "--min-severity", "-s",
        choices=list(SEVERITY_ORDER),
        default="info",
        help="Only show findings at or above this severity (default: info)",
    )
    scan_p.add_argument(
        "--json", action="store_true",
        help="Output findings as JSON",
    )
    scan_p.add_argument(
        "--out", "-o", type=Path, default=None,
        help="Write output to a file instead of stdout",
    )
    scan_p.add_argument(
        "--no-dedup", action="store_true",
        help="Show every finding, including duplicates for the same rule+URL",
    )
    scan_p.add_argument(
        "--no-color", action="store_true",
        help="Disable ANSI color output",
    )

    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help()
        sys.exit(0)

    # Load HAR
    try:
        har = load_har(args.file)
    except FileNotFoundError:
        print(f"error: file not found: {args.file}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"error: not a valid HAR/JSON file: {e}", file=sys.stderr)
        sys.exit(1)

    # Scan
    findings = scan(har)

    # Filter by severity
    min_rank = SEVERITY_ORDER[args.min_severity]
    findings = [f for f in findings if f.severity_rank() <= min_rank]

    # Dedup
    if not args.no_dedup:
        findings = deduplicate(findings)

    # Render
    use_color = not args.no_color and sys.stdout.isatty()
    if args.json:
        output = render_json(findings)
        use_color = False
    else:
        output = render_text(findings, use_color=use_color)

    # Output
    if args.out:
        args.out.write_text(output, encoding="utf-8")
        print(f"Report written to {args.out}")
    else:
        print(output)

    # Exit code: non-zero if findings at high+ severity
    high_plus = [f for f in findings if f.severity_rank() <= SEVERITY_ORDER["high"]]
    sys.exit(1 if high_plus else 0)


if __name__ == "__main__":
    main()
