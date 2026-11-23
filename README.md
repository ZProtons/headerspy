# headerspy

A HAR file security auditor. Export your browser traffic, hand it to headerspy, get a prioritized finding list across every single request/response pair.

```
$ headerspy scan capture.har

── CRITICAL ────────────────────────────────────────────────
  [CRITICAL] Potential secret exposed in response body: AWS access key ID
  Rule:   SECRET_IN_RESPONSE
  URL:    https://api.example.com/user?api_key=sk_live_abc123

── HIGH ────────────────────────────────────────────────────
  [HIGH] Sensitive parameter in URL query string
  Rule:   TOKEN_IN_URL
  Found:  api_key=sk_live_abc123

  [HIGH] CORS policy reflects the request Origin verbatim
  Rule:   CORS_REFLECTED_ORIGIN
  Found:  Request Origin: https://evil.com | ACAO: https://evil.com

── Summary: 1 critical, 4 high, 7 medium, 7 low ── 19 total findings
```

---

## Why

Security header audits are normally done with online tools, on the homepage only. But the real bugs — tokens in URLs, stack traces in error responses, missing CORS on API endpoints, cookies set without `HttpOnly` on the login page — only appear in the full traffic capture.

headerspy reads every request and response in a `.har` file and runs a security rule set across all of them. No network required. No API keys. Entirely offline.

---

## Getting a HAR file

**Browser DevTools** (Chrome/Firefox/Edge):
1. Open DevTools → Network tab
2. Browse the app (log in, do something, trigger errors)
3. Right-click any request → "Save all as HAR with content"

**Burp Suite**:
Proxy → HTTP history → select requests → right-click → "Save items" → export as HAR

---

## Install

```bash
git clone https://github.com/ZProtons/headerspy
cd headerspy
# No runtime dependencies — stdlib only
python headerspy.py scan capture.har
```

---

## Usage

```bash
# Basic scan
headerspy scan capture.har

# Only show medium and above
headerspy scan capture.har --min-severity medium

# JSON output (for piping into jq or other tools)
headerspy scan capture.har --json | jq '.[] | select(.severity == "critical")'

# Write report to a file
headerspy scan capture.har --out report.txt --no-color

# Show every finding including duplicates (default: deduped by rule+URL)
headerspy scan capture.har --no-dedup
```

**Exit codes**: `0` = no high/critical findings. `1` = at least one high or critical.  
Useful for CI: `headerspy scan traffic.har || echo "Security findings — check report"`

---

## Rules

| Rule ID | Severity | What it checks |
|---------|----------|----------------|
| `SECRET_IN_RESPONSE` | critical | AWS keys, GitHub tokens, OpenAI keys, private keys in response bodies |
| `CORS_WILDCARD_WITH_CREDENTIALS` | critical | `ACAO: *` + `Allow-Credentials: true` |
| `TOKEN_IN_URL` | high | `api_key=`, `token=`, `password=`, etc. in query strings |
| `BEARER_IN_URL` | high | `Bearer <token>` literal embedded in a URL |
| `CSP_UNSAFE_INLINE` | high | `unsafe-inline` in `script-src` |
| `CSP_WILDCARD` | high | `script-src *` |
| `CORS_REFLECTED_ORIGIN` | high/medium | Server echoes back whatever `Origin` the client sends |
| `AUTH_OVER_HTTP` | high | `Authorization` or `Cookie` sent over plain HTTP |
| `STACK_TRACE` | high | Python/PHP/Java/Rails/.NET stack traces in response bodies |
| `MISSING_CSP` | medium | No `Content-Security-Policy` on HTML responses |
| `MISSING_XFO` | medium | No `X-Frame-Options` and no `frame-ancestors` CSP |
| `MISSING_HSTS` | medium | No `Strict-Transport-Security` on HTTPS responses |
| `BASIC_AUTH` | medium | HTTP Basic authentication in use |
| `COOKIE_NO_HTTPONLY` | medium/low | Cookie missing `HttpOnly` flag |
| `COOKIE_NO_SECURE` | medium/low | Cookie missing `Secure` flag on HTTPS |
| `MIXED_CONTENT` | medium | HTTP resource fetched from an HTTPS page |
| `CSP_UNSAFE_EVAL` | medium | `unsafe-eval` in CSP |
| `MISSING_XCTO` | low | Missing `X-Content-Type-Options: nosniff` |
| `MISSING_RP` | low | Missing `Referrer-Policy` |
| `COOKIE_NO_SAMESITE` | low | Session cookie missing `SameSite` |
| `HSTS_SHORT_MAX_AGE` | low | HSTS `max-age` less than 1 year |
| `HEADER_LEAKS_TECH` | low/info | `Server`, `X-Powered-By`, `X-Generator` disclosing version info |

---

## Dev

```bash
pip install -r requirements-dev.txt
pytest tests/ -v        # 65 tests, no network needed
ruff check .
```

[![CI](https://github.com/ZProtons/headerspy/actions/workflows/ci.yml/badge.svg)](https://github.com/ZProtons/headerspy/actions/workflows/ci.yml)

---
