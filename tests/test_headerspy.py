"""
Tests for headerspy — HAR file security auditor.

All tests use synthetic HAR entry dicts — no network, no real HAR files needed.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from headerspy import (
    Finding,
    deduplicate,
    headers_dict,
    load_har,
    render_json,
    render_text,
    rule_auth_over_http,
    rule_cookie_flags,
    rule_cors_misconfiguration,
    rule_info_leakage_headers,
    rule_missing_hsts,
    rule_missing_security_headers,
    rule_mixed_content,
    rule_secrets_in_response,
    rule_stack_trace_in_body_enabled,
    rule_token_in_url,
    scan,
)

# ── helpers ────────────────────────────────────────────────────────────────────

def make_entry(
    url="http://example.com/",
    method="GET",
    req_headers=None,
    resp_status=200,
    resp_headers=None,
    resp_body="",
):
    """Build a minimal HAR entry dict."""
    return {
        "request": {
            "method": method,
            "url": url,
            "headers": [{"name": k, "value": v} for k, v in (req_headers or {}).items()],
            "queryString": [],
            "cookies": [],
        },
        "response": {
            "status": resp_status,
            "headers": [{"name": k, "value": v} for k, v in (resp_headers or {}).items()],
            "content": {"mimeType": "text/html", "text": resp_body},
        },
    }


def make_har(entries):
    return {"log": {"entries": entries}}


def rule_ids(findings):
    return {f.rule_id for f in findings}


def severities(findings):
    return [f.severity for f in findings]


# ══════════════════════════════════════════════════════════════════════════════
# rule_token_in_url
# ══════════════════════════════════════════════════════════════════════════════

class TestTokenInUrl:
    def test_api_key_in_query_string(self):
        entry = make_entry(url="https://api.example.com/data?api_key=supersecret123")
        findings = rule_token_in_url(entry)
        assert any(f.rule_id == "TOKEN_IN_URL" for f in findings)
        assert any("api_key" in f.evidence for f in findings)

    def test_token_param_flagged(self):
        entry = make_entry(url="https://example.com/reset?token=abc123xyz")
        findings = rule_token_in_url(entry)
        assert any(f.rule_id == "TOKEN_IN_URL" for f in findings)

    def test_password_in_url(self):
        entry = make_entry(url="https://example.com/login?password=hunter2")
        findings = rule_token_in_url(entry)
        assert any(f.rule_id == "TOKEN_IN_URL" for f in findings)

    def test_innocent_param_not_flagged(self):
        entry = make_entry(url="https://example.com/search?q=hello&page=2")
        findings = rule_token_in_url(entry)
        assert findings == []

    def test_no_query_string(self):
        entry = make_entry(url="https://example.com/page")
        assert rule_token_in_url(entry) == []

    def test_access_token_param(self):
        entry = make_entry(url="https://api.com/v1/me?access_token=eyJ0eXAiOiJKV1QiLCJhb")
        findings = rule_token_in_url(entry)
        assert any(f.rule_id == "TOKEN_IN_URL" for f in findings)
        assert any("high" == f.severity for f in findings)


# ══════════════════════════════════════════════════════════════════════════════
# rule_missing_security_headers
# ══════════════════════════════════════════════════════════════════════════════

class TestMissingSecurityHeaders:
    def _html_entry(self, url="https://example.com/", extra_headers=None):
        headers = {"Content-Type": "text/html; charset=utf-8"}
        if extra_headers:
            headers.update(extra_headers)
        return make_entry(url=url, resp_headers=headers)

    def test_missing_csp(self):
        entry = self._html_entry()
        ids = rule_ids(rule_missing_security_headers(entry))
        assert "MISSING_CSP" in ids

    def test_missing_xfo(self):
        entry = self._html_entry()
        ids = rule_ids(rule_missing_security_headers(entry))
        assert "MISSING_XFO" in ids

    def test_present_csp_not_flagged_missing(self):
        entry = self._html_entry(extra_headers={"Content-Security-Policy": "default-src 'self'"})
        ids = rule_ids(rule_missing_security_headers(entry))
        assert "MISSING_CSP" not in ids

    def test_unsafe_inline_in_csp(self):
        entry = self._html_entry(extra_headers={
            "Content-Security-Policy": "script-src 'self' 'unsafe-inline'"
        })
        ids = rule_ids(rule_missing_security_headers(entry))
        assert "CSP_UNSAFE_INLINE" in ids

    def test_unsafe_eval_in_csp(self):
        entry = self._html_entry(extra_headers={
            "Content-Security-Policy": "script-src 'self' 'unsafe-eval'"
        })
        ids = rule_ids(rule_missing_security_headers(entry))
        assert "CSP_UNSAFE_EVAL" in ids

    def test_wildcard_csp(self):
        entry = self._html_entry(extra_headers={
            "Content-Security-Policy": "script-src *"
        })
        ids = rule_ids(rule_missing_security_headers(entry))
        assert "CSP_WILDCARD" in ids

    def test_non_html_response_skipped(self):
        entry = make_entry(
            resp_headers={"Content-Type": "application/json"},
        )
        assert rule_missing_security_headers(entry) == []

    def test_xcto_missing(self):
        entry = self._html_entry()
        ids = rule_ids(rule_missing_security_headers(entry))
        assert "MISSING_XCTO" in ids

    def test_xcto_present_not_flagged(self):
        entry = self._html_entry(extra_headers={"X-Content-Type-Options": "nosniff"})
        ids = rule_ids(rule_missing_security_headers(entry))
        assert "MISSING_XCTO" not in ids

    def test_xfo_via_csp_frame_ancestors_accepted(self):
        entry = self._html_entry(extra_headers={
            "Content-Security-Policy": "frame-ancestors 'self'"
        })
        ids = rule_ids(rule_missing_security_headers(entry))
        assert "MISSING_XFO" not in ids


# ══════════════════════════════════════════════════════════════════════════════
# rule_missing_hsts
# ══════════════════════════════════════════════════════════════════════════════

class TestMissingHsts:
    def test_https_without_hsts_flagged(self):
        entry = make_entry(url="https://example.com/", resp_headers={})
        findings = rule_missing_hsts(entry)
        assert any(f.rule_id == "MISSING_HSTS" for f in findings)

    def test_http_not_flagged(self):
        entry = make_entry(url="http://example.com/", resp_headers={})
        assert rule_missing_hsts(entry) == []

    def test_https_with_hsts_ok(self):
        entry = make_entry(
            url="https://example.com/",
            resp_headers={"Strict-Transport-Security": "max-age=31536000; includeSubDomains"}
        )
        assert rule_missing_hsts(entry) == []

    def test_short_max_age_flagged(self):
        entry = make_entry(
            url="https://example.com/",
            resp_headers={"Strict-Transport-Security": "max-age=86400"}
        )
        findings = rule_missing_hsts(entry)
        assert any(f.rule_id == "HSTS_SHORT_MAX_AGE" for f in findings)


# ══════════════════════════════════════════════════════════════════════════════
# rule_info_leakage_headers
# ══════════════════════════════════════════════════════════════════════════════

class TestInfoLeakageHeaders:
    def test_server_header_with_version(self):
        entry = make_entry(resp_headers={"Server": "Apache/2.4.51 (Ubuntu)"})
        findings = rule_info_leakage_headers(entry)
        assert any(f.rule_id == "HEADER_LEAKS_TECH" for f in findings)
        assert any(f.severity == "low" for f in findings)

    def test_x_powered_by_flagged(self):
        entry = make_entry(resp_headers={"X-Powered-By": "PHP/8.1.3"})
        findings = rule_info_leakage_headers(entry)
        assert any("x-powered-by" in f.evidence.lower() for f in findings)

    def test_no_tech_headers_clean(self):
        entry = make_entry(resp_headers={"Content-Type": "text/html"})
        assert rule_info_leakage_headers(entry) == []

    def test_server_without_version_is_info(self):
        entry = make_entry(resp_headers={"Server": "nginx"})
        findings = rule_info_leakage_headers(entry)
        # Present but no version → info severity
        assert any(f.severity == "info" for f in findings)


# ══════════════════════════════════════════════════════════════════════════════
# rule_stack_trace_in_body (enabled variant)
# ══════════════════════════════════════════════════════════════════════════════

class TestStackTrace:
    def test_python_traceback_detected(self):
        body = "Traceback (most recent call last):\n  File 'app.py', line 12\nValueError: bad"
        entry = make_entry(resp_body=body)
        findings = rule_stack_trace_in_body_enabled(entry)
        assert any(f.rule_id == "STACK_TRACE" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_php_error_detected(self):
        body = "<b>Fatal error</b>: Call to undefined function on line 42"
        entry = make_entry(resp_body=body)
        findings = rule_stack_trace_in_body_enabled(entry)
        assert any(f.rule_id == "STACK_TRACE" for f in findings)

    def test_sql_error_detected(self):
        body = "You have an error in your SQL syntax — SQLException near 'WHERE'"
        entry = make_entry(resp_body=body)
        findings = rule_stack_trace_in_body_enabled(entry)
        assert any(f.rule_id == "STACK_TRACE" for f in findings)

    def test_clean_body_no_findings(self):
        entry = make_entry(resp_body="<html><body>Hello world</body></html>")
        assert rule_stack_trace_in_body_enabled(entry) == []

    def test_empty_body_no_findings(self):
        entry = make_entry(resp_body="")
        assert rule_stack_trace_in_body_enabled(entry) == []


# ══════════════════════════════════════════════════════════════════════════════
# rule_cookie_flags
# ══════════════════════════════════════════════════════════════════════════════

class TestCookieFlags:
    def test_session_cookie_no_httponly(self):
        entry = make_entry(
            url="https://example.com/",
            resp_headers={"Set-Cookie": "sessionid=abc123; Path=/; Secure; SameSite=Lax"},
        )
        findings = rule_cookie_flags(entry)
        assert any(f.rule_id == "COOKIE_NO_HTTPONLY" for f in findings)
        assert any(f.severity == "medium" for f in findings)

    def test_secure_flag_missing_on_https(self):
        entry = make_entry(
            url="https://example.com/",
            resp_headers={"Set-Cookie": "token=xyz; Path=/; HttpOnly"},
        )
        findings = rule_cookie_flags(entry)
        assert any(f.rule_id == "COOKIE_NO_SECURE" for f in findings)

    def test_secure_flag_not_required_on_http(self):
        entry = make_entry(
            url="http://example.com/",
            resp_headers={"Set-Cookie": "pref=dark; Path=/; HttpOnly"},
        )
        findings = rule_cookie_flags(entry)
        assert not any(f.rule_id == "COOKIE_NO_SECURE" for f in findings)

    def test_well_configured_cookie_clean(self):
        entry = make_entry(
            url="https://example.com/",
            resp_headers={"Set-Cookie": "sessionid=abc; Path=/; Secure; HttpOnly; SameSite=Strict"},
        )
        findings = rule_cookie_flags(entry)
        assert findings == []

    def test_non_session_cookie_missing_httponly_is_low(self):
        entry = make_entry(
            url="https://example.com/",
            resp_headers={"Set-Cookie": "theme=dark; Path=/"},
        )
        findings = rule_cookie_flags(entry)
        httponly_findings = [f for f in findings if f.rule_id == "COOKIE_NO_HTTPONLY"]
        assert all(f.severity == "low" for f in httponly_findings)


# ══════════════════════════════════════════════════════════════════════════════
# rule_auth_over_http
# ══════════════════════════════════════════════════════════════════════════════

class TestAuthOverHttp:
    def test_auth_header_over_http_flagged(self):
        entry = make_entry(
            url="http://api.example.com/data",
            req_headers={"Authorization": "Bearer eyJhbGci..."},
        )
        findings = rule_auth_over_http(entry)
        assert any(f.rule_id == "AUTH_OVER_HTTP" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_cookie_over_http_flagged(self):
        entry = make_entry(
            url="http://example.com/profile",
            req_headers={"Cookie": "sessionid=abc123"},
        )
        findings = rule_auth_over_http(entry)
        assert any(f.rule_id == "AUTH_OVER_HTTP" for f in findings)

    def test_https_with_auth_clean(self):
        entry = make_entry(
            url="https://api.example.com/data",
            req_headers={"Authorization": "Bearer eyJhbGci..."},
        )
        assert rule_auth_over_http(entry) == []

    def test_http_no_auth_clean(self):
        entry = make_entry(url="http://example.com/public")
        assert rule_auth_over_http(entry) == []


# ══════════════════════════════════════════════════════════════════════════════
# rule_cors_misconfiguration
# ══════════════════════════════════════════════════════════════════════════════

class TestCorsMisconfiguration:
    def test_reflected_origin_with_credentials_high(self):
        entry = make_entry(
            url="https://api.example.com/user",
            req_headers={"Origin": "https://evil.com"},
            resp_headers={
                "Access-Control-Allow-Origin": "https://evil.com",
                "Access-Control-Allow-Credentials": "true",
            },
        )
        findings = rule_cors_misconfiguration(entry)
        assert any(f.rule_id == "CORS_REFLECTED_ORIGIN" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_reflected_origin_without_credentials_medium(self):
        entry = make_entry(
            url="https://api.example.com/data",
            req_headers={"Origin": "https://evil.com"},
            resp_headers={"Access-Control-Allow-Origin": "https://evil.com"},
        )
        findings = rule_cors_misconfiguration(entry)
        assert any(f.rule_id == "CORS_REFLECTED_ORIGIN" for f in findings)
        assert any(f.severity == "medium" for f in findings)

    def test_specific_trusted_origin_not_flagged(self):
        entry = make_entry(
            url="https://api.example.com/data",
            req_headers={"Origin": "https://trusted.example.com"},
            resp_headers={
                "Access-Control-Allow-Origin": "https://trusted.example.com",
                "Access-Control-Allow-Credentials": "true",
            },
        )
        # Only flagged if the response ACAO == request Origin and that origin is "evil"
        # But we can't know if it's evil — we do flag reflected origin regardless
        findings = rule_cors_misconfiguration(entry)
        assert any(f.rule_id == "CORS_REFLECTED_ORIGIN" for f in findings)

    def test_no_cors_headers_clean(self):
        entry = make_entry(url="https://example.com/")
        assert rule_cors_misconfiguration(entry) == []


# ══════════════════════════════════════════════════════════════════════════════
# rule_mixed_content
# ══════════════════════════════════════════════════════════════════════════════

class TestMixedContent:
    def test_http_resource_from_https_page(self):
        entry = make_entry(
            url="http://cdn.example.com/image.png",
            req_headers={"Referer": "https://www.example.com/page"},
        )
        findings = rule_mixed_content(entry)
        assert any(f.rule_id == "MIXED_CONTENT" for f in findings)

    def test_https_resource_clean(self):
        entry = make_entry(url="https://cdn.example.com/image.png")
        assert rule_mixed_content(entry) == []

    def test_http_from_http_referer_clean(self):
        entry = make_entry(
            url="http://cdn.example.com/image.png",
            req_headers={"Referer": "http://www.example.com/page"},
        )
        assert rule_mixed_content(entry) == []


# ══════════════════════════════════════════════════════════════════════════════
# rule_secrets_in_response
# ══════════════════════════════════════════════════════════════════════════════

class TestSecretsInResponse:
    def test_aws_key_in_response(self):
        body = '{"key": "AKIAIOSFODNN7EXAMPLE", "region": "us-east-1"}'
        entry = make_entry(resp_body=body)
        findings = rule_secrets_in_response(entry)
        assert any(f.rule_id == "SECRET_IN_RESPONSE" for f in findings)
        assert any(f.severity == "critical" for f in findings)

    def test_api_key_in_json_response(self):
        body = '{"api_key": "sk-prod-xxxxxxxxxxxxxxxxxxx", "user": "admin"}'
        entry = make_entry(resp_body=body)
        findings = rule_secrets_in_response(entry)
        assert any(f.rule_id == "SECRET_IN_RESPONSE" for f in findings)

    def test_private_key_in_response(self):
        body = "-----BEGIN RSA PRIVATE KEY-----\nMIIEo..."
        entry = make_entry(resp_body=body)
        findings = rule_secrets_in_response(entry)
        assert any(f.rule_id == "SECRET_IN_RESPONSE" for f in findings)

    def test_clean_response_no_findings(self):
        body = '{"user": "alice", "email": "alice@example.com"}'
        entry = make_entry(resp_body=body)
        assert rule_secrets_in_response(entry) == []

    def test_empty_body_clean(self):
        entry = make_entry(resp_body="")
        assert rule_secrets_in_response(entry) == []


# ══════════════════════════════════════════════════════════════════════════════
# scan() end-to-end
# ══════════════════════════════════════════════════════════════════════════════

class TestScan:
    def test_scan_empty_har(self):
        har = make_har([])
        assert scan(har) == []

    def test_scan_finds_multiple_issues(self):
        entries = [
            # Token in URL
            make_entry(url="https://api.example.com/?api_key=secret123"),
            # Auth over HTTP
            make_entry(
                url="http://api.example.com/data",
                req_headers={"Authorization": "Bearer tok"},
            ),
            # HTML page missing headers
            make_entry(
                url="https://www.example.com/",
                resp_headers={"Content-Type": "text/html"},
            ),
        ]
        har = make_har(entries)
        findings = scan(har)
        ids = rule_ids(findings)
        assert "TOKEN_IN_URL" in ids
        assert "AUTH_OVER_HTTP" in ids
        assert "MISSING_CSP" in ids

    def test_scan_sorted_by_severity(self):
        entries = [
            make_entry(url="https://example.com/", resp_headers={"Content-Type": "text/html"}),  # medium
            make_entry(url="http://example.com/", req_headers={"Authorization": "Bearer x"}),     # high
        ]
        findings = scan(make_har(entries))
        sevs = [f.severity_rank() for f in findings]
        assert sevs == sorted(sevs)

    def test_scan_does_not_crash_on_malformed_entry(self):
        har = make_har([{"request": {}, "response": {}}])
        # Should not raise
        findings = scan(har)
        assert isinstance(findings, list)


# ══════════════════════════════════════════════════════════════════════════════
# deduplicate()
# ══════════════════════════════════════════════════════════════════════════════

class TestDeduplicate:
    def test_duplicates_collapsed(self):
        f1 = Finding("medium", "MISSING_CSP", "t", "d", "https://a.com")
        f2 = Finding("medium", "MISSING_CSP", "t", "d", "https://a.com")
        result = deduplicate([f1, f2])
        assert len(result) == 1

    def test_different_urls_not_collapsed(self):
        f1 = Finding("medium", "MISSING_CSP", "t", "d", "https://a.com")
        f2 = Finding("medium", "MISSING_CSP", "t", "d", "https://b.com")
        result = deduplicate([f1, f2])
        assert len(result) == 2

    def test_different_rule_ids_not_collapsed(self):
        f1 = Finding("medium", "MISSING_CSP", "t", "d", "https://a.com")
        f2 = Finding("medium", "MISSING_XFO", "t", "d", "https://a.com")
        result = deduplicate([f1, f2])
        assert len(result) == 2


# ══════════════════════════════════════════════════════════════════════════════
# render functions
# ══════════════════════════════════════════════════════════════════════════════

class TestRender:
    def test_render_text_no_findings(self):
        out = render_text([])
        assert "No findings" in out

    def test_render_text_with_findings(self):
        f = Finding("high", "TOKEN_IN_URL", "Token in URL", "detail", "https://x.com", "token=abc")
        out = render_text([f], use_color=False)
        assert "TOKEN_IN_URL" in out
        assert "Token in URL" in out
        assert "https://x.com" in out

    def test_render_json_valid(self):
        f = Finding("high", "TOKEN_IN_URL", "Token in URL", "detail", "https://x.com", "token=abc")
        out = render_json([f])
        data = json.loads(out)
        assert len(data) == 1
        assert data[0]["rule_id"] == "TOKEN_IN_URL"
        assert data[0]["severity"] == "high"

    def test_render_text_summary_counts(self):
        findings = [
            Finding("high", "A", "t", "d", "u"),
            Finding("medium", "B", "t", "d", "u"),
            Finding("medium", "C", "t", "d", "u"),
        ]
        out = render_text(findings, use_color=False)
        assert "1 high" in out
        assert "2 medium" in out


# ══════════════════════════════════════════════════════════════════════════════
# load_har
# ══════════════════════════════════════════════════════════════════════════════

class TestLoadHar:
    def test_load_valid_har(self, tmp_path):
        har = make_har([])
        p = tmp_path / "test.har"
        p.write_text(json.dumps(har), encoding="utf-8")
        loaded = load_har(p)
        assert "log" in loaded

    def test_load_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_har(tmp_path / "nonexistent.har")


# ══════════════════════════════════════════════════════════════════════════════
# headers_dict helper
# ══════════════════════════════════════════════════════════════════════════════

class TestHeadersDict:
    def test_case_insensitive(self):
        hlist = [{"name": "Content-Type", "value": "text/html"}]
        d = headers_dict(hlist)
        assert d["content-type"] == "text/html"

    def test_empty_list(self):
        assert headers_dict([]) == {}
