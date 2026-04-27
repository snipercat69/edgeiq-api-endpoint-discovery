#!/usr/bin/env python3
"""
EdgeIQ Labs — API Endpoint Discovery
Passive + active API endpoint discovery, OpenAPI/Swagger detection,
JavaScript endpoint extraction, path brute-forcing, parameter enumeration.
"""

import argparse
import json
import os
import random
import re
import sys
import threading
import time
import urllib.request
import urllib.parse
import urllib.error
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─────────────────────────────────────────────
# ANSI helpers
# ─────────────────────────────────────────────
_GRN = '\033[92m'; _YLW = '\033[93m'; _RED = '\033[91m'; _CYA = '\033[96m'
_BLD = '\033[1m'; _RST = '\033[0m'; _MAG = '\033[35m'

def ok(t):    return f"{_GRN}{t}{_RST}"
def warn(t):  return f"{_YLW}{t}{_RST}"
def fail(t):  return f"{_RED}{t}{_RST}"
def info(t):  return f"{_CYA}{t}{_RST}"
def bold(t):  return f"{_BLD}{t}{_RST}"

# ─────────────────────────────────────────────
# Licensing
# ─────────────────────────────────────────────
LICENSE_FILE = Path.home() / ".edgeiq" / "license.key"

def is_pro():
    if LICENSE_FILE.exists():
        key = LICENSE_FILE.read().strip()
        if key in ("bundle", "pro"):
            return True
    email = os.environ.get("EDGEIQ_EMAIL", "").strip().lower()
    if email in ("gpalmieri21@gmail.com",):
        return True
    return False

# ─────────────────────────────────────────────
# Wordlists
# ─────────────────────────────────────────────
COMMON_API_PATHS = [
    # Auth
    "api/v1/auth/login", "api/v2/auth/login", "api/auth", "auth/login",
    "api/v1/auth/register", "auth/register", "api/v1/auth/refresh",
    "auth/refresh", "api/v1/auth/logout", "auth/logout", "auth/token",
    "api/v1/session", "api/v1/auth/session", "auth/me", "api/me",
    # Users
    "api/v1/users", "api/v2/users", "api/users", "users", "api/v1/users/:id",
    "api/v2/users/:id", "users/:id", "api/v1/user/:id", "user/:id",
    "api/v1/profile", "profile", "api/v1/accounts", "accounts",
    # Admin
    "api/v1/admin", "admin", "api/v1/admin/users", "admin/users",
    "api/v1/admin/settings", "admin/settings", "api/v1/admin/dashboard",
    "api/v1/admin/stats", "admin/stats", "api/v1/admin/logs",
    "api/debug", "debug", "api/v1/debug/config", "debug/config",
    # Products
    "api/v1/products", "api/v2/products", "products", "api/products",
    "api/v1/products/:id", "products/:id", "api/v1/catalog", "catalog",
    "api/v1/inventory", "inventory", "api/v1/items", "items",
    # Orders/Payments
    "api/v1/orders", "orders", "api/v1/order/:id", "order/:id",
    "api/v1/checkout", "checkout", "api/v1/payment", "payment",
    "api/v1/payments", "payments", "api/v1/billing", "billing",
    "api/v1/subscriptions", "subscriptions", "api/v1/invoices",
    # Search
    "api/v1/search", "search", "api/v1/query", "query", "api/v1/lookup",
    "lookup", "api/v1/find", "find",
    # Files/Media
    "api/v1/upload", "upload", "api/v1/files", "files", "api/v1/media",
    "media", "api/v1/attachments", "attachments", "api/v1/images",
    "images", "api/v1/cdn",
    # Social/Comments
    "api/v1/posts", "posts", "api/v1/comments", "comments",
    "api/v1/feed", "feed", "api/v1/activity", "activity",
    "api/v1/notifications", "notifications", "api/v1/messages",
    "messages", "api/v1/chat",
    # Analytics
    "api/v1/analytics", "analytics", "api/v1/stats", "stats",
    "api/v1/metrics", "metrics", "api/v1/reports", "reports",
    "api/v1/events", "events", "api/v1/logs", "logs",
    # Config/Settings
    "api/v1/config", "config", "api/v1/settings", "settings",
    "api/v1/preferences", "preferences", "api/v1/options",
    # Health
    "api/v1/health", "health", "api/health", "api/v1/status",
    "status", "api/v1/ping", "ping", "api/v1/version", "version",
    # Swagger/OpenAPI
    "swagger/v1/api.json", "swagger/v2/api.json", "swagger.json",
    "api/v1/swagger.json", "api/v2/swagger.json", "api-docs",
    "swagger-ui", "swagger/", "api/swagger", "openapi.json",
    "api/openapi.json", "api/v1/openapi.json", "/swagger/v1/api.yaml",
    # GraphQL
    "graphql", "api/graphql", "api/v1/graphql", "graphiql",
    # Misc
    "api/v1/tokens", "tokens", "api/v1/keys", "keys", "api/v1/webhooks",
    "webhooks", "api/v1/hooks", "hooks", "api/v1/callback", "callback",
]

COMMON_QUERY_PARAMS = [
    "q", "query", "search", "filter", "page", "limit", "offset", "sort",
    "order", "orderby", "sortby", "sort_dir", "asc", "desc", "count",
    "fields", "include", "expand", "format", "callback", "jsonp",
    "access_token", "api_key", "apikey", "auth", "token", "key",
    "v", "version", "lang", "locale", "tz", "timezone", "debug",
    "start", "end", "from", "to", "since", "until", "date", "daterange",
    "min", "max", "price_min", "price_max", "lat", "lng", "lon",
    "radius", "distance", "category", "type", "status", "state",
    "user_id", "uid", "id", "ids", "item_id", "post_id", "page_id",
    "tab", "view", "layout", "mode", "theme", "lang",
]

PARAMETER_PLACEHOLDERS = [
    ":id", ":uuid", ":user_id", ":post_id", ":item_id", ":id_",
    "{id}", "{uuid}", "{user_id}", "{post_id}", "{item_id}",
    "<id>", "<uuid>",
]

# ─────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────
def normalize_url(base: str, path: str) -> str:
    base = base.rstrip("/")
    path = path.lstrip("/")
    return f"{base}/{path}"

def method_color(method: str) -> str:
    m = method.upper()
    colors = {"GET": _GRN, "POST": _CYA, "PUT": _YLW, "PATCH": _MAG, "DELETE": _RED, "HEAD": _BLD}
    return f"{colors.get(m, _GRN)}{bold(m)}{_RST}"

# ─────────────────────────────────────────────
# Passive discovery
# ─────────────────────────────────────────────
def discover_swagger(target: str) -> List[Dict]:
    """Discover Swagger/OpenAPI specification files."""
    results = []
    spec_paths = [
        "/swagger/v1/api.json", "/swagger/v2/api.json", "/swagger.json",
        "/api/v1/swagger.json", "/api/v2/swagger.json", "/api/swagger.json",
        "/api-docs", "/swagger-ui", "/swagger/", "/api/openapi.json",
        "/openapi.json", "/api/v1/openapi.yaml", "/swagger/v1/api.yaml",
        "/api-docs.json", "/api-docs.yaml",
    ]
    parsed = urllib.parse.urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"

    for spec_path in spec_paths:
        url = normalize_url(base, spec_path)
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                ct = resp.headers.get("Content-Type", "")
                content = resp.read()
                if b"<html" in content[:100].lower():
                    # Check if Swagger UI is present
                    if any(x in content.lower() for x in [b"swagger", b"swagger-ui", b"openapi"]):
                        results.append({"type": "swagger_ui", "url": url, "status": resp.status})
                    continue
                # Valid JSON spec
                try:
                    json.loads(content)
                    results.append({
                        "type": "openapi_spec",
                        "url": url,
                        "status": resp.status,
                        "format": "json" if ".json" in spec_path else "yaml"
                    })
                except:
                    pass
        except:
            pass

    return results

def parse_robots_txt(target: str) -> List[str]:
    """Extract API-related paths from robots.txt."""
    paths = []
    parsed = urllib.parse.urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"
    robots_url = normalize_url(base, "robots.txt")

    try:
        req = urllib.request.Request(robots_url, headers={"User-Agent": "*"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            content = resp.read().decode("utf-8", errors="ignore")
            for line in content.split("\n"):
                line = line.strip()
                if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and ("api" in path.lower() or path.startswith("/api")):
                        paths.append(path)
    except:
        pass

    return paths

def extract_from_js(target: str) -> List[str]:
    """Extract API endpoint patterns from JavaScript files."""
    endpoints = []
    parsed = urllib.parse.urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"

    js_url = normalize_url(base, "app.js")
    if parsed.path:
        js_url = normalize_url(base, parsed.path.rsplit("/", 1)[0] + "/app.js")

    try:
        req = urllib.request.Request(js_url, headers={
            "User-Agent": "Mozilla/5.0 (compatible; EdgeIQ-Discover/1.0)"
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            content = resp.read().decode("utf-8", errors="ignore")

            # fetch/axios/XMLHttpRequest patterns
            fetch_patterns = [
                r'fetch\(["\']([^"\']+)["\']',
                r'axios\.(?:get|post|put|delete|patch)\(["\']([^"\']+)["\']',
                r'XMLHttpRequest\.open\s*\(\s*["\'](\w+)["\']\s*,\s*["\']([^"\']+)["\']',
                r'\.get\(["\']([^"\']+)["\']',
                r'\.post\(["\']([^"\']+)["\']',
                r'\.put\(["\']([^"\']+)["\']',
                r'\.delete\(["\']([^"\']+)["\']',
                r'url:\s*["\']([^"\']+)["\']',
                r'endpoint:\s*["\']([^"\']+)["\']',
                r'baseURL:\s*["\']([^"\']+)["\']',
                r'["\'](\/api\/[^"\']+)["\']',
                r'["\'](\/v\d+\/[^"\']+)["\']',
            ]

            found_paths = set()
            for pat in fetch_patterns:
                for match in re.finditer(pat, content):
                    path = match.group(match.lastindex)
                    if "/" in path and "http" not in path[:10]:
                        clean = path.split("?")[0].split("#")[0]
                        if clean not in found_paths:
                            found_paths.add(clean)
                            endpoints.append(clean)
    except:
        pass

    return list(set(endpoints))

def analyze_favicon(target: str) -> Dict:
    """Analyze favicon for API hints."""
    parsed = urllib.parse.urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"
    favicon_url = normalize_url(base, "favicon.ico")

    result = {"favicon_found": False, "ico_hash": None, "api_hints": []}

    try:
        req = urllib.request.Request(favicon_url, headers={"User-Agent": "EdgeIQ-Discover/1.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            result["favicon_found"] = True
            content = resp.read()
            import hashlib
            result["ico_hash"] = hashlib.md5(content[:4096]).hexdigest()
    except:
        pass

    return result

# ─────────────────────────────────────────────
# Active discovery
# ─────────────────────────────────────────────
def probe_endpoint(base_url: str, path: str, method: str = "GET") -> Dict:
    """Probe a single endpoint."""
    url = normalize_url(base_url, path)
    result = {"path": path, "method": method, "url": url, "status": None, "found": False}

    try:
        req = urllib.request.Request(url, method=method, headers={
            "User-Agent": "Mozilla/5.0 (compatible; EdgeIQ-API-Discovery/1.0)",
            "Accept": "application/json, */*",
        })
        with urllib.request.urlopen(req, timeout=10) as resp:
            result["status"] = resp.status
            result["found"] = True
            result["content_type"] = resp.headers.get("Content-Type", "")
            result["headers"] = dict(resp.headers)
    except urllib.error.HTTPError as e:
        result["status"] = e.code
        result["found"] = True  # Found but not 2xx
        result["error"] = str(e)
    except urllib.error.URLError:
        pass
    except Exception:
        pass

    return result

def brute_force_endpoints(base_url: str, paths: List[str] = None,
                           threads: int = 10) -> List[Dict]:
    """Brute-force common API paths."""
    if paths is None:
        paths = COMMON_API_PATHS

    results = []
    parsed = urllib.parse.urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    def probe(path):
        # Try GET first
        r = probe_endpoint(base, path)
        if r["found"]:
            return r
        # Try HEAD
        r2 = probe_endpoint(base, path, "HEAD")
        if r2["found"]:
            return r2
        return None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(probe, p): p for p in paths}
        for future in as_completed(futures):
            try:
                r = future.result()
                if r and r.get("found"):
                    results.append(r)
            except:
                pass

    return results

def enumerate_params(base_url: str, endpoint: str) -> List[Dict]:
    """Enumerate query parameters on a discovered endpoint."""
    results = []
    parsed = urllib.parse.urlparse(endpoint)
    path = parsed.path or endpoint

    # Test common params with a known value
    test_val = "test"

    for param in COMMON_QUERY_PARAMS:
        test_url = f"{endpoint}{'?' if '?' not in endpoint else '&'}{param}={test_val}"
        try:
            req = urllib.request.Request(test_url, headers={
                "User-Agent": "Mozilla/5.0 (compatible; EdgeIQ-Discover/1.0)",
                "Accept": "application/json",
            })
            with urllib.request.urlopen(req, timeout=8) as resp:
                status = resp.status
                results.append({
                    "param": param,
                    "endpoint": path,
                    "status": status,
                    "behavior": "accepted" if status in (200, 201, 204) else "unknown"
                })
        except urllib.error.HTTPError as e:
            if e.code == 400:
                results.append({"param": param, "endpoint": path, "status": e.code, "behavior": "rejected"})
            else:
                results.append({"param": param, "endpoint": path, "status": e.code, "behavior": "error"})
        except:
            pass

    return results

# ─────────────────────────────────────────────
# API versioning detection
# ─────────────────────────────────────────────
def detect_api_version(base_url: str, endpoints: List[Dict]) -> Dict:
    """Detect API version from response headers and content."""
    info = {"versions": [], "headers": {}, "server": None}

    # Sample headers from a successful response
    sample_endpoints = [e["url"] for e in endpoints if e.get("found")][:3]

    for url in sample_endpoints[:1]:
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                info["headers"] = dict(resp.headers)
                info["server"] = resp.headers.get("Server", "")
                info["content_type"] = resp.headers.get("Content-Type", "")

                # Check for version header
                for h in ["X-API-Version", "X-API-Version", "API-Version", "DataCenter"]:
                    if h in resp.headers:
                        info["versions"].append(resp.headers[h])
        except:
            pass

    # Extract from URL paths
    for ep in endpoints:
        path = ep.get("path", "")
        ver_match = re.search(r'/v(\d+)/', path)
        if ver_match and f"v{ver_match.group(1)}" not in info["versions"]:
            info["versions"].append(f"v{ver_match.group(1)}")

    return info

# ─────────────────────────────────────────────
# Sensitive endpoint detection
# ─────────────────────────────────────────────
def detect_sensitive_endpoints(endpoints: List[Dict]) -> List[Dict]:
    """Flag potentially sensitive or dangerous endpoints."""
    sensitive = []
    sensitive_patterns = [
        ("admin", "Admin-only endpoint"),
        ("debug", "Debug endpoint — information exposure"),
        ("config", "Configuration exposure"),
        ("internal", "Internal endpoint"),
        ("private", "Private API"),
        ("secret", "Secret API key exposed in URL"),
        ("password", "Password-related endpoint"),
        (".env", "Environment file exposure"),
        (".git", "Git repository exposure"),
        ("backup", "Backup file"),
        ("swagger", "Swagger docs (potential info leak)"),
        ("api-docs", "API documentation"),
        ("graphiql", "GraphiQL interface"),
        ("/auth/roles", "Role enumeration"),
        ("/users/:id", "User ID enumeration"),
        ("/admin/users", "Admin user list"),
        ("/debug/config", "Debug configuration"),
    ]

    for ep in endpoints:
        path = ep.get("path", "").lower()
        url = ep.get("url", "").lower()
        for pattern, desc in sensitive_patterns:
            if pattern in path or pattern in url:
                ep_copy = dict(ep)
                ep_copy["sensitive"] = True
                ep_copy["sensitive_reason"] = desc
                sensitive.append(ep_copy)
                break

    return sensitive

# ─────────────────────────────────────────────
# Main discovery
# ─────────────────────────────────────────────
def discover(target: str, pro: bool = False, bundle: bool = False,
            wordlist_path: Optional[str] = None,
            threads: int = 10, output: Optional[str] = None) -> dict:
    print()
    print(f"{_CYA}{_BLD}╔{'═' * 54}╗{_RST}")
    print(f"{_CYA}{_BLD}║   API Endpoint Discovery — EdgeIQ Labs       ║{_RST}")
    print(f"{_CYA}{_BLD}╚{'═' * 54}╝{_RST}")
    print()

    tier = "BUNDLE" if bundle else ("PRO" if pro else "FREE")
    print(f"  {_MAG}▶{_RST} Target: {bold(target)}")
    print(f"  {_MAG}▶{_RST} Tier: {tier}")
    print()

    parsed = urllib.parse.urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"

    results = {
        "target": target,
        "specs": [],
        "robots_paths": [],
        "js_endpoints": [],
        "brute_forced": [],
        "parameters": [],
        "sensitive": [],
        "api_version": {},
        "threat_level": "LOW",
    }

    all_found_paths = set()

    # Swagger/OpenAPI discovery
    print(f"  {info('⏳')} Scanning for Swagger/OpenAPI specs...")
    specs = discover_swagger(target)
    results["specs"] = specs
    for s in specs:
        print(f"  {ok('✔')} {s['type']}: {s['url']} (HTTP {s['status']})")
    if not specs:
        print(f"  {warn('—')} No Swagger/OpenAPI specs found")
    print()

    # robots.txt
    print(f"  {info('⏳')} Parsing robots.txt...")
    robots_paths = parse_robots_txt(target)
    results["robots_paths"] = robots_paths
    for rp in robots_paths[:10]:
        print(f"  {ok('→')} Disallowed path: {rp}")
    if not robots_paths:
        print(f"  {warn('—')} No API-relevant paths in robots.txt")
    print()

    # JavaScript extraction (Pro+)
    if pro or bundle:
        print(f"  {info('⏳')} Scraping JavaScript files for endpoint patterns...")
        js_endpoints = extract_from_js(target)
        results["js_endpoints"] = js_endpoints
        for ep in js_endpoints[:15]:
            all_found_paths.add(ep)
            print(f"  {ok('→')} JS: {ep}")
        if not js_endpoints:
            print(f"  {warn('—')} No endpoints found in JS files")
        print()

    # Favicon analysis (Pro+)
    if pro or bundle:
        print(f"  {info('⏳')} Analyzing favicon fingerprints...")
        fav = analyze_favicon(target)
        if fav["favicon_found"]:
            print(f"  {ok('✔')} Favicon found: ICO hash {fav.get('ico_hash', 'unknown')}")
        else:
            print(f"  {warn('—')} No favicon found")
        print()

    # Brute-force paths (Pro+)
    if pro or bundle:
        print(f"  {info('⏳')} Brute-forcing common API paths ({threads} threads)...")
        wordlist = COMMON_API_PATHS
        if wordlist_path and os.path.exists(wordlist_path):
            wordlist = open(wordlist_path).read().splitlines()
            wordlist = [w.strip() for w in wordlist if w.strip() and not w.startswith("#")]

        bf_results = brute_force_endpoints(base, wordlist, threads)
        results["brute_forced"] = bf_results

        for r in bf_results:
            sc_color = _GRN if r.get("status", 0) < 400 else _RED
            sc = sc_color + str(r.get("status", "???")) + _RST
            print(f"  {ok('→')} [{method_color(r.get('method', 'GET'))}] {r['path']} — HTTP {sc}")
            all_found_paths.add(r["path"])

        print(f"  {ok('✔')} Found {len(bf_results)} endpoints via brute-force")
        print()

    # Parameter enumeration (Bundle)
    if bundle and bf_results:
        print(f"  {info('⏳')} Enumerating query parameters...")
        target_ep = bf_results[0]["url"]
        params = enumerate_params(base, target_ep)
        results["parameters"] = params
        accepted = [p for p in params if p["behavior"] == "accepted"]
        print(f"  {ok('✔')} {len(accepted)} accepted params on {bf_results[0]['path']}")
        for p in params[:10]:
            print(f"    {p['param']}: HTTP {p['status']} ({p['behavior']})")
        print()

    # Sensitive endpoint detection
    all_endpoints = list(all_found_paths)
    sensitive = detect_sensitive_endpoints([
        {"path": p, "url": normalize_url(base, p), "method": "GET"}
        for p in all_endpoints
    ])
    results["sensitive"] = [
        {"path": s["path"], "reason": s["sensitive_reason"]}
        for s in sensitive
    ]

    if sensitive:
        print(f"  {bold('Hidden/sensitive endpoints:')}")
        for s in sensitive[:10]:
            print(f"  {fail('⚠️ ')} {s['path']} — {s['sensitive_reason']}")
        print()

    # API version detection
    if bf_results:
        ver_info = detect_api_version(base, bf_results)
        results["api_version"] = ver_info
        if ver_info.get("versions"):
            print(f"  {ok('✔')} API versions detected: {', '.join(ver_info['versions'])}")
        if ver_info.get("server"):
            print(f"  {info('→')} Server: {ver_info['server']}")
        print()

    # Threat assessment
    total_found = len(all_found_paths)
    sensitive_count = len(sensitive)

    if sensitive_count >= 3:
        threat = "HIGH"
    elif sensitive_count >= 1:
        threat = "MEDIUM"
    elif total_found >= 20:
        threat = "LOW"
    else:
        threat = "INFO"

    results["threat_level"] = threat
    results["total_endpoints"] = total_found

    print(f"  {'─' * 55}")
    print()
    tc = _RED if threat == "HIGH" else (_YLW if threat == "MEDIUM" else _GRN)
    print(f"=== Discovery Complete ===")
    print(f"  Endpoints Found: {bold(total_found)}")
    print(f"  Sensitive: {fail(sensitive_count) if sensitive_count > 0 else ok(0)}")
    print(f"  Threat Level: {tc}{bold(threat)}{_RST}")
    print(f"  Specs Found: {len(specs)} | Brute-forced: {len(bf_results)}")

    if output:
        Path(output).write_text(json.dumps(results, indent=2))
        print(f"  {ok('✔')} JSON inventory saved: {output}")

    print()
    return results

# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="EdgeIQ API Endpoint Discovery")
    parser.add_argument("--target", required=True, help="Target base URL (e.g. https://api.target.com)")
    parser.add_argument("--pro", action="store_true", help="Enable Pro features")
    parser.add_argument("--bundle", action="store_true", help="Enable Bundle features")
    parser.add_argument("--wordlist", help="Path to custom wordlist")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("--output", help="Write JSON inventory to file")
    args = parser.parse_args()

    discover(target=args.target, pro=args.pro, bundle=args.bundle,
             wordlist_path=args.wordlist, threads=args.threads,
             output=args.output)