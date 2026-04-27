# 🔎 EdgeIQ API Endpoint Discovery

**Map the exposed attack surface of a web application's API layer.**

Passive OSINT (Swagger/OpenAPI, robots.txt, JavaScript scraping, favicon) plus active path brute-forcing to discover and inventory API endpoints.

[![Project Stage](https://img.shields.io/badge/Stage-Beta-blue)](https://edgeiqlabs.com)
[![Python](https://img.shields.io/badge/Python-3.8+-green)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-orange)](LICENSE)

---

## What It Does

Discovers API endpoints for a target domain through multiple techniques: specification file discovery, robots.txt analysis, JavaScript endpoint extraction, favicon fingerprinting, and path brute-forcing.

> ⚠️ **Legal Notice:** Only audit domains you own or have explicit written authorization to scan.

---

## Key Features

- **Swagger/OpenAPI discovery** — locates and parses live API specification files
- **robots.txt analysis** — extracts API-related paths
- **JavaScript endpoint extraction** — scrapes fetch/axios/XMLHttpRequest calls from JS
- **Favicon/asset fingerprinting** — extracts API hints from CDN assets
- **Path brute-forcing** — common API path patterns with wordlist
- **Parameter enumeration** — discovers API query parameter names
- **API version detection** — identifies version strings in responses
- **JSON export** — structured endpoint inventory

---

## Prerequisites

- Python 3.8+
- `requests` library

---

## Installation

```bash
git clone https://github.com/snipercat69/edgeiq-api-endpoint-discovery.git
cd edgeiq-api-endpoint-discovery
pip install -r requirements.txt
```

---

## Quick Start

```bash
# Passive discovery (no active probes)
python3 endpoint_discovery.py --domain example.com --passive

# Full discovery with brute-forcing
python3 endpoint_discovery.py --domain example.com --brute-force

# Export inventory as JSON
python3 endpoint_discovery.py --domain example.com --output inventory.json
```

---

## Pricing

| Tier | Price | Features |
|------|-------|----------|
| **Free** | $0 | 3 scans/month, passive only |
| **Lifetime** | $39 one-time | Unlimited scans, active brute-forcing, custom wordlists |
| **Monthly** | $7/mo | All Lifetime features, billed monthly |

---

## Integration with EdgeIQ Tools

Works with other EdgeIQ security tools:

- **[EdgeIQ XSS Scanner](https://github.com/snipercat69/edgeiq-xss-scanner)** — test discovered endpoints for XSS
- **[EdgeIQ SQL Injection Scanner](https://github.com/snipercat69/edgeiq-sql-injection-scanner)** — test parameters for SQL injection
- **[EdgeIQ OAuth Security Checker](https://github.com/snipercat69/edgeiq-oauth-security-checker)** — audit OAuth configurations

---

## Support

Open an issue at: https://github.com/snipercat69/edgeiq-api-endpoint-discovery/issues

---

*Part of EdgeIQ Labs — [edgeiqlabs.com](https://edgeiqlabs.com)*
