# API Endpoint Discovery

**Skill Name:** `api-endpoint-discovery`
**Version:** `1.0.0`
**Category:** Security / API / OSINT
**Price:** **Lifetime: $39** / Optional Monthly: $7/mo (includes all Pro features permanently)
**Author:** EdgeIQ Labs
**OpenClaw Compatible:** Yes — Python 3, pure stdlib, WSL + Linux

---

## What It Does

Discovers API endpoints for a target domain using passive OSINT (Swagger docs, OpenAPI specs, robots.txt, JavaScript scraping, favicon analysis) and active techniques (path brute-forcing, parameter enumeration). Maps the exposed attack surface of a web application's API layer.

> ⚠️ **Legal Notice:** Only audit domains you own or have explicit written authorization to scan. Active brute-forcing should only be used on authorized targets.

---

## Features

- **Swagger/OpenAPI discovery** — locates and parses live API specification files
- **robots.txt analysis** — extracts API-related paths from robots exclusion
- **JavaScript endpoint extraction** — scrapes fetch/axios/XMLHttpRequest calls from JS files
- **Favicon/asset fingerprinting** — extracts API hints from CDN-hosted assets
- **Path brute-forcing** — common API path patterns with wordlist
- **Parameter enumeration** — discovers API query parameter names
- **API version detection** — identifies API version strings in responses
- **JSON export** — structured endpoint inventory

---

## Tier Comparison

| Feature | Free | **Lifetime ($39)** | Optional Monthly ($7/mo) |
|---------|------|----------------|----------------------|
| Target scan | ✅ (3 scans) | ✅ (unlimited) | ✅ (unlimited) |
| Swagger/OpenAPI discovery | ✅ | ✅ | ✅ |
| robots.txt analysis | ✅ | ✅ | ✅ |
| JS endpoint extraction | ✅ | ✅ | ✅ |
| Favicon fingerprinting | ✅ | ✅ | ✅ |
| Path brute-forcing | ✅ | ✅ | ✅ |
| Parameter enumeration | ✅ | ✅ | ✅ |
| JSON export | ✅ | ✅ | ✅ |

---

## Installation

```bash
cp -r /home/guy/.openclaw/workspace/apps/api-endpoint-discovery ~/.openclaw/skills/api-endpoint-discovery
```

---

## Usage

### Basic passive discovery (free tier)

```bash
python3 endpoint_discovery.py --target "https://api.target.com"
```

### Pro scan with brute-forcing (Pro)

```bash
EDGEIQ_EMAIL=your_email@gmail.com python3 endpoint_discovery.py \
  --target "https://api.target.com" --pro
```

### Bundle — full active + passive scan

```bash
python3 endpoint_discovery.py --target "https://api.target.com" \
  --bundle --output inventory.json
```

---

## Parameters

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--target` | string | — | Target base URL (e.g. https://api.target.com) |
| `--pro` | flag | False | Enable Pro features |
| `--bundle` | flag | False | Enable Bundle features |
| `--wordlist` | string | built-in | Path to custom wordlist for brute-forcing |
| `--threads` | int | 10 | Number of concurrent threads |
| `--output` | string | — | Write JSON inventory to file |

---

## Output Example

```
=== API Endpoint Discovery ===
Target: https://api.target.com

  [1m[92m✔[0m Discovered 24 endpoints across 3 API versions

  Swagger/OpenAPI:
    [1m[92m✔[0m /swagger/v1/api.json — OpenAPI 3.0 spec found
    [1m[92m✔[0m /api-docs — Swagger UI detected

  Endpoints by category:

    Authentication (5 endpoints)
      POST /api/v1/auth/login         — 200 OK
      POST /api/v1/auth/register      — 201 Created
      POST /api/v1/auth/refresh      — 200 OK
      POST /api/v1/auth/logout        — 204 No Content
      GET  /api/v1/auth/session       — 200 OK

    Users (7 endpoints)
      GET  /api/v1/users             — 200 OK (paginated)
      GET  /api/v1/users/:id         — 200 OK
      POST /api/v1/users             — 201 Created
      PUT  /api/v1/users/:id          — 200 OK
      DELETE /api/v1/users/:id       — 204 No Content

    Products (6 endpoints)
      GET  /api/v1/products          — 200 OK
      GET  /api/v1/products/:id     — 200 OK
      POST /api/v1/products         — 201 Created
      ...

  Hidden/exposed sensitive endpoints:
    ⚠️ GET /api/v1/admin/users      — Admin-only, no auth observed
    ⚠️ POST /api/v1/debug/config   — Debug endpoint — INFORMATION EXPOSURE

  Version fingerprinting:
    X-API-Version: 1.2.3
    Server: Apache-Coyote/1.1

  Threat Level: MEDIUM — 2 sensitive endpoints exposed without auth
```

---

## Pro Upgrade

Full API discovery with brute-forcing, JS scraping, and parameter enumeration:

👉 [Buy Lifetime — $39](https://buy.stripe.com/6oU6oJam76d75s05os7wA0Z)
👉 [Subscribe Monthly — $7/mo](https://buy.stripe.com/6oU7sN9i3dFzaMkcQU7wA1a)

---

## Support

Open a ticket in [#edgeiq-support](https://discord.gg/PaP7nsFUJT) or email [gpalmieri21@gmail.com](mailto:gpalmieri21@gmail.com)

---

## 🔗 More from EdgeIQ Labs

**edgeiqlabs.com** — Security tools, OSINT utilities, and micro-SaaS products for developers and security professionals.

- 🛠️ **Subdomain Hunter** — Passive subdomain enumeration via Certificate Transparency
- 📸 **Screenshot API** — URL-to-screenshot API for developers
- 🔔 **uptime.check** — URL uptime monitoring with alerts
- 🛡️ **headers.check** — HTTP security headers analyzer

👉 [Visit edgeiqlabs.com →](https://edgeiqlabs.com)
