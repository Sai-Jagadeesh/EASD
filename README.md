<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-blue?style=for-the-badge" alt="Platform">
  <img src="https://img.shields.io/badge/Status-Active-success?style=for-the-badge" alt="Status">
</p>

<h1 align="center">EASD - External Attack Surface Discovery</h1>

<p align="center">
  <b>A comprehensive external attack surface discovery tool for red team engagements</b>
</p>

<p align="center">
  Provide a company name or domain, and EASD will automatically discover websites, applications, exposed services, cloud assets, employees, leaked credentials, and potential vulnerabilities.
</p>

---

## Features

### Discovery Modules

| Module | Description | Type |
|:------:|-------------|:----:|
| **Subdomain Enumeration** | Multi-source discovery via Certificate Transparency, DNS, passive sources | Passive |
| **ASN & IP Range Discovery** | BGP/WHOIS lookups to find organization IP space | Passive |
| **Port Scanning** | 100+ ports including SFTP, FTP, SMB, databases, admin panels | Active |
| **Technology Fingerprinting** | 60+ technology signatures (frameworks, CMS, servers) | Active |
| **Cloud Asset Discovery** | AWS S3, Azure Blob, GCP bucket enumeration | Active |

### OSINT Capabilities

| Capability | Description |
|:----------:|-------------|
| **GitHub Intelligence** | Organization repos, commit history, leaked secrets in code |
| **Employee Discovery** | Email patterns, names, positions via Hunter.io |
| **Secret Detection** | API keys, AWS credentials, database passwords, private keys |
| **Credential Exposure** | Check employee emails against breach databases |

### Intelligence Platforms

<table>
<tr>
<td width="50%">

| Platform | Features |
|:--------:|----------|
| **Shodan InternetDB** | CVEs, open ports, hostnames |
| **Wayback Machine** | Historical URLs, config files |
| **AlienVault OTX** | Threat pulses, IOCs |
| **URLScan.io** | Screenshots, DOM analysis |
| **GreyNoise** | Scanner identification |

</td>
<td width="50%">

| Platform | Features |
|:--------:|----------|
| **IPinfo** | Geolocation, ASN, VPN detection |
| **BuiltWith** | Technology stack profiling |
| **Chaos** | Massive subdomain database |
| **PassiveTotal** | Passive DNS, WHOIS history |
| **Censys** | Certificate & host discovery |

</td>
</tr>
</table>

### Breach & Credential Checking

| Service | Features |
|:-------:|----------|
| **HaveIBeenPwned** | Check if employee emails appear in breaches |
| **DeHashed** | Search breach databases for exposed credentials |
| **LeakCheck** | Credential leak verification |
| **Intelligence X** | Dark web, paste sites, breach data |

---

## Interactive HTML Reports

EASD generates professional HTML reports with:

- **Dark theme** with modern UI
- **Collapsible sections** for easy navigation
- **Screenshot gallery** with zoom/preview modal
- **Service exploitation guides** with detailed attack techniques
- **Risk scoring** and severity indicators
- **Filtering & search** capabilities

### Service Exploitation Guides

Reports include detailed exploitation guidance for discovered services:

| Service | Risk | Attack Vectors |
|:-------:|:----:|----------------|
| **MongoDB** | CRITICAL | No-auth access, data dump, server-side JS execution |
| **Redis** | CRITICAL | SSH key injection, cron RCE, webshell upload |
| **Docker API** | CRITICAL | Container escape, host filesystem mount, root shell |
| **Kubernetes** | CRITICAL | Anonymous access, secret theft, pod deployment |
| **etcd** | CRITICAL | K8s secrets in plaintext, cluster compromise |
| **Elasticsearch** | HIGH | Index enumeration, data exfiltration |
| **SMB** | HIGH | EternalBlue, null sessions, relay attacks |
| **RDP** | HIGH | BlueKeep, brute force, session hijacking |
| **PostgreSQL** | HIGH | Default creds, command execution |
| **MySQL** | HIGH | UDF exploitation, file read/write |

---

## Installation

```bash
# Clone the repository
git clone https://github.com/Sai-Jagadeesh/EASD.git
cd EASD

# Install dependencies
pip install -e .

# Or install from requirements
pip install -r requirements.txt
```

### Optional Dependencies

```bash
# For Screenshots (recommended)
pip install playwright
playwright install chromium

# Alternative: gowitness
go install github.com/sensepost/gowitness@latest
```

---

## Quick Start

```bash
# Interactive mode - guided setup
easd

# Start a scan directly
easd scan -c "Acme Corp" -d acme.com

# Setup API keys (interactive wizard)
easd setup
```

---

## Usage

### Interactive Wizard

```bash
easd
```

Launches an interactive wizard that guides you through:
1. Target information (company name, domains, IP ranges)
2. Scan intensity (passive, normal, aggressive)
3. Module selection
4. Output configuration

### Direct Commands

```bash
# Discover with company name
easd discover --company "Acme Corporation"

# Discover with domains
easd discover --domains acme.com,acmecorp.com

# Passive only (OSINT, no direct contact)
easd discover -c "Acme Corp" --passive-only

# Aggressive scan
easd discover -d acme.com --intensity aggressive

# Skip specific modules
easd discover -c "Acme" --skip-modules infrastructure,cloud
```

### Managing Sessions

```bash
# List all scan sessions
easd list

# Resume a previous scan
easd resume <session-id>

# Generate reports
easd report <session-id>                    # CLI display
easd report <session-id> --format html      # HTML report
easd report <session-id> --format json      # JSON export
easd report <session-id> --format csv       # CSV export
```

### Targeted Resource Hunting

```bash
# Hunt for specific resource types
easd hunt -c "Acme Corp" --type storage     # Cloud storage buckets
easd hunt -c "Acme Corp" --type code        # Code repositories
easd hunt -c "Acme Corp" --type secrets     # Exposed secrets
```

---

## Configuration

### Interactive Setup

```bash
easd setup
```

Walks you through configuring all 20+ API keys with descriptions and signup links.

### Manual Configuration

Create `config/config.yaml`:

```yaml
easd:
  api_keys:
    # Core
    shodan: "your-shodan-key"
    censys_id: "your-censys-id"
    censys_secret: "your-censys-secret"
    securitytrails: "your-securitytrails-key"
    virustotal: "your-virustotal-key"

    # OSINT
    hunter: "your-hunter-key"
    github: "your-github-token"

    # Intelligence
    urlscan: "your-urlscan-key"
    greynoise: "your-greynoise-key"
    alienvault: "your-otx-key"
    ipinfo: "your-ipinfo-token"
    builtwith: "your-builtwith-key"
    chaos: "your-chaos-key"
    passivetotal: "your-passivetotal-key"
    passivetotal_user: "your-email"

    # Breach Checking
    hibp: "your-hibp-key"
    dehashed: "your-dehashed-key"
    dehashed_email: "your-email"
    leakcheck: "your-leakcheck-key"
    intelx: "your-intelx-key"

  scan:
    intensity: normal
    threads: 50
    timeout: 10
    rate_limit: 500
```

### Environment Variables

<details>
<summary>Click to expand environment variables</summary>

```bash
# Core
export SHODAN_API_KEY="xxx"
export CENSYS_API_ID="xxx"
export CENSYS_API_SECRET="xxx"
export SECURITYTRAILS_API_KEY="xxx"
export VIRUSTOTAL_API_KEY="xxx"

# OSINT
export HUNTER_API_KEY="xxx"
export GITHUB_TOKEN="xxx"

# Intelligence
export URLSCAN_API_KEY="xxx"
export GREYNOISE_API_KEY="xxx"
export ALIENVAULT_API_KEY="xxx"
export IPINFO_TOKEN="xxx"
export BUILTWITH_API_KEY="xxx"
export CHAOS_API_KEY="xxx"
export PASSIVETOTAL_API_KEY="xxx"
export PASSIVETOTAL_USER="xxx"

# Breach Checking
export HIBP_API_KEY="xxx"
export DEHASHED_API_KEY="xxx"
export DEHASHED_EMAIL="xxx"
export LEAKCHECK_API_KEY="xxx"
export INTELX_API_KEY="xxx"
```

</details>

---

## Modules

| Module | Description | Active/Passive |
|:------:|-------------|:--------------:|
| `seed` | WHOIS, Certificate Transparency, ASN discovery | Passive |
| `domain` | Subdomain enumeration from multiple sources | Passive |
| `dns` | DNS resolution for discovered domains | Active |
| `infrastructure` | Port scanning, service detection | Active |
| `enrichment` | Shodan, Censys, SecurityTrails lookups | Passive |
| `intel` | URLScan, GreyNoise, Wayback, CVEs, breach data | Passive |
| `osint` | GitHub repos, commits, employee discovery | Passive |
| `web` | HTTP probing, tech detection, screenshots | Active |
| `cloud` | S3/Azure/GCP bucket enumeration | Active |
| `correlation` | Risk scoring and data correlation | - |

---

## Port Coverage

EASD scans **100+ ports** across multiple categories:

<table>
<tr>
<td>

| Category | Ports |
|:--------:|-------|
| **File Transfer** | FTP (21), SFTP/SSH (22), FTPS (990), TFTP (69) |
| **Databases** | MySQL (3306), PostgreSQL (5432), MongoDB (27017), Redis (6379), MSSQL (1433) |
| **Remote Access** | RDP (3389), VNC (5900), WinRM (5985), Telnet (23) |

</td>
<td>

| Category | Ports |
|:--------:|-------|
| **Directory** | LDAP (389), LDAPS (636), Kerberos (88) |
| **File Sharing** | SMB (445), NFS (2049), NetBIOS (137-139) |
| **Containers** | Docker (2375), Kubernetes (6443), etcd (2379) |

</td>
</tr>
</table>

---

## Secret Detection

GitHub reconnaissance scans for sensitive data:

| Type | Severity |
|:----:|:--------:|
| AWS Access Keys | `CRITICAL` |
| Private Keys (RSA, PGP) | `CRITICAL` |
| Database Connection Strings | `CRITICAL` |
| Stripe Secret Keys | `CRITICAL` |
| API Keys / Tokens | `HIGH` |
| Hardcoded Passwords | `HIGH` |
| JWT Secrets | `HIGH` |
| Slack/Discord Tokens | `HIGH` |

---

## Output Structure

```
results/
└── <session-id>/
    └── easd.db          # TinyDB database

reports/
└── easd_<target>_<timestamp>.html

screenshots/
└── <session-id>/
    └── *.png
```

---

## API Keys Reference

### Core Enrichment

| Service | Features | Get Key |
|:-------:|----------|:-------:|
| Shodan | IP enrichment, services, vulns | [Link](https://account.shodan.io/) |
| Censys | Certs, hosts, TLS analysis | [Link](https://search.censys.io/account/api) |
| SecurityTrails | DNS history, subdomains | [Link](https://securitytrails.com/app/account/credentials) |
| VirusTotal | Domain/IP reputation | [Link](https://www.virustotal.com/gui/my-apikey) |
| BinaryEdge | Port scanning data | [Link](https://app.binaryedge.io/account/api) |

### OSINT

| Service | Features | Get Key |
|:-------:|----------|:-------:|
| Hunter.io | Employees, email patterns | [Link](https://hunter.io/api-keys) |
| GitHub | Repos, commits, code search | [Link](https://github.com/settings/tokens) |

### Intelligence Platforms

| Service | Features | Get Key |
|:-------:|----------|:-------:|
| URLScan.io | Screenshots, DOM, tech detection | [Link](https://urlscan.io/user/signup) |
| GreyNoise | Scanner/malicious IP detection | [Link](https://viz.greynoise.io/account/api-key) |
| AlienVault OTX | Threat pulses, IOCs | [Link](https://otx.alienvault.com/api) |
| IPinfo | Geolocation, ASN, VPN detection | [Link](https://ipinfo.io/signup) |
| BuiltWith | Technology profiling | [Link](https://builtwith.com/) |
| Chaos | Subdomain database | [Link](https://chaos.projectdiscovery.io/) |
| PassiveTotal | Passive DNS, WHOIS | [Link](https://community.riskiq.com/) |

### Breach Checking

| Service | Features | Get Key |
|:-------:|----------|:-------:|
| HaveIBeenPwned | Email breach lookup | [Link](https://haveibeenpwned.com/API/Key) |
| DeHashed | Credential search | [Link](https://dehashed.com/) |
| LeakCheck | Leak verification | [Link](https://leakcheck.io/) |
| Intelligence X | Dark web, pastes | [Link](https://intelx.io/) |

### Free (No Auth Required)

- **Shodan InternetDB** - CVEs, ports, hostnames
- **Wayback Machine** - Historical URLs
- **AlienVault OTX** - Basic threat intel
- **GreyNoise Community** - Basic IP classification

---

## Requirements

- **Python 3.10+**
- **Dependencies:** httpx, typer, rich, pydantic, tinydb, dnspython, netaddr

### Optional Tools

| Tool | Purpose | Installation |
|:----:|---------|--------------|
| Playwright | Screenshots | `pip install playwright && playwright install chromium` |
| gowitness | Screenshots (alt) | `go install github.com/sensepost/gowitness@latest` |
| masscan | Fast port scanning | Used automatically in normal/aggressive modes |

---

## License

MIT License

---

## Disclaimer

> **Warning**
> This tool is intended for authorized security testing and red team engagements only. Always obtain proper authorization before scanning any systems you do not own. The authors are not responsible for misuse of this tool.

---

<p align="center">
  <b>Made for Red Teams</b>
</p>
