# EASD - External Attack Surface Discovery

A comprehensive external attack surface discovery tool designed for red team engagements. Provide a company name or domain, and EASD will automatically discover websites, applications, exposed services, cloud assets, employees, and potential vulnerabilities.

## Features

### Discovery Modules
- **Subdomain Enumeration** - Multi-source discovery via Certificate Transparency, DNS, passive sources
- **ASN & IP Range Discovery** - BGP/WHOIS lookups to find organization IP space
- **Port Scanning** - 100+ ports including SFTP, FTP, SMB, databases, admin panels
- **Technology Fingerprinting** - 60+ technology signatures (frameworks, CMS, servers)
- **Cloud Asset Discovery** - AWS S3, Azure Blob, GCP bucket enumeration

### OSINT Capabilities
- **GitHub Intelligence** - Organization repos, commit history, leaked secrets in code
- **Employee Discovery** - Email patterns, names, positions via Hunter.io
- **Secret Detection** - API keys, AWS credentials, database passwords, private keys

### Integrations
- Shodan - IP enrichment, service detection, vulnerabilities
- Censys - Certificate transparency, host discovery
- SecurityTrails - DNS history, subdomain intelligence
- Hunter.io - Employee and email discovery
- VirusTotal - Domain/IP reputation

### Reporting
- Professional HTML reports with dark theme
- JSON/CSV export
- Interactive CLI display
- Risk scoring and correlation

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

## Quick Start

```bash
# Interactive mode - guided setup
easd

# Or start a scan directly
easd scan -c "Acme Corp" -d acme.com

# Setup API keys (interactive)
easd setup
```

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
easd report <session-id> --format html      # HTML report (saved to ./reports/)
easd report <session-id> --format json      # JSON export
easd report <session-id> --format csv       # CSV export
```

## Configuration

### Interactive Setup
```bash
easd setup
```

Walks you through configuring all API keys with descriptions and links.

### Manual Configuration

Create `config/config.yaml`:

```yaml
easd:
  api_keys:
    shodan: "your-shodan-key"
    censys_id: "your-censys-id"
    censys_secret: "your-censys-secret"
    securitytrails: "your-securitytrails-key"
    hunter: "your-hunter-key"
    github: "your-github-token"
    virustotal: "your-virustotal-key"

  scan:
    intensity: normal
    threads: 50
    timeout: 10
    rate_limit: 500
```

### Environment Variables

```bash
export SHODAN_API_KEY="xxx"
export CENSYS_API_ID="xxx"
export CENSYS_API_SECRET="xxx"
export SECURITYTRAILS_API_KEY="xxx"
export HUNTER_API_KEY="xxx"
export GITHUB_TOKEN="xxx"
export VIRUSTOTAL_API_KEY="xxx"
```

## Modules

| Module | Description | Active/Passive |
|--------|-------------|----------------|
| `seed` | WHOIS, Certificate Transparency, ASN discovery | Passive |
| `domain` | Subdomain enumeration from multiple sources | Passive |
| `dns` | DNS resolution for discovered domains | Active |
| `infrastructure` | Port scanning, service detection | Active |
| `enrichment` | Shodan, Censys, SecurityTrails lookups | Passive |
| `osint` | GitHub repos, commits, employee discovery | Passive |
| `web` | HTTP probing, tech detection, screenshots | Active |
| `cloud` | S3/Azure/GCP bucket enumeration | Active |
| `correlation` | Risk scoring and data correlation | - |

## Port Coverage

EASD scans 100+ ports including:

| Category | Ports |
|----------|-------|
| File Transfer | FTP (21), SFTP/SSH (22), FTPS (990), TFTP (69), rsync (873) |
| Databases | MySQL (3306), PostgreSQL (5432), MongoDB (27017), Redis (6379), MSSQL (1433) |
| Remote Access | RDP (3389), VNC (5900), WinRM (5985), Telnet (23) |
| Directory | LDAP (389), LDAPS (636), Kerberos (88) |
| File Sharing | SMB (445), NFS (2049), NetBIOS (137-139) |
| Containers | Docker (2375), Kubernetes (6443), etcd (2379) |
| Message Queues | RabbitMQ (5672), Kafka (9092), Redis (6379) |
| Web | HTTP (80, 8080, 8000), HTTPS (443, 8443) |

## Secret Detection

GitHub reconnaissance scans for:

| Type | Severity |
|------|----------|
| AWS Access Keys | CRITICAL |
| Private Keys (RSA, PGP) | CRITICAL |
| Database Connection Strings | CRITICAL |
| Stripe Secret Keys | CRITICAL |
| API Keys / Tokens | HIGH |
| Hardcoded Passwords | HIGH |
| JWT Secrets | HIGH |
| Slack/Discord Tokens | HIGH |

## Output

### HTML Report
Reports are saved to `./reports/` with:
- Executive summary with metrics
- Findings sorted by severity
- Subdomain inventory
- IP addresses with open ports
- Web applications with technologies
- Cloud assets
- GitHub repositories
- Employee directory

### Directory Structure
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

## API Keys

| Service | Features | Get Key |
|---------|----------|---------|
| Shodan | IP enrichment, services, vulns | https://account.shodan.io/ |
| Censys | Certs, hosts, TLS analysis | https://search.censys.io/account/api |
| SecurityTrails | DNS history, subdomains | https://securitytrails.com/app/account/credentials |
| Hunter.io | Employees, email patterns | https://hunter.io/api-keys |
| GitHub | Repos, commits, code search | https://github.com/settings/tokens |
| VirusTotal | Domain/IP reputation | https://www.virustotal.com/gui/my-apikey |

## Requirements

- Python 3.10+
- Dependencies: httpx, typer, rich, pydantic, tinydb, dnspython, netaddr

Optional:
- masscan (for fast port scanning)
- gowitness/playwright (for screenshots)

## License

MIT License

## Disclaimer

This tool is intended for authorized security testing and red team engagements only. Always obtain proper authorization before scanning any systems you do not own. The authors are not responsible for misuse of this tool.
