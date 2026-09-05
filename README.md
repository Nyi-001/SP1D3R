# SP1D3R — Web Security Testing Assistant

SP1D3R is a scoped web and API security assessment project for authorized
laboratories and internal testing. It classifies the target before testing,
normalizes discovery-tool output, performs bounded active verification, and
produces reader-friendly HTML, PDF, and JSON reports.

Captured request files are intentionally excluded from version control because
they can contain session cookies or bearer tokens.

> Web-focused upgrade requirements: see [WEB_PENTEST_REQUIREMENTS.md](WEB_PENTEST_REQUIREMENTS.md). The original framework is being evolved toward scoped web attack-surface mapping, controlled active verification, normalized tool integrations, and evidence-backed reporting.

External tool profiles can be selected explicitly. The recon adapters are based on the workflow documented by [Bug-Bounty-Script](https://github.com/shubham-rooter/Bug-Bounty-Script), but are executed independently with this project’s scope and normalization controls:

```bash
python main.py --target https://lab.example.test \
  --allow lab.example.test \
  --active \
  --tool subfinder --tool httpx --tool nuclei --tool wpscan
```

When `--active` is enabled for a web scan (`--module web`, or the standard/deep profiles), `dirsearch` runs automatically with its built-in wordlist. It continues until completion by default; set `dirsearch_timeout` in `config/config.yaml` when an operational time limit is required. Request timeout, thread limit, rate limit, cookies, and scope policy still apply. Other external tools remain opt-in; `--tool dirsearch` can be used when an explicit standalone run is preferred. Active profiles require `--active`.

Directory discovery with FFUF still requires an explicit wordlist with `-w` and `--tool ffuf`. Dirsearch results are normalized into the report with the discovered URL, HTTP status, response length, and source. The HTML report colors 2xx, 3xx, 4xx, 5xx, and unknown status values consistently in the finding index and directory inventory.

Recon examples:

```bash
# Passive subdomain/DNS/domain and HTTP fingerprinting
python main.py --target https://lab.example.test --allow lab.example.test \
  --tool subfinder --tool amass --tool dnsx --tool whois --tool httpx --tool whatweb

# Explicit active service/content audit against an authorized lab
python main.py --target https://lab.example.test --allow lab.example.test --active \
  --wordlist wordlists/content.txt --tool nmap --tool dirb --tool nikto
```

Subdomain enumeration uses Assetfinder as the default passive candidate source when it is installed, alongside certificate-transparency and DNS-bruteforce sources. Every candidate is scope-filtered and DNS-verified before it appears in the report. An apex rule such as `--allow example.test` permits discovery and verification of `api.example.test`, but active crawling/testing that child still requires `--allow '*.example.test'`. `--tool assetfinder` is also available for an explicit standalone run.

Nmap, Dirb, Nikto, FFUF, Nuclei, and WPScan are opt-in active profiles. A missing binary is recorded as a skipped tool, and tool output is shown in verbose terminal mode with `--verbose` and retained in the detailed report.

For an authorized lab, `--active --all-tests` enables bounded checks across all discovered query parameters and eligible form inputs. It includes reflected-input checks, redirect canaries, traversal indicators, CSRF/header checks, and SQL error-based checks. The scanner still enforces scope exclusions and the shared request budget configured in `config/config.yaml`.

Burp Suite request replay is supported with `-r` / `--request-file`, similar to sqlmap’s `-r`. Export one request from Burp as a raw HTTP message, then use it as the authenticated seed and test its query/body parameters:

```bash
python main.py --active --all-tests \
  --request-file burp_request.txt --verbose
```

The request file may contain an absolute or relative request target, cookies, authorization headers, URL-encoded form data, or a JSON body. For a relative request target, SPID3R infers the URL from the `Host` header and defaults to HTTP unless `X-Forwarded-Proto: https` is present. With `-r` alone, scope is automatically limited to that request’s host; use `--allow` only when a broader or path-restricted scope is intentional. `Host`, `Content-Length`, and other hop-by-hop headers are not replayed; the captured cookies, authorization context, content type, and safe application headers are retained. Use a fresh authorized request and review the request-budget limit before running active checks.

The default output is a print-ready PDF security assessment report saved under `reports/`. It includes a cover page, executive summary, severity dashboard, scope and methodology, coverage, findings with evidence and remediation, attack-surface review, technology/services inventory, directory results, version-based CVE suggestions, tool status, and assessment notes. HTML remains available with `--output-format html` for interactive findings search and filters; JSON is available with `--output-format json`.

After fingerprinting and port discovery, SPID3R automatically matches verified product/version observations and Nmap service versions against the editable `data/cve_catalog.json`. These entries are reported as `suggested` CVE matches—not confirmed vulnerabilities—because banners may be spoofed and distributions may backport fixes. Confirm the exact package build and vendor advisory before remediation or exploitation decisions.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Status](https://img.shields.io/badge/status-active-success)

## Overview

Advanced automated penetration testing framework designed for comprehensive security assessments. This tool provides multi-layered scanning capabilities including port scanning, vulnerability detection, subdomain enumeration, web application testing, and automated reporting.

## Features

### Core Capabilities
- **Port Scanning**: Fast TCP/UDP port scanning with service detection
- **Subdomain Enumeration**: Multiple techniques (DNS brute-force, certificate transparency, API queries)
- **Vulnerability Scanning**: CVE detection, misconfigurations, weak ciphers
- **Web Application Testing**: SQL injection, XSS, CSRF, directory traversal detection
- **SSL/TLS Analysis**: Certificate validation, cipher suite testing, protocol vulnerabilities
- **DNS Analysis**: Zone transfers, DNS record enumeration, cache poisoning checks
- **WAF Detection**: Identifies Web Application Firewalls and security measures
- **Technology Fingerprinting**: CMS detection, framework identification, server fingerprinting
- **Automated Reporting**: HTML, JSON, and PDF reports with severity ratings

### Advanced Features
- Multi-threaded scanning for performance optimization
- Configurable scan profiles (quick, standard, deep)
- Rate limiting and stealth mode
- Custom payload injection
- Integration with CVE databases
- CI/CD pipeline integration
- Docker containerization
- REST API for automation

## Architecture

```
automated-pentest-tool/
├── core/
│   ├── scanner.py          # Main scanner orchestrator
│   ├── port_scanner.py     # Port scanning module
│   ├── cve_matcher.py      # Version-aware CVE suggestions
│   ├── subdomain_enum.py   # Subdomain discovery
│   ├── vuln_scanner.py     # Vulnerability detection
│   └── web_scanner.py      # Web app security testing
├── modules/
│   ├── dns_analyzer.py     # DNS security checks
│   ├── ssl_tester.py       # SSL/TLS testing
│   ├── waf_detector.py     # WAF identification
│   └── fingerprint.py      # Technology detection
├── payloads/
│   ├── sqli_payloads.txt   # SQL injection patterns
│   ├── xss_payloads.txt    # XSS test vectors
│   └── fuzzing_lists.txt   # Fuzzing wordlists
├── reports/
│   ├── generator.py        # Report generation
│   └── templates/          # Report templates
├── utils/
│   ├── logger.py           # Logging utility
│   ├── config.py           # Configuration handler
│   └── helpers.py          # Helper functions
├── api/
│   └── rest_api.py         # REST API interface
├── tests/
│   └── test_*.py           # Unit tests
├── config/
│   ├── config.yaml         # Main configuration
│   └── profiles.yaml       # Scan profiles
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── main.py                 # Entry point
```

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager
- Virtual environment (recommended)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/Nyi-001/SP1D3R.git
cd SP1D3R

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run a single-target scan; scope is automatically limited to example.com
python main.py --target https://example.com --scan-type quick
```

### Docker Installation

```bash
# Build image
docker build -t pentest-tool .

# Run container
docker run -it pentest-tool --target https://example.com --allow example.com

# Using docker-compose
docker-compose up
```

## Usage

### Basic Scanning

```bash
# Quick scan (ports + basic enum)
python main.py --target https://example.com --allow example.com --scan-type quick

# Standard scan (comprehensive)
python main.py --target https://example.com --allow example.com --scan-type standard

# Deep scan (all modules)
python main.py --target https://example.com --allow example.com --scan-type deep --output report.pdf

# PDF is the default report format; choose the output path explicitly if desired
python main.py --target https://example.com --allow example.com --scan-type standard --output reports/security-assessment.pdf

# Interactive HTML alternative
python main.py --target https://example.com --allow example.com --output-format html --output reports/security-assessment.html
```

### Advanced Options

```bash
# Subdomain enumeration
python main.py --target https://example.com --allow example.com --module subdomain --wordlist subdomains.txt

# Port scanning with custom range
python main.py --target https://example.com --allow example.com --module port --ports 1-10000 --threads 100

# Vulnerability scanning
python main.py --target https://example.com --allow example.com --module vuln --cve-check

# Web application testing
python main.py --target https://example.com --allow example.com --module web --active --test-sqli --test-xss

# Replay a Burp Suite request and test its captured parameters in an authorized lab
python main.py --active --all-tests --request-file burp_request.txt --verbose

# Stealth mode with rate limiting
python main.py --target https://example.com --allow example.com --stealth --rate-limit 10
```

### API Usage

```python
import requests

# Start scan via API
response = requests.post('http://localhost:5000/api/scan', json={
    'target': 'https://example.com',
    'allowed_hosts': ['example.com'],
    'scan_type': 'standard',
    'modules': ['port', 'subdomain', 'vuln'],
    'active': False
})

scan_id = response.json()['scan_id']

# Check scan status
status = requests.get(f'http://localhost:5000/api/scan/{scan_id}/status')

# Get results
results = requests.get(f'http://localhost:5000/api/scan/{scan_id}/results')
```

## Configuration

Edit `config/config.yaml` to customize:

```yaml
scanning:
  timeout: 30
  threads: 50
  retries: 3
  user_agent: "PentestTool/1.0"

modules:
  port_scanner:
    enabled: true
    ports: "1-65535"
    tcp_scan: true
    udp_scan: false
  
  subdomain_enum:
    enabled: true
    sources:
      - dns_brute
      - crt_sh
      - virustotal
    wordlist: "wordlists/subdomains.txt"
  
  vuln_scanner:
    enabled: true
    cve_check: true
    exploit_db: true
    nist_nvd: true

reporting:
  formats: ["html", "json", "pdf"]
  severity_threshold: "medium"
  include_screenshots: true
```

## Modules

### Port Scanner
- TCP SYN/Connect scanning
- UDP scanning
- Service version detection
- OS fingerprinting
- Banner grabbing

### Subdomain Enumerator
- DNS brute-force with wordlists
- Certificate transparency logs (crt.sh)
- Search engine queries
- DNS zone transfers
- Reverse DNS lookups

### Vulnerability Scanner
- CVE database integration
- Common misconfigurations
- Weak credentials testing
- Known exploit detection
- Version-based vulnerability matching

### Web Application Scanner
- SQL injection testing (blind, error-based, time-based)
- Cross-Site Scripting (reflected, stored, DOM-based)
- CSRF vulnerability detection
- Directory traversal testing
- File inclusion vulnerabilities (LFI/RFI)
- Command injection testing
- SSRF detection
- Security headers analysis
- Cookie security testing

### SSL/TLS Tester
- Certificate validation
- Cipher suite analysis
- Protocol version testing
- Heartbleed detection
- POODLE vulnerability check
- Certificate transparency verification

## Reporting

Generated reports include:
- Executive summary
- Detailed findings with severity ratings
- Technical details and evidence
- Remediation recommendations
- CVSS scores
- OWASP Top 10 mapping
- Visual graphs and statistics

## Legal Disclaimer

⚠️ **WARNING**: This tool is designed for authorized security testing only.

- Only use on systems you own or have explicit written permission to test
- Unauthorized access to computer systems is illegal
- Users are responsible for compliance with local laws and regulations
- The developers assume no liability for misuse of this tool

## Roadmap

- [ ] Machine learning-based anomaly detection
- [ ] Integration with SIEM systems
- [ ] Mobile application testing module
- [ ] Cloud infrastructure security scanning (AWS, Azure, GCP)
- [ ] API security testing
- [ ] Blockchain/smart contract auditing
- [ ] Active exploitation module (with safeguards)
- [ ] Collaborative team features
- [ ] Integration with Burp Suite/OWASP ZAP

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-module`)
3. Commit changes (`git commit -am 'Add new scanning module'`)
4. Push to branch (`git push origin feature/new-module`)
5. Create Pull Request

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments

- OWASP for security testing methodologies
- MITRE ATT&CK framework
- CVE database maintainers
- Open-source security community

## Contact

- **Developer**: Nyi-001
- **GitHub**: [@Nyi-001](https://github.com/Nyi-001)

---

**Note**: Always practice responsible disclosure when finding vulnerabilities.
