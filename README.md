# Automated Penetration Testing Tool 1v


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
git clone https://github.com/pangerlkr/automated-pentest-tool.git
cd automated-pentest-tool

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run basic scan
python main.py --target example.com --scan-type quick
```

### Docker Installation

```bash
# Build image
docker build -t pentest-tool .

# Run container
docker run -it pentest-tool --target example.com

# Using docker-compose
docker-compose up
```

## Usage

### Basic Scanning

```bash
# Quick scan (ports + basic enum)
python main.py --target example.com --scan-type quick

# Standard scan (comprehensive)
python main.py --target example.com --scan-type standard

# Deep scan (all modules)
python main.py --target example.com --scan-type deep --output report.html
```

### Advanced Options

```bash
# Subdomain enumeration
python main.py --target example.com --module subdomain --wordlist subdomains.txt

# Port scanning with custom range
python main.py --target example.com --module port --ports 1-10000 --threads 100

# Vulnerability scanning
python main.py --target example.com --module vuln --cve-check --exploit-db

# Web application testing
python main.py --target https://example.com --module web --test-sqli --test-xss

# Stealth mode with rate limiting
python main.py --target example.com --stealth --rate-limit 10
```

### API Usage

```python
import requests

# Start scan via API
response = requests.post('http://localhost:5000/api/scan', json={
    'target': 'example.com',
    'scan_type': 'standard',
    'modules': ['port', 'subdomain', 'vuln']
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

- **Developer**: Pangerkumzuk Longkumer
- **GitHub**: [@pangerlkr](https://github.com/pangerlkr)
- **Organization**: NEXUSCIPHERGUARD INDIA

---

**Note**: Always practice responsible disclosure when finding vulnerabilities.
