# Quick Start Guide

Get started with the Automated Penetration Testing Tool in minutes.

## Installation

### Option 1: Local Installation

```bash
# Clone the repository
git clone https://github.com/pangerlkr/automated-pentest-tool.git
cd automated-pentest-tool

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Verify installation
python3 main.py --help
```

### Option 2: Docker Installation

```bash
# Clone the repository
git clone https://github.com/pangerlkr/automated-pentest-tool.git
cd automated-pentest-tool

# Build and run with Docker Compose
docker-compose up -d

# Run a scan
docker-compose run pentest-tool --target example.com --scan-type quick
```

## Basic Usage

### 1. Quick Scan (Fast reconnaissance)

```bash
python3 main.py --target example.com --scan-type quick
```

**What it does:**
- Technology fingerprinting
- WAF detection
- Port scanning (1-1000)
- Subdomain enumeration

**Time:** ~30-60 seconds

### 2. Standard Scan (Comprehensive)

```bash
python3 main.py --target example.com --scan-type standard --output report.html
```

**What it does:**
- All quick scan features
- DNS analysis
- SSL/TLS testing
- Web application security checks
- Generates HTML report

**Time:** ~2-5 minutes

### 3. Deep Scan (Complete assessment)

```bash
python3 main.py --target example.com --scan-type deep --output report.html -v
```

**What it does:**
- All standard scan features
- Vulnerability scanning
- CVE checks
- Detailed security analysis
- Verbose output

**Time:** ~5-15 minutes

## Targeted Scanning

### Port Scanning

```bash
# Scan specific port range
python3 main.py --target example.com --module port --ports 1-10000

# Fast scan with more threads
python3 main.py --target example.com --module port --ports 1-65535 --threads 100
```

### Subdomain Enumeration

```bash
# With custom wordlist
python3 main.py --target example.com --module subdomain --wordlist custom.txt

# Quick subdomain scan
python3 main.py --target example.com --module subdomain
```

### Web Application Testing

```bash
# Test for SQL injection and XSS
python3 main.py --target https://example.com --module web --test-sqli --test-xss

# Full web security scan
python3 main.py --target https://example.com --scan-type deep --test-sqli --test-xss
```

### Vulnerability Scanning

```bash
# Scan for vulnerabilities with CVE checking
python3 main.py --target example.com --module vuln --cve-check

# Deep vulnerability scan
python3 main.py --target example.com --scan-type deep --cve-check
```

### SSL/TLS Testing

```bash
python3 main.py --target example.com --module ssl
```

### DNS Analysis

```bash
python3 main.py --target example.com --module dns
```

## Advanced Options

### Stealth Mode

```bash
# Slower but less detectable
python3 main.py --target example.com --stealth --rate-limit 5
```

### Custom User Agent

```bash
python3 main.py --target example.com --user-agent "Mozilla/5.0 Custom"
```

### Multiple Targets

```bash
# Create targets file
echo "example1.com" > targets.txt
echo "example2.com" >> targets.txt
echo "example3.com" >> targets.txt

# Scan all targets
python3 main.py --target-list targets.txt --scan-type standard
```

### Custom Configuration

```bash
# Use custom config file
python3 main.py --target example.com --config /path/to/custom-config.yaml
```

## Report Generation

### Generate HTML Report

```bash
python3 main.py --target example.com --scan-type standard --output report.html
```

### Generate JSON Report

```bash
python3 main.py --target example.com --scan-type standard --output-format json --output results.json
```

### Multiple Formats

```bash
# HTML report
python3 main.py --target example.com --scan-type deep --output scan1.html

# JSON report
python3 main.py --target example.com --scan-type deep --output-format json --output scan1.json
```

### Skip Report Generation

```bash
python3 main.py --target example.com --scan-type quick --no-report
```

## REST API Usage

### Start API Server

```bash
python3 api/rest_api.py
```

Server starts on `http://localhost:5000`

### API Endpoints

#### Start a Scan

```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "scan_type": "standard",
    "test_sqli": true,
    "test_xss": true
  }'
```

**Response:**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "running"
}
```

#### Check Scan Status

```bash
curl http://localhost:5000/api/scan/{scan_id}/status
```

**Response:**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "created_at": 1234567890.123,
  "completed_at": 1234567920.456,
  "duration": 30.333
}
```

#### Get Scan Results

```bash
curl http://localhost:5000/api/scan/{scan_id}/results
```

#### List All Scans

```bash
curl http://localhost:5000/api/scans
```

#### Health Check

```bash
curl http://localhost:5000/api/health
```

## Docker Usage

### Using Docker Compose

```bash
# Start services
docker-compose up -d

# Run CLI scan
docker-compose run pentest-tool --target example.com --scan-type quick

# Start API service
docker-compose up pentest-api

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Using Docker Directly

```bash
# Build image
docker build -t pentest-tool .

# Run scan
docker run -it \
  -v $(pwd)/reports:/app/reports \
  -v $(pwd)/logs:/app/logs \
  pentest-tool --target example.com --scan-type standard

# Run API server
docker run -d \
  -p 5000:5000 \
  -v $(pwd)/reports:/app/reports \
  pentest-tool python3 api/rest_api.py
```

## Programmatic Usage

### Python Script

```python
import asyncio
from core.scanner import PentestScanner
from utils.logger import setup_logger
from utils.config import load_config
from reports.generator import ReportGenerator

async def run_scan():
    # Setup
    logger = setup_logger(verbose=True)
    config = load_config('config/config.yaml')

    # Initialize scanner
    scanner = PentestScanner(config, logger)

    # Configure scan
    scan_params = {
        'target': 'example.com',
        'scan_type': 'standard',
        'module': 'all',
        'ports': '1-1000',
        'test_sqli': True,
        'test_xss': True
    }

    # Execute scan
    results = await scanner.scan(scan_params)

    # Generate report
    report_gen = ReportGenerator(config, logger)
    report_gen.generate(
        results=[results],
        output_file='my_report.html',
        format='html'
    )

    # Print summary
    print(f"Findings: {len(results['findings'])}")
    print(f"Critical: {results['stats']['critical']}")
    print(f"High: {results['stats']['high']}")

    return results

# Run scan
if __name__ == '__main__':
    results = asyncio.run(run_scan())
```

## Configuration

### Edit config/config.yaml

```yaml
scanning:
  threads: 50
  timeout: 30
  retries: 2
  rate_limit: 0
  user_agent: "AutomatedPentestTool/1.0"
  stealth_mode: false

modules:
  port_scanner:
    enabled: true
    ports: "1-1000"

  subdomain_enum:
    enabled: true
    wordlist: "wordlists/subdomains.txt"

  vuln_scanner:
    enabled: true
    cve_check: false

  web_scanner:
    enabled: true
    depth: 2

reporting:
  formats: ["html", "json"]
  output_dir: "reports/output"
  severity_threshold: "low"
```

## Tips & Best Practices

### 1. Start Small
- Begin with quick scans
- Test on your own systems first
- Understand each module before combining

### 2. Use Verbose Mode for Debugging
```bash
python3 main.py --target example.com -v
```

### 3. Save Results
- Always generate reports for documentation
- Use JSON format for further processing
- Keep reports organized by date/target

### 4. Rate Limiting
- Use `--stealth` for sensitive targets
- Set `--rate-limit` to avoid detection
- Consider `--threads` reduction for slow networks

### 5. Legal Compliance
- ✅ Get written permission before testing
- ✅ Document your authorization
- ✅ Follow responsible disclosure
- ❌ Never test without permission

## Common Issues

### Issue: DNS Resolution Failed
**Solution:** Check network connectivity or use IP addresses directly

### Issue: Port Scan Too Slow
**Solution:** Reduce port range or increase threads
```bash
python3 main.py --target example.com --ports 1-100 --threads 100
```

### Issue: Module Not Found Error
**Solution:** Ensure you're in the project directory and dependencies are installed
```bash
pip install -r requirements.txt
```

### Issue: Permission Denied
**Solution:** Some scans require elevated privileges
```bash
sudo python3 main.py --target example.com --scan-type quick
```

## Example Workflows

### Workflow 1: Complete Web Application Assessment

```bash
# Step 1: Quick reconnaissance
python3 main.py --target example.com --scan-type quick -v

# Step 2: Deep web testing
python3 main.py --target https://example.com --module web \
  --test-sqli --test-xss --output web_report.html

# Step 3: SSL/TLS analysis
python3 main.py --target example.com --module ssl --output ssl_report.html

# Step 4: Full deep scan
python3 main.py --target example.com --scan-type deep \
  --cve-check --test-sqli --test-xss --output final_report.html
```

### Workflow 2: Infrastructure Assessment

```bash
# Step 1: Port scanning
python3 main.py --target example.com --module port --ports 1-65535 \
  --threads 100 --output ports.html

# Step 2: Subdomain enumeration
python3 main.py --target example.com --module subdomain \
  --wordlist wordlists/subdomains.txt --output subdomains.html

# Step 3: DNS analysis
python3 main.py --target example.com --module dns --output dns.html

# Step 4: Vulnerability scan
python3 main.py --target example.com --module vuln --cve-check \
  --output vulns.html
```

### Workflow 3: API-Driven Scanning

```bash
# Start API server
python3 api/rest_api.py &

# Submit multiple scans
for target in $(cat targets.txt); do
  curl -X POST http://localhost:5000/api/scan \
    -H "Content-Type: application/json" \
    -d "{\"target\": \"$target\", \"scan_type\": \"standard\"}"
done

# Monitor progress
watch -n 5 'curl http://localhost:5000/api/scans'
```

## Getting Help

- **Documentation**: See README.md and IMPLEMENTATION_SUMMARY.md
- **Issues**: https://github.com/pangerlkr/automated-pentest-tool/issues
- **Verbose Mode**: Use `-v` flag for detailed output
- **Help Command**: `python3 main.py --help`

## Next Steps

1. ✅ Install the tool
2. ✅ Run `python3 main.py --help`
3. ✅ Try a quick scan on your own system
4. ✅ Review the generated reports
5. ✅ Read IMPLEMENTATION_SUMMARY.md for technical details
6. ✅ Customize config/config.yaml for your needs
7. ✅ Explore specific modules
8. ✅ Integrate into your security workflow

---

**Remember**: This tool is for authorized security testing only. Always obtain proper authorization before testing any system you don't own.

**Happy Testing! 🔒**
