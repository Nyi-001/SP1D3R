#!/usr/bin/env python3
"""
Example script demonstrating the Automated Penetration Testing Tool

This script shows how to use the tool programmatically
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from core.scanner import PentestScanner
from utils.logger import setup_logger, log_banner
from utils.config import load_config
from reports.generator import ReportGenerator


async def example_basic_scan():
    """Example: Basic port scan"""
    print("\n" + "="*60)
    print("Example 1: Basic Port Scan")
    print("="*60)
    
    logger = setup_logger(verbose=True)
    config = load_config('config/config.yaml')
    
    scanner = PentestScanner(config, logger)
    
    # Scan parameters
    params = {
        'target': 'localhost',
        'scan_type': 'quick',
        'module': 'port',
        'ports': '80,443,8080',
        'wordlist': None,
        'test_sqli': False,
        'test_xss': False,
        'cve_check': False
    }
    
    results = await scanner.scan(params)
    
    print(f"\nScan completed!")
    print(f"Total findings: {len(results.get('findings', []))}")
    print(f"Critical: {results.get('stats', {}).get('critical', 0)}")
    print(f"High: {results.get('stats', {}).get('high', 0)}")
    
    return results


async def example_web_scan():
    """Example: Web application scan"""
    print("\n" + "="*60)
    print("Example 2: Web Application Security Scan")
    print("="*60)
    
    logger = setup_logger(verbose=False)
    config = load_config('config/config.yaml')
    
    scanner = PentestScanner(config, logger)
    
    params = {
        'target': 'http://testphp.vulnweb.com',  # Test site for demonstration
        'scan_type': 'standard',
        'module': 'web',
        'ports': '80,443',
        'wordlist': None,
        'test_sqli': True,
        'test_xss': True,
        'cve_check': False
    }
    
    print("Note: Using vulnweb.com test site (safe for testing)")
    results = await scanner.scan(params)
    
    print(f"\nScan completed!")
    print(f"Total findings: {len(results.get('findings', []))}")
    
    # Show sample findings
    findings = results.get('findings', [])
    if findings:
        print("\nSample findings:")
        for finding in findings[:3]:  # Show first 3
            print(f"  - [{finding.get('severity', 'N/A').upper()}] {finding.get('title', 'N/A')}")
    
    return results


async def example_comprehensive_scan():
    """Example: Comprehensive scan with reporting"""
    print("\n" + "="*60)
    print("Example 3: Comprehensive Scan with Report Generation")
    print("="*60)
    
    logger = setup_logger(verbose=True)
    config = load_config('config/config.yaml')
    
    scanner = PentestScanner(config, logger)
    
    params = {
        'target': 'example.com',
        'scan_type': 'standard',
        'module': 'all',
        'ports': '80,443',
        'wordlist': 'wordlists/subdomains.txt',
        'test_sqli': False,
        'test_xss': False,
        'cve_check': False
    }
    
    results = await scanner.scan(params)
    
    # Generate report
    report_gen = ReportGenerator(config, logger)
    output_file = report_gen.generate(
        results=[results],
        output_file='reports/output/example_report.html',
        format='html'
    )
    
    print(f"\nReport generated: {output_file}")
    
    return results


async def example_module_usage():
    """Example: Using individual modules directly"""
    print("\n" + "="*60)
    print("Example 4: Using Individual Modules")
    print("="*60)
    
    logger = setup_logger(verbose=True)
    config = load_config('config/config.yaml')
    
    from modules.waf_detector import WAFDetector
    from modules.fingerprint import TechFingerprint
    
    # WAF Detection
    print("\n[*] Testing WAF Detection...")
    waf_detector = WAFDetector(config, logger)
    waf_info = await waf_detector.detect('https://example.com')
    print(f"WAF Detected: {waf_info.get('detected', False)}")
    if waf_info.get('detected'):
        print(f"WAF Name: {waf_info.get('name', 'Unknown')}")
    
    # Technology Fingerprinting
    print("\n[*] Testing Technology Fingerprinting...")
    tech_fp = TechFingerprint(config, logger)
    technologies = await tech_fp.scan('https://example.com')
    print(f"Technologies found: {len(technologies)}")
    for tech in technologies[:5]:
        print(f"  - {tech.get('name', 'Unknown')} ({tech.get('category', 'N/A')})")


def main():
    """Main example runner"""
    log_banner()
    print("\nAutomated Penetration Testing Tool - Examples\n")
    print("This script demonstrates various ways to use the tool.\n")
    
    print("Available examples:")
    print("1. Basic port scan")
    print("2. Web application security scan")
    print("3. Comprehensive scan with reporting")
    print("4. Using individual modules")
    print("\nRunning example 4 (module usage)...")
    
    # Run a safe example
    asyncio.run(example_module_usage())
    
    print("\n" + "="*60)
    print("Examples completed!")
    print("="*60)
    print("\nTo run the full tool, use:")
    print("  python3 main.py --target example.com --scan-type quick")
    print("\nFor more options:")
    print("  python3 main.py --help")


if __name__ == '__main__':
    main()
