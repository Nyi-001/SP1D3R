#!/usr/bin/env python3
"""
Automated Penetration Testing Tool
Main entry point for the scanner

Author: Pangerkumzuk Longkumer
Organization: NEXUSCIPHERGUARD INDIA
"""

import argparse
import sys
import asyncio
from pathlib import Path
from datetime import datetime

from core.scanner import PentestScanner
from utils.logger import setup_logger, log_banner
from utils.config import load_config
from reports.generator import ReportGenerator


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Automated Penetration Testing Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target example.com --scan-type quick
  %(prog)s --target example.com --module subdomain --wordlist subs.txt
  %(prog)s --target example.com --scan-type deep --output report.html
  %(prog)s --target-list targets.txt --scan-type standard --threads 100
        """
    )
    
    # Target options
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        '-t', '--target',
        help='Target domain or IP address'
    )
    target_group.add_argument(
        '-tL', '--target-list',
        help='File containing list of targets'
    )
    
    # Scan options
    parser.add_argument(
        '-s', '--scan-type',
        choices=['quick', 'standard', 'deep', 'custom'],
        default='standard',
        help='Scan profile to use (default: standard)'
    )
    
    parser.add_argument(
        '-m', '--module',
        choices=['port', 'subdomain', 'vuln', 'web', 'ssl', 'dns', 'all'],
        default='all',
        help='Specific module to run (default: all)'
    )
    
    # Module-specific options
    parser.add_argument(
        '-p', '--ports',
        default='1-1000',
        help='Port range to scan (default: 1-1000)'
    )
    
    parser.add_argument(
        '-w', '--wordlist',
        help='Wordlist file for subdomain enumeration'
    )
    
    parser.add_argument(
        '--test-sqli',
        action='store_true',
        help='Enable SQL injection testing'
    )
    
    parser.add_argument(
        '--test-xss',
        action='store_true',
        help='Enable XSS testing'
    )
    
    parser.add_argument(
        '--cve-check',
        action='store_true',
        help='Check for known CVEs'
    )
    
    # Performance options
    parser.add_argument(
        '--threads',
        type=int,
        default=50,
        help='Number of concurrent threads (default: 50)'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=30,
        help='Connection timeout in seconds (default: 30)'
    )
    
    parser.add_argument(
        '--rate-limit',
        type=int,
        help='Requests per second limit'
    )
    
    # Stealth options
    parser.add_argument(
        '--stealth',
        action='store_true',
        help='Enable stealth mode (slower but less detectable)'
    )
    
    parser.add_argument(
        '--user-agent',
        help='Custom user agent string'
    )
    
    # Output options
    parser.add_argument(
        '-o', '--output',
        help='Output file path (supports .html, .json, .pdf)'
    )
    
    parser.add_argument(
        '--output-format',
        choices=['html', 'json', 'pdf', 'txt'],
        default='html',
        help='Report format (default: html)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--config',
        default='config/config.yaml',
        help='Configuration file path'
    )
    
    parser.add_argument(
        '--no-report',
        action='store_true',
        help='Skip report generation'
    )
    
    return parser.parse_args()


async def main():
    """Main execution function"""
    args = parse_arguments()
    
    # Setup logger
    logger = setup_logger(verbose=args.verbose)
    log_banner()
    
    # Load configuration
    try:
        config = load_config(args.config)
        logger.info(f"Configuration loaded from {args.config}")
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        sys.exit(1)
    
    # Override config with command line arguments
    if args.threads:
        config['scanning']['threads'] = args.threads
    if args.timeout:
        config['scanning']['timeout'] = args.timeout
    if args.rate_limit:
        config['scanning']['rate_limit'] = args.rate_limit
    if args.user_agent:
        config['scanning']['user_agent'] = args.user_agent
    if args.stealth:
        config['scanning']['stealth_mode'] = True
    
    # Prepare targets
    targets = []
    if args.target:
        targets.append(args.target)
    elif args.target_list:
        try:
            with open(args.target_list, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
            logger.info(f"Loaded {len(targets)} targets from {args.target_list}")
        except Exception as e:
            logger.error(f"Failed to read target list: {e}")
            sys.exit(1)
    
    # Initialize scanner
    scanner = PentestScanner(config, logger)
    
    # Process each target
    all_results = []
    for target in targets:
        logger.info(f"\n{'='*60}")
        logger.info(f"Starting scan on target: {target}")
        logger.info(f"Scan type: {args.scan_type}")
        logger.info(f"Module: {args.module}")
        logger.info(f"{'='*60}\n")
        
        try:
            # Configure scan parameters
            scan_params = {
                'target': target,
                'scan_type': args.scan_type,
                'module': args.module,
                'ports': args.ports,
                'wordlist': args.wordlist,
                'test_sqli': args.test_sqli,
                'test_xss': args.test_xss,
                'cve_check': args.cve_check
            }
            
            # Execute scan
            results = await scanner.scan(scan_params)
            all_results.append(results)
            
            # Display summary
            logger.info(f"\n{'='*60}")
            logger.info(f"Scan completed for {target}")
            logger.info(f"Total findings: {len(results.get('findings', []))}")
            logger.info(f"Critical: {results.get('stats', {}).get('critical', 0)}")
            logger.info(f"High: {results.get('stats', {}).get('high', 0)}")
            logger.info(f"Medium: {results.get('stats', {}).get('medium', 0)}")
            logger.info(f"Low: {results.get('stats', {}).get('low', 0)}")
            logger.info(f"{'='*60}\n")
            
        except KeyboardInterrupt:
            logger.warning("\nScan interrupted by user")
            break
        except Exception as e:
            logger.error(f"Error scanning {target}: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()
    
    # Generate report
    if not args.no_report and all_results:
        try:
            output_file = args.output or f"pentest_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{args.output_format}"
            
            logger.info(f"Generating {args.output_format.upper()} report...")
            report_gen = ReportGenerator(config)
            report_gen.generate(
                results=all_results,
                output_file=output_file,
                format=args.output_format
            )
            
            logger.info(f"Report saved to: {output_file}")
        except Exception as e:
            logger.error(f"Failed to generate report: {e}")
    
    logger.info("\nAll scans completed!")


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        sys.exit(1)