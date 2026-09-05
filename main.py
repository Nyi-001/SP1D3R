#!/usr/bin/env python3
"""
SP1D3R — Web Security Testing Assistant
Main entry point for the scanner

Author: Pangerkumzuk Longkumer
Organization: NEXUSCIPHERGUARD INDIA
"""

import argparse
import sys
import asyncio
from pathlib import Path
from datetime import datetime
from urllib.parse import urlsplit

from core.scanner import PentestScanner
from utils.logger import setup_logger, log_banner
from utils.config import load_config
from reports.generator import ReportGenerator
from integrations.tool_manager import TOOL_PROFILES


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='SP1D3R — Web Security Testing Assistant',
        allow_abbrev=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target https://example.com --scan-type quick
  %(prog)s --target https://example.com --module subdomain --wordlist subs.txt
  %(prog)s --target https://example.com --scan-type deep --output report.pdf
  %(prog)s --target https://example.com --active --tool nuclei --tool wpscan
  %(prog)s --target https://lab.example.test --active --all-tests
  %(prog)s --active --all-tests --request-file burp_request.txt
  %(prog)s --target-list targets.txt --allow '*.example.com' --scan-type standard --threads 100
        """
    )
    
    # Target options
    target_group = parser.add_mutually_exclusive_group(required=False)
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
        choices=['quick', 'standard', 'deep'],
        default='standard',
        help='Scan profile: quick, standard, or deep (default: standard)'
    )

    parser.add_argument(
        '--allow',
        dest='allowed_hosts',
        action='append',
        default=[],
        help='Optional scope override: host/path, wildcard domain, or CIDR; single-target scans default to the target host'
    )

    parser.add_argument(
        '--exclude',
        dest='excluded_paths',
        action='append',
        default=[],
        help='Excluded URL path glob; repeat as needed'
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
        help='Wordlist for subdomain enumeration or FFUF content discovery'
    )
    
    parser.add_argument(
        '--test-sqli',
        action='store_true',
        help='Enable SQL injection testing (requires --active; authorized lab use recommended)'
    )
    
    parser.add_argument(
        '--test-xss',
        action='store_true',
        help='Enable XSS testing (requires --active)'
    )

    parser.add_argument(
        '--active',
        action='store_true',
        help='Enable active web verification checks; use only with explicit authorization'
    )

    parser.add_argument(
        '--all-tests',
        '--all-test',
        action='store_true',
        help='Run all bounded active endpoint checks, including SQLi, XSS, SSTI, command injection, file inclusion, and file checks (requires --active; authorized lab use only)'
    )

    parser.add_argument(
        '--cookie',
        help='Cookie header for an authorized authenticated web session, e.g. PHPSESSID=...; security=low'
    )

    parser.add_argument(
        '--header',
        dest='request_headers',
        action='append',
        default=[],
        metavar='NAME: VALUE',
        help='Additional authorized request header; repeat for multiple headers (for example Authorization: Bearer TOKEN)'
    )

    parser.add_argument(
        '-r', '--request-file',
        help='Raw Burp Suite/HTTP request file to replay and use as an active-test seed'
    )

    parser.add_argument(
        '--request-scheme',
        choices=['http', 'https'],
        help='Scheme for relative request-file targets when Burp did not record one (default: http)'
    )

    parser.add_argument(
        '--tool',
        dest='external_tools',
        action='append',
        choices=sorted(TOOL_PROFILES),
        default=[],
        help='Run an approved external tool profile; repeat as needed'
    )

    parser.add_argument(
        '--tool-timeout',
        type=int,
        default=120,
        help='Timeout for each external tool in seconds (default: 120)'
    )
    
    parser.add_argument(
        '--cve-check',
        action='store_true',
        help='Run the legacy vulnerability CVE check; version-based CVE suggestions are automatic'
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
        '--insecure',
        action='store_true',
        help='Allow invalid TLS certificates for an explicitly authorized assessment; certificate issues remain reported'
    )
    
    parser.add_argument(
        '--rate-limit',
        type=int,
        help='Maximum requests per second (0 disables the limit)'
    )

    parser.add_argument(
        '--max-requests',
        type=int,
        help='Maximum web requests per target; 40%% is reserved for crawling (default: config value)'
    )

    parser.add_argument(
        '--payload-limit',
        type=int,
        help='Maximum payloads per payload file and attack class (default: config value)'
    )
    
    # Stealth options
    parser.add_argument(
        '--stealth',
        action='store_true',
        help='Use slower pacing; this does not bypass authorization or security controls'
    )
    
    parser.add_argument(
        '--user-agent',
        help='Custom user agent string'
    )
    
    # Output options
    parser.add_argument(
        '-o', '--output',
        help='Output report file path'
    )
    
    parser.add_argument(
        '--output-format',
        choices=['pdf', 'html', 'json'],
        default=None,
        help='Report format (default: pdf; inferred from -o extension when supplied)'
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

    if not args.target and not args.target_list and not args.request_file:
        print('Error: provide --target, --target-list, or --request-file.', file=sys.stderr)
        sys.exit(2)
    if args.target_list and args.request_file:
        print('Error: --request-file cannot be combined with --target-list.', file=sys.stderr)
        sys.exit(2)

    if args.output_format is None:
        output_suffix = Path(args.output).suffix.lower().lstrip('.') if args.output else ''
        args.output_format = output_suffix if output_suffix in {'pdf', 'html', 'json'} else 'pdf'

    if (args.test_sqli or args.test_xss or args.all_tests) and not args.active:
        print('Error: --test-sqli, --test-xss, and --all-tests require --active.', file=sys.stderr)
        sys.exit(2)
    if args.request_file and not args.active:
        print('Error: --request-file requires --active.', file=sys.stderr)
        sys.exit(2)
    requested_active_tools = [
        name for name in args.external_tools
        if TOOL_PROFILES.get(name, {}).get('active')
    ]
    if requested_active_tools and not args.active:
        tools_text = ', '.join(requested_active_tools)
        print(f'Error: {tools_text} requires --active; rerun with --active for authorized active testing.', file=sys.stderr)
        sys.exit(2)
    if args.rate_limit is not None and args.rate_limit < 0:
        print('Error: --rate-limit must be zero or greater.', file=sys.stderr)
        sys.exit(2)
    if args.tool_timeout < 1:
        print('Error: --tool-timeout must be at least 1 second.', file=sys.stderr)
        sys.exit(2)
    if args.max_requests is not None and args.max_requests < 1:
        print('Error: --max-requests must be at least 1.', file=sys.stderr)
        sys.exit(2)
    if args.payload_limit is not None and args.payload_limit < 1:
        print('Error: --payload-limit must be at least 1.', file=sys.stderr)
        sys.exit(2)
    
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
    
    # Prepare targets before building scope so a single explicit target can
    # safely provide its own default allow rule.
    targets = []
    if args.target:
        targets.append(args.target)
    elif args.request_file:
        try:
            from core.request_file import parse_request_file
            request_preview = parse_request_file(args.request_file, default_scheme=args.request_scheme)
            targets.append(request_preview['url'])
            logger.info(f"Target inferred from request file: {request_preview['url']}")
        except (OSError, ValueError) as exc:
            logger.error(f"Unable to derive target from request file: {exc}")
            sys.exit(2)
    elif args.target_list:
        try:
            with open(args.target_list, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
            logger.info(f"Loaded {len(targets)} targets from {args.target_list}")
        except Exception as e:
            logger.error(f"Failed to read target list: {e}")
            sys.exit(1)

    if args.allowed_hosts:
        effective_allowed_hosts = args.allowed_hosts
    elif args.target or args.request_file:
        try:
            target_value = targets[0] if '://' in targets[0] else f'https://{targets[0]}'
            target_host = urlsplit(target_value).hostname
            if not target_host:
                raise ValueError('target has no hostname')
            effective_allowed_hosts = [target_host]
            logger.info(f"Scope automatically limited to target host: {target_host}")
        except ValueError as exc:
            logger.error(f"Unable to derive a safe default scope: {exc}")
            sys.exit(2)
    else:
        logger.error("--allow is required when using --target-list so every target has an explicit scope")
        sys.exit(2)

    # Override config with command line arguments
    if args.threads:
        config['scanning']['threads'] = args.threads
    if args.timeout:
        config['scanning']['timeout'] = args.timeout
    if args.rate_limit is not None:
        config['scanning']['rate_limit'] = args.rate_limit
    if args.max_requests is not None:
        config['scanning']['max_requests'] = args.max_requests
    if args.payload_limit is not None:
        config['scanning']['payload_limit'] = args.payload_limit
    if args.user_agent:
        config['scanning']['user_agent'] = args.user_agent
    config['scanning']['insecure_tls'] = args.insecure
    if args.cookie:
        # Accept the common mistake of putting a bearer header in --cookie,
        # while keeping normal Cookie values unchanged.
        if args.cookie.lower().startswith('authorization:'):
            name, value = args.cookie.split(':', 1)
            config.setdefault('scanning', {}).setdefault('headers', {})[name.strip()] = value.strip()
            logger.warning('[!] --cookie contained an Authorization header; treating it as --header')
        else:
            config['scanning']['cookie'] = args.cookie
    for raw_header in args.request_headers:
        if ':' not in raw_header:
            logger.error(f"Invalid --header value {raw_header!r}; expected NAME: VALUE")
            sys.exit(2)
        name, value = raw_header.split(':', 1)
        if not name.strip() or not value.strip():
            logger.error(f"Invalid --header value {raw_header!r}; expected NAME: VALUE")
            sys.exit(2)
        config.setdefault('scanning', {}).setdefault('headers', {})[name.strip()] = value.strip()
    config.setdefault('scanning', {})['verbose'] = args.verbose
    if args.stealth:
        config['scanning']['stealth_mode'] = True
    configured_excludes = config.get('scope', {}).get('excluded_paths', [])
    excluded_paths = list(dict.fromkeys([*configured_excludes, *args.excluded_paths]))
    config['scope'] = {
        'allowed_hosts': effective_allowed_hosts,
        'excluded_paths': excluded_paths,
        'active_checks': args.active,
        'wordlist': args.wordlist,
    }
    config['scanning']['tool_timeout'] = args.tool_timeout
    config['scanning']['all_active_tests'] = args.all_tests
    
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
                'all_tests': args.all_tests,
                'cve_check': args.cve_check,
                'external_tools': args.external_tools,
                'request_file': args.request_file,
                'request_scheme': args.request_scheme,
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
            report_dir = Path(config.get('reporting', {}).get('output_dir', 'reports'))
            if args.output:
                requested_output = Path(args.output)
                output_path = requested_output if requested_output.is_absolute() or requested_output.parent != Path('.') else report_dir / requested_output
            else:
                output_path = report_dir / f"bug_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{args.output_format}"
            output_file = str(output_path)
            
            logger.info(f"Generating {args.output_format.upper()} report...")
            report_gen = ReportGenerator(config, logger)
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
