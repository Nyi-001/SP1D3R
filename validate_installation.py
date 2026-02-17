#!/usr/bin/env python3
"""
Validation script to verify all features are working
Run this after installation to ensure everything is functional
"""

import sys
import os
from pathlib import Path

# Color codes for output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

def print_header(text):
    print(f"\n{BLUE}{'='*60}{RESET}")
    print(f"{BLUE}{text}{RESET}")
    print(f"{BLUE}{'='*60}{RESET}")

def print_success(text):
    print(f"{GREEN}✅ {text}{RESET}")

def print_error(text):
    print(f"{RED}❌ {text}{RESET}")

def print_info(text):
    print(f"{YELLOW}ℹ️  {text}{RESET}")

def check_python_version():
    """Check Python version"""
    print_info("Checking Python version...")
    version = sys.version_info
    if version.major == 3 and version.minor >= 8:
        print_success(f"Python {version.major}.{version.minor}.{version.micro}")
        return True
    else:
        print_error(f"Python 3.8+ required, found {version.major}.{version.minor}.{version.micro}")
        return False

def check_dependencies():
    """Check if all dependencies are installed"""
    print_info("Checking dependencies...")
    # Map of package name to import name
    required_packages = {
        'aiohttp': 'aiohttp',
        'requests': 'requests',
        'beautifulsoup4': 'bs4',
        'flask': 'flask',
        'pyyaml': 'yaml',
        'dnspython': 'dns',
        'cryptography': 'cryptography'
    }

    missing = []
    for package, import_name in required_packages.items():
        try:
            __import__(import_name)
        except ImportError:
            missing.append(package)

    if missing:
        print_error(f"Missing packages: {', '.join(missing)}")
        print_info("Run: pip install -r requirements.txt")
        return False
    else:
        print_success("All dependencies installed")
        return True

def check_core_modules():
    """Check if core modules can be imported"""
    print_info("Checking core modules...")
    modules = [
        'core.scanner',
        'core.port_scanner',
        'core.subdomain_enum',
        'core.vuln_scanner',
        'core.web_scanner',
        'modules.dns_analyzer',
        'modules.ssl_tester',
        'modules.waf_detector',
        'modules.fingerprint',
        'utils.logger',
        'utils.config',
        'reports.generator',
        'api.rest_api'
    ]

    failed = []
    for module in modules:
        try:
            __import__(module)
        except Exception as e:
            failed.append((module, str(e)))

    if failed:
        print_error(f"Failed to import {len(failed)} module(s):")
        for module, error in failed:
            print(f"  - {module}: {error}")
        return False
    else:
        print_success(f"All {len(modules)} modules imported successfully")
        return True

def check_configuration():
    """Check configuration files"""
    print_info("Checking configuration files...")
    config_files = [
        'config/config.yaml',
        'config/profiles.yaml',
        'requirements.txt'
    ]

    missing = []
    for file in config_files:
        if not Path(file).exists():
            missing.append(file)

    if missing:
        print_error(f"Missing config files: {', '.join(missing)}")
        return False
    else:
        print_success("All configuration files present")
        return True

def check_directories():
    """Check required directories"""
    print_info("Checking directories...")
    required_dirs = [
        'core', 'modules', 'utils', 'reports', 'api',
        'config', 'wordlists', 'payloads'
    ]

    missing = []
    for dir_name in required_dirs:
        if not Path(dir_name).is_dir():
            missing.append(dir_name)

    if missing:
        print_error(f"Missing directories: {', '.join(missing)}")
        return False
    else:
        print_success("All required directories present")
        return True

def check_main_script():
    """Check if main.py is executable"""
    print_info("Checking main script...")
    if not Path('main.py').exists():
        print_error("main.py not found")
        return False

    # Try to import it
    try:
        import main
        print_success("main.py is valid")
        return True
    except Exception as e:
        print_error(f"main.py error: {e}")
        return False

def validate_installation():
    """Run all validation checks"""
    print_header("AUTOMATED PENTEST TOOL - INSTALLATION VALIDATOR")

    checks = [
        ("Python Version", check_python_version),
        ("Dependencies", check_dependencies),
        ("Core Modules", check_core_modules),
        ("Configuration Files", check_configuration),
        ("Directory Structure", check_directories),
        ("Main Script", check_main_script)
    ]

    results = []
    for name, check_func in checks:
        print()
        result = check_func()
        results.append((name, result))

    # Summary
    print_header("VALIDATION SUMMARY")
    passed = sum(1 for _, result in results if result)
    total = len(results)

    for name, result in results:
        status = f"{GREEN}✅ PASS{RESET}" if result else f"{RED}❌ FAIL{RESET}"
        print(f"{name:.<40} {status}")

    print()
    if passed == total:
        print_success(f"All {total} checks passed! Tool is ready to use.")
        print()
        print_info("Quick start:")
        print("  python3 main.py --help")
        print("  python3 main.py --target example.com --scan-type quick")
        print()
        print_info("Documentation:")
        print("  README.md - Project overview")
        print("  QUICKSTART.md - Usage guide")
        print("  IMPLEMENTATION_SUMMARY.md - Technical details")
        print("  FUNCTIONALITY_STATUS.md - Verification results")
        return 0
    else:
        print_error(f"{total - passed} check(s) failed. Please fix the issues above.")
        return 1

if __name__ == '__main__':
    sys.exit(validate_installation())
