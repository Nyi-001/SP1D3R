#!/usr/bin/env python3
"""Comprehensive functionality test for the pentest tool"""
import sys
import asyncio

def test_imports():
    """Test all critical imports"""
    print("Testing imports...")
    try:
        from core.scanner import PentestScanner
        from core.port_scanner import PortScanner
        from core.subdomain_enum import SubdomainEnumerator
        from core.vuln_scanner import VulnerabilityScanner
        from core.web_scanner import WebScanner
        from modules.dns_analyzer import DNSAnalyzer
        from modules.ssl_tester import SSLTester
        from modules.waf_detector import WAFDetector
        from modules.fingerprint import TechFingerprint
        from utils.logger import setup_logger, log_banner
        from utils.config import load_config
        from reports.generator import ReportGenerator
        from api.rest_api import create_app
        print("✅ All imports successful")
        return True
    except Exception as e:
        print(f"❌ Import failed: {e}")
        return False

def test_config():
    """Test configuration loading"""
    print("\nTesting configuration...")
    try:
        from utils.config import load_config
        config = load_config('config/config.yaml')
        assert 'scanning' in config
        assert 'modules' in config
        assert 'reporting' in config
        print("✅ Configuration loaded successfully")
        return True
    except Exception as e:
        print(f"❌ Configuration test failed: {e}")
        return False

def test_logger():
    """Test logger functionality"""
    print("\nTesting logger...")
    try:
        from utils.logger import setup_logger, log_banner
        logger = setup_logger(verbose=False)
        logger.info("Test log message")
        log_banner()
        print("✅ Logger functional")
        return True
    except Exception as e:
        print(f"❌ Logger test failed: {e}")
        return False

async def test_scanner():
    """Test scanner functionality"""
    print("\nTesting scanner...")
    try:
        from core.scanner import PentestScanner
        from utils.logger import setup_logger
        from utils.config import load_config
        
        logger = setup_logger(verbose=False)
        config = load_config('config/config.yaml')
        scanner = PentestScanner(config, logger)
        
        # Test with minimal scan
        results = await scanner.scan({
            'target': '127.0.0.1',
            'scan_type': 'quick',
            'module': 'port'
        })
        
        assert 'scan_info' in results
        assert 'target' in results
        assert 'findings' in results
        assert 'stats' in results
        print("✅ Scanner functional")
        return True
    except Exception as e:
        print(f"❌ Scanner test failed: {e}")
        return False

def test_report_generator():
    """Test report generation"""
    print("\nTesting report generator...")
    try:
        from reports.generator import ReportGenerator
        from utils.config import load_config
        from utils.logger import setup_logger
        
        config = load_config('config/config.yaml')
        logger = setup_logger(verbose=False)
        report_gen = ReportGenerator(config, logger)
        
        # Test data
        test_results = [{
            'scan_info': {'target': 'test.com', 'scan_type': 'quick', 'duration': '0:00:01'},
            'target': {'technologies': []},
            'findings': [],
            'stats': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        }]
        
        # Generate reports
        report_gen.generate(test_results, '/tmp/test.html', format='html')
        report_gen.generate(test_results, '/tmp/test.json', format='json')
        
        import os
        assert os.path.exists('/tmp/test.html')
        assert os.path.exists('/tmp/test.json')
        print("✅ Report generator functional")
        return True
    except Exception as e:
        print(f"❌ Report generator test failed: {e}")
        return False

def test_api():
    """Test API creation"""
    print("\nTesting API...")
    try:
        from api.rest_api import create_app
        app = create_app()
        assert app is not None
        assert len(app.url_map._rules) >= 5
        print("✅ API functional")
        return True
    except Exception as e:
        print(f"❌ API test failed: {e}")
        return False

async def run_all_tests():
    """Run all tests"""
    print("="*60)
    print("AUTOMATED PENTEST TOOL - COMPREHENSIVE TEST SUITE")
    print("="*60)
    
    tests = [
        ("Imports", test_imports()),
        ("Configuration", test_config()),
        ("Logger", test_logger()),
        ("Scanner", await test_scanner()),
        ("Report Generator", test_report_generator()),
        ("REST API", test_api()),
    ]
    
    passed = sum(1 for _, result in tests if result)
    total = len(tests)
    
    print("\n" + "="*60)
    print(f"RESULTS: {passed}/{total} tests passed")
    print("="*60)
    
    if passed == total:
        print("✅ ALL TESTS PASSED - TOOL IS FULLY FUNCTIONAL")
        return 0
    else:
        print(f"❌ {total - passed} test(s) failed")
        return 1

if __name__ == '__main__':
    sys.exit(asyncio.run(run_all_tests()))
