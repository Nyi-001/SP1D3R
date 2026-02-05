# api/rest_api.py
"""REST API for automated penetration testing"""
from flask import Flask, request, jsonify
from threading import Thread
from typing import Dict, Any
import uuid
import time
import asyncio
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.scanner import PentestScanner
from utils.logger import setup_logger
from utils.config import load_config

app = Flask(__name__)

# Store scan results
scans: Dict[str, Dict[str, Any]] = {}

# Initialize once
logger = setup_logger(verbose=False)
config = load_config('config/config.yaml')


def run_scan_async(scan_id: str, params: Dict[str, Any]) -> None:
    """Run scan asynchronously"""
    try:
        scanner = PentestScanner(config, logger)
        
        # Prepare scan parameters
        scan_params = {
            'target': params['target'],
            'scan_type': params.get('scan_type', 'standard'),
            'module': params.get('module', 'all'),
            'ports': params.get('ports', '1-1000'),
            'wordlist': params.get('wordlist'),
            'test_sqli': params.get('test_sqli', False),
            'test_xss': params.get('test_xss', False),
            'cve_check': params.get('cve_check', False)
        }
        
        # Run scan
        results = asyncio.run(scanner.scan(scan_params))
        
        scans[scan_id]['status'] = 'completed'
        scans[scan_id]['results'] = results
        scans[scan_id]['completed_at'] = time.time()
    
    except Exception as e:
        logger.error(f"Scan error: {e}")
        scans[scan_id]['status'] = 'failed'
        scans[scan_id]['error'] = str(e)
        scans[scan_id]['completed_at'] = time.time()


@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a new scan"""
    data = request.get_json(force=True) or {}
    
    if 'target' not in data:
        return jsonify({'error': 'target is required'}), 400
    
    scan_id = str(uuid.uuid4())
    scans[scan_id] = {
        'status': 'running',
        'created_at': time.time(),
        'params': data,
    }
    
    # Start scan in background thread
    thread = Thread(target=run_scan_async, args=(scan_id, data), daemon=True)
    thread.start()
    
    return jsonify({'scan_id': scan_id, 'status': 'running'}), 202


@app.route('/api/scan/<scan_id>/status', methods=['GET'])
def scan_status(scan_id: str):
    """Get scan status"""
    scan = scans.get(scan_id)
    if not scan:
        return jsonify({'error': 'scan_id not found'}), 404
    
    response = {
        'scan_id': scan_id,
        'status': scan['status'],
        'created_at': scan['created_at']
    }
    
    if 'completed_at' in scan:
        response['completed_at'] = scan['completed_at']
        response['duration'] = scan['completed_at'] - scan['created_at']
    
    if scan['status'] == 'failed' and 'error' in scan:
        response['error'] = scan['error']
    
    return jsonify(response)


@app.route('/api/scan/<scan_id>/results', methods=['GET'])
def scan_results(scan_id: str):
    """Get scan results"""
    scan = scans.get(scan_id)
    if not scan:
        return jsonify({'error': 'scan_id not found'}), 404
    
    if scan['status'] == 'running':
        return jsonify({'error': 'scan still running', 'status': 'running'}), 409
    
    if scan['status'] == 'failed':
        return jsonify({'error': scan.get('error', 'scan failed'), 'status': 'failed'}), 500
    
    return jsonify(scan.get('results', {}))


@app.route('/api/scans', methods=['GET'])
def list_scans():
    """List all scans"""
    scan_list = []
    for scan_id, scan_data in scans.items():
        scan_list.append({
            'scan_id': scan_id,
            'target': scan_data['params'].get('target'),
            'status': scan_data['status'],
            'created_at': scan_data['created_at']
        })
    
    return jsonify({'scans': scan_list, 'count': len(scan_list)})


@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'service': 'automated-pentest-tool'})


def create_app():
    """Application factory"""
    return app


if __name__ == '__main__':
    print("Starting Automated Penetration Testing Tool API")
    print("API will be available at http://localhost:5000")
    print("Endpoints:")
    print("  POST   /api/scan              - Start new scan")
    print("  GET    /api/scan/{id}/status  - Check scan status")
    print("  GET    /api/scan/{id}/results - Get scan results")
    print("  GET    /api/scans             - List all scans")
    print("  GET    /api/health            - Health check")
    app.run(host='0.0.0.0', port=5000, debug=False)
