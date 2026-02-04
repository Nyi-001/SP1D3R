# api/rest_api.py
from flask import Flask, request, jsonify
from threading import Thread
from typing import Dict, Any
import uuid
import time

# You need to import your actual scanner orchestrator here
# from core.scanner import Scanner

app = Flask(__name__)

scans: Dict[str, Dict[str, Any]] = {}


def run_scan(scan_id: str, params: Dict[str, Any], config: Dict, logger) -> None:
    try:
        target = params["target"]
        scan_type = params.get("scan_type", "standard")
        modules = params.get("modules")  # list or None

        # scanner = Scanner(config=config, logger=logger)
        # results = scanner.run(target=target, scan_type=scan_type, modules=modules)
        # For now: stub result
        time.sleep(2)  # simulate work
        results = {
            "meta": {
                "target": target,
                "scan_type": scan_type,
            },
            "modules": {
                "stub": {
                    "findings": []
                }
            }
        }

        scans[scan_id]["status"] = "completed"
        scans[scan_id]["results"] = results
    except Exception as e:
        scans[scan_id]["status"] = "failed"
        scans[scan_id]["error"] = str(e)


@app.route("/api/scan", methods=["POST"])
def start_scan():
    data = request.get_json(force=True) or {}
    if "target" not in data:
        return jsonify({"error": "target is required"}), 400

    scan_id = str(uuid.uuid4())
    scans[scan_id] = {
        "status": "running",
        "created_at": time.time(),
        "params": data,
    }

    # In real integration you will pass actual config/logger
    t = Thread(target=run_scan, args=(scan_id, data, {}, None), daemon=True)
    t.start()

    return jsonify({"scan_id": scan_id}), 202


@app.route("/api/scan/<scan_id>/status", methods=["GET"])
def scan_status(scan_id: str):
    scan = scans.get(scan_id)
    if not scan:
        return jsonify({"error": "scan_id not found"}), 404
    return jsonify({"scan_id": scan_id, "status": scan["status"]})


@app.route("/api/scan/<scan_id>/results", methods=["GET"])
def scan_results(scan_id: str):
    scan = scans.get(scan_id)
    if not scan:
        return jsonify({"error": "scan_id not found"}), 404

    if scan["status"] != "completed":
        return jsonify({"error": "scan not completed", "status": scan["status"]}), 409

    return jsonify(scan["results"])


def create_app():
    return app


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
