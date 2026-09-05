"""Run approved external tools and normalize their machine-readable output."""

import json
import os
import shutil
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib.parse import urlsplit, urlunsplit

from colorama import Fore, Style

from core.finding_model import normalize_finding
from core.scope import ScopePolicy, ScopeError, normalize_url


TOOL_PROFILES = {
    # Passive/low-impact recon profiles inspired by Bug-Bounty-Script.
    "assetfinder": {"executable": "assetfinder", "active": False, "role": "subdomains"},
    "subfinder": {"executable": "subfinder", "active": False, "role": "subdomains"},
    "amass": {"executable": "amass", "active": False, "role": "subdomains"},
    "sublist3r": {"executable": "sublist3r", "active": False, "role": "subdomains"},
    "dnsx": {"executable": "dnsx", "active": False, "role": "dns"},
    "dnsenum": {"executable": "dnsenum", "active": False, "role": "dns"},
    "whois": {"executable": "whois", "active": False, "role": "domain-info"},
    "httpx": {"executable": "httpx", "active": False, "role": "http"},
    "whatweb": {"executable": "whatweb", "active": False, "role": "fingerprint"},
    "katana": {"executable": "katana", "active": False, "role": "crawl"},
    # Active profiles are never selected implicitly and always require --active.
    "nmap": {"executable": "nmap", "active": True, "role": "ports"},
    "nikto": {"executable": "nikto", "active": True, "role": "web-audit"},
    "dirb": {"executable": "dirb", "active": True, "role": "content"},
    "dirsearch": {"executable": "dirsearch", "active": True, "role": "content"},
    "ffuf": {"executable": "ffuf", "active": True, "role": "content"},
    "nuclei": {"executable": "nuclei", "active": True, "role": "vulnerability"},
    "wpscan": {"executable": "wpscan", "active": True, "role": "wordpress"},
}


class ToolManager:
    # A content discovery result is useful when it represents an accessible
    # or protected resource. Ordinary 404s are noise and are not reported.
    DIRSEARCH_INTERESTING_STATUSES = {
        200, 201, 202, 204, 206, 301, 302, 307, 308,
        401, 403, 405, 500, 502, 503,
    }

    def __init__(self, config: Dict[str, Any], logger):
        self.config = config
        self.logger = logger
        scope = config.get("scope", {})
        self.scope = ScopePolicy(scope.get("allowed_hosts", []), scope.get("excluded_paths", []))
        self.verbose = bool(config.get("scanning", {}).get("verbose", False))

    def run_requested(self, target: str, names: List[str]) -> Dict[str, Any]:
        result = {"findings": [], "assets": {}, "tool_runs": [], "errors": []}
        if names:
            self._console(f"[TOOLS] Starting {len(names)} external tool profile(s)", Fore.CYAN)
        for name in names:
            self._console(f"[TOOL] {name}: starting", Fore.BLUE)
            try:
                findings, assets, run = self._run_one(name, target)
                result["findings"].extend(findings)
                for category, entries in assets.items():
                    result["assets"].setdefault(category, []).extend(entries)
                run["finding_count"] = len(findings)
                run["asset_count"] = sum(len(entries) for entries in assets.values())
                result["tool_runs"].append(run)
                color = Fore.GREEN if run["status"] == "completed" else Fore.RED
                self._console(f"[TOOL] {name}: {run['status']} in {run['duration_seconds']}s | findings={run['finding_count']} assets={run['asset_count']}", color)
                if self.verbose:
                    self._console(f"[RESULT] {name}: normalized findings={run['finding_count']} | discovered assets={run['asset_count']}", Fore.WHITE)
                    self._print_verbose_results(name, findings, assets)
                elif findings or assets:
                    self.logger.debug(f"{name}: normalized findings={run['finding_count']} | discovered assets={run['asset_count']}")
            except Exception as exc:
                message = f"{name}: {exc}"
                self.logger.warning(message)
                result["errors"].append(message)
                result["tool_runs"].append({"tool": name, "status": "skipped", "finding_count": 0, "asset_count": 0, "error": str(exc)})
                self._console(f"[TOOL] {name}: skipped — {exc}", Fore.YELLOW)
        if names:
            self._console(f"[TOOLS] Finished | findings={len(result['findings'])} assets={sum(len(v) for v in result['assets'].values())}", Fore.CYAN)
        return result

    @staticmethod
    def _console(message: str, color: str) -> None:
        print(f"{color}{message}{Style.RESET_ALL}", flush=True)

    @staticmethod
    def _status_color(value: Any) -> str:
        try:
            status = int(str(value).strip())
        except (TypeError, ValueError):
            return Fore.WHITE
        if 200 <= status < 300:
            return Fore.GREEN
        if 300 <= status < 400:
            return Fore.CYAN
        if 400 <= status < 500:
            return Fore.YELLOW
        if 500 <= status < 600:
            return Fore.RED
        return Fore.WHITE

    def _print_verbose_results(self, name: str, findings: List[Dict[str, Any]], assets: Dict[str, List[Dict[str, Any]]]) -> None:
        for finding in findings[:25]:
            severity = str(finding.get("severity", "info")).lower()
            color = {"critical": Fore.RED, "high": Fore.RED, "medium": Fore.YELLOW, "low": Fore.GREEN, "info": Fore.WHITE}.get(severity, Fore.WHITE)
            title = finding.get("title", "Unnamed finding")
            location = finding.get("location", "")
            status = finding.get("status_code")
            status_text = ""
            if status not in (None, ""):
                status_text = f" | {self._status_color(status)}HTTP {status}{Style.RESET_ALL}"
            self._console(f"  [{severity.upper()}] {title} | {location}{status_text}", color)
        if len(findings) > 25:
            self._console(f"  ... {len(findings) - 25} additional findings omitted from terminal output", Fore.WHITE)
        for category, entries in assets.items():
            self._console(f"  [{category}] {len(entries)} discovered", Fore.MAGENTA)
            for entry in entries[:10]:
                value = entry.get("url") or entry.get("host") or entry.get("name") or entry
                status = entry.get("status")
                status_text = f" | {self._status_color(status)}HTTP {status}{Style.RESET_ALL}" if status not in (None, "") else ""
                self._console(f"    - {value}{status_text}", Fore.WHITE)
            if len(entries) > 10:
                self._console(f"    ... {len(entries) - 10} additional assets omitted from terminal output", Fore.WHITE)

    def _run_one(self, name: str, target: str) -> Tuple[List[Dict[str, Any]], Dict[str, List[Dict[str, Any]]], Dict[str, Any]]:
        if name not in TOOL_PROFILES:
            raise ValueError("unknown tool profile")
        profile = TOOL_PROFILES[name]
        if profile["active"] and not self.config.get("scope", {}).get("active_checks", False):
            raise ValueError("active mode is required; rerun with --active")
        executable = shutil.which(profile["executable"])
        if not executable:
            raise FileNotFoundError(f"executable not found: {profile['executable']}")
        command = self._build_command(name, target)
        scanning = self.config.get("scanning", {})
        timeout = float(scanning.get("tool_timeout", 120))
        if name == "dirsearch":
            # Content discovery can legitimately take longer than the other
            # profiles. By default it is allowed to finish; set
            # dirsearch_timeout to a positive value for an operational cap.
            configured_dirsearch_timeout = float(scanning.get("dirsearch_timeout", 0) or 0)
            timeout = configured_dirsearch_timeout if configured_dirsearch_timeout > 0 else None
        started = time.monotonic()
        report_path = None
        if name == "dirsearch":
            report_file = tempfile.NamedTemporaryFile(prefix="websentinel-dirsearch-", suffix=".json", delete=False)
            report_path = Path(report_file.name)
            report_file.close()
            command.extend(["--format", "json", "--output", str(report_path)])
        try:
            completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False, shell=False)
            tool_output = completed.stdout
            if report_path and report_path.exists():
                tool_output = report_path.read_text(encoding="utf-8", errors="replace") or completed.stdout
        except subprocess.TimeoutExpired as exc:
            # Keep partial stdout/stderr so the report can distinguish a
            # timeout from a missing binary or a clean no-result scan.
            partial_stdout = exc.stdout or ''
            partial_stderr = exc.stderr or ''
            if isinstance(partial_stdout, bytes):
                partial_stdout = partial_stdout.decode('utf-8', errors='replace')
            if isinstance(partial_stderr, bytes):
                partial_stderr = partial_stderr.decode('utf-8', errors='replace')
            tool_output = str(partial_stdout)
            if report_path and report_path.exists():
                tool_output = report_path.read_text(encoding="utf-8", errors="replace") or tool_output
            duration = round(time.monotonic() - started, 3)
            findings = self._normalize_findings(name, target, tool_output)
            assets = self._extract_assets(name, tool_output)
            run = {
                "tool": name,
                "status": "timeout",
                "returncode": None,
                "duration_seconds": duration,
                "stderr": (str(partial_stderr) or f"timed out after {timeout:.1f} seconds")[-2000:],
            }
            return findings, assets, run
        finally:
            if report_path:
                report_path.unlink(missing_ok=True)
        duration = round(time.monotonic() - started, 3)
        findings = self._normalize_findings(name, target, tool_output)
        assets = self._extract_assets(name, tool_output)
        if completed.returncode == 0:
            status = "completed"
        elif name == "whatweb" and self._valid_whatweb_output(tool_output):
            # WhatWeb may return a non-zero code when one plugin or one
            # request fails even though it produced valid JSON observations.
            # Preserve stderr as a diagnostic, but do not discard usable
            # fingerprint data or label the whole phase as failed.
            status = "completed-with-warnings"
        elif tool_output.strip() or findings or assets:
            status = "completed-with-errors"
        else:
            status = "failed"
        run = {"tool": name, "status": status, "returncode": completed.returncode, "duration_seconds": duration, "stderr": completed.stderr[-2000:]}
        return findings, assets, run

    def _build_command(self, name: str, target: str) -> List[str]:
        if name in {"assetfinder", "subfinder", "amass", "sublist3r", "dnsx", "dnsenum", "whois", "nmap"}:
            host = self._host(target)
            if not self.scope.is_allowed(f"https://{host}/"):
                raise ScopeError(f"host is outside scope: {host}")
        else:
            target = self.scope.assert_allowed(normalize_url(target))
        executable = TOOL_PROFILES[name]["executable"]
        host = self._host(target)
        if name == "subfinder":
            return [executable, "-d", host, "-silent", "-json"]
        if name == "assetfinder":
            return [executable, "--subs-only", host]
        if name == "amass":
            return [executable, "enum", "-passive", "-d", host]
        if name == "sublist3r":
            return [executable, "-d", host, "-n"]
        if name == "dnsx":
            return [executable, "-d", host, "-silent", "-json"]
        if name == "dnsenum":
            return [executable, "--noreverse", "--noping", host]
        if name == "whois":
            return [executable, host]
        if name == "httpx":
            return [executable, "-u", target, "-silent", "-json"]
        if name == "whatweb":
            scanning = self.config.get("scanning", {})
            configured_timeout = int(scanning.get("whatweb_timeout", 15))
            tool_timeout = int(scanning.get("tool_timeout", 120))
            request_timeout = max(1, min(configured_timeout, tool_timeout))
            command = [
                executable, "--color=never", "--quiet", "--aggression=1",
                "--open-timeout", str(request_timeout),
                "--read-timeout", str(request_timeout),
                "--log-json=-", target,
            ]
            # Keep passive fingerprinting aligned with the authenticated
            # crawler. Without this, WhatWeb can fingerprint the login page
            # while the native scanner is testing an authenticated route.
            cookie = scanning.get("cookie")
            if cookie:
                command[-1:-1] = ["--cookie", str(cookie)]
            for header_name, header_value in scanning.get("headers", {}).items():
                if str(header_name).lower() in {"host", "content-length", "connection", "transfer-encoding", "user-agent"}:
                    continue
                command[-1:-1] = ["--header", f"{header_name}: {header_value}"]
            return command
        if name == "katana":
            return [executable, "-u", target, "-silent", "-jsonl", "-depth", str(self.config.get("modules", {}).get("web_scanner", {}).get("depth", 2)), "-rate-limit", "2"]
        if name == "nmap":
            return [executable, "-Pn", "-T2", "-sV", "--version-light", "--top-ports", "100", "-oX", "-", host]
        if name == "nikto":
            return [executable, "-host", target, "-nointeractive", "-Format", "txt"]
        if name == "dirb":
            wordlist = self.config.get("scope", {}).get("wordlist")
            if not wordlist or not Path(wordlist).is_file():
                raise ValueError("dirb requires an existing --wordlist")
            return [executable, target, str(Path(wordlist)), "-S"]
        if name == "dirsearch":
            scanning = self.config.get("scanning", {})
            parsed = urlsplit(target)
            scan_path = parsed.path or "/"
            # A target that points at a file should fuzz its containing
            # directory, not append a wordlist to `file/`.
            if not scan_path.endswith("/"):
                scan_path = scan_path.rsplit("/", 1)[0] + "/"
            scan_target = urlunsplit((parsed.scheme, parsed.netloc, scan_path, "", ""))
            command = [
                executable, "--url", scan_target, "--quiet-mode", "--no-color",
                "--wordlists", str(Path(__file__).resolve().parents[1] / "wordlists" / "web_paths.txt"),
                "--threads", "5",
                "--timeout", str(int(scanning.get("timeout", 30))),
            ]
            dirsearch_timeout = int(scanning.get("dirsearch_timeout", 0) or 0)
            if dirsearch_timeout > 0:
                command.extend(["--max-time", str(dirsearch_timeout)])
            if scanning.get("user_agent"):
                command.extend(["--user-agent", str(scanning["user_agent"])])
            cookie = scanning.get("cookie")
            if cookie:
                command.extend(["--cookie", str(cookie)])
            for header_name, header_value in scanning.get("headers", {}).items():
                if str(header_name).lower() in {"host", "content-length", "connection", "transfer-encoding", "user-agent"}:
                    continue
                command.extend(["--header", f"{header_name}: {header_value}"])
            if scanning.get("rate_limit"):
                command.extend(["--max-rate", str(int(scanning["rate_limit"]))])
            return command
        if name == "ffuf":
            wordlist = self.config.get("scope", {}).get("wordlist")
            if not wordlist or not Path(wordlist).is_file():
                raise ValueError("ffuf requires an existing --wordlist")
            return [executable, "-u", target.rstrip("/") + "/FUZZ", "-w", str(Path(wordlist)), "-of", "json", "-o", "-", "-rate", "10", "-t", "2", "-noninteractive"]
        if name == "nuclei":
            return [executable, "-u", target, "-jsonl", "-rate-limit", "5", "-concurrency", "1", "-bulk-size", "1", "-no-interactsh"]
        if name == "wpscan":
            command = [executable, "--url", target, "--format", "json", "--no-update", "--plugins-detection", "passive", "--enumerate", "vp,vt,cb", "--max-threads", "2", "--request-timeout", str(int(self.config.get("scanning", {}).get("timeout", 30)))]
            if os.environ.get("WPSCAN_API_TOKEN"):
                command.extend(["--api-token", os.environ["WPSCAN_API_TOKEN"]])
            return command
        raise ValueError("tool profile has no command")

    @staticmethod
    def _host(target: str) -> str:
        parsed = urlsplit(target if "://" in target else "https://" + target)
        if not parsed.hostname:
            raise ValueError("target has no hostname")
        return parsed.hostname.encode("idna").decode("ascii").lower()

    def _normalize_findings(self, name: str, target: str, output: str) -> List[Dict[str, Any]]:
        findings = []
        if name == "nuclei":
            for item in self._json_lines(output):
                info = item.get("info", {})
                location = item.get("matched-at") or item.get("host") or target
                if self._location_allowed(location):
                    findings.append(normalize_finding({"title": info.get("name") or item.get("template-id", "Nuclei finding"), "severity": info.get("severity", "info"), "location": location, "description": json.dumps(item)[:3000], "remediation": info.get("remediation", "Review the referenced template and remediate the underlying condition."), "tool": name}))
        elif name == "wpscan":
            try:
                data = json.loads(output)
            except json.JSONDecodeError:
                data = {}
            for key, severity in (("vulnerabilities", "high"), ("interesting_findings", "medium")):
                for item in data.get(key, []) or []:
                    location = item.get("url") or data.get("target_url") or target
                    if self._location_allowed(location):
                        findings.append(normalize_finding({"title": item.get("title") or "WordPress finding", "severity": severity, "location": location, "description": json.dumps(item)[:3000], "remediation": "Update or remove the affected WordPress component.", "tool": name}))
        elif name == "ffuf":
            try:
                data = json.loads(output)
            except json.JSONDecodeError:
                data = {}
            for item in data.get("results", []) or []:
                location = item.get("url") or target
                if self._location_allowed(location):
                    findings.append(normalize_finding({"title": "Discovered web path", "severity": "info", "location": location, "description": f"HTTP status {item.get('status')}; size {item.get('length')}", "remediation": "Review whether the path should be public.", "tool": name}))
        elif name == "dirsearch":
            try:
                data = json.loads(output)
            except json.JSONDecodeError:
                data = {}
            for item in data.get("results", []) or []:
                location = item.get("url") or target
                if not self._location_allowed(location):
                    continue
                status = item.get("status")
                try:
                    status_code = int(status)
                except (TypeError, ValueError):
                    status_code = None
                if status_code not in self.DIRSEARCH_INTERESTING_STATUSES:
                    continue
                findings.append(normalize_finding({
                    "title": f"Discovered web path ({status})",
                    "severity": "info",
                    "location": location,
                    "status_code": status,
                    "content_length": item.get("content-length"),
                    "content_type": item.get("content-type"),
                    "redirect": item.get("redirect"),
                    "description": "Dirsearch discovered a response at this path.",
                    "remediation": "Review whether the path should be public and remove or protect it if unnecessary.",
                    "tool": name,
                }))
        elif name in {"nikto", "dirb"}:
            # These tools primarily emit human-readable observations. Keep the
            # raw output in the run record and add a low-confidence review item
            # rather than pretending every banner is a verified vulnerability.
            if output.strip():
                findings.append(normalize_finding({
                    "title": f"{name.title()} reported observations",
                    "severity": "info",
                    "location": target,
                    "description": output[-3000:],
                    "confidence": "low",
                    "state": "possible",
                    "remediation": "Review the tool output and validate each observation manually.",
                    "tool": name,
                }))
        return findings

    def _location_allowed(self, location: Any) -> bool:
        if not location or "://" not in str(location):
            return True
        try:
            return self.scope.is_allowed(str(location))
        except (ValueError, UnicodeError):
            return False

    def _extract_assets(self, name: str, output: str) -> Dict[str, List[Dict[str, Any]]]:
        assets: Dict[str, List[Dict[str, Any]]] = {}
        if name in {"assetfinder", "amass", "sublist3r"}:
            for host in self._extract_hosts(output):
                if self.scope.is_allowed(f"https://{host}/"):
                    assets.setdefault("subdomains", []).append({"host": host, "source": name})
            return assets
        if name == "nmap":
            return self._extract_nmap_services(output, name)
        if name == "whatweb":
            return self._extract_whatweb(output, name)
        if name == "dirsearch":
            for data in self._dirsearch_results(output):
                for result in data.get("results", []) or []:
                    url = result.get("url")
                    try:
                        status = int(result.get("status"))
                    except (TypeError, ValueError):
                        status = None
                    if not url or status not in self.DIRSEARCH_INTERESTING_STATUSES:
                        continue
                    if self.scope.is_allowed(str(url)):
                        assets.setdefault("directories", []).append({
                            "url": url,
                            "status": status,
                            "length": result.get("content-length"),
                            "content_type": result.get("content-type"),
                            "source": name,
                        })
            return assets
        if name in {"dnsenum", "whois"} and output.strip():
            assets.setdefault("recon_observations", []).append({"tool": name, "details": output[-5000:]})
            return assets
        for item in self._json_lines(output):
            if name == "subfinder":
                host = item.get("host") or item.get("name")
                if host and self.scope.is_allowed(f"https://{host}/"):
                    assets.setdefault("subdomains", []).append({"host": host, "source": name})
            elif name == "dnsx":
                host = item.get("host") or item.get("name")
                if host and self.scope.is_allowed(f"https://{host}/"):
                    assets.setdefault("dns_records", []).append({"host": host, "a": item.get("a", []), "aaaa": item.get("aaaa", []), "cname": item.get("cname", []), "source": name})
            elif name == "httpx":
                url = item.get("url") or item.get("input")
                if url and self.scope.is_allowed(str(url)):
                    assets.setdefault("services", []).append({"url": url, "status": item.get("status-code"), "title": item.get("title", ""), "server": item.get("webserver", ""), "source": name})
            elif name == "katana":
                url = item.get("endpoint") or item.get("request", {}).get("endpoint")
                if url and self.scope.is_allowed(str(url)):
                    assets.setdefault("urls", []).append({"url": url, "source": name})
            elif name == "ffuf":
                for result in item.get("results", []) or []:
                    url = result.get("url")
                    if url and self.scope.is_allowed(str(url)):
                        assets.setdefault("directories", []).append({"url": url, "status": result.get("status"), "source": name})
        return assets

    @staticmethod
    def _dirsearch_results(output: str) -> List[Dict[str, Any]]:
        """Parse dirsearch's single JSON document (not JSON Lines)."""
        try:
            value = json.loads(output)
        except json.JSONDecodeError:
            return []
        if not isinstance(value, dict):
            return []
        return [value]

    def _extract_hosts(self, output: str) -> List[str]:
        """Extract only hostname-shaped lines and retain scope filtering."""
        hosts = set()
        for line in output.splitlines():
            value = line.strip().lower().rstrip(".")
            if value.startswith("http://") or value.startswith("https://"):
                value = urlsplit(value).hostname or ""
            if value and all(part and part.replace("-", "").isalnum() for part in value.split(".")):
                hosts.add(value)
        return sorted(hosts)

    @staticmethod
    def _extract_nmap_services(output: str, name: str) -> Dict[str, List[Dict[str, Any]]]:
        services = []
        try:
            root = ET.fromstring(output)
        except ET.ParseError:
            return {}
        for port in root.findall(".//port"):
            state = port.find("state")
            service = port.find("service")
            if state is None or state.get("state") != "open":
                continue
            services.append({
                "port": port.get("portid"),
                "protocol": port.get("protocol"),
                "service": service.get("name") if service is not None else "",
                "product": service.get("product") if service is not None else "",
                "version": service.get("version") if service is not None else "",
                "source": name,
            })
        return {"services": services} if services else {}

    @staticmethod
    def _extract_whatweb(output: str, name: str) -> Dict[str, List[Dict[str, Any]]]:
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return {}
        records = data if isinstance(data, list) else [data]
        services = []
        for item in records:
            if not isinstance(item, dict):
                continue
            target = item.get("target") or item.get("url")
            if target:
                services.append({"url": target, "status": item.get("http_status"), "technologies": item.get("plugins", {}), "source": name})
        return {"services": services} if services else {}

    @staticmethod
    def _valid_whatweb_output(output: str) -> bool:
        """Return whether WhatWeb emitted parseable JSON despite warnings."""
        try:
            value = json.loads(output)
        except (TypeError, ValueError):
            return False
        return isinstance(value, (list, dict))

    @staticmethod
    def _json_lines(output: str) -> List[Dict[str, Any]]:
        records = []
        for line in output.splitlines():
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                records.append(value)
        return records
