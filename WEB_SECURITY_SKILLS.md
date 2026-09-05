# Web Security Expert — Complete Skill Inventory

Catalog of every agent and built-in skill available in this environment, organized
the way a web security expert actually works: by pentest lifecycle phase.

> **Authorization gate:** All execution-capable agents are bound by the shared
> `_scope-guard` prompt block — no commands run against a target until scope is
> declared, and every command is validated against that scope before execution.

---

## 0. The Guardrail

| Skill | Role |
|---|---|
| `_scope-guard` (shared prompt block) | Mandatory scope declaration, pre-execution validation, no destructive actions, no permission-bypass attempts. Loaded by all Tier-2 execution agents. |

---

## 1. Web Application Security (Core Domain)

The heart of the toolkit — these agents cover the OWASP Top 10, API, and modern
web attack surfaces.

| Agent | Exec | Delegation triggers (use when…) |
|---|---|---|
| **web-hunter** | ✅ Bash | Web app pentesting, directory brute force (ffuf/gobuster), SQLi testing, hidden endpoint discovery, parameter fuzzing, active web testing |
| **api-security** | 📖 Advisory | REST API attacks, GraphQL exploitation, OAuth/OIDC flaws, JWT attacks, API enumeration, web service methodology |
| **bizlogic-hunter** | ✅ Bash | Business logic flaws, workflow bypasses, price/payment tampering, race conditions, IDOR/authz boundaries, flaws scanners miss |
| **vuln-scanner** | ✅ Bash | Running nuclei/nikto/OpenVAS scans, CVE identification, parsing scan results, prioritizing vulns for exploitation |
| **poc-validator** | ✅ Bash | Validating findings with safe PoCs, killing false positives, generating/executing PoC scripts, verifying bugs before reporting |
| **exploit-guide** | 📖 Advisory | Exploitation techniques, attack methodology, tool configuration, post-exploitation paths for specific vulns |
| **exploit-chainer** | ✅ Bash | Chaining isolated vulns into multi-step attack paths, low-severity → full compromise, step-by-step escalation demos |
| **payload-crafter** | 📖 Advisory | Offensive payload generation, shellcode, msfvenom, packing/encoding, reverse shells, EDR-test binaries |
| **llm-redteam** | ✅ Bash | Prompt injection (direct/indirect), jailbreaks, RAG poisoning, model exfiltration, agent/tool-use abuse, guardrail bypass |
| **credential-tester** | 📖 Advisory | Password attacks, hash cracking, brute force methodology, default creds, password spraying (hydra/john/hashcat/medusa) |
| **bug-bounty** | 📖 Advisory | Bug bounty program work, HackerOne/Bugcrowd methodology, target prioritization, writing quality bounty reports |
| **ctf-solver** | 📖 Advisory | CTF/HackTheBox/TryHackMe challenges — web, binary, crypto, forensics, RE, privesc |

---

## 2. Reconnaissance & Attack Planning

| Agent | Exec | Delegation triggers |
|---|---|---|
| **osint-collector** | 📖 Advisory | OSINT, target profiling, email harvesting, subdomain enumeration, social media recon, breach data, target dossiers |
| **recon-advisor** | ✅ Bash | Parsing scan output (Nmap/Nessus/Nikto/masscan), enumeration help, attack surface analysis, running recon tools |
| **attack-planner** | 📖 Advisory | Correlating findings across tools/agents, building attack chains, optimal exploitation paths, prioritizing attack vectors |
| **threat-modeler** | 📖 Advisory | Threat modeling, STRIDE/DREAD, attack trees, data flow diagrams, trust boundaries, architecture review |
| **engagement-planner** | 📖 Advisory | Pentest planning, attack methodology, scoping, MITRE ATT&CK mapping, rules of engagement |
| **swarm-orchestrator** | 📖 Advisory | Coordinating multiple pentest agents as a team, full automated red team lifecycle (planning → reporting) |

---

## 3. Adjacent Attack Surfaces

Web apps don't live in a vacuum — these cover the infrastructure around them.

| Agent | Exec | Delegation triggers |
|---|---|---|
| **cloud-security** | 📖 Advisory | AWS/Azure/GCP pentesting, cloud misconfigs, IAM privesc, Kubernetes attacks, serverless security |
| **container-breakout** | 📖 Advisory | Container escape, Docker/K8s pod escape, runc/containerd CVEs, kubelet attacks, service account token abuse |
| **mobile-pentester** | 📖 Advisory | Android/iOS testing, APK/IPA analysis, mobile API testing, cert pinning bypass, mobile RE |
| **wireless-pentester** | 📖 Advisory | WiFi pentesting, WPA attacks, Bluetooth security, rogue APs, evil twin, RF security |
| **ad-attacker** | ✅ Bash | Active Directory attacks, BloodHound, Impacket, Kerberos, CrackMapExec/NetExec, lateral movement |
| **c2-operator** | 📖 Advisory | Sliver/Mythic/Havoc/Cobalt Strike config, listeners, malleable C2, redirectors, foothold operation |
| **phishing-operator** | 📖 Advisory | Evilginx3/GoPhish, AiTM credential capture, MFA token relay, dnstwist lookalikes, landing pages |
| **social-engineer** | 📖 Advisory | Phishing campaigns, pretexting, vishing, physical SE, awareness testing |
| **privesc-advisor** | 📖 Advisory | Local enumeration, Linux/Windows privesc, container escape, post-compromise escalation |

---

## 4. Operational Security

| Agent | Exec | Delegation triggers |
|---|---|---|
| **opsec-anonymizer** | 📖 Advisory | Source IP separation, Tor/proxy chains, burner infrastructure, attribution avoidance, pre-engagement posture |

---

## 5. Defense, Analysis & Deliverables

| Agent | Exec | Delegation triggers |
|---|---|---|
| **report-generator** | 📖 Advisory | Pentest reports, finding compilation, executive summaries, technical finding formatting |
| **forensics-analyst** | 📖 Advisory | Digital forensics, IR, memory/disk/network forensics, timelines, chain of custody |
| **malware-analyst** | 📖 Advisory | Malware triage, static/dynamic analysis, sandboxing, suspicious file analysis |
| **reverse-engineer** | 📖 Advisory | Ghidra/Radare2/IDA/JadX, firmware with Binwalk, disassembly without execution |
| **detection-engineer** | 📖 Advisory | Detection rules, SIEM queries, threat hunting, blue-team coverage for attack techniques |
| **stig-analyst** | 📖 Advisory | STIG findings, hardening, GPO, security baselines, compliance documentation |
| **cicd-redteam** | ✅ Bash | Red teaming in CI/CD pipelines, automated security testing on push, scheduled assessments |

---

## 6. Built-in Skills (Harness)

| Skill | Use for |
|---|---|
| **code-review** | Review diffs/PRs for bugs — use on SP1D3R code changes before commits |
| **security-review** | Security review of pending changes on the current branch |
| **run** | Launch and drive SP1D3R to verify changes work end-to-end |
| **workflow-authoring** | Script multi-agent orchestration (parallel scan + verify pipelines) |
| **dataviz** | Charts/dashboards for pentest reports and finding visualizations |
| **simplify** | Cleanup passes on changed code (quality-only, pairs with code-review) |
| **loop** | Recurring tasks — scheduled scans, polling job status |
| **fewer-permission-prompts** | Allowlist common read-only commands to reduce prompt noise |
| **init** | Generate CLAUDE.md project documentation |
| **update-config** | Configure settings.json — permissions, hooks, env vars |

---

## 7. SP1D3R Project Mapping

Which agents apply to each part of this codebase:

| SP1D3R module | Best-fit agents |
|---|---|
| `core/subdomain_enum.py`, `core/port_scanner.py` | recon-advisor, osint-collector, web-hunter |
| `core/web_scanner.py`, `core/attack_surface.py` | web-hunter, attack-planner, threat-modeler |
| `core/vuln_scanner.py`, `core/cve_matcher.py` | vuln-scanner, poc-validator |
| `core/verification_engine.py` | poc-validator, exploit-chainer |
| `modules/waf_detector.py`, `modules/fingerprint.py` | web-hunter, recon-advisor |
| `api/rest_api.py`, `integrations/` | api-security, cicd-redteam |
| `reports/generator.py` | report-generator, dataviz |
| `payloads/*.txt` | payload-crafter, web-hunter, bizlogic-hunter |
| Scan result triage | attack-planner, exploit-guide, exploit-chainer |
| Full assessment lifecycle | engagement-planner → swarm-orchestrator → report-generator |

---

## 8. Quick Reference — Pentest Lifecycle

```
SCOPE        → _scope-guard (declare scope, always first)
PLAN         → engagement-planner → threat-modeler
RECON        → osint-collector + recon-advisor (parallel)
ENUMERATE    → web-hunter + api-security + vuln-scanner
ANALYZE      → attack-planner (correlate) → bizlogic-hunter (logic flaws)
VALIDATE     → poc-validator (kill false positives)
EXPLOIT      → exploit-guide → exploit-chainer (chain) → payload-crafter (payloads)
CREDENTIALS  → credential-tester
LLM SURFACE  → llm-redteam
INFRA PIVOT  → cloud-security → container-breakout → ad-attacker → privesc-advisor
OPSEC        → opsec-anonymizer (throughout)
REPORT       → report-generator + dataviz
CONTINUOUS   → cicd-redteam
```

**Execution rule:** Agents marked ✅ can run Bash against in-scope targets;
📖 agents are advisory (analyze, design, write — hand execution to you or a ✅ agent).

**Environment note:** No MCP servers are currently configured. All 36 agents live in
`~/.claude/agents/` and are loaded automatically each session.
