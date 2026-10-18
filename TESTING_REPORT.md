# SP1D3R — Lab Testing Report & Weakness Analysis

| Field | Value |
|---|---|
| **Tool tested** | SP1D3R `main.py` (this repo, HEAD) |
| **Labs** | DVWA (low) @ `http://127.0.0.1:8080/DVWA/` · VAmPI @ `http://127.0.0.1:8081/` |
| **Ground truth DVWA** | `DVWA_BUG_BOUNTY_REPORT.md` in this repo (20 confirmed vulns, Burp-based) |
| **Ground truth VAmPI** | Verified manually during this test (SQLi, JWT forgery, data exposure, Regex DoS, authz confusion) |
| **Runs** | `--active --all-tests --module web` (DVWA, VAmPI) + `--request-file` seed (VAmPI) |
| **Date** | 2026-10-18 |

---

## 1. Executive summary

SP1D3R is a well-engineered scanner (scope policy, request budget, baseline-aware
verification, marker-based confirmation, 74 passing unit tests), but its detection
engine is built around **HTML forms and query strings**. It performs well on classic
form-driven apps (DVWA) and misses almost everything on modern APIs (VAmPI).

**DVWA (low): 5/20 ground-truth vulns fully detected, 5 partial, 10 missed, 3 false positives.**
**VAmPI: 0/6 verified API vulns detected — the scan issued 0 attack requests against the API.**

Top weaknesses:

1. **No error-based SQLi probing** — the lone-quote `'` probe is deliberately excluded
   (`core/web_scanner.py:198-221`), so DVWA's critical SQLi is only reported as
   "Boolean response difference" (high/suspected) instead of critical/confirmed.
2. **Path parameters are never tested** — VAmPI's SQLi lives in `/users/v1/{username}`
   (verified: `name1' OR '1'='1' LIMIT 1 OFFSET 1--` → `name2`'s data). The scanner
   only tests query params and form fields, so it sent 0 SQLi requests.
3. **CSRF check only inspects POST forms** (`core/web_scanner.py:1824`) — DVWA's
   flagship CSRF (password change) is a **GET** form at low and was missed, while
   less interesting POST forms got flagged.
4. **API testing is passive-only** — route verification is GET/HEAD/OPTIONS
   (`core/web_scanner.py:864-902`); no JWT analysis, no BOLA, no JSON-body fuzzing,
   no method probing. VAmPI's hardcoded JWT secret (`"random"` — admin token forged
   in 5 lines) was invisible to the tool.
5. **Soft-404 false positives** — `config.php`, `info.php`, `sitemap.xml` were
   reported as exposed sensitive files although they don't exist; the PHP dev server
   serves the DVWA index (200) for missing files and the signatures (`'database'`,
   `'php version'`) matched that page. `.env`/`config.yml` checks guard against
   `text/html`, but the PHP-file checks don't.
6. **Missing modules entirely** (also missing from README claims): file upload,
   SSRF, DOM XSS, rate-limit/brute-force, session-ID/cookie analysis, authz/IDOR.

Full matrix and code references below.

---

## 2. DVWA (low) — results vs ground truth

Command: `python3 main.py --target http://127.0.0.1:8080/DVWA/ --active --all-tests
--module web --cookie "PHPSESSID=…; security=low" --output-format json --verbose`

Result: **32 findings** (0 critical / 9 high / 15 medium / 1 low), 675 requests,
47 pages crawled, 16 forms. Scan duration ~3 min.

| # | Ground truth (DVWA_BUG_BOUNTY_REPORT.md) | SP1D3R result | Verdict |
|---|---|---|---|
| 1 | OS Command Injection → RCE (critical) | **Confirmed** marker in `ip` (high, 2 requests) | ✅ Detected |
| 2 | SQLi UNION full dump (critical) | "Boolean response difference in id" — suspected | ⚠️ Partial (downgraded) |
| 3 | File upload → RCE (critical) | — | ❌ Missed (no module) |
| 4 | Blind SQLi boolean (high) | "Boolean response difference in id" — suspected | ⚠️ Partial |
| 5 | LFI `/etc/passwd` (high) | **Confirmed** `root:x:0:0:` ×4 (duplicates) | ✅ Detected (4 dup findings) |
| 6 | Authz bypass / IDOR (high) | — | ❌ Missed (no authz tests) |
| 7 | Stored XSS guestbook (high) | "Potential reflected XSS" in `txtName`/`mtxMessage` | ⚠️ Partial (detected, mislabeled) |
| 8 | CSRF password change (high) | — | ❌ Missed (GET form not checked) |
| 9 | Reflected XSS (medium) | "Potential reflected XSS in name" | ✅ Detected (suspected) |
| 10 | DOM XSS (medium) | — | ❌ Missed (no DOM analysis) |
| 11 | Open redirect (medium) | **Confirmed** canary in Location | ✅ Detected |
| 12 | Weak session IDs (medium) | — | ❌ Missed |
| 13 | Insecure CAPTCHA (medium) | — | ❌ Missed |
| 14 | Weak crypto XOR (medium) | — | ❌ Missed |
| 15 | Brute force (medium) | — | ❌ Missed |
| 16 | Session fixation / HttpOnly (low) | — | ❌ Missed (no cookie analysis) |
| 17 | CSP bypass (low) | "Potential reflected XSS in include" | ⚠️ Partial (detected as XSS reflection) |
| 18 | Client-side anti-bot token (low) | — | ❌ Missed |
| 19 | Full path disclosure (low) | — | ❌ Missed |
| 20 | Verbose DB errors (info) | — | ❌ Missed (500 query-echo not analyzed) |

**Bonus true positive** (not in the Burp ground truth): "Potential reflected XSS in
`id`" on `/vulnerabilities/sqli/` — verified real; the error page renders the raw SQL
query, so the payload executes.

**False positives (verified):**

- `Sensitive file exposed: config.php` (high) — file does not exist on disk.
- `Sensitive file exposed: info.php` (medium) — does not exist.
- `Publicly accessible sitemap.xml` (info) — does not exist.
  All three: the PHP dev server returns 200 + DVWA index for missing paths, and the
  signatures `'database'` / `'php version'` match the welcome page ("Setup check").

**Real lab-specific findings** (correct on this box): `.git/config` (DVWA was installed
by git clone), `phpinfo.php`, `php.ini` — all exist on disk.

**Note on the level-flip scare:** the scanner POSTs payloads into the `security.php`
settings form (12 requests; the `security` select is treated as a text input). On this
DVWA build the level is cookie-driven and the client ignores `Set-Cookie`, so the
scan itself stayed at low — but on a real app this pattern *can* mutate state. See W14.

---

## 3. VAmPI (API lab) — results vs ground truth

Commands:
- `main.py --target http://127.0.0.1:8081/ --active --all-tests --module web …`
- `main.py --active --all-tests --request-file seed_get.req …` (seed: `GET /users/v1/name1`)

Result: **3 findings both runs** (info path via dirsearch `/me`, missing X-Frame-Options,
HTTP protocol). 1 page crawled, 0 forms, **0 attack requests** for 7 of 10 attack classes.
Only 1 of 14 API routes discovered (`/` via JSON sniffing; `/me` via dirsearch).

| Verified ground truth | SP1D3R | Notes |
|---|---|---|
| SQLi in `/users/v1/{username}` (f-string SQL, `user_model.py:72`) | ❌ | Path params never fuzzed — 0 SQLi requests |
| JWT forgery — HS256 secret hardcoded `"random"` (`config.py`); forged admin token → `/me` 200 admin | ❌ | No JWT analysis module |
| Excessive data exposure — `/users/v1/_debug` leaks usernames+passwords | ❌ | Route never discovered |
| Authz confusion — `update_email` ignores `{username}` path, trusts token `sub` | ❌ | No authz tests |
| Regex DoS — catastrophic email regex in `update_email` | ❌ | No DoS checks |
| No rate limiting on `/users/v1/login` | ❌ | No rate-limit tests |
| Other routes (`/users/v1`, `/books/v1`, `/createdb`, …) | ❌ | Never discovered |

The request-file seed did **not** help: `/users/v1/name1` was registered as a JSON
endpoint, but with no query params and no forms, every attack class ran 0 probes.

---

## 4. Weaknesses (code-referenced)

### W1 — Error-based SQLi is structurally impossible
`core/web_scanner.py:198-221` filters probes to those containing `--`, `#`, or `/*` —
the lone quote `'` (the single most reliable error trigger) is never sent, and only the
first 3 comment payloads are used for error detection (`:1110`). On DVWA low, `1'-- -`,
`' OR '1'='1'-- -`, `' AND '1'='2'-- -` are all *valid* SQL → no error → detection
falls back to boolean diff ("suspected", high). `id=1'` is the classic probe and
returns a 500 (or a MySQL error on other stacks) — never tested.
Also: no time-based blind SQLi at all (README claims it).

### W2 — Path parameters are untested
`_test_sqli_on_query` / `_test_xss_on_query` iterate `parse_qs(parsed.query)` only
(`:1061-1064`, `:1163`). REST resources like `/users/v1/{username}` or `/books/v1/{book_title}`
are never fuzzed. This is the single biggest reason VAmPI scored 0.

### W3 — XSS: one payload, no DOM, no stored classification
`_test_xss_on_query`/`_test_xss_on_input` send exactly `<script>alert('XSS')</script>`
(`:1278`, `:1322`). No attribute/JS-context polyglots, no encoding bypasses, no DOM-sink
analysis (DVWA DOM XSS missed), no stored-XSS persistence check (guestbook stored XSS is
reported as "reflected", because the POST response happens to render the new comment).

### W4 — CSRF check ignores GET forms and trusts field names
`:1823-1824` only inspects `form['method'] == 'post'`. DVWA low password-change is a
GET form → the flagship CSRF was missed while 6 POST forms were flagged. The token
heuristic (`'csrf'`/`'token'` substring in the field name, `:1834-1837`) can also miss
unconventionally named tokens and mis-credit non-CSRF fields.

### W5 — API module is read-only and passive
`_test_api_surface` (`:864-902`) only GETs discovered endpoints (filtered to
GET/HEAD/OPTIONS) and checks for JSON. No method probing (POST/PUT/DELETE on routes),
no JWT decode/alg=none/weak-secret checks, no BOLA two-identity comparison, no
mass-assignment, no rate-limit check. `attack_surface.py` *recommends* these reviews
in the report — but nothing executes them. VAmPI's entire vuln surface fell through.

### W6 — API discovery needs OpenAPI docs or JS bundles
`_discover_api_documentation` (`:814-862`) only probes 8 doc paths; route discovery
otherwise relies on crawled links/JS. A pure JSON API with no HTML (VAmPI) yields
1 crawled page and 1 discovered route. No API-route wordlist, no POSTMAN-style
spec import, no guessing of `/v1` siblings.

### W7 — Sensitive-file false positives on soft-404 pages
`_check_common_files` (`:1727-1811`) follows redirects (no `allow_redirects=False`)
and guards `.env`/`config.yml`/`settings.py` against `text/html` (`:1782`, `:1785`,
`:1788`) but **not** `config.php`, `wp-config.php`, `web.config`, `.htaccess`,
`phpinfo.php`, `info.php` (`:1789-1790`). `robots.txt`/`sitemap.xml` have no content
check at all. Result: 3 false positives on DVWA (see §2).

### W8 — Duplicate findings
The same `page` parameter on `/vulnerabilities/fi/` produced 4 separate LFI findings
(one per crawled URL value: `include.php`, `file1.php`, …). Dedup keys on location,
not on (type, parameter, endpoint). SQLi/XSS emit one finding per candidate but
re-running the same scan also re-emits everything (no cross-run dedup).

### W9 — Missing modules vs README claims
README advertises SSRF detection, DOM-based XSS, time-based SQLi, and file-inclusion
RFI — none exist in the code. Missing entirely: file upload (DVWA upload→RCE missed),
SSRF, brute-force/rate-limit, session-ID/cookie analysis, IDOR/authz, CAPTCHA,
weak-crypto checks. Either implement or trim the README.

### W10 — Early `return` aborts whole checks
`_test_open_redirect` (`:1709-1711`) and `_check_common_files` (`:1766-1767`) do
`return` when a single response is `None` (e.g., budget exhaustion) — the remaining
candidates are silently skipped instead of continuing.

### W11 — Sequential probing ignores `threads`
`config: scanning.threads=50` is never used by `WebScanner`; every probe is awaited
sequentially (SQLi phase alone: 150 requests). On localhost fine, on real targets slow.

### W12 — Time-based detection absent
No SLEEP/WAITFOR payloads, no response-time differential — blind SQLi where the app
renders identical pages (DVWA high, real-world) would be missed.

### W13 — No state-change awareness for settings/admin forms
The scanner treats every discovered form identically: `security.php` (the DVWA
settings form) received 12 payload POSTs during SQLi/XSS/SSTI phases, using the
captured CSRF token which this app keeps valid across posts. On this DVWA the level
is cookie-driven so the scan stayed at low — on an app that stores the setting
server-side, a scan can silently change configuration. The exclusion list
(`/logout*`, `/delete*`, `/remove*`, `/checkout*`, `/payment*`, `/password/reset*`)
doesn't cover settings/config/admin forms. Suggest: never active-test forms whose
fields look like `security`/`config`/`role`, or add a `--safe-forms` default.

### W14 — Cookie flags / session analysis absent
No checks for `HttpOnly`/`Secure`/`SameSite`, no session-ID entropy test — DVWA's
weak session IDs (ground-truth #12/#16) were missed.

---

## 5. Strengths (keep these)

- **Scope enforcement** (`core/scope.py`) — host/CIDR/wildcard/path rules, loopback
  handling, logout-style exclusions. Solid.
- **Shared request budget + rate limiting** (`_reserve_request`, `:252-271`) with
  crawl/attack split — bounded and pace-able.
- **Baseline-aware verification** (`core/verification_engine.py`) — SSTI check sent
  110 requests with 0 false positives because it requires the computed value absent
  from baseline; command injection required marker-absent-from-baseline; confirmed
  DVWA command injection with just 2 requests.
- **Marker anchoring for LFI** (`^root:x:0:0:` line-anchored, hosts-file structure)
  — avoids trivial FPs.
- **Auth-gate detection** — skips attack tests when the crawl sees a login page
  unless a request file/seed is supplied.
- **Request-file (Burp) seeding** with hop-by-hop header filtering.
- **Report quality** — severity dashboard, evidence, per-check coverage table.
- **74/74 unit tests passing.**

---

## 6. Proposed modifications (priority order)

### P0 — detection wins (lab-proven)
1. **SQLi**: add lone-quote error probe + status-delta signal (200→500 with query
   echo = error-based); add time-based probes behind `--test-sqli`; optionally UNION
   column enumeration for confirmed error-based points.
2. **Path-param fuzzing**: derive candidates from URL path segments
   (`/users/v1/{segment}`), replay with SQLi/XSS/traversal payloads.
3. **CSRF**: include GET forms; re-fetch fresh tokens between probes (avoids the
   W13 token-reuse hazard); add settings/config form exclusion.
4. **Sensitive files**: apply the `text/html` guard to *all* file checks; require
   signature for robots/sitemap; `allow_redirects=False`.
5. **XSS**: payload matrix (attr/JS contexts), DOM-sink scan (document.write,
   innerHTML, location.hash), stored-XSS re-fetch after POST.
6. **API module**: JWT decode/alg=none/weak-secret wordlist, BOLA two-token mode,
   method probing on discovered routes, JSON-body fuzzing.

### P1 — robustness & docs
7. Fix W10 early returns; dedup findings by (type, parameter, endpoint); use
   `threads` for probe concurrency.
8. Sync README with implemented checks (or implement SSRF/file-upload/rate-limit).
9. Add regression tests for each new check (existing suite must stay green).

### P2 — attribution (requested)
10. Contributor list → **Nyi-001 + Claude Code only**: drop
    `NEXUSCIPHERGUARD INDIA` from `main.py`, `IMPLEMENTATION_SUMMARY.md`,
    `COMPLETION_REPORT.md`, `FUNCTIONALITY_STATUS.md`; add a Contributors section
    naming Nyi-001 and Claude Code.

---

## 7. Lab notes (reproducibility)

- **DVWA**: pre-installed at `/var/www/html/DVWA` (git clone, MariaDB
  `dvwa:p@ssw0rd`). Served via `php -S 127.0.0.1:8080 -t /var/www/html` (Apache needs
  root). Session cookie + `security=low` cookie required — DVWA's level is
  **cookie-driven** on this build, so every request must carry `Cookie: security=low`
  or it silently runs at `impossible`.
- **VAmPI**: `git clone https://github.com/erev0s/VAmPI /tmp/VAmPI`, venv with
  `flask`, `flask-sqlalchemy`, `sqlalchemy>=2.0.36`, `jsonschema`, `PyJWT`.
  Python 3.14 + connexion 2.14 is broken, so `run.py` (in this repo's lab notes)
  re-registers the spec routes on plain Flask. Run: `venv/bin/python run.py`
  (port 8081), then `GET /createdb` to seed.
- Soft-404 behavior of `php -S` on this box (missing paths under `/DVWA/` return
  200 + index) is what produced the §2 false positives — a good SPA-soft-404
  simulation, keep it in mind when testing W7 fixes.

---

## 8. Fixes applied (2026-10-18)

Implemented in `core/web_scanner.py` (plus tests, README, and attribution):

| Weakness | Fix | Evidence (DVWA low re-run) |
|---|---|---|
| W1 no error-based SQLi | `_run_sqli_probes` shared engine: lone-quote probe prepended; HTTP status-delta (baseline <500 → probe ≥500) as confirmed-critical evidence; time-based SLEEP probe as fallback | `SQL injection verified in id` — **critical/confirmed** (was high/suspected) |
| W1/W12 | Time-based blind SQLi (`SLEEP(3)`, 2.5s threshold vs baseline) | unit test |
| W2 path params untested | `_path_param_candidates` + `_test_sqli_on_path`/`_test_xss_on_path`; payloads appended to the original segment so they still route (concat mode); boolean diff disabled on paths (404 noise) | VAmPI: see §9 |
| W3 single XSS payload | `XSS_PAYLOAD_MATRIX` (4 payloads), stored-XSS classification via post-then-GET persistence check | `Stored XSS in txtName/mtxMessage` — high (was "reflected") |
| W4 CSRF POST-only | GET forms with state-changing fields also checked | `Missing CSRF protection` on `/vulnerabilities/csrf/` — the flagship GET-form CSRF |
| W7 soft-404 FPs | Root-page body comparison (soft-404 reference), `allow_redirects=False`, robots/sitemap now require real directive/XML content | `config.php`, `info.php`, `sitemap.xml` FPs **gone**; `.git/config` + `phpinfo.php` (real files) still reported |
| W8 duplicate findings | `_already_reported` dedup by (type, parameter, endpoint path) in LFI/traversal checks | 4× LFI deduped to 1 |
| W10 early returns | `continue` instead of `return` in open-redirect and sensitive-file loops | code review |
| W13 settings forms fuzzed | Settings/config forms (`security.php`, `setup.php`, token/csrf/role fields, `/settings*` paths) excluded from active testing; token-bearing forms re-fetched once before probing | 0 payload POSTs to `security.php`/`setup.php` (was 12+6); forms logged in coverage `skipped_forms` |
| Attribution | Author Nyi-001 + Claude Code contributors; NEXUSCIPHERGUARD INDIA removed | main.py, IMPLEMENTATION_SUMMARY.md, COMPLETION_REPORT.md, FUNCTIONALITY_STATUS.md, CONTRIBUTING.md |
| Banner | Correct ANSI-shadow "SP1D3R" wordmark (the old one misdrew the 1 as I) | utils/logger.py, README.md |
| README sync | Web-scanner capability list rewritten to match implemented checks; SSRF/file-upload/DOM-XSS moved to Roadmap | README.md |

Test suite: **81 passing** (was 74) — new coverage for the probe plan, status-delta
(including the 404-not-an-error rule), time-based detection, path candidates,
settings-form exclusion, CSRF-on-GET, and finding dedup.

## 9. VAmPI re-validation (seeded `--request-file` run)

**Result: path-parameter SQLi now detected.**

```
CRITICAL | SQL Injection | SQL injection verified in path:name1 | /users/v1/name1
state: confirmed | confidence: high
evidence: HTTP status delta: 200 (baseline) -> 500 ("'" probe)
payload: '
```

7 SQLi requests total. The appended lone quote (`name1'`) reaches the Flask
handler, crashes the f-string SQL query, and the 200→500 delta is recorded as
confirmed-critical. dirsearch also surfaced `/users/v1/admin` this run.

Still out of scope for this iteration (Roadmap): JWT analysis, BOLA/two-identity
testing, mass assignment, regex-DoS and rate-limit checks, route discovery via
API wordlists — the `_debug` credential leak and the hardcoded JWT secret remain
invisible to the scanner unless the operator reads the route inventory.

