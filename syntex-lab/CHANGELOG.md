# Changelog — Syntex Lab

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [4.1.0] — 2025-06-23

### Added
- **12 new vulnerability modules** from OWASP and real-world bug bounty checklist:
  - Server-Side Template Injection (SSTI) via EJS at `/template-preview`
  - Host Header Injection / Password Reset Poisoning at `/forgot-password-v2`
  - CRLF / Header Injection at `/redirect-v2`
  - Email Header Injection (BCC spam relay) at `/newsletter`
  - Log Injection at `/api/v1/log-event`
  - Session Fixation at `/login-v2`
  - Clickjacking (missing X-Frame-Options) at `/iframe-test`
  - 2FA Bypass via OTP brute force at `/2fa`
  - XXE — XML External Entity file read at `/xml-upload`
  - Mass Assignment — role escalation via API at `/api/v1/profile-update`
  - Prototype Pollution via deep merge at `/api/v1/merge`
  - Zip Slip — archive path traversal at `/zip-upload`
- `fast-xml-parser` dependency for XXE simulation
- `FLAG_SSTI` environment variable planted for SSTI discovery
- 12 new flags seeded via `seedExtraFlags()`
- 12 new progressive hint sets under `/program/hints`
- New endpoint entries added to `wordlist.txt`
- `SOLUTIONS.md` — 15 full exploitation walkthroughs
- `.env.example` — Template with all environment variables
- `TROUBLESHOOTING.md` — Common setup issues and fixes
- `CONTRIBUTING.md` — Contribution guidelines
- `.editorconfig` — Code style consistency config

### Fixed
- **Dockerfile** — replaced `npm ci` (requires lockfile) with `npm install --omit=dev`
- **docker-compose.yml** — removed obsolete `version: '3.8'` attribute
- **Upload route** — remounted at `/upload` (was at `/`, causing 404 on File Manager page)
- **Download link** — updated from `/download?file=` to `/upload/download?file=`

---

## [4.0.0] — 2025-06-19

### Added
- **Dual-site architecture**: `syntex.local` (target) + `program.syntex.local` (platform)
- **Separate program platform** at `/program` with full HackerOne/Bugcrowd-style UI
- **Flag verification system**: submit FLAG{...} with report → instant auto-acceptance
- **First Blood system**: first researcher to find each bug earns +50% bonus points
- **`researcher_stats` table**: tracks total points, valid/invalid reports, first bloods per user
- **`first_blood_claims` table**: one first blood per vulnerability globally
- **37 unique flags** covering all vulnerability categories
- **30-entry progressive hint system** under `/program/hints` with 3 levels per vuln
- **5 vulnerability chain missions** under `/program/challenges`
- **Program platform UI**: scope, rules, submit, reports, flags, leaderboard, hall of fame
- **4 example reports**: accepted, duplicate, informative, not-applicable
- **GraphQL module**: introspection, IDOR, over-fetching, broken auth mutations at `/graphql`
- **WebSocket module**: support chat at `/ws/chat` — no auth, room IDOR, stored XSS
- **OAuth/SSO module**: missing state, open redirect, account takeover at `/oauth`
- **Race condition module**: wallet, reward claim, coupon at `/race`
- **Enhanced recon targets**: swagger.json, openapi.json, source maps, OIDC config, actuator
- **dnsmasq DNS server** in Docker for gobuster/ffuf subdomain discovery
- **27 nginx vhosts** including dead subdomains for recon practice
- **LAB_MODE system**: beginner / intermediate / hard / realistic
- **`blockBountyOnMainSite` middleware**: returns 404 for bounty paths on main site
- **`database/reset.js`**: clears all user-generated data, re-seeds to factory state

### Changed
- Main website navbar cleaned — all bug bounty links removed
- All bounty features moved exclusively to `/program/*` routes
- Reports redirected: old `/reports/*` → `/program/*`
- Old hints redirect loops removed — hints served directly at `/program/hints`
- `seed.js` — removed duplicate `seedFlags()`, single source `seedAllFlags()`

### Fixed
- **init.sql**: replaced invalid `ALTER TABLE ... ADD CONSTRAINT IF NOT EXISTS` with `CREATE UNIQUE INDEX IF NOT EXISTS`
- **Admin EJS includes**: fixed `partials/navbar` → `../partials/navbar` in all 5 admin views
- **Route ordering**: `/program/admin/reports` defined before `:id` param catch-all
- **SQL query**: fixed `WHERE id=$1` duplicate param bug in flag validation
- **Docker ports**: all bound to `127.0.0.1` only

---

## [3.1.0] — 2025-06-10

### Added
- **Flag-based report verification**: paste FLAG{...} on submit for instant auto-accept
- **`vuln_flags` table** with per-vulnerability flags, points, difficulty, endpoints
- **`user_flags` table** tracking which flags each user has captured
- **Flag Hunt page** at `/reports/flags` showing captured vs uncaptured flags
- **15 flags** seeded covering SQLi, XSS, IDOR, auth bypass, SSRF, exposure categories
- Flags planted at exact proof points: `secret_note`, `notes`, `debug` endpoint, `.env`
- `flag_verified`, `flag_submitted`, `verified_at` columns added to `reports` table

---

## [3.0.0] — 2025-06-05

### Added
- **Bug bounty program page** at `/bug-bounty` (HackerOne/Bugcrowd-style)
- **Report submission system** at `/reports/new` with full triage workflow
- **Report statuses**: New, Needs More Info, Accepted, Duplicate, Informative, N/A, Resolved
- **Admin triage dashboard** at `/admin/reports`
- **Hall of Fame** with 8 seeded researchers
- **8 example triaged reports** with realistic bounty amounts
- **3-level hint system** at `/hints/:slug`
- **5 vulnerability chain missions** at `/challenges`
- **Scope page**, **rules of engagement**, severity guide P1–P5
- `researcher_stats` tracking per-user report counts and bounties

### Fixed
- Removed `child_process` npm dependency (built-in module)
- Docker ports bound to `127.0.0.1` only
- Nginx `proxy_pass` trailing slash fixes for subdomain routing
- Ghost brace-expansion directories removed from backend structure

---

## [2.4.1] — 2025-05-20

### Added
- Initial public release of Syntex Lab
- 57 vulnerabilities across SQLi, XSS, IDOR, SSRF, file upload, command injection, CORS, JWT, OAuth, race conditions, GraphQL, WebSocket
- Docker Compose setup with PostgreSQL + Nginx
- 7 seeded user accounts with realistic business data
- Custom wordlist for subdomain discovery
- README with quick start, /etc/hosts setup, default accounts table

---

*Dates reflect lab development milestones, not calendar release dates.*
