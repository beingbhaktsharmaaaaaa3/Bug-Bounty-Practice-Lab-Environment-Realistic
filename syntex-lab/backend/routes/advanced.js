'use strict';

// ── Advanced Vulnerabilities Module ──────────────────────────────
// NEW vulns (does not modify any existing route):
//   1. Server-Side Template Injection (SSTI) — /template-preview
//   2. Host Header Injection — /forgot-password-v2
//   3. CRLF / Header Injection — /redirect-v2
//   4. Email Header Injection — /newsletter
//   5. Log Injection — /api/v1/log-event
//   6. Session Fixation — /session-fix-login
//   7. Clickjacking — missing X-Frame-Options on /iframe-test
//   8. 2FA bypass — /2fa

const express   = require('express');
const router    = express.Router();
const db        = require('../database/db');
const crypto    = require('crypto');
const path      = require('path');
const { requireAuth } = require('../middleware/auth');

// ─────────────────────────────────────────────────────────────────
// 1. SSTI — Server-Side Template Injection
//    Endpoint: GET/POST /template-preview
//    Vulnerability: user-supplied template string executed by EJS
//    Payload: <%= 7*7 %>  or  <%= process.env.DB_PASS %>
//    Flag planted: in template output when process.env.FLAG_SSTI accessed
// ─────────────────────────────────────────────────────────────────
const ejs = require('ejs');

router.get('/template-preview', requireAuth, (req, res) => {
    res.render('vulns/ssti', {
        title:    'Email Template Preview — Syntex Solutions',
        output:   null,
        template: '',
        error:    null,
        user:     req.session.user,
    });
});

router.post('/template-preview', requireAuth, async (req, res) => {
    const { template } = req.body;

    let output = null;
    let error  = null;

    try {
        // VULNERABILITY: User-supplied string rendered directly by EJS
        // ejs.render() executes arbitrary JavaScript in the template
        // Payloads:
        //   <%= 7*7 %>                           → 49
        //   <%= process.env.DB_PASS %>           → Synx@2024!Prod
        //   <%= process.env.FLAG_SSTI %>         → FLAG{...}
        //   <% global.process.mainModule.require('child_process').execSync('id') %>
        output = ejs.render(template, {
            user:    req.session.user,
            company: 'Syntex Solutions',
            year:    new Date().getFullYear(),
            // Intentionally expose env for SSTI discovery
            env:     process.env,
            // Flag planted here — accessible via <%= env.FLAG_SSTI %> or <%= process.env.FLAG_SSTI %>
        });

        // Log for demo purposes
        await db.query(
            `INSERT INTO audit_logs (user_id, action, details) VALUES ($1, 'template_preview', $2)`,
            [req.session.userId, `Template rendered: ${template.slice(0, 100)}`]
        ).catch(() => {});

    } catch (err) {
        error = err.message;
    }

    res.render('vulns/ssti', {
        title:    'Email Template Preview — Syntex Solutions',
        output,
        template,
        error,
        user:     req.session.user,
    });
});

// ─────────────────────────────────────────────────────────────────
// 2. Host Header Injection — Password Reset Poisoning
//    Endpoint: POST /forgot-password-v2
//    Vulnerability: reset link uses Host header instead of configured domain
//    Attack: Set Host: attacker.com → reset email contains attacker URL
//    Payload: curl -X POST /forgot-password-v2 -H "Host: attacker.com" -d "email=admin@syntex.local"
//    Flag: in the "email" body returned in dev mode
// ─────────────────────────────────────────────────────────────────
router.get('/forgot-password-v2', (req, res) => {
    res.render('vulns/host-header', {
        title:   'Password Reset — Syntex Solutions',
        sent:    false,
        resetLink: null,
        user:    req.session.user || null,
    });
});

router.post('/forgot-password-v2', async (req, res) => {
    const { email } = req.body;

    // VULNERABILITY: Host header trusted directly — never use req.headers.host for security-critical URLs
    // Attacker sets: Host: evil.com → victim receives: http://evil.com/reset?token=...
    const host  = req.headers.host || req.headers['x-forwarded-host'] || 'syntex.local';
    const token = crypto.randomBytes(20).toString('hex');

    // Reset link built from attacker-controlled Host header
    const resetLink = `http://${host}/reset-password?token=${token}&email=${encodeURIComponent(email || '')}`;

    try {
        await db.query(
            `INSERT INTO password_resets (email, token, expires_at)
             VALUES ($1, $2, NOW() + INTERVAL '1 hour')
             ON CONFLICT (email) DO UPDATE SET token=$2, expires_at=NOW() + INTERVAL '1 hour'`,
            [email, token]
        ).catch(() => {});
    } catch (_) {}

    // Dev mode: return the link in response (shows the poisoned URL)
    res.render('vulns/host-header', {
        title:    'Password Reset — Syntex Solutions',
        sent:     true,
        // VULNERABILITY: Shows reset link containing attacker-controlled host
        // In a real app this would be emailed — flag visible in link when Host is poisoned
        resetLink,
        flag:     host !== 'syntex.local' && host !== 'localhost:3000' && host !== 'localhost'
                    ? `FLAG{HOST_HEADER_INJECT_PASSWORD_RESET_POISONED}` : null,
        user:     req.session.user || null,
    });
});

// ─────────────────────────────────────────────────────────────────
// 3. CRLF / Header Injection
//    Endpoint: GET /redirect-v2?url=
//    Vulnerability: url param placed directly in Location header
//    Payload: /redirect-v2?url=http://evil.com%0d%0aSet-Cookie:%20admin=true
//    Flag: returned in response when CRLF detected
// ─────────────────────────────────────────────────────────────────
router.get('/redirect-v2', (req, res) => {
    const { url } = req.query;

    if (!url) {
        return res.render('vulns/crlf', {
            title: 'Link Forwarder — Syntex Solutions',
            url:   null,
            user:  req.session.user || null,
        });
    }

    // VULNERABILITY: Raw url value placed in Location header
    // CRLF (%0d%0a) allows injecting additional headers
    // Payload: ?url=http://evil.com%0d%0aX-Injected:%20pwned%0d%0aSet-Cookie:%20role=admin
    const hasCRLF = url.includes('\r') || url.includes('\n') || url.includes('%0d') || url.includes('%0a');

    if (hasCRLF) {
        // Demonstrate the injection — in a real app this would split the response
        res.setHeader('X-CRLF-Detected', 'true');
        return res.status(200).json({
            message:  'CRLF characters detected in redirect parameter',
            flag:     'FLAG{CRLF_HEADER_INJECT_RESPONSE_SPLIT_CONFIRMED}',
            injected: url,
            note:     'In an unpatched server, this would split the HTTP response and inject arbitrary headers.',
        });
    }

    // VULNERABILITY: Unvalidated open redirect (no allowlist)
    res.setHeader('Location', url);
    res.status(302).send('Redirecting...');
});

// ─────────────────────────────────────────────────────────────────
// 4. Email Header Injection
//    Endpoint: POST /newsletter
//    Vulnerability: name field injected into email To: header
//    Payload: name = "victim@x.com\nBCC: attacker@evil.com"
//    Flag: returned when injection detected
// ─────────────────────────────────────────────────────────────────
router.get('/newsletter', (req, res) => {
    res.render('vulns/email-header', {
        title:  'Newsletter Signup — Syntex Solutions',
        result: null,
        user:   req.session.user || null,
    });
});

router.post('/newsletter', async (req, res) => {
    const { name, email } = req.body;

    // VULNERABILITY: User-supplied name injected into simulated email header
    // Attacker input: name = "Attacker\nBCC: spam@evil.com\nCC: another@evil.com"
    // This injects additional email headers, enabling spam relay / phishing

    const hasInjection = (name || '').match(/(\r|\n|%0d|%0a|bcc:|cc:|to:|from:|subject:)/i) ||
                         (email || '').match(/(\r|\n|%0d|%0a|bcc:|cc:)/i);

    // Simulate building the email header (vulnerable pattern)
    const simulatedHeader = [
        `To: ${email}`,
        `Subject: Welcome to Syntex Newsletter`,
        `From: noreply@syntex.local`,
        // VULNERABILITY: name placed directly into header without sanitisation
        `X-Mailer-Tag: ${name}`,
    ].join('\n');

    res.render('vulns/email-header', {
        title:           'Newsletter Signup — Syntex Solutions',
        result:          hasInjection ? 'injection_detected' : 'subscribed',
        flag:            hasInjection ? 'FLAG{EMAIL_HEADER_INJECT_BCC_SPAM_RELAY}' : null,
        simulatedHeader,
        name, email,
        user:            req.session.user || null,
    });
});

// ─────────────────────────────────────────────────────────────────
// 5. Log Injection
//    Endpoint: POST /api/v1/log-event
//    Vulnerability: user-supplied event logged without sanitisation
//    Payload: {"event": "login\n[FAKE] admin:admin123 logged in as SUPERADMIN"}
//    Flag: returned in log output when newline detected
// ─────────────────────────────────────────────────────────────────
router.post('/api/v1/log-event', requireAuth, async (req, res) => {
    const { event, level } = req.body;

    if (!event) return res.status(400).json({ error: 'event required' });

    // VULNERABILITY: User input written directly to log without stripping newlines
    // Attacker injects fake log entries to cover tracks or mislead analysts
    const timestamp  = new Date().toISOString();
    const user       = req.session.user?.username || 'unknown';

    // Simulate log line (vulnerable: contains raw user input)
    const logLine = `[${timestamp}] [${level || 'INFO'}] user=${user} event=${event}`;

    const hasInjection = event.includes('\n') || event.includes('\r') ||
                         event.includes('%0a') || event.includes('%0d');

    // Store in audit log
    await db.query(
        `INSERT INTO audit_logs (user_id, action, details) VALUES ($1, 'custom_event', $2)`,
        [req.session.userId, logLine]
    ).catch(() => {});

    res.json({
        logged:   true,
        log_line: logLine,
        flag:     hasInjection ? 'FLAG{LOG_INJECTION_FAKE_ENTRIES_FORGED}' : undefined,
        note:     hasInjection
            ? 'Newline characters allow injecting fake log entries. SIEM/monitoring tools may be deceived.'
            : 'Event logged.',
    });
});

// ─────────────────────────────────────────────────────────────────
// 6. Session Fixation
//    Vulnerability: session ID not rotated after login
//    Attack: attacker pre-sets SYNTEX_SESS cookie, victim logs in with same ID
//    Endpoint: POST /login-v2 (alternative login demonstrating session fixation)
// ─────────────────────────────────────────────────────────────────
router.get('/login-v2', (req, res) => {
    // Show current session ID — attacker can set this before victim logs in
    res.render('vulns/session-fixation', {
        title:     'Login (Session Fixation Demo) — Syntex Solutions',
        sessionId: req.sessionID,
        loggedIn:  !!req.session.userId,
        user:      req.session.user || null,
        flag:      null,
    });
});

router.post('/login-v2', async (req, res) => {
    const { username, password } = req.body;
    const crypto = require('crypto');
    const hash   = crypto.createHash('md5').update(password || '').digest('hex');

    const result = await db.query(
        `SELECT * FROM users WHERE username=$1 AND password_hash=$2`,
        [username, hash]
    );

    if (!result.rows.length) {
        return res.render('vulns/session-fixation', {
            title:     'Login (Session Fixation Demo)',
            sessionId: req.sessionID,
            loggedIn:  false,
            user:      null,
            flag:      null,
            error:     'Invalid credentials',
        });
    }

    const user = result.rows[0];
    const oldSessionId = req.sessionID;

    // VULNERABILITY: Session ID NOT regenerated after login
    // Fix would be: req.session.regenerate(() => { ... })
    // Here we intentionally skip regeneration so a pre-set session ID is preserved
    req.session.userId   = user.id;
    req.session.username = user.username;
    req.session.role     = user.role;
    req.session.user     = user;

    res.render('vulns/session-fixation', {
        title:        'Login (Session Fixation Demo)',
        sessionId:    req.sessionID,
        oldSessionId,
        loggedIn:     true,
        sameSession:  req.sessionID === oldSessionId,
        // Flag revealed when session ID matches the pre-login ID (demonstrating fixation)
        flag:         req.sessionID === oldSessionId
                        ? 'FLAG{SESSION_FIXATION_ID_NOT_ROTATED_ON_LOGIN}'
                        : null,
        user,
    });
});

// ─────────────────────────────────────────────────────────────────
// 7. Clickjacking — missing X-Frame-Options
//    Endpoint: GET /iframe-test
//    Vulnerability: page can be embedded in an iframe on any domain
//    PoC: <iframe src="http://syntex.local/iframe-test"></iframe>
// ─────────────────────────────────────────────────────────────────
router.get('/iframe-test', requireAuth, (req, res) => {
    // VULNERABILITY: No X-Frame-Options or frame-ancestors CSP
    // Any attacker page can iframe this and trick users into clicking
    // Flag planted in page source comment
    res.type('html').send(`<!DOCTYPE html>
<html>
<head><title>Account Settings — Syntex Solutions</title>
<link rel="stylesheet" href="/css/style.css">
<!-- FLAG{CLICKJACKING_NO_XFRAME_OPTIONS_SET} -->
</head>
<body style="padding:20px;">
<h2>Delete Account</h2>
<p>This page has no X-Frame-Options or Content-Security-Policy: frame-ancestors header.</p>
<p>It can be embedded in an iframe on any domain, enabling clickjacking attacks.</p>
<form action="/profile/${req.session.userId}/edit" method="POST">
  <input type="hidden" name="bio" value="[CLICKJACKED]">
  <button type="submit" class="btn btn-danger">Confirm Delete Account</button>
</form>
<p style="font-size:12px;color:#666;margin-top:20px;">
PoC: &lt;iframe src="http://syntex.local/iframe-test" style="opacity:0;position:absolute;top:0;left:0;width:100%;height:100%;"&gt;&lt;/iframe&gt;
</p>
</body></html>`);
});

// ─────────────────────────────────────────────────────────────────
// 8. 2FA Bypass — OTP brute force, no rate limit, long expiry
//    Endpoint: GET/POST /2fa
//    Vulnerability: 6-digit OTP, no lockout, 1-hour expiry → brute forceable
// ─────────────────────────────────────────────────────────────────
const otpStore = {}; // in-memory: userId → { otp, expires, attempts }

router.get('/2fa', requireAuth, (req, res) => {
    const uid    = req.session.userId;
    const otp    = Math.floor(100000 + Math.random() * 900000).toString();
    otpStore[uid] = { otp, expires: Date.now() + 3600000, attempts: 0 }; // 1 hour, no attempt limit

    res.render('vulns/2fa', {
        title:  '2FA Verification — Syntex Solutions',
        otp_hint: process.env.LAB_MODE === 'beginner' ? otp : null,
        result: null,
        user:   req.session.user,
    });
});

router.post('/2fa', requireAuth, (req, res) => {
    const uid     = req.session.userId;
    const { otp } = req.body;
    const entry   = otpStore[uid];

    if (!entry) {
        return res.render('vulns/2fa', {
            title: '2FA Verification', otp_hint: null,
            result: 'expired', user: req.session.user,
        });
    }

    // VULNERABILITY: No attempt limit — brute force all 1,000,000 combinations
    entry.attempts++;

    // VULNERABILITY: OTP expires after 1 hour (should be 5 minutes)
    if (Date.now() > entry.expires) {
        return res.render('vulns/2fa', {
            title: '2FA Verification', otp_hint: null,
            result: 'expired', user: req.session.user,
        });
    }

    if (otp === entry.otp) {
        delete otpStore[uid];
        return res.render('vulns/2fa', {
            title:    '2FA Verification', otp_hint: null,
            result:   'success',
            flag:     'FLAG{2FA_OTP_BRUTE_FORCEABLE_NO_LOCKOUT}',
            attempts: entry.attempts,
            user:     req.session.user,
        });
    }

    res.render('vulns/2fa', {
        title:    '2FA Verification',
        otp_hint: null,
        result:   'invalid',
        attempts: entry.attempts,
        // VULNERABILITY: Leaks attempt count — helps attacker confirm progress
        user:     req.session.user,
    });
});

module.exports = router;
