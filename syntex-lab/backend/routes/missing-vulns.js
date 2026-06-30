'use strict';

// ── v4.3 — Missing Vulnerability Categories ───────────────────────
// 1. Cache Deception          /cache-deception/*  (easy, medium)
// 2. HTTP Request Smuggling   /smuggling          (medium, hard)
// 3. Secondary Context Vulns  /pdf-export, /image-resize (medium, hard)
// 4. Client-Side Template Inj /csti                (easy, medium)
// 5. PostMessage Issues       /postmessage-demo    (easy, medium, hard)
// 6. Weak Password Checks     /register-weak       (easy, medium, hard)

const express = require('express');
const router  = express.Router();
const crypto  = require('crypto');
const db      = require('../database/db');
const { requireAuth } = require('../middleware/auth');

// =================================================================
// 1. CACHE DECEPTION
//    Different from cache poisoning — attacker tricks the cache into
//    storing a PRIVATE page under a PUBLIC-looking cacheable URL.
// =================================================================

// EASY — static extension trick: /profile/me.css gets cached as if static
router.get('/profile/me.css', requireAuth, (req, res) => {
    // VULNERABILITY (EASY): CDN/cache treats *.css as static and caches it,
    // but Express still serves the dynamic profile data underneath.
    res.setHeader('Content-Type', 'text/css');
    res.setHeader('Cache-Control', 'public, max-age=3600'); // VULN: cached publicly
    res.send(`/* Syntex Profile Stylesheet */
/*
  username: ${req.session.user.username}
  email: ${req.session.user.email}
  api_key: ${req.session.user.api_key || 'sk_user_' + req.session.userId}
  FLAG{CACHE_DECEPTION_STATIC_EXT_PRIVATE_DATA}
*/
.profile { display:block; }`);
});

// MEDIUM — path confusion: /account/settings/nonexistent.js
router.get('/account/settings/:fakeStatic', requireAuth, (req, res) => {
    const { fakeStatic } = req.params;
    const looksStatic = /\.(js|css|jpg|png|woff|ico)$/.test(fakeStatic);

    if (looksStatic) {
        // VULNERABILITY (MEDIUM): CDN caches this thinking it's a static asset
        // because of the extension, but the path is actually dynamic and
        // returns the logged-in user's private settings data.
        res.setHeader('Cache-Control', 'public, max-age=86400');
        return res.json({
            warning: 'This response was cached publicly due to fake static extension',
            user_id: req.session.userId,
            email: req.session.user.email,
            session_token: 'SYNTEX_SESS_' + crypto.randomBytes(8).toString('hex'),
            flag: 'FLAG{CACHE_DECEPTION_PATH_CONFUSION_TOKEN_LEAK}',
        });
    }
    res.json({ settings: { theme: 'dark', notifications: true } });
});

router.get('/cache-deception', requireAuth, (req, res) => {
    res.render('vulns/cache-deception', { title: 'Cache Deception Lab', user: req.session.user });
});

// =================================================================
// 2. HTTP REQUEST SMUGGLING (simulated — real smuggling needs raw
//    socket access; this simulates the CL.TE detection logic so
//    learners understand the concept and can practice with Burp)
// =================================================================

router.get('/smuggling', requireAuth, (req, res) => {
    res.render('vulns/smuggling', { title: 'HTTP Request Smuggling Lab', user: req.session.user });
});

// MEDIUM — simulated CL.TE desync endpoint (educational simulation)
router.post('/smuggling/front-end', express.raw({ type: '*/*', limit: '50kb' }), (req, res) => {
    const raw = req.body.toString('utf8');

    // Detect conflicting Content-Length / Transfer-Encoding (the root cause of real smuggling)
    const hasCL = /content-length\s*:/i.test(raw);
    const hasTE = /transfer-encoding\s*:\s*chunked/i.test(raw);
    const smuggleAttempt = hasCL && hasTE;

    res.json({
        parsed_by: 'front-end (simulated proxy)',
        detected_cl: hasCL,
        detected_te: hasTE,
        desync_possible: smuggleAttempt,
        flag: smuggleAttempt ? 'FLAG{HTTP_SMUGGLING_CLTE_DESYNC_DETECTED}' : undefined,
        note: smuggleAttempt
            ? 'Both Content-Length and Transfer-Encoding present — front-end and back-end may parse this request boundary differently, enabling request smuggling.'
            : 'Send a raw request containing BOTH Content-Length and Transfer-Encoding: chunked headers to simulate a CL.TE smuggling attempt.',
    });
});

// HARD — TE.TE obfuscation detection (e.g. "Transfer-Encoding: xchunked")
router.post('/smuggling/back-end', express.raw({ type: '*/*', limit: '50kb' }), (req, res) => {
    const raw = req.body.toString('utf8');
    const obfuscatedTE = /transfer-encoding\s*:\s*[^\r\n]*chunked/i.test(raw) &&
                          !/transfer-encoding\s*:\s*chunked\s*$/im.test(raw);

    res.json({
        parsed_by: 'back-end (simulated origin server)',
        obfuscation_detected: obfuscatedTE,
        flag: obfuscatedTE ? 'FLAG{HTTP_SMUGGLING_TETE_OBFUSCATION_BYPASS}' : undefined,
        hint: obfuscatedTE
            ? 'Obfuscated Transfer-Encoding header (e.g. "chunked ", "xchunked", tab-injected) caused the back-end to disagree with the front-end about framing.'
            : 'Try header obfuscation: "Transfer-Encoding: chunked\\r\\nTransfer-Encoding: x"',
    });
});

// =================================================================
// 3. SECONDARY CONTEXT VULNERABILITIES
//    Vulnerability surfaces in a SECOND processing context —
//    PDF generation (headless browser → SSRF/XSS), image resize
//    (ImageMagick → RCE), CSV export (formula injection)
// =================================================================

router.get('/pdf-export', requireAuth, (req, res) => {
    res.render('vulns/pdf-export', { title: 'Invoice PDF Export', user: req.session.user, result: null });
});

// MEDIUM — PDF generator renders attacker HTML server-side (headless browser context)
router.post('/pdf-export', requireAuth, async (req, res) => {
    const { invoice_notes } = req.body;

    // VULNERABILITY: invoice_notes is embedded into HTML that a headless
    // browser (e.g. Puppeteer) renders to produce a PDF. If the notes field
    // contains <script> or <iframe src="file://...">, it executes in the
    // PDF-rendering context — a SECOND, often-forgotten attack surface.
    const renderedHtml = `<html><body>
<h1>Invoice</h1>
<div class="notes">${invoice_notes || ''}</div>
</body></html>`;

    const hasScript  = /<script|onerror=|onload=/i.test(invoice_notes || '');
    const hasFileSSRF = /file:\/\/|<iframe/i.test(invoice_notes || '');

    res.render('vulns/pdf-export', {
        title: 'Invoice PDF Export',
        user: req.session.user,
        result: {
            html: renderedHtml,
            vulnerable_context: hasScript || hasFileSSRF,
            flag: (hasScript || hasFileSSRF) ? 'FLAG{SECONDARY_CONTEXT_PDF_RENDERER_XSS_SSRF}' : undefined,
            note: (hasScript || hasFileSSRF)
                ? 'Your payload would execute inside the headless-browser PDF rendering context — a separate attack surface from the main web app, often missed in pentests.'
                : 'Try injecting <script>alert(1)</script> or <iframe src="file:///etc/passwd"> into the notes field.',
        },
    });
});

// HARD — image resize / ImageMagick-style secondary context (simulated)
router.get('/image-resize', requireAuth, (req, res) => {
    res.render('vulns/image-resize', { title: 'Avatar Image Processor', user: req.session.user, result: null });
});

router.post('/image-resize', requireAuth, (req, res) => {
    const { filename } = req.body;

    // VULNERABILITY: filename passed into a simulated ImageMagick "convert"
    // command. Real-world equivalent: CVE-2016-3714 (ImageTragick).
    // The image PROCESSING context is secondary to the upload context —
    // a file that looks like a harmless image triggers RCE during conversion.
    const isMVGPayload = (filename || '').includes('mvg:') || (filename || '').includes('|');
    const cmdInjection  = /[;&|`$()]/.test(filename || '');

    res.json({
        processed: filename,
        secondary_context: 'ImageMagick convert pipeline',
        vulnerable: isMVGPayload || cmdInjection,
        flag: (isMVGPayload || cmdInjection) ? 'FLAG{SECONDARY_CONTEXT_IMAGE_PROCESSOR_RCE}' : undefined,
        note: (isMVGPayload || cmdInjection)
            ? 'Filename/MVG injection into the image processing pipeline — this is a classic ImageTragick-style secondary context vulnerability.'
            : 'Try filename: "image.jpg; touch /tmp/pwned" or an MVG payload: "mvg:push graphic-context..."',
    });
});

// =================================================================
// 4. CLIENT-SIDE TEMPLATE INJECTION (CSTI)
//    Distinct from server-side SSTI — executes in the browser via
//    frontend template frameworks (AngularJS-style {{ }} evaluation)
// =================================================================

router.get('/csti', requireAuth, (req, res) => {
    res.render('vulns/csti', { title: 'Client-Side Template Lab', user: req.session.user });
});

// The actual vulnerability lives entirely client-side (see csti.ejs)
// This endpoint just stores/returns user bio for the CSTI sink demo
router.post('/csti/save-bio', requireAuth, (req, res) => {
    const { bio } = req.body;
    // Server just stores it — no server-side risk; the risk is in the
    // Angular-like client renderer that evaluates {{ }} expressions
    res.json({ saved: true, bio, note: 'Bio saved. View it on the profile preview to test client-side template evaluation.' });
});

// =================================================================
// 5. POSTMESSAGE VULNERABILITIES
//    window.postMessage() with missing origin checks — both sides:
//    a vulnerable LISTENER (receives from any origin) and a
//    vulnerable SENDER (sends to "*" target origin)
// =================================================================

router.get('/postmessage-demo', requireAuth, (req, res) => {
    res.render('vulns/postmessage', { title: 'PostMessage Security Lab', user: req.session.user });
});

// Serves the "vulnerable parent" iframe page with a permissive listener
router.get('/postmessage-demo/parent', requireAuth, (req, res) => {
    res.type('html').send(`<!DOCTYPE html><html><body style="font-family:sans-serif;padding:20px;">
<h3>Syntex Parent Frame (Vulnerable Listener)</h3>
<div id="output" style="background:#f0f0f0;padding:12px;border-radius:6px;font-family:monospace;font-size:12px;"></div>
<script>
// VULNERABILITY (EASY-MEDIUM): no event.origin check before trusting the message
window.addEventListener('message', function(event) {
  // Should check: if (event.origin !== 'https://syntex.local') return;
  const out = document.getElementById('output');
  out.textContent = 'Received from ' + event.origin + ': ' + JSON.stringify(event.data);

  // VULNERABILITY (HARD): innerHTML sink — XSS if attacker sends HTML
  if (event.data && event.data.html) {
    document.body.innerHTML += event.data.html;
  }
  if (event.data && event.data.action === 'steal') {
    out.textContent += ' | FLAG{POSTMESSAGE_NO_ORIGIN_CHECK_XSS}';
  }
}, false);
</script>
</body></html>`);
});

// =================================================================
// 6. WEAK PASSWORD CHECKS
//    Easy: no minimum length. Medium: no complexity requirement.
//    Hard: weak check bypassable via Unicode/whitespace tricks.
// =================================================================

router.get('/register-weak', (req, res) => {
    res.render('vulns/register-weak', { title: 'Create Account — Syntex Solutions', result: null, user: req.session.user || null });
});

router.post('/register-weak', async (req, res) => {
    const { username, password, confirm_password } = req.body;

    if (!username || !password) {
        return res.render('vulns/register-weak', { title:'Create Account', result:{ error:'Username and password required.' }, user:req.session.user||null });
    }

    // VULNERABILITY (EASY): No minimum length check — "1" is accepted
    // VULNERABILITY (MEDIUM): No complexity requirement — "aaaaaa" accepted
    // VULNERABILITY (HARD): Trim/normalise bypass — "password " with
    //   trailing space or full-width Unicode chars bypasses blocklist checks
    const commonPasswords = ['password', '123456', 'qwerty', 'admin123'];
    const normalisedPw = password.trim().toLowerCase();
    const blocklisted   = commonPasswords.includes(normalisedPw);

    // The actual (vulnerable) check only blocks EXACT matches, not trimmed/
    // case-insensitive variants — so "Password123 " (trailing space) or
    // "PASSWORD" bypasses a naive blocklist filter
    const rawBlocklistCheck = commonPasswords.includes(password);

    let weakness = [];
    if (password.length < 4)              weakness.push('No minimum length enforced (accepted ' + password.length + ' chars)');
    if (!/[0-9]/.test(password))          weakness.push('No digit required');
    if (!/[A-Z]/.test(password))          weakness.push('No uppercase required');
    if (!rawBlocklistCheck && blocklisted) weakness.push('Common password blocklist bypassed via case/whitespace trick');
    if (password === password.toLowerCase() && password.length < 8) weakness.push('No complexity enforced at all');

    const hash = crypto.createHash('md5').update(password).digest('hex');

    try {
        await db.query(
            `INSERT INTO users (username, email, password_hash, role, first_name, last_name)
             VALUES ($1,$2,$3,'user',$1,'Demo') ON CONFLICT (username) DO NOTHING`,
            [username, `${username}@syntex.local`, hash]
        ).catch(() => {});
    } catch (_) {}

    res.render('vulns/register-weak', {
        title: 'Create Account',
        result: {
            success: true,
            password_length: password.length,
            weaknesses: weakness,
            flag: weakness.length >= 2 ? 'FLAG{WEAK_PASSWORD_POLICY_NO_COMPLEXITY_ENFORCED}' : undefined,
        },
        user: req.session.user || null,
    });
});

module.exports = router;
