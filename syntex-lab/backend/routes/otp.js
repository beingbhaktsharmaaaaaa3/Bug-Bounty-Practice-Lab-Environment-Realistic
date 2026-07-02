'use strict';

// ── OTP Lab Module ────────────────────────────────────────────────
// 6 OTP vulnerability scenarios for bug bounty practice.
//
// Scenario 1: /otp/brute-force    — No rate limit, 6-digit, 1-hour expiry
// Scenario 2: /otp/bypass         — Parameter manipulation skips verification
// Scenario 3: /otp/leaked         — OTP returned in API response body
// Scenario 4: /otp/predictable    — OTP = MD5(username+minute) — guessable
// Scenario 5: /otp/reuse          — Valid OTP never invalidated after use
// Scenario 6: /otp/short          — 4-digit OTP (only 10,000 combinations)
//
// Tools: Burp Suite Intruder, Turbo Intruder, curl, Python

const express = require('express');
const router  = express.Router();
const crypto  = require('crypto');
const db      = require('../database/db');
const { requireAuth } = require('../middleware/auth');

// ── In-memory OTP stores (per scenario) ──────────────────────────
const stores = {
    bruteforce:  {},  // uid → { otp, expires, attempts }
    bypass:      {},  // uid → { otp, expires, verified }
    leaked:      {},  // uid → { otp, expires }
    predictable: {},  // uid → { otp, expires, username }
    reuse:       {},  // uid → { otp, expires, usedCount }
    short:       {},  // uid → { otp, expires, attempts }
};

// ── Helper — generate N-digit OTP ────────────────────────────────
const genOTP = (digits = 6) =>
    String(Math.floor(Math.random() * Math.pow(10, digits))).padStart(digits, '0');

// ─────────────────────────────────────────────────────────────────
// HUB — GET /otp
// ─────────────────────────────────────────────────────────────────
router.get('/', requireAuth, (req, res) => {
    res.render('otp/index', {
        title: 'OTP Security Lab — Syntex Solutions',
        user:  req.session.user,
    });
});

// =================================================================
// SCENARIO 1 — OTP Brute Force (No Rate Limit, No Lockout)
// =================================================================
router.get('/brute-force', requireAuth, (req, res) => {
    const uid = req.session.userId;
    const otp = genOTP(6);
    stores.bruteforce[uid] = { otp, expires: Date.now() + 3600000, attempts: 0 }; // 1 HOUR expiry

    res.render('otp/brute-force', {
        title:    'OTP Verification — Syntex Solutions',
        scenario: 'brute-force',
        result:   null,
        attempts: 0,
        otp_hint: require('../middleware/program').getLabMode() === 'beginner' ? otp : null,
        user:     req.session.user,
    });
});

router.post('/brute-force/verify', requireAuth, (req, res) => {
    const uid   = req.session.userId;
    const { otp } = req.body;
    const entry = stores.bruteforce[uid];

    if (!entry) {
        return res.render('otp/brute-force', {
            title:'OTP Verification', scenario:'brute-force',
            result:'expired', attempts:0, otp_hint:null, user:req.session.user,
        });
    }

    // VULNERABILITY 1: No attempt limit — brute force all 1,000,000
    // VULNERABILITY 2: No lockout after N failures
    // VULNERABILITY 3: 1-hour expiry (should be 5 minutes)
    entry.attempts++;

    if (Date.now() > entry.expires) {
        return res.render('otp/brute-force', {
            title:'OTP Verification', scenario:'brute-force',
            result:'expired', attempts:entry.attempts, otp_hint:null, user:req.session.user,
        });
    }

    if (otp === entry.otp) {
        delete stores.bruteforce[uid];
        return res.json({
            success:  true,
            flag:     'FLAG{OTP_BRUTE_FORCE_NO_RATELIMIT_CONFIRMED}',
            attempts: entry.attempts,
            message:  `OTP verified after ${entry.attempts} attempt(s). No rate limit or lockout was enforced.`,
        });
    }

    // VULNERABILITY: Attempt count in response helps attacker gauge progress
    res.json({
        success:  false,
        message:  'Invalid OTP. Try again.',
        attempts: entry.attempts, // should NOT be exposed
        hint:     entry.attempts > 100 ? 'No lockout detected — keep going.' : null,
    });
});

// Also serve verify via GET for easy Burp Intruder testing
router.get('/brute-force/verify', requireAuth, (req, res) => {
    const uid   = req.session.userId;
    const { otp } = req.query;
    const entry = stores.bruteforce[uid];

    if (!entry) return res.json({ success:false, message:'Session expired. Visit /otp/brute-force to get a new OTP.' });

    entry.attempts++;
    if (Date.now() > entry.expires) return res.json({ success:false, message:'OTP expired' });

    if (otp === entry.otp) {
        delete stores.bruteforce[uid];
        return res.json({ success:true, flag:'FLAG{OTP_BRUTE_FORCE_NO_RATELIMIT_CONFIRMED}', attempts:entry.attempts });
    }
    res.json({ success:false, attempts:entry.attempts });
});

// =================================================================
// SCENARIO 2 — OTP Bypass via Parameter Manipulation
// =================================================================
router.get('/bypass', requireAuth, (req, res) => {
    const uid = req.session.userId;
    const otp = genOTP(6);
    stores.bypass[uid] = { otp, expires: Date.now() + 300000, verified: false };

    res.render('otp/bypass', {
        title:    '2FA Verification — Syntex Solutions',
        result:   null,
        user:     req.session.user,
    });
});

router.post('/bypass/verify', requireAuth, (req, res) => {
    const uid  = req.session.userId;
    const entry = stores.bypass[uid];

    if (!entry || Date.now() > entry.expires) {
        return res.json({ success:false, message:'Session expired.' });
    }

    // VULNERABILITY: Server trusts client-supplied bypass fields
    // Attacker payload: {"otp":"000000","bypass":true}
    // Or:              {"otp":"000000","skip_otp":true}
    // Or:              {"otp":"000000","verified":true}
    // Or:              {"otp":"000000","status":"success"}
    const {
        otp,
        bypass,        // VULNERABILITY: client can set this
        skip_otp,      // VULNERABILITY: alternative bypass param
        verified,      // VULNERABILITY: another bypass
        status,        // VULNERABILITY: status override
        otp_required,  // VULNERABILITY: can be set to false
    } = req.body;

    const isBypassed = bypass === true   || bypass === 'true'   ||
                       skip_otp === true || skip_otp === 'true' ||
                       verified === true || verified === 'true' ||
                       status === 'success' || status === 'verified' ||
                       otp_required === false || otp_required === 'false';

    if (isBypassed) {
        // VULNERABILITY: bypass accepted without OTP validation
        delete stores.bypass[uid];
        return res.json({
            success: true,
            flag:    'FLAG{OTP_BYPASS_PARAMETER_MANIPULATION}',
            method:  'parameter_bypass',
            message: 'OTP bypassed via parameter manipulation. No OTP was validated.',
            bypassed_with: { bypass, skip_otp, verified, status, otp_required },
        });
    }

    if (otp === entry.otp) {
        delete stores.bypass[uid];
        return res.json({ success:true, message:'OTP correct.', flag:'FLAG{OTP_BYPASS_PARAMETER_MANIPULATION}' });
    }

    res.json({ success:false, message:'Invalid OTP.' });
});

// =================================================================
// SCENARIO 3 — OTP Leaked in API Response (Debug Mode)
// =================================================================
router.get('/leaked', requireAuth, (req, res) => {
    res.render('otp/leaked', {
        title: 'Verify Your Phone — Syntex Solutions',
        sent:  false,
        user:  req.session.user,
    });
});

router.post('/leaked/send', requireAuth, async (req, res) => {
    const uid  = req.session.userId;
    const otp  = genOTP(6);
    stores.leaked[uid] = { otp, expires: Date.now() + 300000 };

    // VULNERABILITY: OTP returned directly in the API response body
    // Should only be sent to the user's phone/email, never in the HTTP response
    res.json({
        success:  true,
        message:  'OTP sent to your registered phone number.',
        // VULNERABILITY: debug fields expose the OTP
        debug: {
            otp_generated:   otp,              // CRITICAL: OTP in plaintext
            expires_in:      '5 minutes',
            sms_provider:    'Syntex-SMS-v2',
            delivery_status: 'queued',
            // In a real app, these debug fields would be removed before production
        },
        // Some apps leak it at top level too
        otp: otp,  // VULNERABILITY: direct top-level leak
    });
});

router.post('/leaked/verify', requireAuth, (req, res) => {
    const uid   = req.session.userId;
    const { otp } = req.body;
    const entry = stores.leaked[uid];

    if (!entry || Date.now() > entry.expires) {
        return res.json({ success:false, message:'OTP expired.' });
    }

    if (otp === entry.otp) {
        delete stores.leaked[uid];
        return res.json({ success:true, flag:'FLAG{OTP_LEAKED_IN_API_RESPONSE_BODY}', message:'OTP verified.' });
    }
    res.json({ success:false, message:'Invalid OTP.' });
});

// =================================================================
// SCENARIO 4 — Predictable OTP (MD5 of username + current minute)
// =================================================================
router.get('/predictable', requireAuth, (req, res) => {
    res.render('otp/predictable', {
        title:  'Account Verification — Syntex Solutions',
        result: null,
        user:   req.session.user,
    });
});

router.post('/predictable/send', requireAuth, async (req, res) => {
    const uid  = req.session.userId;
    const user = await db.query(`SELECT username FROM users WHERE id=$1`, [uid]);
    const username = user.rows[0]?.username || 'user';

    // VULNERABILITY: OTP derived from predictable inputs
    // MD5(username + current_minute_timestamp) truncated to 6 digits
    // An attacker who knows the username can compute the OTP offline
    const minuteTs = Math.floor(Date.now() / 60000); // changes every minute
    const hash = crypto.createHash('md5').update(`${username}_${minuteTs}`).digest('hex');
    const otp  = (parseInt(hash.slice(0, 8), 16) % 1000000).toString().padStart(6, '0');

    stores.predictable[uid] = { otp, expires: Date.now() + 120000, username };

    res.json({
        success: true,
        message: `OTP sent to your registered email.`,
        // VULNERABILITY: Algorithm hints in response for lab purposes
        debug:   require('../middleware/program').getLabMode() === 'beginner' ? {
            note:      'OTP generation is time-based and username-dependent',
            algorithm: 'MD5(username + floor(now/60000))',
        } : undefined,
    });
});

router.post('/predictable/verify', requireAuth, (req, res) => {
    const uid   = req.session.userId;
    const { otp } = req.body;
    const entry = stores.predictable[uid];

    if (!entry || Date.now() > entry.expires) {
        return res.json({ success:false, message:'OTP expired.' });
    }

    if (otp === entry.otp) {
        delete stores.predictable[uid];
        return res.json({ success:true, flag:'FLAG{OTP_PREDICTABLE_MD5_TIMESTAMP_ALGO}', message:'Correct! You predicted the OTP.' });
    }

    // Hint: check adjacent minutes (generation might have spanned a minute boundary)
    const minuteTs = Math.floor(Date.now() / 60000);
    const prevHash = crypto.createHash('md5').update(`${entry.username}_${minuteTs - 1}`).digest('hex');
    const prevOTP  = (parseInt(prevHash.slice(0, 8), 16) % 1000000).toString().padStart(6, '0');

    if (otp === prevOTP) {
        delete stores.predictable[uid];
        return res.json({ success:true, flag:'FLAG{OTP_PREDICTABLE_MD5_TIMESTAMP_ALGO}', message:'Correct (previous minute window).' });
    }

    res.json({ success:false, message:'Invalid OTP. Try computing: MD5(username_floor(now/60000)) % 1000000' });
});

// =================================================================
// SCENARIO 5 — OTP Reuse (Not Invalidated After Use)
// =================================================================
router.get('/reuse', requireAuth, (req, res) => {
    const uid = req.session.userId;
    const otp = genOTP(6);
    stores.reuse[uid] = { otp, expires: Date.now() + 600000, usedCount: 0 };

    res.render('otp/reuse', {
        title:    'Login Verification — Syntex Solutions',
        result:   null,
        otp_hint: require('../middleware/program').getLabMode() === 'beginner' ? otp : null,
        user:     req.session.user,
    });
});

router.post('/reuse/verify', requireAuth, (req, res) => {
    const uid   = req.session.userId;
    const { otp } = req.body;
    const entry = stores.reuse[uid];

    if (!entry || Date.now() > entry.expires) {
        return res.json({ success:false, message:'OTP expired.' });
    }

    if (otp === entry.otp) {
        // VULNERABILITY: OTP NOT deleted/invalidated after successful verification
        // The same OTP can be reused any number of times within the expiry window
        entry.usedCount++; // just increment — don't invalidate

        const flag = entry.usedCount >= 2
            ? 'FLAG{OTP_REUSE_NOT_INVALIDATED_AFTER_USE}'
            : undefined;

        return res.json({
            success:    true,
            message:    entry.usedCount === 1 ? 'OTP verified.' : `OTP reused ${entry.usedCount} times — same OTP still valid!`,
            used_count: entry.usedCount,
            flag,
            note: entry.usedCount >= 2 ? 'VULNERABILITY: OTP should be invalidated immediately after first use.' : undefined,
        });
    }

    res.json({ success:false, message:'Invalid OTP.' });
});

// =================================================================
// SCENARIO 6 — Short OTP (4-digit, only 10,000 combinations)
// =================================================================
router.get('/short', requireAuth, (req, res) => {
    const uid = req.session.userId;
    const otp = genOTP(4); // only 4 digits
    stores.short[uid] = { otp, expires: Date.now() + 3600000, attempts: 0 };

    res.render('otp/short', {
        title:    'Phone Verification — Syntex Solutions',
        result:   null,
        otp_hint: require('../middleware/program').getLabMode() === 'beginner' ? otp : null,
        user:     req.session.user,
    });
});

router.post('/short/verify', requireAuth, (req, res) => {
    const uid   = req.session.userId;
    const { otp } = req.body;
    const entry = stores.short[uid];

    if (!entry || Date.now() > entry.expires) {
        return res.json({ success:false, message:'OTP expired.' });
    }

    // VULNERABILITY: 4-digit OTP = only 10,000 combinations
    // No rate limit = brute forceable in seconds
    entry.attempts++;

    if (otp === entry.otp) {
        delete stores.short[uid];
        return res.json({
            success:  true,
            flag:     'FLAG{OTP_SHORT_4DIGIT_LOW_ENTROPY_BYPASS}',
            attempts: entry.attempts,
            message:  `Verified after ${entry.attempts} attempt(s). Only 10,000 possible combinations exist.`,
        });
    }

    res.json({ success:false, attempts:entry.attempts, message:'Invalid OTP.' });
});

// GET version for Burp Intruder
router.get('/short/verify', requireAuth, (req, res) => {
    const uid   = req.session.userId;
    const { otp } = req.query;
    const entry = stores.short[uid];
    if (!entry) return res.json({ success:false });
    entry.attempts++;
    if (otp === entry.otp) {
        delete stores.short[uid];
        return res.json({ success:true, flag:'FLAG{OTP_SHORT_4DIGIT_LOW_ENTROPY_BYPASS}', attempts:entry.attempts });
    }
    res.json({ success:false, attempts:entry.attempts });
});

module.exports = router;
