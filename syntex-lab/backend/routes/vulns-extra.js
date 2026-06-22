'use strict';

// ── Additional Advanced Vulnerabilities ───────────────────────────
// NEW vulns:
//   1. XXE — XML External Entity Injection (/xml-upload)
//   2. Mass Assignment — Role escalation via API (/api/v1/profile-update)
//   3. Prototype Pollution — JSON merge endpoint (/api/v1/merge)
//   4. Zip Slip — Archive extraction path escape (/zip-upload)
//
// All additive — zero changes to existing routes

const express  = require('express');
const router   = express.Router();
const db       = require('../database/db');
const path     = require('path');
const fs       = require('fs');
const { requireAuth } = require('../middleware/auth');
const { XMLParser } = require('fast-xml-parser');

// Vulnerable XML parser helper — simulates XXE file read
function parseXML(xmlString) {
    let processedXml = xmlString;
    // VULNERABILITY: resolve SYSTEM entities (file:// reads)
    const entityMatch = xmlString.match(/<!ENTITY\s+(\w+)\s+SYSTEM\s+"file:\/\/([^"]+)"/);
    if (entityMatch) {
        const [, entityName, filePath] = entityMatch;
        let fileContent = '';
        try {
            fileContent = fs.readFileSync(filePath, 'utf8').slice(0, 500);
        } catch (e) {
            fileContent = `[Cannot read: ${e.message}]`;
        }
        processedXml = processedXml.replace(new RegExp(`&${entityName};`, 'g'), fileContent);
    }
    const parser = new XMLParser({ processEntities: true, allowBooleanAttributes: true });
    return parser.parse(processedXml);
}

// ─────────────────────────────────────────────────────────────────
// 1. XXE — XML External Entity Injection
// ─────────────────────────────────────────────────────────────────
router.get('/xml-upload', requireAuth, (req, res) => {
    res.render('vulns/xxe', {
        title:  'XML Invoice Upload — Syntex Solutions',
        result: null,
        error:  null,
        user:   req.session.user,
    });
});

router.post('/xml-upload', requireAuth, async (req, res) => {
    const { xml_data } = req.body;

    if (!xml_data) {
        return res.render('vulns/xxe', {
            title:'XML Invoice Upload', result:null,
            error:'No XML data provided.', user:req.session.user,
        });
    }

    let result = null;
    let error  = null;
    let xxeFlag = null;

    try {
        // VULNERABILITY: XML parsed with external entity resolution
        const parsed = parseXML(xml_data);
        result = parsed;

        // Detect XXE attempt and plant flag
        const resultStr = JSON.stringify(parsed);
        if (xml_data.includes('SYSTEM') || xml_data.includes('file://') ||
            xml_data.includes('<!ENTITY') || xml_data.includes('<!DOCTYPE')) {
            xxeFlag = 'FLAG{XXE_EXTERNAL_ENTITY_LOCAL_FILE_READ}';
        }

        await db.query(
            `INSERT INTO audit_logs (user_id, action, details) VALUES ($1, 'xml_upload', $2)`,
            [req.session.userId, `XML parsed: ${xml_data.slice(0,100)}`]
        ).catch(() => {});

    } catch (err) {
        error = `XML Parse Error: ${err.message}`;
    }

    res.render('vulns/xxe', {
        title: 'XML Invoice Upload — Syntex Solutions',
        result, error, xxeFlag,
        rawXml: xml_data,
        user: req.session.user,
    });
});

// ─────────────────────────────────────────────────────────────────
// 2. Mass Assignment
//    Endpoint: PUT /api/v1/profile-update
//    Vulnerability: all body fields passed to UPDATE query including role/is_admin
//    Payload: {"username":"hacker","role":"admin","is_admin":true}
//    Flag: returned when role or is_admin successfully set
// ─────────────────────────────────────────────────────────────────
router.put('/api/v1/profile-update', requireAuth, async (req, res) => {
    const uid  = req.session.userId;
    const body = req.body;

    // VULNERABILITY: Mass Assignment — all fields from request body are accepted
    // Should only allow: first_name, last_name, bio, department, job_title
    // But also accepts: role, is_admin, email, wallet_balance, api_key, password_hash
    const allowed = ['first_name', 'last_name', 'bio', 'department', 'job_title', 'email'];
    const sensitive = ['role', 'is_admin', 'wallet_balance', 'api_key', 'password_hash'];

    // Build SET clause from ALL provided fields (no allowlist applied)
    const setClauses = [];
    const values     = [];
    let   idx        = 1;

    for (const [key, val] of Object.entries(body)) {
        // Validate key is a real column name (basic injection prevention) but no field allowlist
        if (/^[a-z_]+$/.test(key)) {
            setClauses.push(`${key} = $${idx++}`);
            values.push(val);
        }
    }

    if (!setClauses.length) {
        return res.status(400).json({ error: 'No fields to update' });
    }

    values.push(uid);

    try {
        await db.query(
            `UPDATE users SET ${setClauses.join(', ')} WHERE id = $${idx}`,
            values
        );

        const updated = await db.query(`SELECT * FROM users WHERE id=$1`, [uid]);
        const updatedFields = Object.keys(body);
        const massAssigned  = updatedFields.filter(f => sensitive.includes(f));

        res.json({
            success:        true,
            updated_fields: updatedFields,
            mass_assigned:  massAssigned,
            flag:           massAssigned.length > 0
                              ? 'FLAG{MASS_ASSIGNMENT_ROLE_ESCALATION_VIA_API}'
                              : undefined,
            note:           massAssigned.length > 0
                              ? `⚠️ Sensitive fields updated via mass assignment: ${massAssigned.join(', ')}`
                              : 'Profile updated.',
            user:           updated.rows[0],
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// GET endpoint to show mass assignment demo page
router.get('/mass-assignment', requireAuth, async (req, res) => {
    const user = await db.query(`SELECT * FROM users WHERE id=$1`, [req.session.userId]);
    res.render('vulns/mass-assignment', {
        title: 'Profile Update API — Syntex Solutions',
        user:  user.rows[0],
        result: null,
    });
});

// ─────────────────────────────────────────────────────────────────
// 3. Prototype Pollution
//    Endpoint: POST /api/v1/merge
//    Vulnerability: deep merge without __proto__ sanitisation
//    Payload: {"__proto__":{"admin":true,"role":"admin"}}
//    Effect: pollutes Object.prototype — all objects gain {admin:true}
//    Flag: in response when __proto__ detected
// ─────────────────────────────────────────────────────────────────

// VULNERABLE deep merge function
function deepMerge(target, source) {
    for (const key of Object.keys(source)) {
        // VULNERABILITY: __proto__ key not blocked
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            deepMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

router.post('/api/v1/merge', requireAuth, (req, res) => {
    const { config } = req.body;

    if (!config || typeof config !== 'object') {
        return res.status(400).json({ error: 'config object required' });
    }

    // VULNERABILITY: User-supplied object merged into base config
    // Payload: {"__proto__": {"isAdmin": true, "role": "admin"}}
    const baseConfig = {
        theme:    'dark',
        language: 'en',
        timezone: 'UTC',
    };

    const hasProtoPollution = JSON.stringify(config).includes('__proto__') ||
                              JSON.stringify(config).includes('constructor') ||
                              JSON.stringify(config).includes('prototype');

    deepMerge(baseConfig, config);

    // Check if Object.prototype was polluted
    const isPolluted = ({}).isAdmin === true || ({}).role === 'admin' ||
                       Object.keys({}).length > 0;

    res.json({
        merged:           baseConfig,
        prototype_polluted: isPolluted || hasProtoPollution,
        flag:             hasProtoPollution
                            ? 'FLAG{PROTOTYPE_POLLUTION_PROTO_OBJECT_TAINTED}'
                            : undefined,
        note:             hasProtoPollution
                            ? '⚠️ Prototype pollution detected. Object.prototype may be tainted — check ({}).isAdmin'
                            : 'Config merged.',
        check:            { isAdmin: ({}).isAdmin, role: ({}).role },
    });
});

// GET endpoint for prototype pollution demo
router.get('/proto-pollution', requireAuth, (req, res) => {
    res.render('vulns/proto-pollution', {
        title: 'Config Merge API — Syntex Solutions',
        user:  req.session.user,
        result: null,
    });
});

// ─────────────────────────────────────────────────────────────────
// 4. Zip Slip
//    Endpoint: POST /zip-upload
//    Vulnerability: archive extraction uses filename without path sanitisation
//    Payload: ZIP containing file named: ../../public/js/evil.js
//    Effect: file written outside intended extract directory
//    Flag: in response when path traversal in filename detected
// ─────────────────────────────────────────────────────────────────
const multer = require('multer');
const upload = multer({
    dest:   '/tmp/zip-uploads/',
    limits: { fileSize: 5 * 1024 * 1024 },
});

router.get('/zip-upload', requireAuth, (req, res) => {
    res.render('vulns/zipslip', {
        title:  'ZIP Archive Upload — Syntex Solutions',
        result: null,
        user:   req.session.user,
    });
});

router.post('/zip-upload', requireAuth, upload.single('archive'), async (req, res) => {
    if (!req.file) {
        return res.render('vulns/zipslip', {
            title:'ZIP Archive Upload', result:{ error:'No file uploaded.' }, user:req.session.user,
        });
    }

    // Simulate ZIP extraction vulnerability
    // In a real implementation, AdmZip or unzipper would be used
    // Here we demonstrate the path check that is MISSING

    const extractDir    = '/tmp/syntex-extract/';
    const simulatedFiles = [
        { name: 'invoice.pdf',              safe: true },
        { name: 'report.docx',             safe: true },
        { name: '../../public/js/evil.js', safe: false },  // Zip Slip path
        { name: '../../../etc/cron.d/evil', safe: false }, // Zip Slip path
    ];

    // VULNERABILITY: Filename used directly without normalisation
    // Fix would be: path.normalize(filename) and check it stays within extractDir
    const dangerous = simulatedFiles.filter(f => {
        const fullPath = path.join(extractDir, f.name);
        // VULNERABLE check — resolve() would catch this, but normalize alone won't
        return !f.safe;
    });

    // Detect if real upload has suspicious filename
    const uploadName = req.file.originalname || '';
    const hasTraversal = uploadName.includes('..') || uploadName.includes('/') || uploadName.includes('\\');

    const result = {
        filename:      uploadName,
        size:          req.file.size,
        extract_dir:   extractDir,
        simulated_files: simulatedFiles.map(f => ({
            ...f,
            resolved_path: path.join(extractDir, f.name),
            // VULNERABILITY: resolved path escapes extractDir
            escapes_dir: !path.resolve(extractDir, f.name).startsWith(path.resolve(extractDir)),
        })),
        zip_slip_demo: dangerous.map(f => f.name),
        flag:          dangerous.length > 0 || hasTraversal
                         ? 'FLAG{ZIP_SLIP_PATH_TRAVERSAL_EXTRACT_ESCAPE}'
                         : undefined,
    };

    // Clean up
    try { fs.unlinkSync(req.file.path); } catch(_) {}

    res.render('vulns/zipslip', {
        title: 'ZIP Archive Upload — Syntex Solutions',
        result,
        user:  req.session.user,
    });
});

module.exports = router;
