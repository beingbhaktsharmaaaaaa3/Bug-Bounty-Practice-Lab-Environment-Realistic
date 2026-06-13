'use strict';

const express = require('express');
const router  = express.Router();
const db      = require('../database/db');
const { requireAuth, requireAdmin } = require('../middleware/auth');

const VALID_STATUSES = ['new','needs_more_info','accepted','duplicate','informative','not_applicable','resolved'];
const VULN_TYPES = [
    'sqli','xss_reflected','xss_stored','xss_dom','idor','csrf',
    'ssrf','lfi','path_traversal','cmd_injection','file_upload',
    'open_redirect','cors','jwt','auth_bypass','broken_access',
    'business_logic','rate_limit','exposure','weak_crypto',
    'info_disclosure','missing_headers','other',
];

// ─── User-facing routes ──────────────────────────────────────

// GET /reports
router.get('/', requireAuth, async (req, res) => {
    const uid = req.session.userId;
    const { status } = req.query;
    let q = `SELECT id,title,vuln_type,severity,status,bounty_amount,created_at,updated_at
             FROM reports WHERE user_id = $1`;
    const params = [uid];
    if (status) { q += ` AND status = $2`; params.push(status); }
    q += ` ORDER BY created_at DESC`;

    try {
        const result = await db.query(q, params);
        const counts = await db.query(
            `SELECT status, COUNT(*) AS n FROM reports WHERE user_id=$1 GROUP BY status`, [uid]
        );
        const statusMap = {};
        counts.rows.forEach(r => { statusMap[r.status] = parseInt(r.n); });

        res.render('reports/list', {
            title: 'My Reports — Syntex Bug Bounty',
            reports: result.rows,
            statusMap,
            filterStatus: status || null,
            user: req.session.user,
        });
    } catch (err) {
        res.render('error', { title: 'Error', message: err.message, status: 500, user: req.session.user });
    }
});

// GET /reports/new
router.get('/new', requireAuth, (req, res) => {
    res.render('reports/new', {
        title: 'Submit Bug Report — Syntex Bug Bounty',
        vulnTypes: VULN_TYPES,
        error: null,
        user: req.session.user,
    });
});

// POST /reports
router.post('/', requireAuth, async (req, res) => {
    const uid = req.session.userId;
    const {
        title, vuln_type, severity, cvss_score,
        affected_url, steps, impact, proof_of_concept, suggested_fix,
    } = req.body;

    if (!title || !vuln_type || !severity || !affected_url || !steps || !impact) {
        return res.render('reports/new', {
            title: 'Submit Bug Report',
            vulnTypes: VULN_TYPES,
            error: 'Title, type, severity, URL, steps, and impact are required.',
            user: req.session.user,
        });
    }

    try {
        const r = await db.query(
            `INSERT INTO reports
               (user_id,title,vuln_type,severity,cvss_score,affected_url,
                steps,impact,proof_of_concept,suggested_fix,status)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'new')
             RETURNING id`,
            [uid, title, vuln_type, severity, cvss_score || null,
             affected_url, steps, impact,
             proof_of_concept || null, suggested_fix || null]
        );
        res.redirect(`/reports/${r.rows[0].id}`);
    } catch (err) {
        res.render('error', { title: 'Error', message: err.message, status: 500, user: req.session.user });
    }
});

// GET /reports/:id
router.get('/:id', requireAuth, async (req, res) => {
    const uid  = req.session.userId;
    const role = req.session.role;
    const { id } = req.params;

    try {
        const result = await db.query(
            `SELECT r.*, u.username AS reporter, u.first_name, u.last_name,
                    t.username AS triager
             FROM reports r
             JOIN users u ON u.id = r.user_id
             LEFT JOIN users t ON t.id = r.triaged_by
             WHERE r.id = $1`, [id]
        );
        if (!result.rows.length) return res.status(404).render('404', { title: '404', user: req.session.user });

        const report = result.rows[0];
        // Only owner or admin/support can view
        if (report.user_id !== uid && !['admin','support','developer'].includes(role)) {
            return res.status(403).render('error', {
                title: 'Access Denied', message: 'You can only view your own reports.', status: 403, user: req.session.user,
            });
        }

        res.render('reports/detail', {
            title: `Report #${report.id} — ${report.title}`,
            report,
            isStaff: ['admin','support','developer'].includes(role),
            validStatuses: VALID_STATUSES,
            user: req.session.user,
        });
    } catch (err) {
        res.render('error', { title: 'Error', message: err.message, status: 500, user: req.session.user });
    }
});

// ─── Admin / triage routes ───────────────────────────────────

// GET /admin/reports  (mounted via admin router in server.js)
router.get('/admin/all', requireAdmin, async (req, res) => {
    const { status, severity } = req.query;
    let q = `SELECT r.id,r.title,r.vuln_type,r.severity,r.status,r.bounty_amount,
                    r.created_at, u.username AS reporter
             FROM reports r JOIN users u ON u.id=r.user_id WHERE 1=1`;
    const params = [];
    if (status)   { params.push(status);   q += ` AND r.status=$${params.length}`; }
    if (severity) { params.push(severity); q += ` AND r.severity=$${params.length}`; }
    q += ` ORDER BY r.created_at DESC`;

    try {
        const result = await db.query(q, params);
        const totals = await db.query(
            `SELECT status, COUNT(*) n FROM reports GROUP BY status ORDER BY status`
        );
        res.render('admin/reports', {
            title: 'Report Triage — Admin',
            reports: result.rows,
            totals: totals.rows,
            filters: { status, severity },
            user: req.session.user,
        });
    } catch (err) {
        res.render('error', { title: 'Error', message: err.message, status: 500, user: req.session.user });
    }
});

// POST /reports/:id/triage  — update status, add notes, set bounty
router.post('/:id/triage', requireAdmin, async (req, res) => {
    const { id } = req.params;
    const { status, triage_notes, bounty_amount, duplicate_of } = req.body;

    if (!VALID_STATUSES.includes(status)) {
        return res.status(400).json({ error: 'Invalid status' });
    }
    try {
        await db.query(
            `UPDATE reports SET
               status=$1, triage_notes=$2, bounty_amount=$3,
               duplicate_of=$4, triaged_by=$5, updated_at=NOW()
             WHERE id=$6`,
            [status, triage_notes || null, parseFloat(bounty_amount) || 0,
             duplicate_of || null, req.session.userId, id]
        );
        res.redirect(`/reports/${id}`);
    } catch (err) {
        res.render('error', { title: 'Error', message: err.message, status: 500, user: req.session.user });
    }
});

module.exports = router;
