'use strict';

const express      = require('express');
const session      = require('express-session');
const cookieParser = require('cookie-parser');
const path         = require('path');

const app = express();

// ─── View engine ──────────────────────────────────────────────
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ─── Body parsers + cookies ───────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ─── Session (intentionally weak) ────────────────────────────
app.use(session({
    secret: process.env.SESSION_SECRET || 'syntex_session_secret_2024',
    resave: true,
    saveUninitialized: true,
    name: 'SYNTEX_SESS',
    cookie: { httpOnly: false, secure: false, maxAge: 30 * 24 * 60 * 60 * 1000 },
}));

// ─── CORS (misconfigured) ─────────────────────────────────────
app.use(require('./middleware/cors'));

// ─── LAB_MODE middleware ──────────────────────────────────────
// Sets res.locals so every view knows the current difficulty mode
app.use((req, res, next) => {
    const mode = (process.env.LAB_MODE || 'easy').toLowerCase();
    res.locals.labMode = mode;
    res.locals.lab = {
        mode,
        showHints:      mode === 'easy',
        showFlags:      mode !== 'realistic',
        showComments:   mode === 'easy',
        showBanner:     true,
        bannerColor:    { easy:'#15803D', medium:'#B45309', hard:'#B91C1C', realistic:'#1B3A6B' }[mode] || '#1B3A6B',
        bannerLabel:    { easy:'EASY', medium:'MEDIUM', hard:'HARD', realistic:'REALISTIC' }[mode] || mode.toUpperCase(),
    };
    next();
});

// ─── Inject session user into all views ───────────────────────
app.use((req, res, next) => {
    res.locals.user    = req.session.user    || null;
    res.locals.isAdmin = (req.session.role === 'admin') || (req.cookies.role === 'admin');
    next();
});

// ─── Static files ─────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

// ─── Routes ───────────────────────────────────────────────────
// Core app
app.use('/',          require('./routes/misc'));
app.use('/',          require('./routes/auth'));
app.use('/dashboard', require('./routes/dashboard'));
app.use('/profile',   require('./routes/profile'));
app.use('/products',  require('./routes/products'));
app.use('/blog',      require('./routes/blog'));
app.use('/orders',    require('./routes/orders'));
app.use('/tickets',   require('./routes/tickets'));
app.use('/search',    require('./routes/search'));
app.use('/contact',   require('./routes/contact'));
app.use('/',          require('./routes/upload'));

// Admin
app.use('/admin',     require('./routes/admin'));

// API
app.use('/api/v1',    require('./routes/api/v1'));
app.use('/api/v2',    require('./routes/api/v2'));

// ── v3 additions ──────────────────────────────────────────────
app.use('/bug-bounty', require('./routes/bugbounty'));
app.use('/reports',    require('./routes/reports'));
app.use('/hints',      require('./routes/hints'));
app.use('/challenges', require('./routes/challenges'));

// Convenience aliases
app.get('/scope',         (req, res) => res.redirect('/bug-bounty/scope'));
app.get('/hall-of-fame',  (req, res) => res.redirect('/bug-bounty/hall-of-fame'));
app.get('/security/policy',(req,res) => res.redirect('/bug-bounty'));

// Admin triage shortcut
const reportRouter = require('./routes/reports');
app.get('/admin/reports',         reportRouter.stack
    ? (req, res, next) => next()   // let admin router handle below
    : (req, res) => res.redirect('/admin')
);
// Mount admin report triage under admin router path
const db = require('./database/db');
const { requireAdmin } = require('./middleware/auth');
app.get('/admin/reports', requireAdmin, async (req, res) => {
    const { status, severity } = req.query;
    let q = `SELECT r.id,r.title,r.vuln_type,r.severity,r.status,
                    r.bounty_amount,r.created_at, u.username AS reporter
             FROM reports r JOIN users u ON u.id=r.user_id WHERE 1=1`;
    const params = [];
    if (status)   { params.push(status);   q += ` AND r.status=$${params.length}`; }
    if (severity) { params.push(severity); q += ` AND r.severity=$${params.length}`; }
    q += ` ORDER BY r.created_at DESC`;
    try {
        const result = await db.query(q, params);
        const totals = await db.query(`SELECT status, COUNT(*) n FROM reports GROUP BY status`);
        res.render('admin/reports', {
            title:'Report Triage — Admin', reports:result.rows,
            totals:totals.rows, filters:{status,severity}, user:req.session.user,
        });
    } catch(err) {
        res.render('error',{title:'Error',message:err.message,status:500,user:req.session.user});
    }
});

// ─── Homepage ─────────────────────────────────────────────────
app.get('/', (req, res) => {
    if (req.session.userId) return res.redirect('/dashboard');
    res.render('index', { title: 'Syntex Solutions — Enterprise Resource Management' });
});

// Settings
app.get('/settings', require('./middleware/auth').requireAuth, (req, res) => {
    res.render('settings', { title:'Account Settings — Syntex Solutions', user:req.session.user, success:req.query.saved||null, error:null });
});

// ─── 404 ──────────────────────────────────────────────────────
app.use((req, res) => {
    res.status(404).render('404', { title:'404 — Not Found', path:req.path, user:req.session.user||null });
});

// ─── Error handler (exposes stack trace intentionally) ────────
app.use((err, req, res, next) => {
    console.error('[ERROR]', err);
    res.status(err.status||500).render('error', {
        title:'Server Error', message:err.message, stack:err.stack,
        status:err.status||500, user:req.session.user||null,
    });
});

// ─── Start ────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`[SYNTEX] http://0.0.0.0:${PORT}  mode=${process.env.LAB_MODE||'easy'}`);
});

module.exports = app;
