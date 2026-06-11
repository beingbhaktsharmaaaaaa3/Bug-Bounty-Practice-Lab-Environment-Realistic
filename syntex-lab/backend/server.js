'use strict';

const express      = require('express');
const session      = require('express-session');
const cookieParser = require('cookie-parser');
const path         = require('path');

const app = express();

// ─── VIEW ENGINE ─────────────────────────────────────────────────────────────
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ─── MIDDLEWARE ───────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// VULNERABILITY: Weak session configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'syntex_session_secret_2024',
    resave: true,
    saveUninitialized: true,
    name: 'SYNTEX_SESS',          // Predictable session cookie name
    cookie: {
        httpOnly: false,          // VULNERABILITY: JS-accessible cookie (XSS can steal it)
        secure:   false,          // VULNERABILITY: Sent over HTTP
        maxAge:   30 * 24 * 60 * 60 * 1000,  // 30 days — too long
    },
}));

// CORS middleware (misconfigured — reflects any origin)
app.use(require('./middleware/cors'));

// Inject session user into all views
app.use((req, res, next) => {
    res.locals.user    = req.session.user    || null;
    res.locals.isAdmin = (req.session.role === 'admin') || (req.cookies.role === 'admin');
    next();
});

// ─── STATIC FILES ─────────────────────────────────────────────────────────────
// VULNERABILITY: Serves uploads directory publicly — no access control
app.use(express.static(path.join(__dirname, 'public')));

// ─── ROUTES ───────────────────────────────────────────────────────────────────
app.use('/',          require('./routes/misc'));          // robots.txt, sitemap, .env, debug, etc.
app.use('/',          require('./routes/auth'));          // login, register, logout
app.use('/dashboard', require('./routes/dashboard'));
app.use('/profile',   require('./routes/profile'));
app.use('/products',  require('./routes/products'));
app.use('/blog',      require('./routes/blog'));
app.use('/orders',    require('./routes/orders'));
app.use('/tickets',   require('./routes/tickets'));
app.use('/search',    require('./routes/search'));
app.use('/contact',   require('./routes/contact'));
app.use('/',          require('./routes/upload'));        // /upload, /download, /files
app.use('/admin',     require('./routes/admin'));
app.use('/api/v1',    require('./routes/api/v1'));
app.use('/api/v2',    require('./routes/api/v2'));

// Homepage
app.get('/', (req, res) => {
    if (req.session.userId) return res.redirect('/dashboard');
    res.render('index', { title: 'Syntex Solutions — Enterprise Resource Management' });
});

// ─── SETTINGS PAGE ────────────────────────────────────────────────────────────
const db = require('./database/db');
const { requireAuth } = require('./middleware/auth');

app.get('/settings', requireAuth, (req, res) => {
    res.render('settings', {
        title: 'Account Settings — Syntex Solutions',
        user: req.session.user,
        success: req.query.saved || null,
        error: null,
    });
});

// ─── 404 ──────────────────────────────────────────────────────────────────────
app.use((req, res) => {
    // VULNERABILITY: Reflects request path without sanitization (potential open redirect info)
    res.status(404).render('404', {
        title: '404 — Page Not Found',
        path:  req.path,
        user:  req.session.user || null,
    });
});

// ─── ERROR HANDLER ────────────────────────────────────────────────────────────
// VULNERABILITY: Exposes stack traces in all environments
app.use((err, req, res, next) => {
    console.error('[SERVER ERROR]', err);
    res.status(err.status || 500).render('error', {
        title:   'Server Error',
        message: err.message,
        stack:   err.stack,        // VULNERABILITY: Stack trace exposed to client
        status:  err.status || 500,
        user:    req.session.user || null,
    });
});

// ─── START ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`[SYNTEX] Server running on http://0.0.0.0:${PORT}`);
    console.log(`[SYNTEX] VULN_MODE: ${process.env.VULN_MODE || 'true'}`);
    console.log(`[SYNTEX] Environment: ${process.env.NODE_ENV || 'development'}`);
});

module.exports = app;
