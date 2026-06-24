# Contributing to Syntex Lab

Thank you for your interest in improving Syntex Lab. This document explains how to contribute new vulnerabilities, fixes, documentation, and features.

---

## ⚠️ Important — Ethical Scope

All contributions must be for **local, educational use only**. Do not add:
- Features that facilitate attacks on real third-party systems
- Modules that connect to external services without disclosure
- Real credentials, tokens, or API keys (use obviously fake placeholders)
- Content that targets specific real individuals or companies

---

## What You Can Contribute

| Type | Examples |
|------|---------|
| New vulnerability modules | SSTI, XXE, HTTP smuggling, cache poisoning |
| New flags | Additional proof points for existing vulns |
| Hint improvements | Clearer progression, better technical accuracy |
| Bug fixes | Route errors, view rendering bugs, seed failures |
| Documentation | Walkthroughs, methodology guides, tool tips |
| UI improvements | Better dark theme, mobile layout, accessibility |
| New challenge chains | Multi-step exploitation scenarios |

---

## Adding a New Vulnerability

Follow this checklist when adding a new vuln module:

### 1. Create the route file

Place new routes in `backend/routes/`. Use an existing file like `routes/advanced.js` as a reference.

```javascript
'use strict';

// ── Your Vulnerability Name ───────────────────────────────────────
// Vulnerability: describe what is intentionally broken here
// Tools: tools useful for exploiting this
// Payload: example attack payload

const express = require('express');
const router  = express.Router();
const { requireAuth } = require('../middleware/auth');

router.get('/your-endpoint', requireAuth, (req, res) => {
    // Intentionally vulnerable code here
    // Add a comment explaining the vulnerability
    res.render('vulns/your-view', { user: req.session.user });
});

module.exports = router;
```

### 2. Mount in server.js

Add your route to `backend/server.js` in the additive section:
```javascript
app.use('/', require('./routes/your-new-route'));
```

### 3. Create the view

Add `backend/views/vulns/your-view.ejs`. Use the existing vuln views as a template. Always include:
- `<%- include('../partials/navbar') %>` at the top
- `<%- include('../partials/footer') %>` at the bottom
- A lab notes section gated by `<% if(locals.lab && lab.showHints){ %>`

### 4. Add a flag

Add the flag to `seedExtraFlags()` in `backend/database/seed.js`:
```javascript
{
    slug:       'your-vuln-slug',
    flag:       'FLAG{YOUR_VULN_NAME_CONFIRMED}',
    title:      'Your Vulnerability Title',
    category:   'Category Name',
    severity:   'high',          // critical | high | medium | low | info
    points:     200,
    difficulty: 'medium',        // easy | medium | hard
    endpoint:   'POST /your-endpoint',
    hint:       'One sentence hint pointing to the proof point.',
},
```

**Flag naming convention:**
```
FLAG{CATEGORY_DESCRIPTION_OUTCOME}

Examples:
FLAG{SQLI_LOGIN_BYPASS_AUTH_COMPROMISED}
FLAG{SSTI_EJS_TEMPLATE_CODE_EXEC}
FLAG{IDOR_ADMIN_APIKEY_SECRETNOTE_LEAKED}
```

### 5. Add hints

Add 3 progressive hints to the `HINTS` object in `backend/routes/hints.js`:
```javascript
'your-vuln-slug': {
    title:    'Descriptive Title',
    category: 'Category',
    difficulty: 'medium',
    endpoint: 'POST /your-endpoint',
    file:     'routes/your-route.js',
    hints: [
        'Very subtle direction — do not give away the attack.',
        'More specific — name the parameter or field involved.',
        'Direct exploitation direction — which payload category to use.',
    ],
    solution: '/program/solutions/your-vuln-slug',
},
```

### 6. Add a walkthrough to SOLUTIONS.md

Follow the existing format:
- Severity, CVSS score, endpoint
- Vulnerability explanation with code snippet
- Step-by-step exploitation (numbered)
- Flag value
- Remediation code snippet

### 7. Update wordlist.txt

Add your new endpoint so it can be discovered by ffuf/gobuster:
```
your-endpoint
api/v1/your-endpoint
```

### 8. Update CHANGELOG.md

Add your change under a new version or the `[Unreleased]` section.

---

## Code Style

- Use `'use strict';` at the top of every JS file
- 4-space indentation
- Single quotes for strings
- Always add a vulnerability comment explaining what is intentionally broken
- Never sanitise inputs on vulnerable endpoints (that defeats the purpose)
- Gate hint content behind `LAB_MODE` checks where appropriate

---

## Vulnerability Design Rules

1. **Flags must be at the proof point** — the flag should only be readable if the vulnerability was actually exploited, not guessable from source code alone.

2. **No external dependencies** — the lab must work fully offline. Don't add modules that phone home or require internet access.

3. **Main site must look real** — `syntex.local` should feel like a corporate SaaS app. Don't add obvious CTF-style labels, hint banners, or vulnerability names to the main site UI.

4. **Platform site is the guide** — all hints, flags, challenges, and bounty features belong under `program.syntex.local` / `/program`.

5. **Docker safety** — bind any new ports to `127.0.0.1` only. Never expose services externally.

---

## Submitting Changes

Since this lab runs locally, the best way to share improvements is:

1. Fork the repository on GitHub
2. Make your changes following the checklist above
3. Test that `docker-compose up --build` works cleanly from scratch
4. Open a Pull Request with a clear description of what vulnerability was added and why it's useful for bug bounty practice

---

## Reporting Actual Bugs

If you find a real bug in the lab infrastructure (not an intentional vulnerability):

- Open a GitHub Issue
- Label it `bug` (not `vulnerability`)
- Include: exact error message, Docker version, OS, steps to reproduce

---

## Questions

Open a GitHub Discussion or Issue. We're happy to review new vulnerability ideas before you spend time implementing them.

---

*Build things that teach. Break things that are meant to be broken.*
