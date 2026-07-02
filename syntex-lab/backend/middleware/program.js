'use strict';

// ── Program Platform Middleware ───────────────────────────────────

const PROGRAM_PATHS = ['/hints', '/reports', '/challenges', '/flags', '/bug-bounty', '/hall-of-fame', '/leaderboard', '/scope', '/solutions'];

let overrideMode = null;

function blockBountyOnMainSite(req, res, next) {
    const host = req.headers['x-vhost'] || req.headers.host || '';
    const isProgram = host.startsWith('program.') || host.startsWith('bounty.') || req.url.startsWith('/program');
    if (isProgram) return next();
    const path = req.path.toLowerCase();
    if (PROGRAM_PATHS.some(p => path.startsWith(p))) {
        return res.status(404).render('404', { title:'404', path:req.path, user:req.session.user||null });
    }
    next();
}

function getLabMode() {
    if (overrideMode) return overrideMode.toLowerCase();
    return (process.env.LAB_MODE || 'beginner').toLowerCase();
}

function setLabMode(newMode) {
    const valid = ['beginner','intermediate','hard','realistic'];
    if (!valid.includes(newMode.toLowerCase())) throw new Error(`Invalid mode: ${newMode}`);
    overrideMode = newMode.toLowerCase();
    console.log(`[LAB_MODE] Changed to: ${overrideMode}`);
}

// ── Feature visibility per mode ───────────────────────────────────
//
//  beginner     : hints on /program/hints page (3 levels unlocked freely)
//                 vuln pages show NO attack payloads — just the feature UI
//                 flags visible on /program/flags
//                 solutions visible
//
//  intermediate : hints on /program/hints page (must unlock level by level)
//                 vuln pages show NO payloads
//                 flags hidden
//                 solutions hidden
//
//  hard         : hints page LOCKED
//                 vuln pages show NO payloads
//                 flags hidden
//                 solutions hidden
//
//  realistic    : hints page LOCKED, flags LOCKED, challenges LOCKED
//                 only scope / rules / submit visible
//                 vuln pages show NO payloads

function labFeatureVisible(feature) {
    const mode = getLabMode();
    const rules = {
        // Hints PAGE at /program/hints
        hints:             { beginner:true,  intermediate:true,  hard:false, realistic:false },
        // Inline payloads / attack notes inside individual vuln pages
        inline_hints:      { beginner:false, intermediate:false, hard:false, realistic:false },
        // Hint unlock is free (all 3 levels show at once) vs sequential
        free_hint_unlock:  { beginner:true,  intermediate:false, hard:false, realistic:false },
        // Flag list at /program/flags
        flags:             { beginner:true,  intermediate:false, hard:false, realistic:false },
        // Flag values shown on flags page
        flag_values:       { beginner:true,  intermediate:false, hard:false, realistic:false },
        // Challenge missions
        challenges:        { beginner:true,  intermediate:true,  hard:true,  realistic:false },
        // Solutions writeups
        solutions:         { beginner:true,  intermediate:false, hard:false, realistic:false },
        // Vuln category names shown on flags/hints
        vuln_names:        { beginner:true,  intermediate:true,  hard:false, realistic:false },
        // Leaderboard
        leaderboard:       { beginner:true,  intermediate:true,  hard:true,  realistic:true  },
        // Example reports (accepted/duplicate etc)
        examples:          { beginner:true,  intermediate:true,  hard:true,  realistic:false },
    };
    return rules[feature]?.[mode] ?? true;
}

function enforceLabMode(feature) {
    return (req, res, next) => {
        if (!labFeatureVisible(feature)) {
            const mode = getLabMode();
            return res.status(403).render('program/mode-locked', {
                title:   `${feature.charAt(0).toUpperCase()+feature.slice(1)} — Locked`,
                feature, mode,
                user:    req.session.user || null,
                lab: {
                    mode,
                    bannerColor: { beginner:'#15803D', intermediate:'#B45309', hard:'#B91C1C', realistic:'#1B3A6B' }[mode],
                    bannerLabel: mode.toUpperCase(),
                    showBanner: true,
                    showHints: labFeatureVisible('hints'),
                    showFlags: labFeatureVisible('flags'),
                    showChallenges: labFeatureVisible('challenges'),
                },
            });
        }
        next();
    };
}

// Helper for views — cleaner than calling labFeatureVisible everywhere
function labLocals(req) {
    const mode = getLabMode();
    return {
        mode,
        showHints:       labFeatureVisible('hints'),
        showFlags:       labFeatureVisible('flags'),
        showChallenges:  labFeatureVisible('challenges'),
        showSolutions:   labFeatureVisible('solutions'),
        freeHintUnlock:  labFeatureVisible('free_hint_unlock'),
        inlineHints:     false,  // ALWAYS false — hints only on /program/hints
        showBanner:      true,
        bannerColor:     { beginner:'#15803D', intermediate:'#B45309', hard:'#B91C1C', realistic:'#1B3A6B' }[mode] || '#1B3A6B',
        bannerLabel:     mode.toUpperCase(),
    };
}

module.exports = { blockBountyOnMainSite, enforceLabMode, getLabMode, setLabMode, labFeatureVisible, labLocals };
