-- ================================================================
-- Syntex Lab v4.3 — Missing Categories Flags
-- ================================================================

INSERT INTO vuln_flags (slug, flag_value, vuln_title, category, severity, points, difficulty, endpoint, location_hint, is_active)
VALUES

-- Cache Deception
('cache-deception-easy',
 'FLAG{CACHE_DECEPTION_STATIC_EXT_PRIVATE_DATA}',
 'Cache Deception — Static Extension Trick',
 'Cache Deception', 'medium', 150, 'easy',
 'GET /profile/me.css',
 'A .css extension on a dynamic profile page gets publicly cached.', true),

('cache-deception-medium',
 'FLAG{CACHE_DECEPTION_PATH_CONFUSION_TOKEN_LEAK}',
 'Cache Deception — Path Confusion Token Leak',
 'Cache Deception', 'high', 200, 'medium',
 'GET /account/settings/x.js',
 'Append a fake static extension to a dynamic path segment to leak session data.', true),

-- HTTP Request Smuggling
('http-smuggling-clte',
 'FLAG{HTTP_SMUGGLING_CLTE_DESYNC_DETECTED}',
 'HTTP Request Smuggling — CL.TE Desync',
 'HTTP Request Smuggling', 'critical', 300, 'medium',
 'POST /smuggling/front-end',
 'Send a request with both Content-Length and Transfer-Encoding headers.', true),

('http-smuggling-tete',
 'FLAG{HTTP_SMUGGLING_TETE_OBFUSCATION_BYPASS}',
 'HTTP Request Smuggling — TE.TE Obfuscation',
 'HTTP Request Smuggling', 'critical', 350, 'hard',
 'POST /smuggling/back-end',
 'Obfuscate the Transfer-Encoding header to desync front/back-end parsing.', true),

-- Secondary Context Vulnerabilities
('secondary-context-pdf',
 'FLAG{SECONDARY_CONTEXT_PDF_RENDERER_XSS_SSRF}',
 'Secondary Context — PDF Renderer XSS/SSRF',
 'Secondary Context', 'high', 250, 'medium',
 'POST /pdf-export',
 'Inject HTML/script into invoice notes that get rendered by a headless browser PDF generator.', true),

('secondary-context-image',
 'FLAG{SECONDARY_CONTEXT_IMAGE_PROCESSOR_RCE}',
 'Secondary Context — Image Processor RCE',
 'Secondary Context', 'critical', 350, 'hard',
 'POST /image-resize',
 'Inject a command or MVG payload into the filename processed by the image converter.', true),

-- Client-Side Template Injection
('csti-basic',
 'FLAG{CSTI_CLIENT_TEMPLATE_SANDBOX_ESCAPE_XSS}',
 'Client-Side Template Injection — Sandbox Escape',
 'CSTI', 'high', 200, 'medium',
 '/csti (client-side only)',
 'Use {{constructor.constructor(...)()}} to escape the client-side template sandbox.', true),

-- PostMessage Issues
('postmessage-origin',
 'FLAG{POSTMESSAGE_NO_ORIGIN_CHECK_XSS}',
 'PostMessage — Missing Origin Check Leads to XSS',
 'PostMessage', 'high', 200, 'medium',
 '/postmessage-demo',
 'Send a postMessage with an html field to a listener missing origin validation.', true),

-- Weak Password Checks
('weak-password-policy',
 'FLAG{WEAK_PASSWORD_POLICY_NO_COMPLEXITY_ENFORCED}',
 'Weak Password Policy — No Complexity Enforcement',
 'Weak Password Policy', 'medium', 100, 'easy',
 'POST /register-weak',
 'Register with a short, simple, or common password to confirm no policy is enforced.', true)

ON CONFLICT (slug) DO UPDATE SET
    flag_value = EXCLUDED.flag_value, vuln_title = EXCLUDED.vuln_title,
    category = EXCLUDED.category, severity = EXCLUDED.severity,
    points = EXCLUDED.points, difficulty = EXCLUDED.difficulty,
    endpoint = EXCLUDED.endpoint, location_hint = EXCLUDED.location_hint;
