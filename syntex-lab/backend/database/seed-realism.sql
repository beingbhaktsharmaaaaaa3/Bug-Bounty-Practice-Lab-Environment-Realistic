-- ================================================================
-- Syntex Lab v4.2 — Realism Seed
-- Run this ONCE after your main seed to add realistic noise data.
-- Real bug bounty is 80% noise — this simulates that.
-- ================================================================

-- ── Employee Directory (sensitive IDOR target) ──────────────────
CREATE TABLE IF NOT EXISTS employees (
    id             SERIAL PRIMARY KEY,
    user_id        INTEGER REFERENCES users(id) ON DELETE SET NULL,
    full_name      VARCHAR(100),
    email          VARCHAR(100),
    department     VARCHAR(50),
    job_title      VARCHAR(100),
    phone          VARCHAR(30),
    location       VARCHAR(80),
    salary         INTEGER,
    ssn_last4      VARCHAR(4),
    access_level   VARCHAR(20) DEFAULT 'standard',
    internal_notes TEXT,
    is_active      BOOLEAN DEFAULT true,
    hire_date      DATE DEFAULT NOW()
);

INSERT INTO employees (user_id,full_name,email,department,job_title,phone,location,salary,ssn_last4,access_level,internal_notes) VALUES
(1,   'Alex Morrison',  'alex.morrison@syntex.local',  'Engineering',      'Chief Technology Officer',    '+1-415-555-0191','San Francisco, CA',285000,'4421','admin',    'Has root access to all prod systems. SSH key in vault.'),
(2,   'John Doe',       'john.doe@syntex.local',       'Engineering',      'Senior Backend Engineer',     '+1-415-555-0147','San Francisco, CA',165000,'8823','developer','Primary contact for API team. 2FA enrolled.'),
(3,   'Jane Smith',     'jane.smith@syntex.local',     'Finance',          'Finance Director',            '+1-628-555-0183','New York, NY',     195000,'3317','finance',  'QuickBooks admin. SOX compliance lead.'),
(4,   'Alice Wong',     'alice.wong@syntex.local',     'Marketing',        'Growth Marketing Manager',    '+1-310-555-0129','Los Angeles, CA',  125000,'6692','standard', 'HubSpot admin. GA4 property owner.'),
(5,   'Bob Johnson',    'bob.johnson@syntex.local',    'Sales',            'Account Executive',           '+1-312-555-0162','Chicago, IL',       95000,'7734','standard', 'Salesforce CRM. Enterprise quota: $2.1M.'),
(6,   'Dev Patel',      'dev.patel@syntex.local',      'Engineering',      'DevOps Engineer',             '+1-415-555-0104','San Francisco, CA',155000,'2281','admin',    'AWS root account holder. Terraform state in S3.'),
(7,   'Sarah Chen',     'support@syntex.local',        'Customer Success', 'Support Lead',                '+1-415-555-0173','Austin, TX',        88000,'9910','support',  'Zendesk admin. Handles escalated tickets.'),
(NULL,'Maria Garcia',   'maria.garcia@syntex.local',   'Legal',            'General Counsel',             '+1-212-555-0148','New York, NY',     285000,'5567','legal',    'NDA authority. M&A project: CONFIDENTIAL.'),
(NULL,'Tom Bradley',    'tom.bradley@syntex.local',    'Engineering',      'Staff Engineer (Ex)',         '+1-415-555-0119','Remote',                0,'1193','revoked',  'TERMINATED 2024-09-15. Access revoked? Confirm IT.'),
(NULL,'Nina Okafor',    'nina.okafor@syntex.local',    'Finance',          'Senior Accountant',           '+1-628-555-0145','New York, NY',     115000,'4458','finance',  'P&L owner. QuickBooks Admin.')
ON CONFLICT DO NOTHING;

-- ── API Tokens with scopes ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS api_tokens_v2 (
    id         SERIAL PRIMARY KEY,
    user_id    INTEGER REFERENCES users(id),
    token      VARCHAR(80) UNIQUE NOT NULL,
    name       VARCHAR(100),
    scope      TEXT,
    expires_at TIMESTAMP,
    is_revoked BOOLEAN DEFAULT false,
    last_used  TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

INSERT INTO api_tokens_v2 (user_id,token,name,scope,expires_at,is_revoked) VALUES
(1,'sk_prod_9f8e7d6c5b4a3z2y1x_ADMIN_FULL',   'Production Admin Key',      'admin:all read:all write:all delete:all',    NOW()+INTERVAL '1 year',   false),
(1,'sk_prod_OLD_2023_KEY_DEPRECATED_admin',    'Old Admin Key (2023)',       'admin:all read:all write:all',               NOW()-INTERVAL '6 months', false),
(2,'sk_dev_b2c3d4e5f6a7_backend_readwrite',   'Backend Dev Token',          'read:users write:orders read:products',      NOW()+INTERVAL '6 months', false),
(3,'sk_finance_f9e8d7c6b5_readonly',           'Finance Read Token',         'read:invoices read:reports',                 NOW()+INTERVAL '1 year',   false),
(6,'sk_devops_x1y2z3_deploy_k8s',             'DevOps Deploy Token',        'admin:deploy read:all write:config admin:k8s',NOW()+INTERVAL '3 months', false),
(4,'sk_mktg_m1n2o3_analytics_only',           'Marketing Analytics',        'read:analytics read:users',                  NOW()+INTERVAL '1 year',   false),
(2,'sk_test_TESTING_DO_NOT_USE_PROD',         'Test Token (DEV ONLY)',      'admin:all read:all write:all delete:all',    NOW()+INTERVAL '5 years',  false),
(1,'sk_webhook_wh_9k8j7h6g5f4_stripe',       'Stripe Webhook Secret',      'webhook:receive',                             NOW()+INTERVAL '2 years',  false)
ON CONFLICT DO NOTHING;

-- ── Realistic invoices ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS invoices (
    id             SERIAL PRIMARY KEY,
    invoice_number VARCHAR(30) UNIQUE,
    user_id        INTEGER REFERENCES users(id),
    company_name   VARCHAR(100),
    amount         DECIMAL(10,2),
    tax_amount     DECIMAL(10,2),
    status         VARCHAR(20) DEFAULT 'paid',
    billing_email  VARCHAR(100),
    card_last4     VARCHAR(4),
    notes          TEXT,
    due_date       DATE DEFAULT NOW()+30,
    created_at     TIMESTAMP DEFAULT NOW()
);

INSERT INTO invoices (invoice_number,user_id,company_name,amount,tax_amount,billing_email,card_last4,status,notes) VALUES
('INV-2024-001847',2,'Acme Corporation',      4999.00,449.91,'billing@acme.com',      '4242','paid',   'Enterprise license — 500 seats. Renewal due Jan 2025.'),
('INV-2024-001848',3,'GlobalTech Solutions',  1299.00,116.91,'ap@globaltech.com',      '1234','paid',   'Professional plan — annual.'),
('INV-2024-001849',4,'StartupXYZ Inc',         199.00, 17.91,'cfo@startupxyz.io',     '5678','overdue','OVERDUE 45 days — sent 3 reminders — escalate to collections.'),
('INV-2024-001850',5,'MegaCorp Industries',  24999.00,2249.91,'procurement@megacorp.com','9012','paid', 'Enterprise+ unlimited seats. Custom MSA. CONFIDENTIAL.'),
('INV-2024-001851',2,'Dev Studio LLC',         599.00, 53.91,'hello@devstudio.co',    '3456','pending','Trial upgrade — awaiting PO from procurement.'),
('INV-2024-001852',3,'Healthcare Partners',   9999.00,899.91,'it@healthcarepartners.org','7890','paid','HIPAA BAA signed. Data processing addendum attached.')
ON CONFLICT DO NOTHING;

-- ── Tenants (multi-tenant IDOR target) ────────────────────────────
CREATE TABLE IF NOT EXISTS tenants (
    id            SERIAL PRIMARY KEY,
    slug          VARCHAR(50) UNIQUE,
    name          VARCHAR(100),
    plan          VARCHAR(30),
    owner_user_id INTEGER REFERENCES users(id),
    config        JSONB DEFAULT '{}',
    secret_key    VARCHAR(80),
    created_at    TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS tenant_memberships (
    id        SERIAL PRIMARY KEY,
    tenant_id INTEGER REFERENCES tenants(id),
    user_id   INTEGER REFERENCES users(id),
    role      VARCHAR(20) DEFAULT 'member',
    UNIQUE(tenant_id, user_id)
);

INSERT INTO tenants (slug,name,plan,owner_user_id,secret_key) VALUES
('acme-corp',     'Acme Corporation',    'enterprise',  2,'tenant_sk_acme_9f8e7d6c5b4a3b2c1d'),
('globaltech',    'GlobalTech Solutions','professional',3,'tenant_sk_global_a1b2c3d4e5f6g7h8'),
('syntex-internal','Syntex Internal',   'internal',    1,'tenant_sk_internal_CONFIDENTIAL_FLAG{MULTI_TENANT_AUTHZ_CROSS_TENANT_DATA}')
ON CONFLICT (slug) DO NOTHING;

INSERT INTO tenant_memberships (tenant_id,user_id,role)
SELECT id,owner_user_id,'owner' FROM tenants ON CONFLICT DO NOTHING;

-- ── Webhooks ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS webhooks (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER REFERENCES users(id),
    url         VARCHAR(500),
    secret      VARCHAR(80),
    events      TEXT[],
    is_active   BOOLEAN DEFAULT true,
    created_at  TIMESTAMP DEFAULT NOW()
);

INSERT INTO webhooks (user_id,url,secret,events) VALUES
(1,'http://internal-processor:8080/webhook','whsec_k7l8m9n0p1q2r3s4t5u6v7w8x9y0z1a2b3',
 ARRAY['payment.success','payment.failed','user.created'])
ON CONFLICT DO NOTHING;

-- ── Realistic audit log noise ─────────────────────────────────────
INSERT INTO audit_logs (user_id,action,details,created_at) VALUES
(1,'user_login',        'Successful login from 10.0.0.15 (VPN)',                          NOW()-INTERVAL '2 days'),
(1,'admin_action',      'Modified user permissions for user_id=4',                        NOW()-INTERVAL '3 days'),
(2,'api_call',          'GET /api/v1/users — 200 OK — 847 records returned',              NOW()-INTERVAL '1 day'),
(3,'export_data',       'Exported Q3 financial report — 2847 rows',                       NOW()-INTERVAL '5 days'),
(6,'deploy',            'Deployed syntex-api:v2.4.1 to production (ECS)',                 NOW()-INTERVAL '7 days'),
(1,'password_change',   'Admin reset password for user_id=7',                             NOW()-INTERVAL '4 days'),
(4,'login_failed',      'Failed login — wrong password — IP: 185.220.101.45',             NOW()-INTERVAL '1 day'),
(4,'login_failed',      'Failed login — wrong password — IP: 185.220.101.45',             NOW()-INTERVAL '1 day'),
(4,'login_failed',      'Failed login — wrong password — IP: 185.220.101.45',             NOW()-INTERVAL '1 day'),
(1,'security_alert',    'ALERT: 3 consecutive failed logins for alice.wong',               NOW()-INTERVAL '1 day'),
(6,'config_change',     'Updated S3 bucket policy — syntex-uploads-prod — removed public block', NOW()-INTERVAL '10 days'),
(1,'admin_action',      'Granted admin role to user_id=6 (temporary DevOps incident)',    NOW()-INTERVAL '8 days'),
(2,'data_access',       'Accessed user profile user_id=1 (admin) from session abc123',    NOW()-INTERVAL '2 days'),
(7,'ticket_update',     'Escalated ticket #847 to engineering — customer: Acme Corp',     NOW()-INTERVAL '3 days'),
(NULL,'system',         'Scheduled backup completed — syntex_db — 2.4GB — S3',           NOW()-INTERVAL '1 day'),
(NULL,'system',         'SSL cert expiry warning — expires in 30 days — cdn.syntex.local',NOW()-INTERVAL '6 hours'),
(6,'deploy',            'Rolled back syntex-api:v2.4.0 — health check failed',            NOW()-INTERVAL '9 days'),
(1,'admin_action',      'EMERGENCY: Disabled account tom.bradley — termination',          NOW()-INTERVAL '30 days'),
(NULL,'system',         'Cron failed: /opt/syntex/scripts/cleanup_old_sessions.sh — exit 1', NOW()-INTERVAL '2 days'),
(2,'api_call',          'POST /api/v1/orders — created order INV-20241201-0847',          NOW()-INTERVAL '1 day')
ON CONFLICT DO NOTHING;

-- ── Password reset tokens (token reuse vuln targets) ─────────────
INSERT INTO password_resets (email,token,expires_at)
VALUES
 ('john.doe@syntex.local', 'reset_john_2024_USED_NOT_CLEARED', NOW()+INTERVAL '1 hour'),
 ('admin@syntex.local',    'reset_admin_old_TOKEN_REUSABLE',   NOW()+INTERVAL '1 hour')
ON CONFLICT DO NOTHING;

-- ── Realistic notification noise ──────────────────────────────────
INSERT INTO notifications (user_id,title,message,type,link,is_read) VALUES
(2,'Invoice #INV-2024-001847 paid',    'Acme Corp — $4,999.00 received',                'success','/orders',      true),
(3,'Overdue invoice reminder',          'INV-2024-001849 — StartupXYZ — 45 days overdue','warning','/orders',      false),
(1,'Security alert — 3 failed logins', 'User alice.wong had 3 consecutive failures',     'danger', '/admin/logs',  false),
(2,'New ticket submitted',              'Ticket #892 from Acme Corp — P1 severity',      'info',   '/tickets',     false),
(6,'Deployment successful',             'syntex-api:v2.4.1 deployed to production',      'success','/admin',       true),
(1,'SSL certificate expiring',          'cdn.syntex.local cert expires in 30 days',      'warning','/admin/settings',false),
(3,'Q3 report exported',                'Financial report export completed — 2847 rows', 'info',   '/orders',      true),
(4,'Marketing integration connected',   'HubSpot sync configured — 1,247 contacts',     'success','/dashboard',   true),
(7,'Ticket escalated',                  'Ticket #847 escalated to Engineering team',     'info',   '/tickets/847', false),
(2,'API rate limit warning',            'Your API key approached the rate limit (8k/10k)','warning','/settings',    false)
ON CONFLICT DO NOTHING;
