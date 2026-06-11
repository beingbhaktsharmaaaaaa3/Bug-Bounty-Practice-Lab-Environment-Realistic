-- Syntex Solutions - Database Schema
-- Version: 2.4.1

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'user',
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    phone VARCHAR(20),
    address TEXT,
    department VARCHAR(50),
    job_title VARCHAR(100),
    avatar VARCHAR(255) DEFAULT '/img/avatar-default.png',
    bio TEXT,
    api_key VARCHAR(64),
    secret_note TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    two_factor_secret VARCHAR(32),
    login_attempts INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    last_login TIMESTAMP
);

CREATE TABLE IF NOT EXISTS password_resets (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    token VARCHAR(64) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    slug VARCHAR(200) UNIQUE,
    description TEXT,
    short_desc VARCHAR(300),
    price DECIMAL(10,2) NOT NULL,
    category VARCHAR(50),
    sku VARCHAR(50) UNIQUE,
    stock INTEGER DEFAULT 999,
    image_url VARCHAR(255),
    features TEXT,
    version VARCHAR(20),
    license_type VARCHAR(50),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS reviews (
    id SERIAL PRIMARY KEY,
    product_id INTEGER REFERENCES products(id),
    user_id INTEGER REFERENCES users(id),
    author_name VARCHAR(100),
    rating INTEGER CHECK (rating BETWEEN 1 AND 5),
    content TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    product_id INTEGER REFERENCES products(id),
    quantity INTEGER NOT NULL,
    unit_price DECIMAL(10,2) NOT NULL,
    total_price DECIMAL(10,2) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    coupon_code VARCHAR(20),
    discount DECIMAL(10,2) DEFAULT 0.00,
    shipping_address TEXT,
    billing_address TEXT,
    notes TEXT,
    invoice_number VARCHAR(50),
    license_key VARCHAR(64),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS blog_posts (
    id SERIAL PRIMARY KEY,
    title VARCHAR(300) NOT NULL,
    slug VARCHAR(300) UNIQUE,
    content TEXT NOT NULL,
    excerpt TEXT,
    author_id INTEGER REFERENCES users(id),
    category VARCHAR(50),
    tags TEXT,
    status VARCHAR(20) DEFAULT 'published',
    views INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS comments (
    id SERIAL PRIMARY KEY,
    post_id INTEGER REFERENCES blog_posts(id),
    user_id INTEGER REFERENCES users(id),
    author_name VARCHAR(100),
    content TEXT NOT NULL,
    is_approved BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS tickets (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    subject VARCHAR(200) NOT NULL,
    message TEXT NOT NULL,
    status VARCHAR(20) DEFAULT 'open',
    priority VARCHAR(20) DEFAULT 'medium',
    category VARCHAR(50),
    assigned_to INTEGER REFERENCES users(id),
    internal_notes TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ticket_replies (
    id SERIAL PRIMARY KEY,
    ticket_id INTEGER REFERENCES tickets(id),
    user_id INTEGER REFERENCES users(id),
    message TEXT NOT NULL,
    is_staff BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS notifications (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    title VARCHAR(200),
    message TEXT,
    type VARCHAR(20) DEFAULT 'info',
    is_read BOOLEAN DEFAULT FALSE,
    link VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS coupons (
    id SERIAL PRIMARY KEY,
    code VARCHAR(20) UNIQUE NOT NULL,
    discount_percent INTEGER NOT NULL,
    max_uses INTEGER DEFAULT 100,
    used_count INTEGER DEFAULT 0,
    expires_at TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    created_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS coupon_uses (
    id SERIAL PRIMARY KEY,
    coupon_id INTEGER REFERENCES coupons(id),
    user_id INTEGER REFERENCES users(id),
    order_id INTEGER REFERENCES orders(id),
    used_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER,
    action VARCHAR(100),
    resource VARCHAR(100),
    resource_id INTEGER,
    ip_address VARCHAR(50),
    user_agent TEXT,
    details TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS api_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    token VARCHAR(64) UNIQUE NOT NULL,
    name VARCHAR(100),
    permissions TEXT DEFAULT 'read',
    last_used TIMESTAMP,
    expires_at TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS files (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    original_name VARCHAR(255),
    stored_name VARCHAR(255),
    file_path VARCHAR(500),
    file_size INTEGER,
    mime_type VARCHAR(100),
    is_public BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sessions_custom (
    id SERIAL PRIMARY KEY,
    session_token VARCHAR(128) NOT NULL,
    user_id INTEGER REFERENCES users(id),
    ip_address VARCHAR(50),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP
);
