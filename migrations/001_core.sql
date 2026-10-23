-- TELEMAX: esquema inicial
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nickname TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','admin')),
    is_active INTEGER NOT NULL DEFAULT 1,
    failed_logins INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT
);

CREATE TABLE user_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT NOT NULL UNIQUE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip TEXT, user_agent TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT
);
CREATE INDEX idx_sessions_user ON user_sessions(user_id);

CREATE TABLE login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT, email TEXT, ok INTEGER, ts TEXT NOT NULL
);
CREATE INDEX idx_attempts_ip ON login_attempts(ip, email, ts);

CREATE TABLE password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    used_at TEXT
);

CREATE TABLE categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE telegram_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    link TEXT NOT NULL UNIQUE,
    image_path TEXT,
    category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL,
    type TEXT NOT NULL DEFAULT 'group' CHECK (type IN ('group','channel')),
    keywords TEXT NOT NULL DEFAULT '',
    owner_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected','removed')),
    rejection_reason TEXT,
    is_demo INTEGER NOT NULL DEFAULT 0,
    views INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT,
    published_at TEXT
);
CREATE INDEX idx_groups_status ON telegram_groups(status, published_at);
CREATE INDEX idx_groups_category ON telegram_groups(category_id, status);
CREATE INDEX idx_groups_owner ON telegram_groups(owner_id);

CREATE TABLE plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    days INTEGER NOT NULL CHECK (days > 0),
    price_cents INTEGER NOT NULL CHECK (price_cents >= 0),
    description TEXT NOT NULL DEFAULT '',
    is_active INTEGER NOT NULL DEFAULT 1,
    sort INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    group_id INTEGER REFERENCES telegram_groups(id) ON DELETE SET NULL,
    plan_id INTEGER REFERENCES plans(id) ON DELETE SET NULL,
    amount_cents INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','paid','expired','cancelled')),
    provider TEXT NOT NULL,
    provider_ref TEXT UNIQUE,
    pix_code TEXT,
    pix_qr_b64 TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    paid_at TEXT,
    idempotency TEXT UNIQUE
);
CREATE INDEX idx_payments_user ON payments(user_id);

CREATE TABLE promotions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER NOT NULL REFERENCES telegram_groups(id) ON DELETE CASCADE,
    payment_id INTEGER NOT NULL UNIQUE REFERENCES payments(id),
    plan_id INTEGER REFERENCES plans(id) ON DELETE SET NULL,
    starts_at TEXT NOT NULL,
    ends_at TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX idx_promos_group ON promotions(group_id, is_active);

CREATE TABLE banners (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    image_path TEXT,
    link TEXT NOT NULL DEFAULT '',
    position TEXT NOT NULL DEFAULT 'home_top' CHECK (position IN ('home_top','home_mid','home_bottom')),
    is_active INTEGER NOT NULL DEFAULT 1,
    views INTEGER NOT NULL DEFAULT 0,
    clicks INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE contact_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL, email TEXT NOT NULL, message TEXT NOT NULL,
    handled INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
);

CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id INTEGER, action TEXT NOT NULL, entity TEXT NOT NULL,
    entity_id INTEGER, details TEXT, ip TEXT, created_at TEXT NOT NULL
);
CREATE INDEX idx_audit_created ON audit_log(created_at);
