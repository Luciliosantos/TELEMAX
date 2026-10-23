-- Módulo Bot Vendas VPN (assinatura paga, separada dos planos de divulgação)
-- Estende payments com "purpose" p/ despachar a ativação no webhook existente.
ALTER TABLE payments ADD COLUMN purpose TEXT NOT NULL DEFAULT 'promotion';
ALTER TABLE payments ADD COLUMN target_id INTEGER;

CREATE TABLE bv_plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    price_cents INTEGER NOT NULL CHECK (price_cents >= 0),
    days INTEGER NOT NULL CHECK (days > 0),
    max_vpn_plans INTEGER NOT NULL DEFAULT 3,
    features TEXT NOT NULL DEFAULT '',
    is_active INTEGER NOT NULL DEFAULT 1,
    sort INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL, updated_at TEXT
);

CREATE TABLE bv_subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    plan_id INTEGER NOT NULL REFERENCES bv_plans(id),
    status TEXT NOT NULL DEFAULT 'pendente'
        CHECK (status IN ('ativa','pendente','expirada','cancelada','suspensa')),
    starts_at TEXT, ends_at TEXT NOT NULL,
    cancel_reason TEXT, suspend_reason TEXT,
    last_payment_id INTEGER,
    created_at TEXT NOT NULL, updated_at TEXT
);
CREATE INDEX idx_bvsubs_user ON bv_subscriptions(user_id, status);

CREATE TABLE bv_client_config (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    bot_token_enc TEXT, bot_username TEXT,
    owner_tg_id TEXT, link_code TEXT UNIQUE,
    vps_host TEXT, vps_port INTEGER NOT NULL DEFAULT 22,
    vps_user TEXT NOT NULL DEFAULT 'botvendas',
    vps_sshkey_enc TEXT, vps_pubkey TEXT,
    vps_use_sudo INTEGER NOT NULL DEFAULT 1,
    vps_ok INTEGER NOT NULL DEFAULT 0, vps_last_test TEXT,
    mp_token_enc TEXT,
    apk_filename TEXT, apk_size INTEGER,
    published_layout TEXT, draft_layout TEXT,
    bot_status TEXT NOT NULL DEFAULT 'stopped' CHECK (bot_status IN ('stopped','running','error')),
    bot_error TEXT, tg_offset INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL, updated_at TEXT
);

CREATE TABLE bv_vpn_plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    price_cents INTEGER NOT NULL CHECK (price_cents >= 0),
    days INTEGER NOT NULL CHECK (days > 0),
    max_connections INTEGER NOT NULL DEFAULT 1,
    is_test INTEGER NOT NULL DEFAULT 0, test_hours INTEGER,
    is_active INTEGER NOT NULL DEFAULT 1, sort INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE INDEX idx_bvvpn_user ON bv_vpn_plans(user_id, is_active);

CREATE TABLE bv_sales (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    vpn_plan_id INTEGER REFERENCES bv_vpn_plans(id) ON DELETE SET NULL,
    buyer_tg_id TEXT, buyer_name TEXT,
    kind TEXT NOT NULL DEFAULT 'sale' CHECK (kind IN ('sale','test')),
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','delivered','cancelled','expired','failed')),
    ssh_user TEXT, ssh_pass_enc TEXT, ssh_expires_at TEXT,
    mp_payment_id TEXT UNIQUE, amount_cents INTEGER,
    delivered_at TEXT, created_at TEXT NOT NULL, updated_at TEXT
);
CREATE INDEX idx_bvsale_user ON bv_sales(user_id, status);

CREATE TABLE bv_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER, action TEXT NOT NULL, detail TEXT, ts TEXT NOT NULL
);
CREATE INDEX idx_bvaudit_user ON bv_audit(user_id, ts);
