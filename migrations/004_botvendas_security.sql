-- Endurecimento do módulo Bot Vendas VPN (2026-10-22)
-- 1) Confiança explícita da chave do servidor SSH (TOFU com confirmação no painel)
ALTER TABLE bv_client_config ADD COLUMN vps_fingerprint TEXT;
ALTER TABLE bv_client_config ADD COLUMN vps_fp_type TEXT;
ALTER TABLE bv_client_config ADD COLUMN vps_fp_confirmed_at TEXT;

-- 2) Estado 'provisioning' na entrega: reivindicação atômica ANTES de tocar a VPS,
--    com recuperação segura de operações interrompidas (sem conta duplicada).
DROP TABLE IF EXISTS bv_sales_new;
CREATE TABLE bv_sales_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    vpn_plan_id INTEGER REFERENCES bv_vpn_plans(id) ON DELETE SET NULL,
    buyer_tg_id TEXT, buyer_name TEXT,
    kind TEXT NOT NULL DEFAULT 'sale' CHECK (kind IN ('sale','test')),
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','provisioning','delivered','cancelled',
                          'expired','failed')),
    ssh_user TEXT, ssh_pass_enc TEXT, ssh_expires_at TEXT,
    mp_payment_id TEXT UNIQUE, amount_cents INTEGER,
    provision_attempts INTEGER NOT NULL DEFAULT 0,
    delivered_at TEXT, created_at TEXT NOT NULL, updated_at TEXT
);
INSERT INTO bv_sales_new(id, user_id, vpn_plan_id, buyer_tg_id, buyer_name, kind,
    status, ssh_user, ssh_pass_enc, ssh_expires_at, mp_payment_id, amount_cents,
    provision_attempts, delivered_at, created_at, updated_at)
    SELECT id, user_id, vpn_plan_id, buyer_tg_id, buyer_name, kind, status,
           ssh_user, ssh_pass_enc, ssh_expires_at, mp_payment_id, amount_cents,
           0, delivered_at, created_at, updated_at
    FROM bv_sales;
DROP TABLE bv_sales;
ALTER TABLE bv_sales_new RENAME TO bv_sales;
CREATE INDEX idx_bvsale_user ON bv_sales(user_id, status);
CREATE INDEX idx_bvsale_pending ON bv_sales(status, updated_at);

-- 3) Limite de teste grátis imposto pelo banco (1 por comprador/dia/cliente),
--    à prova de toques simultâneos. Só vale para kind='test' (vendas livres).
ALTER TABLE bv_sales ADD COLUMN test_day TEXT;
UPDATE bv_sales SET test_day = substr(created_at,1,10) WHERE kind='test';
CREATE UNIQUE INDEX uq_bvsale_test_dia
    ON bv_sales(user_id, buyer_tg_id, test_day) WHERE kind='test' AND test_day IS NOT NULL;
