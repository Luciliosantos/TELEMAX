-- Fluxo simplificado da conexão SSH (CONFIRMAR SENHA + TESTAR CONEXÃO).
-- Senha SSH guardada criptografada (Fernet) e apagada após a chave funcionar.
-- Resultado do último teste, etapa a etapa, para exibir no painel.
ALTER TABLE bv_client_config ADD COLUMN vps_password_enc TEXT;
ALTER TABLE bv_client_config ADD COLUMN vps_last_result TEXT;
