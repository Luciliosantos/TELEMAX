# TELEMAX — Diretório de Grupos e Canais do Telegram

Plataforma web completa (frontend + backend + banco) para listar, pesquisar e destacar
grupos e canais do Telegram em português. Domínio pretendido: **telemax.lsnet.shop**.

**Stack:** Python 3.10+ · Flask 3 · SQLite (WAL) · Jinja2 · gunicorn + Nginx em produção.
Sem dependências pesadas; instala em qualquer VPS Ubuntu com 1 GB de RAM.

## Recursos implementados

- Home com busca, categorias, destaques patrocinados, recentes, populares (por visualizações reais), banners e paginação
- URLs amigáveis: `/categorias/tecnologia`, `/grupos/nome-do-grupo`, `/busca?q=...`
- Cadastro/login/logout com senha scrypt, CSRF, rate-limit por IP+e-mail, bloqueio de conta, sessões server-side revogáveis, recuperação de senha por token de 1h
- Painel do usuário: publicar/editar grupos e canais (com validação de link `t.me`, deduplicação, upload de imagem seguro), status de moderação, contratação de destaque, histórico de pagamentos, alterar dados/senha
- Moderação administrativa: aprovar, rejeitar (com motivo), editar, remover; usuários, categorias, planos e preços, banners, pagamentos, configurações, logs de auditoria, mensagens de contato
- **Monetização Pix real:** criação de cobrança no gateway, QR Code + copia-e-cola, webhook assinado, verificação no gateway, ativação única (idempotente), expiração automática do destaque, histórico
- SEO: sitemap.xml automático, robots.txt, canonical, meta descriptions, noindex nas áreas privadas, páginas institucionais
- Segurança: hash scrypt, tokens de sessão com SHA-256 no banco, proteção de upload (magic bytes + limite 2 MB), path traversal negado, XSS escapado por Jinja, SQL parametrizado
- Dados de demonstração marcados como "DEMONSTRAÇÃO" (não são grupos reais)

## Instalação rápida (servidor Ubuntu 22.04+)

```bash
# 1) Dependências
sudo apt update && sudo apt install -y python3-venv python3-pip sqlite3
git init 2>/dev/null || true   # ou copie os arquivos do ZIP

# 2) Ambiente
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt gunicorn

# 3) Configuração
cp .env.example .env
nano .env                  # defina SECRET_KEY, PIX_WEBHOOK_SECRET e BASE_URL
export $(grep -v '^#' .env | xargs)

# 4) Banco de dados (migrações + categorias/planos/demos)
python -c "from telemax import create_app; create_app()"

# 5) Administrador inicial (senha forte, nunca padrão)
python scripts/create_admin.py

# 6) Testes (44 testes automatizados)
python -m unittest discover -s tests -v

# 7) Rodar em produção
gunicorn -w 4 -b 127.0.0.1:8000 wsgi:app
```

Em desenvolvimento: `python run.py` (porta 5000).
Veja `docs/DEPLOY.md` para Nginx, HTTPS, systemd, DNS, backups e atualização.

## Pagamentos Pix

- **Produção:** crie a conta no Mercado Pago, gere o token em
  https://www.mercadopago.com.br/developers/panel e preencha
  `PIX_PROVIDER=mercadopago` + `MERCADOPAGO_ACCESS_TOKEN` no `.env`.
  Webhook: `https://telemax.lsnet.shop/webhook/pix`.
  Passo a passo em `docs/PIX.md`.
- **Sandbox (`PIX_PROVIDER=demo`):** gera BR Code EMV real (chave fictícia) com QR,
  para testes locais. NÃO move dinheiro. Confirmação apenas por webhook assinado.

## Estrutura

```
telemax/            pacote (app factory, auth, public, user, admin, payments)
templates/          Jinja2 (público, auth, painel, admin)
static/             CSS neon/dark, JS leve, logo SVG
migrations/         001_core.sql (esquema) e 002_seed.sql (categorias/planos/demos)
tests/test_all.py   44 testes automatizados (auth, busca, moderação, pix, SEO, segurança)
scripts/            create_admin.py, expire_promotions.py, backup.sh
docs/               DEPLOY, PIX, SEO-GOOGLE, RELATORIO-TESTES
instance/           banco, uploads e logs (não versionar)
```

## Auditoria técnica v1.1 (21/10/2026)

Auditoria final executada sobre o ZIP entregue, em venv limpa com `requirements.txt`.
Achados corrigidos (detalhes e evidências em `docs/RELATORIO-TESTES.md`):

1. Webhook do Mercado Pago agora localiza a cobrança exclusivamente pelo
   `provider_ref` (id do gateway), eliminando confusão com ids internos.
2. A reconsulta na API do MP confere status + **valor** + **external_reference**
   antes de ativar qualquer destaque.
3. Ativação de promoção é atômica (reivindicação por UPDATE condicional) e a
   barreira final `UNIQUE(payment_id)` impede duplicação mesmo em corrida.
4. Assinatura `x-signature` do MP validada quando `MERCADOPAGO_WEBHOOK_SECRET`
   estiver configurado.

Suíte ampliada de 35 para **44 testes, todos passando** em venv recém-criada.

## Auditoria técnica v1.2 (21/10/2026)

Ponto apontado pelo usuário corrigido: a ativação da promoção agora é UMA
transação atômica (reivindicação do pagamento + inserção da promoção + COMMIT
único); falha na inserção faz rollback completo e o pagamento volta a 'pending'
(webhook pode reativar). Distingue, com verificação real no banco, promoção já
existente de falha genuína de inserção.

Verificações pedidas e implementadas:
1. Produção RECUSA iniciar com SECRET_KEY padrão/curta (<32).
2. PIX_PROVIDER=mercadopago RECUSA iniciar sem token válido (APP_USR-/TEST-)
   e sem MERCADOPAGO_WEBHOOK_SECRET (16+); cobrança também recusada sem token.
3. Erro temporário no gateway cancela a cobrança — nada fica 'pending' sem
   referência (test_42).
4. Suíte re-executada em venv recém-criada: **44/44 OK** (testes 41-44 novos).

Detalhes e evidências: `docs/RELATORIO-TESTES.md`.

## Pendências externas (nada escondido)

1. **Credenciais do gateway** (Mercado Pago) — código pronto; falta conta/token reais.
2. **Domínio e servidor** — `telemax.lsnet.shop` precisa de DNS apontando para o VPS
   (instruções em docs/DEPLOY.md). HTTPS via Let's Encrypt.
3. **SMTP** para e-mails reais de recuperação de senha (em dev, o link sai no log).
4. **Revisão jurídica** dos textos de Termos/Privacidade (são modelos técnicos).
5. Teste financeiro real (cobrança Pix com dinheiro verdadeiro) só é possível com a conta
   do gateway ativa; a suíte cobre toda a lógica de ativação/expiração com webhook assinado.
