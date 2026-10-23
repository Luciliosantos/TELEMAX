# Relatório de testes e auditoria — TELEMAX v1.2.1 (21/10/2026)

> Histórico de versões:
> - **v1.0** — entrega inicial (35 testes).
> - **v1.1** — auditoria técnica: 3 correções no módulo Pix (lookup por
>   provider_ref; reconsulta confere valor + external_reference; reivindicação
>   com rowcount). Suíte ampliada para 40 testes.
> - **v1.2** — ponto apontado pelo usuário: ativação de promoção agora é
>   transação única atômica; guards de produção (SECRET_KEY e credenciais do
>   Mercado Pago); cancelamento de cobrança em falha temporária do gateway.
>   Suíte ampliada para 44 testes.
> - **v1.2.1** — apenas correção desta documentação: o relatório da v1.2 não
>   chegou a ser gravado com as informações de 44 testes (v1.1/40 ficou no
>   arquivo). Nenhuma mudança de código ou de banco.

## 1. Ambiente de execução (real, verificado nesta versão)

- **Comando:** `python -m unittest discover -s tests -v` (suíte em
  `tests/test_all.py`)
- **Python:** 3.11.17
- **Ambiente:** venv recém-criada, instalando apenas `requirements.txt`
  com `pip install --no-cache-dir` (nenhum pacote de sessões anteriores)
- **Dependências instaladas (pip freeze):** blinker 1.9.0, click 8.5.0,
  Flask 3.1.3, itsdangerous 2.2.0, Jinja2 3.1.6, MarkupSafe 3.0.4,
  segno 1.6.6, Werkzeug 3.1.9
- **Resultado global: `Ran 44 tests — OK` (44 aprovados, 0 falhas, 0 erros)**
  — tempo de execução ~5,5 s

## 2. Achados da auditoria de código

### Rodada v1.1 — 3 bugs reais corrigidos

| # | Problema | Correção |
|---|----------|----------|
| 1 | Webhook localizava cobrança por `id = ? OR provider_ref = ?`; notificação do Mercado Pago com id numérico podia coincidir com id interno de outra cobrança | MP busca SOMENTE por `provider_ref` + `provider='mercadopago'`; demo somente por id interno |
| 2 | `check_paid` do MP conferia apenas `status == "approved"` | Confere status + `transaction_amount == amount_cents` + `external_reference == "telemax-{id}"` |
| 3 | Checagem de status e UPDATE em comandos separados (janela de corrida) | Reivindicação atômica por UPDATE condicional com rowcount |

### Rodada v1.2 — ponto do usuário + verificação de configuração

1. **Transação atômica (ponto apontado pelo usuário):** em v1.1 o pagamento
   virava `paid` com commit ANTES da inserção da promoção; se a inserção
   falhasse, ficava "pago sem promoção" e nenhum webhook retentava. Agora é
   UMA transação (`BEGIN IMMEDIATE` → UPDATE condicional → INSERT → `COMMIT`);
   qualquer falha faz ROLLBACK COMPLETO e o pagamento volta a `pending`.
2. **Descoberta honesta durante o teste:** o SQLite mapeia `RAISE(ABORT)` para
   `IntegrityError`, o mesmo tipo da violação de UNIQUE — o handler antigo
   trataria a falha como "promoção já existe". Corrigido: após ROLLBACK, a
   promoção só é considerada existente se REALMENTE existir no banco.
3. **Guards de produção (não existiam):** produção recusa iniciar com
   SECRET_KEY padrão/vazia/<32 caracteres; `PIX_PROVIDER=mercadopago` recusa
   iniciar sem `MERCADOPAGO_ACCESS_TOKEN` (prefixo APP_USR-/TEST-) e sem
   `MERCADOPAGO_WEBHOOK_SECRET` (16+). Em desenvolvimento, apenas aviso.
   `create_charge` também recusa cobrança MP sem token (defesa dupla).
4. **Erro temporário no gateway:** toda cobrança criada sem confirmação de
   gravação é cancelada — nenhuma fica `pending` sem referência.

## 3. Por que uma cobrança não ativa promoção errada

- **Valor:** gravado no `payments` na criação, direto do plano no banco;
  reconfirmado na API do gateway na ativação.
- **Usuário, plano e grupo:** vêm EXCLUSIVAMENTE das colunas do registro do
  pagamento no banco; a requisição não fornece nada disso.
- **Roteamento:** webhook só alcança o registro pelo identificador do gateway
  (provider_ref), nunca por id interno.
- **Duplicação:** reivindicação atômica + `UNIQUE(payment_id)` + verificação
  real de existência.
- **Estados:** cobranças `cancelled`, `expired` ou já `paid` nunca ativam.

## 4. Execução da suíte — resultado individual (44/44 OK)

`Ran 44 tests — OK`. Resultado por teste, desta execução:

| # | Teste | Resultado |
|---|-------|-----------|
| 01 | home carrega categorias e selo de demonstração | ok |
| 02 | cadastro válido (hash scrypt no banco) | ok |
| 03 | cadastro duplicado e senha fraca recusados | ok |
| 04 | POST sem token CSRF → 400 | ok |
| 05 | login com senha errada | ok |
| 06 | login correto e sessão ativa | ok |
| 07 | logout revoga a sessão | ok |
| 08 | bloqueio após 10 falhas (conta travada) | ok |
| 09 | página privada exige login (302) | ok |
| 10 | recuperação/redefinição de senha por token | ok |
| 11 | categoria e página do grupo + contador de views | ok |
| 12 | grupo inexistente → 404 | ok |
| 13 | busca por palavra com acento | ok |
| 14 | filtro por tipo (grupo/canal) | ok |
| 15 | sitemap.xml e robots.txt corretos | ok |
| 16 | envio vai para moderação (invisível ao público) | ok |
| 17 | link duplicado recusado | ok |
| 18 | link inválido recusado (fora do Telegram) | ok |
| 19 | upload: PNG válido aceito, script malicioso recusado | ok |
| 20 | outro usuário não edita publicação alheia (403) | ok |
| 21 | /admin exige perfil admin (403 para usuário comum) | ok |
| 22 | aprovação publica; rejeição grava motivo | ok |
| 23 | planos: preço em centavos; banner exige imagem e link http | ok |
| 24 | cobrança demo gera BR Code EMV válido com preço do banco | ok |
| 25 | webhook sem assinatura → 401 | ok |
| 26 | webhook assinado ativa destaque; idempotente | ok |
| 27 | expiração automática remove selo PATROCINADO | ok |
| 28 | cobrança vencida expira sozinha | ok |
| 29 | grupo pendente ou de outro dono não gera cobrança | ok |
| 30 | painel do usuário exibe promoções e histórico | ok |
| 31 | XSS escapado no conteúdo armazenado | ok |
| 32 | path traversal em upload negado | ok |
| 33 | SQL injection inofensiva (consultas parametrizadas) | ok |
| 34 | admin não desativa a própria conta | ok |
| 35 | auditoria registra ações administrativas | ok |
| 36 | webhook MP busca por provider_ref; id interno não confunde | ok |
| 37 | assinatura x-signature do MP validada (401 sem/errada; 200 válida) | ok |
| 38 | ativação dupla bloqueada; promoção existente → pagamento re-marca paid sem duplicar | ok |
| 39 | cobrança cancelada/expirada/paga nunca ativa | ok |
| 40 | webhook com id inexistente é ignorado sem erro | ok |
| 41 | `test_41_falha_na_insercao_da_promocao_faz_rollback_completo` — trigger `RAISE(ABORT)` força falha na inserção; rollback devolve pagamento a `pending` sem promoção; sem o gatilho, o mesmo webhook ativa | ok |
| 42 | `test_42_erro_temporario_no_gateway_nao_deixa_cobranca_inconsistente` — provider fora do ar; cobrança cancelada, nenhuma `pending` sem referência | ok |
| 43 | `test_43_producao_rejeita_secret_key_padrao_ou_fraca` — produção recusa SECRET_KEY padrão/vazia/curta; aceita chave forte | ok |
| 44 | `test_44_mercadopago_em_producao_exige_credenciais_validas` — recusa token ausente/inválido e secret curta; aceita credenciais completas; dev só avisa | ok |

## 5. Boots reais verificados (v1.2, evidência complementar)

- Produção recusa iniciar com SECRET_KEY padrão e com `PIX_PROVIDER=mercadopago`
  sem credenciais (mensagens de erro reais nos logs da auditoria).
- Produção com configuração válida serve a home (HTTP 200).
- Rotas públicas 200; `/painel` e `/admin` redirecionam para login.

## 6. Pendências externas (dependem de credenciais/configuração — sem esconder)

O TELEMAX **não está pronto para produção** até resolver:

1. **Domínio e DNS**: `telemax.lsnet.shop` apontando para o servidor
   (passo a passo em docs/DEPLOY.md), incluindo HTTPS via Let's Encrypt.
2. **Credenciais reais do Mercado Pago**: conta ativa, token APP_USR-,
   chave Pix, secret key do webhook e webhook cadastrado no painel
   (docs/PIX.md). O provider de produção só pode ser declarado funcional
   após uma cobrança REAL paga e conferida no ambiente real.
3. **SMTP**: servidor de e-mail real para recuperação de senha (em dev, o
   link sai no log).
4. **Revisão jurídica** dos textos de Termos/Privacidade (modelos técnicos).

O modo demo não move dinheiro e está marcado como tal em toda a interface.
