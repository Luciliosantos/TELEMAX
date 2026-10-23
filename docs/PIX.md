# Gateway Pix — colocar em produção

## Estado atual

- Provider **demo** (padrão): gera BR Code EMV válido com chave fictícia
  `demo@telemax.pix` (formato Banco Central, CRC16 correto) + QR Code PNG.
  Confirmação apenas via webhook assinado HMAC. **Não move dinheiro.**
- Provider **mercadopago**: código completo e pronto (criação de cobrança
  `POST /v1/payments` com `payment_method_id: pix`, leitura do
  `point_of_interaction.transaction_data.qr_code(_base64)`, reconsulta
  `GET /v1/payments/{id}` para confirmar `status == "approved"` antes de ativar).
  **Falta apenas a conta real.**

## Passo a passo (produção)

1. Crie uma conta Mercado Pago vendedor: https://www.mercadopago.com.br
2. Acesse https://www.mercadopago.com.br/developers/panel → **Suas integrações** →
   **Criar aplicação**. Anote o `Application ID`.
3. Cadastre uma **chave Pix** na conta (conta bancária/telefone/e-mail) —
   o Mercado Pago usa para gerar cobranças Pix.
4. Gere o **Access Token de produção** (Credenciais de produção) e preencha no `.env`:
   ```
   PIX_PROVIDER=mercadopago
   MERCADOPAGO_ACCESS_TOKEN=APP_USR-...
   PIX_WEBHOOK_SECRET=<segredo forte>
   ```
5. Configure o webhook em "Webhooks" da aplicação:
   URL: `https://telemax.lsnet.shop/webhook/pix`
   Evento: **Pagamentos** (`payment`)
   (Opcional, forte: informar a "Secret key" do painel como `MERCADOPAGO_WEBHOOK_SECRET`
   e validar a assinatura `x-signature` na sua frente reversa; a ativação no TELEMAX
   NUNCA confia só no corpo do webhook — sempre reconsulta a API.)
6. Teste com valor baixo (ex.: crie um plano de R$ 1) e pague com seu próprio Pix.
   Confirme no painel Admin → Pagamentos: status `paid`, destaque ativado com prazo.
7. Suba os preços reais no painel Admin → Planos.

## Garantias implementadas (v1.1)

- Notificação do MP é localizada exclusivamente pelo id do gateway
  (`provider_ref` + `provider='mercadopago'`); nunca por id interno.
- Assinatura `x-signature` (HMAC-SHA256 sobre `id:...;request-id:...;ts:...;`)
  validada quando `MERCADOPAGO_WEBHOOK_SECRET` estiver configurado.
- Reconsulta obrigatória na API confere TRÊS condições: status "approved",
  `transaction_amount` igual ao valor cobrado e `external_reference`
  "telemax-{id}" idêntico. Qualquer divergência ignora a ativação.
- Preço SEMPRE vem do banco (plano), nunca do formulário.
- Ativação idempotente (webhook duplicado não cria segunda promoção).
- Ativação é UMA transação atômica: pagamento 'paid' + promoção são gravados
  juntos ou juntos desfeitos; falha na inserção devolve o pagamento a 'pending'
  e o próximo webhook reativa normalmente.
- `promotions.payment_id` é UNIQUE; cobrança paga fora de `pending` é ignorada.
- Expiração automática (lazy + timer) retira o selo PATROCINADO na data.
- Toda transação tem histórico em `payments` e entrada na auditoria.
