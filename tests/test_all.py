"""Suíte de testes TELEMAX — executa: python -m unittest discover -s tests -v"""
import base64
import hashlib
import hmac
import io
import json
import os
import sqlite3
import sys
import tempfile
import unittest
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["PIX_PROVIDER"] = "demo"
os.environ["PIX_WEBHOOK_SECRET"] = "segredo-de-teste"
os.environ["FLASK_ENV"] = "development"
os.environ["AUTO_APPROVE"] = "false"

from telemax import create_app                       # noqa: E402
from telemax.db import query, execute                # noqa: E402
from telemax.security import hmac_sign, now         # noqa: E402

PNG_1PX = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8AAAwAB/AF+q6H"
    "xAAAAAElFTkSuQmCC")


def make_config(db_path, uploads_dir):
    from telemax.config import Config
    class TmpConfig(Config):
        pass
    TmpConfig.DATABASE_PATH = db_path
    TmpConfig.UPLOADS_DIR = uploads_dir
    TmpConfig.IS_PROD = False
    return TmpConfig

class TelemaxBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        db = os.path.join(cls.tmp.name, "test.db")
        # roda migrations em banco isolado
        import sqlite3
        from telemax.db import run_migrations
        cls.app = create_app(config_object=make_config(db, cls.tmp.name))
        cls.app.config["TESTING"] = True

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.ctx = self.app.test_request_context()
        self.ctx.push()
        self.c = self.app.test_client()
        execute("DELETE FROM login_attempts")   # rate-limit limpo por teste

    def tearDown(self):
        self.ctx.pop()

    # ------- helpers -------
    def csrf(self):
        with self.c.session_transaction() as s:
            if "_csrf" not in s:
                s["_csrf"] = os.urandom(16).hex()
            return s["_csrf"]

    def post(self, path, data=None, **kw):
        if "data" in kw:
            extra = kw.pop("data")
            merged = dict(data or {})
            merged.update(extra)
            data = merged
        data = dict(data or {})
        data.setdefault("_csrf", self.csrf())
        return self.c.post(path, data=data, **kw)

    def register(self, nick="tester", email="tester@teste.com", pw="senha1234"):
        return self.post("/cadastro", {"nickname": nick, "email": email,
                                       "password": pw, "password2": pw})

    def login(self, email="tester@teste.com", pw="senha1234"):
        return self.post("/entrar", {"email": email, "password": pw})

    def make_admin(self, email="tester@teste.com"):
        execute("UPDATE users SET role='admin' WHERE email = ?", (email,))


class TestAuth(TelemaxBase):
    def test_01_home_carrega_categorias_e_demos(self):
        r = self.c.get("/")
        self.assertEqual(r.status_code, 200)
        html = r.get_data(as_text=True)
        self.assertIn("TELEMAX", html)
        self.assertIn("Tecnologia", html)          # categoria
        self.assertIn("DEMONSTRAÇÃO", html)        # selo demo

    def test_02_cadastro_valido(self):
        r = self.register()
        self.assertEqual(r.status_code, 302)
        u = query("SELECT * FROM users WHERE email='tester@teste.com'", one=True)
        self.assertTrue(u)
        self.assertTrue(u["password_hash"].startswith("scrypt"))

    def test_03_cadastro_duplicado_e_senha_fraca(self):
        self.register()
        r = self.register(nick="outra", email="outro@teste.com", pw="123")
        self.assertIn("ao menos 8", r.get_data(as_text=True))
        r = self.register(nick="tester2", email="tester@teste.com")
        self.assertIn("já está cadastrado", r.get_data(as_text=True))

    def test_04_csrf_obrigatorio(self):
        r = self.c.post("/entrar", data={"email": "a@b.co", "password": "x"})
        self.assertEqual(r.status_code, 400)

    def test_05_login_errado(self):
        self.register()
        r = self.login(pw="errado1234")
        self.assertIn("incorretos", r.get_data(as_text=True))

    def test_06_login_certo_e_sessao(self):
        self.register()
        r = self.login()
        self.assertEqual(r.status_code, 302)
        r = self.c.get("/painel")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Meu Painel", r.get_data(as_text=True))

    def test_07_logout_revoga_sessao(self):
        self.register(); self.login()
        self.c.get("/sair")
        r = self.c.get("/painel")
        self.assertEqual(r.status_code, 302)

    def test_08_bloqueio_apos_varias_falhas(self):
        self.register(nick="locktest", email="locktest@teste.com")
        for _ in range(10):
            self.login(email="locktest@teste.com", pw="errado1234")
        r = self.login(email="locktest@teste.com")
        u = query("SELECT * FROM users WHERE email='locktest@teste.com'", one=True)
        html = r.get_data(as_text=True)
        self.assertTrue(("bloqueada" in html) or ("Muitas tentativas" in html))
        self.assertTrue(u["locked_until"])

    def test_09_pagina_privada_sem_login(self):
        r = self.c.get("/painel")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/entrar", r.headers["Location"])

    def test_10_recuperacao_e_redefinicao(self):
        self.register()
        r = self.c.post("/recuperar", data={"email": "tester@teste.com",
                                            "_csrf": self.csrf()})
        self.assertEqual(r.status_code, 302)
        row = query("SELECT * FROM password_resets ORDER BY id DESC LIMIT 1", one=True)
        self.assertTrue(row)
        # token na tabela é hash; simular e-mail não é possível — pega token direto
        token = "X"  # hash desconhecido não deve funcionar
        r = self.c.post(f"/redefinir/{token}", data={"password": "nova12345",
                                                     "password2": "nova12345",
                                                     "_csrf": self.csrf()},
                        follow_redirects=True)
        self.assertIn("inválido", r.get_data(as_text=True))
        # caminho correto: recriar com hash conhecido
        from telemax.security import new_token, sha256
        real = new_token(24)
        execute("INSERT INTO password_resets(user_id, token_hash, expires_at) VALUES (?,?,?)",
                (row["user_id"], sha256(real), "2099-01-01 00:00:00"))
        r = self.c.post(f"/redefinir/{real}", data={"password": "nova12345",
                                                    "password2": "nova12345",
                                                    "_csrf": self.csrf()},
                        follow_redirects=True)
        self.assertIn("redefinida", r.get_data(as_text=True))
        r = self.login(pw="nova12345")
        self.assertEqual(r.status_code, 302)


class TestPublicContent(TelemaxBase):
    def test_11_categoria_e_grupo_publico(self):
        r = self.c.get("/categorias/tecnologia")
        self.assertEqual(r.status_code, 200)
        self.assertIn("[DEMO] Tech Hub BR", r.get_data(as_text=True))
        r = self.c.get("/grupos/demo-tech-hub-br")
        self.assertEqual(r.status_code, 200)
        before = query("SELECT views FROM telegram_groups WHERE slug='demo-tech-hub-br'",
                       one=True)["views"]
        self.c.get("/grupos/demo-tech-hub-br")
        after = query("SELECT views FROM telegram_groups WHERE slug='demo-tech-hub-br'",
                      one=True)["views"]
        self.assertEqual(after, before + 1)

    def test_12_grupo_inexistente_404(self):
        self.assertEqual(self.c.get("/grupos/nao-existe").status_code, 404)

    def test_13_busca_por_palavra(self):
        r = self.c.get("/busca?q=programação")
        self.assertIn("Tech Hub", r.get_data(as_text=True))
        r = self.c.get("/busca?q=zzz-impossivel")
        self.assertIn("Nada encontrado", r.get_data(as_text=True))

    def test_14_filtro_por_tipo(self):
        r = self.c.get("/busca?tipo=channel")
        html = r.get_data(as_text=True)
        self.assertIn("Notícias 24h", html)
        self.assertNotIn("Games Arena", html)

    def test_15_sitemap_e_robots(self):
        s = self.c.get("/sitemap.xml").get_data(as_text=True)
        self.assertIn("/categorias/tecnologia", s)
        self.assertIn("/grupos/demo-tech-hub-br", s)
        rb = self.c.get("/robots.txt").get_data(as_text=True)
        self.assertIn("Disallow: /admin", rb)
        self.assertIn("Sitemap:", rb)


class TestPublishing(TelemaxBase):
    def _login_and_submit(self, name="Meu Grupo Teste", link="https://t.me/meugrupoteste"):
        self.register(); self.login()
        cat = query("SELECT id FROM categories WHERE slug='amizade'", one=True)
        return self.post("/painel/grupos/novo", {
            "name": name, "description": "Grupo de teste automatizado do TELEMAX",
            "link": link, "type": "group", "category_id": cat["id"],
            "keywords": "teste"})

    def test_16_envio_vai_para_moderacao(self):
        r = self._login_and_submit()
        self.assertEqual(r.status_code, 302)
        g = query("SELECT * FROM telegram_groups WHERE link='https://t.me/meugrupoteste'", one=True)
        self.assertEqual(g["status"], "pending")
        # não aparece em público
        html = self.c.get("/busca?q=meu+grupo").get_data(as_text=True)
        self.assertNotIn("Meu Grupo Teste", html)

    def test_17_link_duplicado_rejeitado(self):
        self._login_and_submit()
        r = self._login_and_submit(name="Outro Nome")
        self.assertIn("já está publicado", r.get_data(as_text=True))

    def test_18_link_invalido_rejeitado(self):
        self.register(); self.login()
        cat = query("SELECT id FROM categories WHERE slug='amizade'", one=True)
        r = self.post("/painel/grupos/novo", {
            "name": "Grupo Link Invalido", "description": "desc suficiente aqui",
            "link": "https://facebook.com/x", "type": "group",
            "category_id": cat["id"], "keywords": ""})
        self.assertIn("Link inválido", r.get_data(as_text=True))
        self.assertFalse(query("SELECT id FROM telegram_groups WHERE link='https://facebook.com/x'", one=True))

    def test_19_upload_imagem_valida_e_invalida(self):
        self.register(); self.login()
        cat = query("SELECT id FROM categories WHERE slug='amizade'", one=True)
        r = self.post("/painel/grupos/novo", {
            "name": "Grupo Com Imagem", "description": "teste de upload de imagem ok",
            "link": "https://t.me/grupocomimagem", "type": "channel",
            "category_id": cat["id"], "keywords": "",
            "image": (io.BytesIO(PNG_1PX), "capa.png")},
            content_type="multipart/form-data")
        g = query("SELECT * FROM telegram_groups WHERE link='https://t.me/grupocomimagem'", one=True)
        self.assertTrue(g)
        self.assertTrue(g["image_path"])
        # upload perigoso é recusado (arquivo não-imagem)
        r = self.post("/painel/grupos/novo", {
            "name": "Grupo Malicioso", "description": "tentativa de script malicioso",
            "link": "https://t.me/grupomal", "type": "channel",
            "category_id": cat["id"], "keywords": "",
            "image": (io.BytesIO(b"#!/bin/sh\nrm -rf /"), "mal.sh")},
            content_type="multipart/form-data")
        g2 = query("SELECT * FROM telegram_groups WHERE link='https://t.me/grupomal'", one=True)
        self.assertTrue(g2 is None or g2["image_path"] is None)

    def test_20_propriedade_editar_outro_negada(self):
        self._login_and_submit()
        g = query("SELECT * FROM telegram_groups WHERE link='https://t.me/meugrupoteste'", one=True)
        self.c.get("/sair")
        self.register(nick="intruso", email="intruso@teste.com")
        self.login(email="intruso@teste.com")
        r = self.c.get(f"/painel/grupos/{g['id']}/editar")
        self.assertEqual(r.status_code, 403)


class TestModerationAdmin(TelemaxBase):
    def test_21_admin_obrigatorio(self):
        self.register(); self.login()
        self.assertEqual(self.c.get("/admin").status_code, 403)
        self.make_admin()
        self.assertEqual(self.c.get("/admin").status_code, 200)

    def test_22_aprovacao_publica_e_rejeicao_com_motivo(self):
        self.register(); self.login()
        cat = query("SELECT id FROM categories WHERE slug='games'", one=True)
        self.post("/painel/grupos/novo", {
            "name": "Clan Teste", "description": "grupo gamer para teste de moderacao",
            "link": "https://t.me/clanteste", "type": "group",
            "category_id": cat["id"], "keywords": "games"})
        g = query("SELECT * FROM telegram_groups WHERE link='https://t.me/clanteste'", one=True)
        self.make_admin()
        r = self.post(f"/admin/grupos/{g['id']}/decidir", {"acao": "aprovar"})
        self.assertEqual(r.status_code, 302)
        g = query("SELECT * FROM telegram_groups WHERE id=?", (g["id"],), one=True)
        self.assertEqual(g["status"], "approved")
        self.assertIn("Clan Teste", self.c.get("/categorias/games").get_data(as_text=True))
        # rejeição com motivo
        self.post("/painel/grupos/novo", {
            "name": "Spam Teste", "description": "grupo spam para teste de rejeicao",
            "link": "https://t.me/spamteste", "type": "channel",
            "category_id": cat["id"], "keywords": ""})
        g2 = query("SELECT * FROM telegram_groups WHERE link='https://t.me/spamteste'", one=True)
        self.post(f"/admin/grupos/{g2['id']}/decidir", {"acao": "rejeitar",
                                                        "motivo": "conteúdo spam"})
        g2 = query("SELECT * FROM telegram_groups WHERE id=?", (g2["id"],), one=True)
        self.assertEqual(g2["status"], "rejected")
        self.assertEqual(g2["rejection_reason"], "conteúdo spam")

    def test_23_plano_e_banner_admin(self):
        self.register(); self.login(); self.make_admin()
        r = self.post("/admin/planos", {"name": "Plano Teste", "days": "3",
                                        "price": "9,90", "description": "3 dias"})
        p = query("SELECT * FROM plans WHERE name='Plano Teste'", one=True)
        self.assertEqual(p["price_cents"], 990)
        self.assertEqual(p["days"], 3)
        # banner sem imagem é recusado
        r = self.post("/admin/banners", {"title": "Banner", "link": "https://exemplo.com",
                                          "position": "home_top"}, follow_redirects=True)
        self.assertIn("precisa de título", r.get_data(as_text=True))
        # banner com imagem PNG válida é criado
        self.post("/admin/banners",
                  {"title": "Banner", "link": "https://exemplo.com",
                   "position": "home_top",
                   "image": (io.BytesIO(PNG_1PX), "b.png")},
                  content_type="multipart/form-data")
        b = query("SELECT * FROM banners WHERE title='Banner'", one=True)
        self.assertTrue(b)
        # banner sem http não é aceito
        self.post("/admin/banners",
                  {"title": "X", "link": "javascript:alert(1)", "position": "home_top",
                   "image": (io.BytesIO(PNG_1PX), "b.png")},
                  content_type="multipart/form-data")
        n = query("SELECT COUNT(*) n FROM banners WHERE title='X'", one=True)["n"]
        self.assertEqual(n, 0)


class TestPixAndPromotions(TelemaxBase):
    def _prepare_approved_group(self, link="https://t.me/sertanejoraiz"):
        self.c.get("/sair")
        self.register(); self.login()
        cat = query("SELECT id FROM categories WHERE slug='musica'", one=True)
        self.post("/painel/grupos/novo", {
            "name": "Grupo Musica " + link[-6:], "description": "grupo de música para testes",
            "link": link, "type": "group",
            "category_id": cat["id"], "keywords": "música"})
        g = query("SELECT * FROM telegram_groups WHERE link=?", (link,), one=True)
        execute("UPDATE telegram_groups SET status='approved', published_at=? WHERE id=?",
                (now(), g["id"]))
        return query("SELECT * FROM telegram_groups WHERE id=?", (g["id"],), one=True)

    def test_24_cobranca_demo_gera_pix(self):
        g = self._prepare_approved_group('https://t.me/pixgrupo24')
        plan = query("SELECT * FROM plans WHERE days=7", one=True)
        r = self.post("/painel/promocoes/contratar", {"group_id": g["id"],
                                                      "plan_id": plan["id"]})
        self.assertEqual(r.status_code, 302)
        pay = query("SELECT * FROM payments ORDER BY id DESC LIMIT 1", one=True)
        self.assertEqual(pay["status"], "pending")
        self.assertEqual(pay["amount_cents"], plan["price_cents"])  # preço vem do banco
        self.assertTrue(pay["pix_code"].startswith("000201"))
        self.assertIn("BR.GOV.BCB.PIX", pay["pix_code"])
        self.assertTrue(pay["pix_qr_b64"])
        # página de pagamento exibe QR
        r = self.c.get(f"/painel/pagamento/{pay['id']}")
        self.assertIn("data:image/png;base64", r.get_data(as_text=True))

    def test_25_webhook_assinatura_invalida(self):
        g = self._prepare_approved_group('https://t.me/pixgrupo25')
        plan = query("SELECT * FROM plans WHERE days=7", one=True)
        self.post("/painel/promocoes/contratar", {"group_id": g["id"], "plan_id": plan["id"]})
        pay = query("SELECT * FROM payments ORDER BY id DESC LIMIT 1", one=True)
        r = self.c.post("/webhook/pix", data=json.dumps({"event": "pix.paid",
                                                         "payment_id": pay["id"]}),
                        content_type="application/json")
        self.assertEqual(r.status_code, 401)

    def test_26_webhook_valido_ativa_e_eh_idempotente(self):
        g = self._prepare_approved_group('https://t.me/pixgrupo26')
        plan = query("SELECT * FROM plans WHERE days=7", one=True)
        self.post("/painel/promocoes/contratar", {"group_id": g["id"], "plan_id": plan["id"]})
        pay = query("SELECT * FROM payments ORDER BY id DESC LIMIT 1", one=True)
        body = json.dumps({"event": "pix.paid", "payment_id": pay["id"]}).encode()
        sig = hmac_sign("segredo-de-teste", body)
        r = self.c.post("/webhook/pix", data=body, content_type="application/json",
                        headers={"X-Telemax-Signature": sig})
        self.assertIn(b"ativado", r.data)
        pay = query("SELECT * FROM payments WHERE id=?", (pay["id"],), one=True)
        self.assertEqual(pay["status"], "paid")
        promo = query("SELECT * FROM promotions WHERE payment_id=?", (pay["id"],), one=True)
        self.assertTrue(promo["is_active"])
        # destaque aparece como patrocinado na home
        self.assertIn("PATROCINADO", self.c.get("/").get_data(as_text=True))
        # segundo webhook não duplica promoção
        r = self.c.post("/webhook/pix", data=body, content_type="application/json",
                        headers={"X-Telemax-Signature": sig})
        n = query("SELECT COUNT(*) n FROM promotions WHERE payment_id=?", (pay["id"],), one=True)["n"]
        self.assertEqual(n, 1)

    def test_27_expiracao_automatica(self):
        g = self._prepare_approved_group('https://t.me/pixgrupo27')
        plan = query("SELECT * FROM plans WHERE days=7", one=True)
        self.post("/painel/promocoes/contratar", {"group_id": g["id"], "plan_id": plan["id"]})
        pay = query("SELECT * FROM payments ORDER BY id DESC LIMIT 1", one=True)
        body = json.dumps({"event": "pix.paid", "payment_id": pay["id"]}).encode()
        sig = hmac_sign("segredo-de-teste", body)
        self.c.post("/webhook/pix", data=body, content_type="application/json",
                    headers={"X-Telemax-Signature": sig})
        execute("UPDATE promotions SET ends_at='2020-01-01 00:00:00' "
                "WHERE payment_id=?", (pay["id"],))
        html = self.c.get(f"/grupos/{g['slug']}").get_data(as_text=True)
        self.assertNotIn("PATROCINADO", html)          # patrocínio vencido sai da página
        promo = query("SELECT * FROM promotions WHERE payment_id=?", (pay["id"],), one=True)
        self.assertEqual(promo["is_active"], 0)        # desativado pela expiração preguiçosa

    def test_28_cobranca_expira(self):
        g = self._prepare_approved_group('https://t.me/pixgrupo28')
        plan = query("SELECT * FROM plans WHERE days=7", one=True)
        self.post("/painel/promocoes/contratar", {"group_id": g["id"], "plan_id": plan["id"]})
        pay = query("SELECT * FROM payments ORDER BY id DESC LIMIT 1", one=True)
        execute("UPDATE payments SET expires_at='2020-01-01 00:00:00' WHERE id=?", (pay["id"],))
        self.c.get("/")
        pay = query("SELECT * FROM payments WHERE id=?", (pay["id"],), one=True)
        self.assertEqual(pay["status"], "expired")

    def test_29_somente_grupo_aprovado_e_dono(self):
        g = self._prepare_approved_group('https://t.me/pixgrupo29')
        execute("UPDATE telegram_groups SET status='pending' WHERE id=?", (g["id"],))
        plan = query("SELECT * FROM plans WHERE days=7", one=True)
        self.post("/painel/promocoes/contratar", {"group_id": g["id"], "plan_id": plan["id"]})
        n = query("SELECT COUNT(*) n FROM payments WHERE group_id=?", (g["id"],), one=True)["n"]
        self.assertEqual(n, 0)      # nenhuma cobrança criada para grupo pendente
        # outro usuário não contrata destaque para o grupo alheio
        execute("UPDATE telegram_groups SET status='approved' WHERE id=?", (g["id"],))
        self.c.get("/sair")
        self.register(nick="esperto", email="esperto@teste.com")
        self.login(email="esperto@teste.com")
        self.post("/painel/promocoes/contratar", {"group_id": g["id"], "plan_id": plan["id"]})
        n2 = query("SELECT COUNT(*) n FROM payments WHERE group_id=?", (g["id"],), one=True)["n"]
        self.assertEqual(n2, 0)

    def test_30_painel_usuario_mostra_promo_e_historico(self):
        g = self._prepare_approved_group('https://t.me/pixgrupo30')
        plan = query("SELECT * FROM plans WHERE days=15", one=True)
        self.post("/painel/promocoes/contratar", {"group_id": g["id"], "plan_id": plan["id"]})
        pay = query("SELECT * FROM payments ORDER BY id DESC LIMIT 1", one=True)
        body = json.dumps({"event": "pix.paid", "payment_id": pay["id"]}).encode()
        sig = hmac_sign("segredo-de-teste", body)
        self.c.post("/webhook/pix", data=body, content_type="application/json",
                    headers={"X-Telemax-Signature": sig})
        html = self.c.get("/painel/promocoes").get_data(as_text=True)
        self.assertIn("Destaque Quinzenal", html)
        html = self.c.get("/painel/pagamentos").get_data(as_text=True)
        self.assertIn("paid", html)
        html = self.c.get("/painel").get_data(as_text=True)
        self.assertIn("destaque", html.lower())



    # ---------- regressões da auditoria v1.1 ----------

    def test_36_webhook_mp_busca_por_provider_ref_e_nao_confunde_ids(self):
        # com provider=mercadopago, a notificação carrega o id do GATEWAY
        self.app.config["PIX_PROVIDER"] = "mercadopago"
        try:
            g = self._prepare_approved_group("https://t.me/mpconfusao36")
            plan = query("SELECT * FROM plans WHERE days=7", one=True)
            dono = query("SELECT owner_id FROM telegram_groups WHERE id=?", (g["id"],), one=True)["owner_id"]
            execute(
                "INSERT INTO payments(user_id, group_id, plan_id, amount_cents, status, "
                "provider, provider_ref, pix_code, created_at, expires_at, idempotency) "
                "VALUES (?,?,?,?,'pending','mercadopago','MP-777','pix',"
                "datetime('now'), datetime('now','+1 hour'),'idm36')",
                (dono, g["id"], plan["id"], plan["price_cents"]))
            mp_pay = query("SELECT * FROM payments WHERE provider_ref='MP-777'", one=True)
            # demo payment cujo ID INTERNO == 777? cria com id conhecido:
            execute("INSERT INTO payments(id, user_id, group_id, plan_id, amount_cents, "
                    "status, provider, provider_ref, pix_code, created_at, expires_at, idempotency) "
                    "VALUES (999001, ?, ?, ?, 100, 'pending','demo','DEMO-999001','pix',"
                    "datetime('now'), datetime('now','+1 hour'),'idm36b')",
                    (dono, g["id"], plan["id"]))
            demo_pay = query("SELECT * FROM payments WHERE id=999001", one=True)
            # webhook MP com id do gateway -> acha MP-777; sem API -> continua pendente
            r = self.c.post("/webhook/pix", data=json.dumps({"data": {"id": "MP-777"}}),
                            content_type="application/json")
            self.assertIn(b"pendente", r.data)
            mp_after = query("SELECT * FROM payments WHERE provider_ref='MP-777'", one=True)
            self.assertEqual(mp_after["status"], "pending")       # nada ativado sem API
            # webhook MP com o ID INTERNO da cobrança demo NÃO pode alcançá-la
            r = self.c.post("/webhook/pix", data=json.dumps({"data": {"id": "999001"}}),
                            content_type="application/json")
            self.assertIn(b"ignorado", r.data)
            demo_after = query("SELECT * FROM payments WHERE id=999001", one=True)
            self.assertEqual(demo_after["status"], "pending")     # intocado
        finally:
            self.app.config["PIX_PROVIDER"] = "demo"

    def test_37_webhook_mp_exige_assinatura_quando_secret_configurada(self):
        import hmac as _hm
        self.app.config["PIX_PROVIDER"] = "mercadopago"
        self.app.config["MERCADOPAGO_WEBHOOK_SECRET"] = "mp-secret-teste"
        try:
            body = json.dumps({"data": {"id": "MP-777"}}).encode()
            # sem x-signature -> recusado
            r = self.c.post("/webhook/pix", data=body, content_type="application/json")
            self.assertEqual(r.status_code, 401)
            # assinatura errada -> recusado
            r = self.c.post("/webhook/pix", data=body, content_type="application/json",
                            headers={"X-Signature": "ts=123,v1=deadbeef",
                                     "X-Request-Id": "req-1"})
            self.assertEqual(r.status_code, 401)
            # assinatura correta (manifesto documentado do MP) -> aceito
            ts = "1700000000"
            manifest = f"id:MP-777;request-id:req-1;ts:{ts};"
            v1 = _hm.new(b"mp-secret-teste", manifest.encode(), "sha256").hexdigest()
            r = self.c.post("/webhook/pix", data=body, content_type="application/json",
                            headers={"X-Signature": f"ts={ts},v1={v1}",
                                     "X-Request-Id": "req-1"})
            self.assertEqual(r.status_code, 200)
        finally:
            self.app.config["PIX_PROVIDER"] = "demo"
            self.app.config["MERCADOPAGO_WEBHOOK_SECRET"] = ""

    def test_38_ativacao_dupla_bloqueada_por_unique_mesmo_em_corrida(self):
        g = self._prepare_approved_group("https://t.me/pixgrupo38")
        plan = query("SELECT * FROM plans WHERE days=7", one=True)
        self.post("/painel/promocoes/contratar", {"group_id": g["id"], "plan_id": plan["id"]})
        pay = query("SELECT * FROM payments ORDER BY id DESC LIMIT 1", one=True)
        body = json.dumps({"event": "pix.paid", "payment_id": pay["id"]}).encode()
        sig = hmac_sign("segredo-de-teste", body)
        self.c.post("/webhook/pix", data=body, content_type="application/json",
                    headers={"X-Telemax-Signature": sig})
        # simula estado inconsistente: pagamento volta a pending com promoção ativa
        execute("UPDATE payments SET status='pending', paid_at=NULL WHERE id=?", (pay["id"],))
        ok = None
        from telemax.payments.pix import activate_promotion
        with self.app.test_request_context("/webhook/pix"):
            ok = activate_promotion(pay["id"])
        # promoção JÁ existia: pagamento é re-marcado paid, sem duplicar (True)
        self.assertTrue(ok)
        n = query("SELECT COUNT(*) n FROM promotions WHERE payment_id=?", (pay["id"],), one=True)["n"]
        self.assertEqual(n, 1)                       # nunca duplica
        promo = query("SELECT * FROM promotions WHERE payment_id=?", (pay["id"],), one=True)
        self.assertEqual(promo["is_active"], 1)       # promoção original intacta
        pay2 = query("SELECT status FROM payments WHERE id=?", (pay["id"],), one=True)
        self.assertEqual(pay2["status"], "paid")     # e o pagamento reflete a realidade

    def test_39_cobranca_cancelada_ou_expirada_nunca_ativa(self):
        g = self._prepare_approved_group("https://t.me/pixgrupo39")
        plan = query("SELECT * FROM plans WHERE days=7", one=True)
        self.post("/painel/promocoes/contratar", {"group_id": g["id"], "plan_id": plan["id"]})
        pay = query("SELECT * FROM payments ORDER BY id DESC LIMIT 1", one=True)
        for novo_status in ("cancelled", "expired", "paid"):
            execute("UPDATE payments SET status=? WHERE id=?", (novo_status, pay["id"]))
            from telemax.payments.pix import activate_promotion
            with self.app.test_request_context("/webhook/pix"):
                self.assertFalse(activate_promotion(pay["id"]))
            n = query("SELECT COUNT(*) n FROM promotions WHERE payment_id=?", (pay["id"],), one=True)["n"]
            self.assertEqual(n, 0)

    def test_40_webhook_demo_com_id_inexistente_e_ignorado(self):
        body = json.dumps({"event": "pix.paid", "payment_id": "987654321"}).encode()
        sig = hmac_sign("segredo-de-teste", body)
        r = self.c.post("/webhook/pix", data=body, content_type="application/json",
                        headers={"X-Telemax-Signature": sig})
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"ignorado", r.data)


    def test_41_falha_na_insercao_da_promocao_faz_rollback_completo(self):
        """Cenário apontado na auditoria: inserção falha após reivindicar o pagamento.
        Agora tudo é uma transação única: pagamento VOLTA a pending, sem 'paid sem promoção'."""
        g = self._prepare_approved_group("https://t.me/pixgrupo41")
        plan = query("SELECT * FROM plans WHERE days=7", one=True)
        self.post("/painel/promocoes/contratar", {"group_id": g["id"], "plan_id": plan["id"]})
        pay = query("SELECT * FROM payments ORDER BY id DESC LIMIT 1", one=True)
        body = json.dumps({"event": "pix.paid", "payment_id": pay["id"]}).encode()
        sig = hmac_sign("segredo-de-teste", body)
        # gatilho que força falha na inserção da promoção
        execute("CREATE TRIGGER tg_falha_promo BEFORE INSERT ON promotions "
                "BEGIN SELECT RAISE(ABORT, 'falha simulada'); END")
        r = self.c.post("/webhook/pix", data=body, content_type="application/json",
                        headers={"X-Telemax-Signature": sig})
        self.assertIn(b"pendente", r.data)            # ativação NÃO aconteceu
        pay2 = query("SELECT * FROM payments WHERE id=?", (pay["id"],), one=True)
        self.assertEqual(pay2["status"], "pending")  # rollback: voltou a pending
        self.assertTrue(pay2["paid_at"] is None)
        self.assertEqual(query("SELECT COUNT(*) n FROM promotions WHERE payment_id=?",
                               (pay["id"],), one=True)["n"], 0)
        # retirando o gatilho, o MESMO webhook recupera e ativa normalmente
        execute("DROP TRIGGER tg_falha_promo")
        r = self.c.post("/webhook/pix", data=body, content_type="application/json",
                        headers={"X-Telemax-Signature": sig})
        self.assertIn(b"ativado", r.data)
        pay3 = query("SELECT * FROM payments WHERE id=?", (pay["id"],), one=True)
        self.assertEqual(pay3["status"], "paid")
        self.assertEqual(query("SELECT COUNT(*) n FROM promotions WHERE payment_id=?",
                               (pay["id"],), one=True)["n"], 1)

    def test_42_erro_temporario_no_gateway_nao_deixa_cobranca_inconsistente(self):
        from telemax.payments import pix as pixmod
        g = self._prepare_approved_group("https://t.me/pixgrupo42")
        plan = query("SELECT * FROM plans WHERE days=7", one=True)
        original = pixmod.DemoProvider.create
        def explode(self_, payment, plan_, group_):
            raise RuntimeError("timeout simulado do gateway")
        pixmod.DemoProvider.create = explode
        try:
            r = self.post("/painel/promocoes/contratar",
                          {"group_id": g["id"], "plan_id": plan["id"]},
                          follow_redirects=True)
            self.assertIn("indispon", r.get_data(as_text=True))
        finally:
            pixmod.DemoProvider.create = original
        # nenhuma cobrança pendente sem referência; a única criada foi cancelada
        pend = query("SELECT COUNT(*) n FROM payments WHERE group_id=? AND status='pending'",
                     (g["id"],), one=True)["n"]
        canc = query("SELECT COUNT(*) n FROM payments WHERE group_id=? AND status='cancelled'",
                     (g["id"],), one=True)["n"]
        self.assertEqual(pend, 0)
        self.assertEqual(canc, 1)

    def test_43_producao_rejeita_secret_key_padrao_ou_fraca(self):
        from telemax import create_app
        from telemax.config import Config
        def cfg(**over):
            class C(Config): pass
            C.DATABASE_PATH = os.path.join(self.tmp.name, "guard-%d.db" % abs(hash(tuple(sorted(over.items())))) )
            C.UPLOADS_DIR = self.tmp.name
            C.IS_PROD = True
            for k, v in over.items(): setattr(C, k, v)
            return C
        for fraca in ("telemax-dev-insecure-key", "", "curta"):
            with self.assertRaises(RuntimeError):
                create_app(config_object=cfg(SECRET_KEY=fraca))
        # chave forte: inicia normalmente
        app = create_app(config_object=cfg(SECRET_KEY="x" * 40, PIX_PROVIDER="demo"))
        self.assertTrue(app)

    def test_44_mercadopago_em_producao_exige_credenciais_validas(self):
        from telemax import create_app
        from telemax.config import Config
        def cfg(**over):
            class C(Config): pass
            C.DATABASE_PATH = os.path.join(self.tmp.name, "guard-mp-%d.db" % abs(hash(tuple(sorted(over.items())))) )
            C.UPLOADS_DIR = self.tmp.name
            C.IS_PROD = True
            C.SECRET_KEY = "k" * 40
            C.PIX_PROVIDER = "mercadopago"
            for k, v in over.items(): setattr(C, k, v)
            return C
        # sem token
        with self.assertRaises(RuntimeError):
            create_app(config_object=cfg(MERCADOPAGO_ACCESS_TOKEN=""))
        # token inválido (prefixo errado)
        with self.assertRaises(RuntimeError):
            create_app(config_object=cfg(MERCADOPAGO_ACCESS_TOKEN="TOKEN-FORMATO-ERRADO"))
        # token válido mas sem secret do webhook
        with self.assertRaises(RuntimeError):
            create_app(config_object=cfg(MERCADOPAGO_ACCESS_TOKEN="APP_USR-123456-teste",
                                         MERCADOPAGO_WEBHOOK_SECRET="curta"))
        # credenciais completas: inicia
        app = create_app(config_object=cfg(MERCADOPAGO_ACCESS_TOKEN="APP_USR-123456-teste",
                                           MERCADOPAGO_WEBHOOK_SECRET="segredo-forte-do-webhook-16+"))
        self.assertTrue(app)
        # em desenvolvimento, falta de token é apenas aviso (não derruba o app)
        class Dev(Config): pass
        Dev.DATABASE_PATH = os.path.join(self.tmp.name, "guard-mp-dev.db")
        Dev.UPLOADS_DIR = self.tmp.name
        Dev.IS_PROD = False
        Dev.PIX_PROVIDER = "mercadopago"
        Dev.MERCADOPAGO_ACCESS_TOKEN = ""
        app2 = create_app(config_object=Dev)
        self.assertTrue(app2)


class TestSecurity(TelemaxBase):
    def test_31_xss_e_armazenado_escapado(self):
        g = self._prepare_xss_group()
        html = self.c.get("/grupos/" + g["slug"]).get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def _prepare_xss_group(self):
        self.c.get("/sair")
        self.register(nick="xsstest", email="xss@teste.com"); self.login(email="xss@teste.com")
        cat = query("SELECT id FROM categories WHERE slug='outras'", one=True)
        self.post("/painel/grupos/novo", {
            "name": "Grupo <script>alert(1)</script>",
            "description": "tentativa de XSS <script>alert(1)</script> no telemax",
            "link": "https://t.me/grupoxss", "type": "group",
            "category_id": cat["id"], "keywords": ""})
        g = query("SELECT * FROM telegram_groups WHERE link='https://t.me/grupoxss'", one=True)
        execute("UPDATE telegram_groups SET status='approved', published_at=? WHERE id=?",
                (now(), g["id"]))
        return query("SELECT * FROM telegram_groups WHERE id=?", (g["id"],), one=True)

    def test_32_upload_path_traversal_negado(self):
        r = self.c.get("/uploads/../../etc/passwd")
        self.assertIn(r.status_code, (404, 403))

    def test_33_sql_injection_nao_funciona(self):
        r = self.c.get("/busca?q=' OR '1'='1")
        self.assertEqual(r.status_code, 200)          # sem erro de SQL
        r = self.c.get("/categorias/' OR 1=1 --")
        self.assertEqual(r.status_code, 404)

    def test_34_admin_nao_pode_desativar_a_si_mesmo(self):
        self.register(nick="adminsup", email="adminsup@teste.com")
        self.login(email="adminsup@teste.com")
        self.make_admin(email="adminsup@teste.com")
        uid = query("SELECT id FROM users WHERE email='adminsup@teste.com'", one=True)["id"]
        self.post(f"/admin/usuarios/{uid}/acao", {"acao": "desativar"})
        u = query("SELECT is_active FROM users WHERE id=?", (uid,), one=True)
        self.assertEqual(u["is_active"], 1)

    def test_35_audit_log_registra_acoes(self):
        self.register(); self.login(); self.make_admin()
        self.c.get("/admin")
        n = query("SELECT COUNT(*) n FROM audit_log", one=True)["n"]
        self.assertGreater(n, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
