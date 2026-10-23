-- Categorias iniciais
INSERT INTO categories(slug, name, description, created_at) VALUES
('amizade','Amizade','Grupos para fazer amizades e conversar.',datetime('now')),
('ofertas','Ofertas','Promoções, cupons e descontos compartilhados pela comunidade.',datetime('now')),
('tecnologia','Tecnologia','Programação, hardware, gadgets e discussões técnicas.',datetime('now')),
('noticias','Notícias','Canais de notícias e atualizações do Brasil e do mundo.',datetime('now')),
('games','Games','Comunidades gamer, clans, dicas e servidores.',datetime('now')),
('musica','Música','Playlists, lançamentos e comunidades musicais.',datetime('now')),
('filmes','Filmes e Séries','Debates, recomendações e lançamentos de cinema e streaming.',datetime('now')),
('educacao','Educação','Estudos, idiomas, concursos e materiais de aprendizagem.',datetime('now')),
('empregos','Empregos','Vagas, networking e oportunidades profissionais.',datetime('now')),
('negocios','Negócios','Empreendedorismo, marketing e negócios online.',datetime('now')),
('esportes','Esportes','Futebol, MMA, corrida e comunidades esportivas.',datetime('now')),
('compra-e-venda','Compra e Venda','Classificados da comunidade. Cuidado com golpes.',datetime('now')),
('cidades','Cidades','Grupos regionais e comunidades por cidade/estado.',datetime('now')),
('outras','Outras','Publicações que não se encaixam nas demais categorias.',datetime('now'));

-- Planos iniciais de destaque (administrador pode alterar no painel)
INSERT INTO plans(name, days, price_cents, description, sort, created_at) VALUES
('Destaque Semanal', 7, 1990, 'Sua publicação no topo das listagens por 7 dias.', 1, datetime('now')),
('Destaque Quinzenal', 15, 3990, '15 dias de destaque com melhor custo por dia.', 2, datetime('now')),
('Destaque Mensal', 30, 6990, '30 dias de máxima visibilidade na home e categorias.', 3, datetime('now'));

-- Publicações de DEMONSTRAÇÃO (is_demo=1, links fictícios)
INSERT INTO telegram_groups(slug, name, description, link, category_id, type, keywords, owner_id, status, is_demo, views, created_at, published_at) VALUES
('demo-tech-hub-br','[DEMO] Tech Hub BR','Comunidade de tecnologia, programação e carreira técnica. Publicação de demonstração do TELEMAX.','https://t.me/telemax_demo_tech', (SELECT id FROM categories WHERE slug='tecnologia'), 'group','tecnologia,programação,dev,carreira',NULL,'approved',1,120,datetime('now','-3 days'),datetime('now','-3 days')),
('demo-noticias-24h','[DEMO] Notícias 24h','Canal de notícias atualizadas do Brasil e do mundo. Publicação de demonstração.','https://t.me/telemax_demo_news',(SELECT id FROM categories WHERE slug='noticias'),'channel','notícias,atualidades,brasil',NULL,'approved',1,95,datetime('now','-2 days'),datetime('now','-2 days')),
('demo-games-arena','[DEMO] Games Arena','Clan gamer multiplataforma, dicas e sorteios. Publicação de demonstração.','https://t.me/telemax_demo_games',(SELECT id FROM categories WHERE slug='games'),'group','games,clan,sorteio',NULL,'approved',1,80,datetime('now','-2 days'),datetime('now','-2 days')),
('demo-vagas-remoto','[DEMO] Vagas Remoto','Vagas de emprego 100% remoto para devs e suporte. Publicação de demonstração.','https://t.me/telemax_demo_jobs',(SELECT id FROM categories WHERE slug='empregos'),'channel','vagas,emprego,remoto',NULL,'approved',1,140,datetime('now','-1 days'),datetime('now','-1 days')),
('demo-cinema-br','[DEMO] Cinema BR','Recomendações de filmes e séries dubladas/legendadas. Publicação de demonstração.','https://t.me/telemax_demo_cine',(SELECT id FROM categories WHERE slug='filmes'),'channel','filmes,séries,streaming',NULL,'approved',1,60,datetime('now','-1 days'),datetime('now','-1 days')),
('demo-aulas-online','[DEMO] Aulas Online','Materiais de estudo, idiomas e concursos. Publicação de demonstração.','https://t.me/telemax_demo_edu',(SELECT id FROM categories WHERE slug='educacao'),'group','estudos,idiomas,concursos',NULL,'approved',1,45,datetime('now'),datetime('now')),
('demo-sao-paulo','[DEMO] São Paulo FC','Grupo da cidade de São Paulo: eventos, indicações e papo reto. Publicação de demonstração.','https://t.me/telemax_demo_sp',(SELECT id FROM categories WHERE slug='cidades'),'group','são paulo,cidade,eventos',NULL,'approved',1,33,datetime('now'),datetime('now')),
('demo-achados-promo','[DEMO] Achados e Promo','Ofertas, cupons e achados de lojas brasileiras. Publicação de demonstração.','https://t.me/telemax_demo_ofertas',(SELECT id FROM categories WHERE slug='ofertas'),'channel','ofertas,cupons,promoções',NULL,'approved',1,150,datetime('now','-4 days'),datetime('now','-4 days'));

INSERT INTO settings(key, value) VALUES
('site_name','TELEMAX'),
('site_tagline','O diretório de grupos e canais do Telegram em português'),
('contact_email','contato@telemax.lsnet.shop');
