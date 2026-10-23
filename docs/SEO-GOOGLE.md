# SEO e Google Search Console

## Já implementado

- `sitemap.xml` automático (home, institucionais, categorias e todas as publicações
  aprovadas com lastmod); `robots.txt` com `Disallow` das áreas privadas e link do sitemap.
- URLs legíveis (`/categorias/tecnologia`, `/grupos/nome-do-grupo`), canonical em todas
  as páginas, meta description exclusiva por página, `noindex` em painel/admin/login.
- Busca paginada com `noindex` a partir da página 2 (evita duplicação de filtros).
- Conteúdo único nas páginas de categoria e grupo (descrição, palavras-chave, relacionados).
- Open Graph implícito (título/descrição); imagens otimizadas (upload limitado a 2 MB).
- Página leve: CSS único minificado, JS mínimo, sem rastreadores de terceiros.

## Cadastro no Google

1. Acesse https://search.google.com/search-console
2. Adicione a propriedade `https://telemax.lsnet.shop` (verificação por DNS: registro TXT
   que o Search Console fornece — adicionar no provedor do domínio lsnet.shop).
3. Menu **Sitemaps** → enviar `https://telemax.lsnet.shop/sitemap.xml`
4. Menu **Inspeção de URL** → solicitar indexação da home e das principais categorias.
5. Acompanhe "Páginas" (indexação) e "Experiência de página" (Core Web Vitals mobile).

## Boas práticas contínuas

- Prefira publicações com descrição rica e real; conteúdo de qualidade vence tudo.
- Não crie páginas vazias em massa; categorias sem publicações mostram convite amigável.
- Nenhum sistema garante posição no Google; a base técnica aqui está pronta para
  crescer organicamente.
