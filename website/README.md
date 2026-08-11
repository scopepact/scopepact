# ScopePact Website

This is the dependency-free public introduction site for ScopePact. Open
`public/index.html` directly or serve `public/` from any static host.

Production: <https://scopepact.org>

Public protocol and Community Guard: <https://github.com/scopepact/scopepact>

Files under `node_modules`, `dist`, tool caches, and common deployment state
directories are ignored at the repository root. No build step is required for
the checked-in site.

The product image is a real local conformance-workbench capture. Regenerate it
after material UI changes at a `2038x1212` viewport and publish it under a new
dated asset name. Update the page and article references together so CDN caches
cannot retain an older product view at the current URL.

The long-form introduction is published from
`public/articles/ai-agents-need-bounded-authority.html`. Its semantic HTML,
article metadata, canonical URL, and image references are suitable for importing
the deployed page into Medium. `MEDIUM_DRAFT.md` remains the editable source and
publishing-note companion.

## Search discovery

The public site includes canonical and social metadata, connected Schema.org
graphs, explicit indexing directives, an XML sitemap, an RSS feed at
`/feed.xml`, and a concise machine-readable project brief at `/llms.txt`.
`robots.txt` allows public crawlers and advertises the sitemap.

After a production deployment, submit the homepage and field note to IndexNow:

```sh
node scripts/submit-indexnow.mjs
```

The script checks the public verification key stored in `public/` before it
submits URLs. IndexNow acceptance requests discovery but does not guarantee
indexing or ranking. Google discovery should use the advertised sitemap and a
verified Search Console property; its retired sitemap-ping endpoint is not used.

## Cloudflare Pages

The checked-in Wrangler configuration deploys only `public/`:

```sh
npx wrangler pages deploy
```

For Git integration, use this directory as the project root, leave the build
command blank, and set `public` as the output directory.
