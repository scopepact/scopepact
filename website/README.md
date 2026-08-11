# ScopePact Website

This is the dependency-free public introduction site for ScopePact. Open
`public/index.html` directly or serve `public/` from any static host.

Production: <https://scopepact.org>

Public protocol and Community Guard: <https://github.com/scopepact/scopepact>

Files under `node_modules`, `dist`, tool caches, and common deployment state
directories are ignored at the repository root. No build step is required for
the checked-in site.

The product image is a real local conformance-workbench capture. Regenerate it
after material UI changes at a `2038x1212` viewport and preserve the same asset
path so the hero and product view remain stable.

The long-form introduction is published from
`public/articles/ai-agents-need-bounded-authority.html`. Its semantic HTML,
article metadata, canonical URL, and image references are suitable for importing
the deployed page into Medium. `MEDIUM_DRAFT.md` remains the editable source and
publishing-note companion.

## Cloudflare Pages

The checked-in Wrangler configuration deploys only `public/`:

```sh
npx wrangler pages deploy
```

For Git integration, use this directory as the project root, leave the build
command blank, and set `public` as the output directory.
