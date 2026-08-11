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

## Cloudflare Pages

The checked-in Wrangler configuration deploys only `public/`:

```sh
npx wrangler pages deploy
```

For Git integration, use this directory as the project root, leave the build
command blank, and set `public` as the output directory.
