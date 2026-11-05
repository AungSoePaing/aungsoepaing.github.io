# aungsoepaing.github.io

Personal blog — [https://aungsoepaing.github.io](https://aungsoepaing.github.io)

Built with [Astro](https://astro.build) and the
[Fuwari](https://github.com/saicaca/fuwari) theme. Deploys to GitHub Pages via
`.github/workflows/deploy.yml` on every push to `main`.

## Write a post

```sh
pnpm install                 # first time only
pnpm new-post my-post-name   # creates src/content/posts/my-post-name.md
```

Then edit the front matter:

```yaml
---
title: My Post Title
published: 2026-11-05
description: One-line summary used in listings and SEO.
tags: [web, sqli]
category: CTF
draft: true   # set to false (or remove) to publish
---
```

Posts with `draft: true` are excluded from the production build — keep
work-in-progress posts as drafts. A CTF writeup skeleton is available as
`src/content/posts/writeup-template.md` (kept as a draft).

## Local preview

```sh
pnpm dev       # dev server at http://localhost:4321
pnpm build     # production build to ./dist/ (what GitHub Pages serves)
```

## Customize

- Site title, subtitle, colors, profile, nav links: `src/config.ts`
- About page: `src/content/spec/about.md`
- Site URL / base path: `astro.config.mjs`
