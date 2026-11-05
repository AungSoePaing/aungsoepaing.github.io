---
title: Hello World
published: 2026-11-05
description: First post — what this blog is about and how it's built.
tags: [meta]
category: Misc
draft: false
---

## Welcome

This blog is built with [Astro](https://astro.build) and the
[Fuwari](https://github.com/saicaca/fuwari) theme, hosted on GitHub Pages.
Every post is a Markdown file in `src/content/posts/` — push to `main` and
GitHub Actions rebuilds the site automatically.

## How to write a post

```sh
pnpm new-post my-post-name
```

That creates `src/content/posts/my-post-name.md` with front matter ready to
fill in:

```yaml
---
title: My Post Title
published: 2026-11-05
description: One-line summary used in listings and SEO.
tags: [web, sqli]
category: CTF
draft: false
---
```

Write Markdown below it, then `git push`. Posts with `draft: true` stay hidden
from the live site — there's a CTF writeup skeleton waiting at
`src/content/posts/writeup-template.md` as a draft.

## What I plan to write about

- **CTF / HTB writeups** — category `CTF`
- **Bug bounty / web security notes**
- **Projects and tooling**

See you in the next post.
