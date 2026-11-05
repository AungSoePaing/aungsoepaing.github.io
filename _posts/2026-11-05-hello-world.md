---
date: 2026-11-05 00:00:00 +0630
description: First post — what this blog is about and how it's built.
categories: [Misc]
tags: [meta]
---

## Welcome

This blog runs on [GitHub Pages](https://pages.github.com/) with the
[Chirpy](https://github.com/cotes2020/jekyll-theme-chirpy) Jekyll theme. Every
post is a Markdown file in `_posts/` — push to `main` and GitHub Actions
rebuilds the site automatically.

## How to write a post

1. Create a file in `_posts/` named `YYYY-MM-DD-post-title.md` (the date in the
   filename decides the post date and sort order).
2. Add front matter at the top:

   ```yaml
   ---
   title: My Post Title
   date: 2026-11-05 00:00:00 +0630
   description: One-line summary used in listings and SEO.
   categories: [CTF, HTB]
   tags: [web, sqli]
   ---
   ```

3. Write Markdown below it and `git push`. Done.

Work-in-progress posts go in `_drafts/` — they are never published. There's
already a CTF writeup skeleton waiting there as `_drafts/writeup-template.md`{: .filepath }.

## What I plan to write about

- **CTF / HTB writeups** — tagged `ctf` and `htb`
- **Bug bounty / web security notes**
- **Projects and tooling**

See you in the next post.
