---
# Drafts live in _drafts/ and are NEVER published to the live site.
# To publish: move this file into _posts/ and rename it to
#   YYYY-MM-DD-machine-name.md
#   (e.g. 2026-11-05-lame.md) — the filename date controls the post date.

title: "Machine/Challenge Name — Writeup"
# date gets set from the filename once moved to _posts/
description: One-line summary of the target and the intended path.
categories: [CTF, HTB]
tags: [web, sqli, privesc]
---

## Info

| Field | Value |
|---|---|
| Platform | Hack The Box |
| Type | Machine / Challenge |
| Difficulty | Easy / Medium / Hard / Insane |
| Points | 20 |

## Recon

```console
$ nmap -sC -sV -oN nmap.txt TARGET_IP
```

Findings and initial attack surface notes.

## Enumeration

What stood out and why.

## Exploitation

The steps that got the initial foothold / flag.

## Privilege Escalation

Path from user to root, if applicable.

## Flag

```text
HTB{...}
```

## Lessons learned

- What the intended technique was
- What I'd do differently next time
