---
title: ASEAN Cyber Shield Hacking Contest 2023 Writeup
published: 2023-10-14
description: Writeups from the 1st ASEAN Cyber Shield Hacking Contest (Jakarta) — web, misc, crypto and reversing challenges by Team mm_cyb3r_s4g3.
tags: [ctf, web, crypto, reversing, misc]
category: CTF
draft: false
---

Write-ups by **Team mm_cyb3r_s4g3**.

## My First To do List — Web

![My First To do List](/images/acs-2023/acs-2023-p01-21.png)

We were given a React app.

![React app](/images/acs-2023/acs-2023-p01-22.png)

At first I had no idea what the question wanted. Then I remembered
"Rea**cversing**" — it suggested I might need to reverse engineer the React app
to find the flag.

![JS files](/images/acs-2023/acs-2023-p02-25.png)

At the very bottom of one of the JavaScript files, I found a function called
`evaluate()`. It returned a string that included the pattern `ACS{}`,
constructed as:

```js
return String.fromCharCode(65, 67, 83, 123) + n + String.fromCharCode(125)
```

The `evaluate()` function was responsible for returning a string that started
with `ACS{` and ended with `}`, with a dynamic portion in the middle. The
function had several conditions:

![evaluate() conditions](/images/acs-2023/acs-2023-p02-26.png)

I began debugging the function and noting which characters passed through the
conditions and returned valid outputs. I found the first 10 characters of the
sequence by tracking those that passed through the conditions.

The function `__(e)` had obfuscated code, which seemed designed to complicate
the process of understanding what was happening. After some time, I managed to
extract the following character sequence after the first 10 characters:
`B`, `Z`, `$`, `0`, `M`, `1`, `w`, `A`.

With the initial 10 characters identified, I attempted to construct the flag.
Initially I tried submitting `w`Efs@W0LKB$0M1wA`, but it was incorrect. After
relaxing a bit and reflecting on the hint, I realized that `Z` was equivalent
to the underscore `_` in this case. I adjusted the string to
`w`Efs@W0LKBZ$0ZM1wA` and it worked.

## Lutella — Misc

![Lutella](/images/acs-2023/acs-2023-p03-30.png)

After downloading the file, we were given a Lua jail.

The program runs `init()` first, and then the string we enter is run as Lua
code because of the usage of `loadstring()`. However, there are some
restrictions.

![Restrictions](/images/acs-2023/acs-2023-p04-33.png)

The `io` functions and the whole `os` module are set to nil, so we can't use
those. However, `safe_methods` is stored somewhere — we can use it to retrieve
those functions and exploit the program.

![safe_methods](/images/acs-2023/acs-2023-p04-34.png)

Here is my final script:

![Final script](/images/acs-2023/acs-2023-p05-39.png)

Then this is the flag:

![Flag](/images/acs-2023/acs-2023-p05-40.png)

## Can you REDIRECT me ? — Web

In this challenge there are 2 conditions we must satisfy in order to get the
flag: the `url.hostname` we send to the bot must be `www.google.com`, however...

![Condition 1](/images/acs-2023/acs-2023-p05-41.png)

...the final URL must not be `www.google.com`.

![Condition 2](/images/acs-2023/acs-2023-p05-42.png)

So I tried this payload:

```text
https://www.google.com/url?q=https://youtube.com
```

and got the flag.

![Flag](/images/acs-2023/acs-2023-p06-45.png)

## Drone Hijacking — Misc

We were given a pcap file. I searched around Google and found out this is RTP
payload type, so I filtered it.

![RTP filter](/images/acs-2023/acs-2023-p06-46.png)

And tried to extract it using Wireshark:

![Extracting RTP stream](/images/acs-2023/acs-2023-p07-49.png)

![Saving the payload](/images/acs-2023/acs-2023-p07-50.png)

And then I opened it and got the flag:

![Flag](/images/acs-2023/acs-2023-p08-53.png)

## Secret Encrypt — Crypto

This is my final script:

```python
from sympy import mod_inverse
from Crypto.Util.number import long_to_bytes

# Given values
n = 2000981708956959996953850003472613711386018037844414452068072038069215592170 \
    0313466801113645321964859714346152831289324522691712373980295752612143787805 \
    5137445968451429475655748592144312501368400180609270718751395323384602123352 \
    1342028490191851610155729131567827276241597990272712458815607949380707320054 \
    6288791822792848832017274870268954552045671250363562973791606622534055827461 \
    9292150793208447196497633637901741876887723154932667414290355246223607717781 \
    4403732233765388411323094431855446890427779612727507719615435939394858218915 \
    6560613101425299832337719592901727785865373121552005054050809254799001160651 \
    919041273
enc = 1734429078816301544256403813924733424606064299602044685090485232203956029011 \
    8766056392172895820951735374997354582709325518744702347901024840385769459937 \
    9978190179549143671357330322340421609508097271873664039321009804676555422799 \
    2805846443522475990031568351970607345587846519184128696525561796837221373773 \
    1942678587359354085082039577400390336690085883027339539322625462749425424798 \
    8768605591416681034071996650823528259620615803730661508439354210080527822700 \
    9649572340007139070097928196130353100156291039992955175342362555331825021132 \
    1347445434080128164118499925998330651792925936876711132409460643630484260433 \
    317617505
secret_out = [230042188645681635133303865769026515170836044386713068695324844863 \
    0531093021776734868674112240095418467093081756335930515843525383128738534202 \
    0963483775603861735706234413415203950249184934917247492131781020091510132187 \
    3577714794124287300922618162690346155877774836307024245809713440225416497941 \
    6319966395006,
    1189648934650087609061485138038807404274261315977067065687060057989201251219 \
    8556271281988569286493595602778296283669198856716904036535015041605534696075 \
    5633472875717465898683139277419122088292007600766276511481224635277838009319 \
    6844829647672101923663035337644663543027096790130428723434303665403261939870 \
    64645,
    9082290905482001949584898129077983059742463315025407331540697410643838832001 \
    2099062499510476986746519431915469091680034456400733513195561250293814032158 \
    6845720162783968106869584742052999871433306508900608833721705778233009040235 \
    2985878281940773724057611760913651464496608794773056390544662013690419464369 \
    8198]

# Secret modulus
secret2 = 2**1024

# Recover LCG parameters (a, c, m)
def recover_lcg_parameters(out1, out2, out3, m):
    """
    Recover LCG parameters (a, c) given three outputs and modulus.
    """
    a = ((out2 - out3) * mod_inverse(out1 - out2, m)) % m
    c = (out2 - a * out1) % m
    return a, c

# Use the first three outputs to recover parameters
out1, out2, out3 = secret_out[:3]
a, c = recover_lcg_parameters(out1, out2, out3, secret2)

# Backtrack to find the initial value (X_0)
X0 = (out1 - c) * mod_inverse(a, secret2) % secret2

# Check if X0 (p) is a factor of n
if X0 != 0 and n % X0 == 0:
    p = X0
    q = n // p

    # Compute totient (phi)
    phi = (p - 1) * (q - 1)

    # Compute private key d
    d = mod_inverse(e, phi)

    # Decrypt the ciphertext
    message_int = pow(enc, d, n)

    # Convert decrypted integer to bytes to retrieve the flag
    flag = long_to_bytes(message_int).decode()
    print(f"Recovered flag: {flag}")
else:
    print("Failed to recover a valid p using LCG parameters.")
```

## CS1338: Script Programming — Reversing

I decompiled the library file on [luadec.metaworm.site](https://luadec.metaworm.site/):

![Decompiling](/images/acs-2023/acs-2023-p11-61.png)

I tried to retrieve the key using this Lua script:

![Lua script](/images/acs-2023/acs-2023-p12-64.png)

After running the script, we got the key XD

I used an online decompiler to decompile `server.exe` and `client.exe` and
found the same key that they used for communication.

## SecureChat — Reversing

![SecureChat](/images/acs-2023/acs-2023-p13-69.png)

```text
Kek = 129FE83152B29A1DA9B00D42D63C771E
```

I also found a keygen function, which generates a 16-character key randomly.

In the main function, this key is XORed with the key we found in the
decompiler and used to encrypt the message.

![XOR in main](/images/acs-2023/acs-2023-p14-73.png)

I found this shared key in the pcap file provided — each byte of the key in one
packet.

![Shared key in pcap](/images/acs-2023/acs-2023-p14-74.png)

```text
Share key = 8c0952afa58452c55eb837e078ff8a2b
```

XORing Kek and the shared key gives the final key:

```text
Final key = 9e96ba9ef736c8def7083aa2aec3fd35
```

I used the final key to retrieve the original message using CyberChef:

![CyberChef decode](/images/acs-2023/acs-2023-p15-77.png)
