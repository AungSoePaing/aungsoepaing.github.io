---
title: ImaginaryCTF 2023 Writeup
published: 2023-07-16
description: Web writeups from ImaginaryCTF 2023 — IDOR, LFI, SQLi and an image-metadata challenge.
tags: [ctf, web, sqli, lfi]
category: CTF
draft: false
---

## inspection

![inspection](/images/ictf-2023/ictf-2023-p01-8.png)

![inspection solution](/images/ictf-2023/ictf-2023-p01-9.png)

Flag: `ictf{m4rkdown_parser_fail_1a211b44}`

## Idoriot

First visit the challenge URL — found a login page.

![Login page](/images/ictf-2023/ictf-2023-p02-16.png)

I tried logging in with default credentials — didn't work. So I registered.

![Register](/images/ictf-2023/ictf-2023-p02-17.png)

![Registered](/images/ictf-2023/ictf-2023-p02-18.png)

The PHP code says only the user with the admin `user_id` (which is `0`) will
see the flag. So I registered a user with the admin user_id.

![user_id 0 is admin](/images/ictf-2023/ictf-2023-p03-26.png)

![Registering with user_id 0](/images/ictf-2023/ictf-2023-p04-32.png)

![Flag](/images/ictf-2023/ictf-2023-p04-33.png)

Flag: `ictf{1ns3cure_direct_object_reference_from_hidden_post_param_i_guess}`

## Rok

I downloaded the source file and read the source code — `file.php` has an LFI
vulnerability. It filters `/` and `.`, so I bypassed it with triple URL
encoding.

![The challenge](/images/ictf-2023/ictf-2023-p05-40.png)

![file.php source](/images/ictf-2023/ictf-2023-p05-41.png)

## Perfect Picture

I downloaded the source file and read the source of `app.py`.

![Source files](/images/ictf-2023/ictf-2023-p06-48.png)

![app.py](/images/ictf-2023/ictf-2023-p06-49.png)

```python
from flask import Flask, render_template, request
from PIL import Image
import exiftool
import random
import os

app = Flask(__name__)
app.debug = False
os.system("mkdir /dev/shm/uploads/")

app.config['UPLOAD_FOLDER'] = '/dev/shm/uploads/'
app.config['ALLOWED_EXTENSIONS'] = {'png'}

def check(uploaded_image):
    with open('flag.txt', 'r') as f:
        flag = f.read()
    with Image.open(app.config['UPLOAD_FOLDER'] + uploaded_image) as image:
        w, h = image.size
        if w != 690 or h != 420:
            return 0
        if image.getpixel((412, 309)) != (52, 146, 235, 123):
            return 0
        if image.getpixel((12, 209)) != (42, 16, 125, 231):
            return 0
        if image.getpixel((264, 143)) != (122, 136, 25, 213):
            return 0
    with exiftool.ExifToolHelper() as et:
        metadata = et.get_metadata(app.config['UPLOAD_FOLDER'] + uploaded_image)[0]
        try:
            if metadata["PNG:Description"] != "jctf{not_the_flag}":
                return 0
            if metadata["PNG:Title"] != "kool_pic":
                return 0
            if metadata["PNG:Author"] != "anon":
                return 0
        except:
            return 0
    return flag

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in \
        app.config['ALLOWED_EXTENSIONS']

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return 'no file selected'
    file = request.files['file']
    if file.filename == '':
        return 'no file selected'
    if file and allowed_file(file.filename):
        filename = file.filename
        img_name = f'{str(random.randint(10000, 99999))}.png'
        file.save(app.config['UPLOAD_FOLDER'] + img_name)
        res = check(img_name)
        if res == 0:
            os.remove(app.config['UPLOAD_FOLDER'] + img_name)
            return("hmmph. that image didn't seem to be good enough.")
        else:
            os.remove(app.config['UPLOAD_FOLDER'] + img_name)
            return("now that's the perfect picture:<br>" + res)
    return 'invalid file'

if __name__ == '__main__':
    app.run()
```

The server wants a 690x420 PNG with three exact pixel values and three PNG
metadata fields. So I wrote a Python script to resize and repixel the image:

```python
from PIL import Image

def resize_and_repixel_image(image_path):
    # Open the image using PIL
    image = Image.open(image_path)

    # Resize the image to the desired dimensions (690x420)
    desired_size = (690, 420)
    image = image.resize(desired_size)

    # Repixel the image at specific coordinates with the specified pixel values
    pixels_to_repixel = {
        (412, 309): (52, 146, 235, 123),
        (12, 209): (42, 16, 125, 231),
        (264, 143): (122, 136, 25, 213)
    }

    for coord, pixel_value in pixels_to_repixel.items():
        image.putpixel(coord, pixel_value)

    # Save the modified image in the same directory with a new name
    modified_image_path = image_path.replace('.png', '_modified.png')
    image.save(modified_image_path)

    return modified_image_path

modified_image_path = resize_and_repixel_image('ctf.png')
print(f"Modified image saved at: {modified_image_path}")
```

And added the metadata with exiftool:

```console
$ exiftool -Description="jctf{blabla}" -Title="kool_pic" -Author="anon" image.png
```

Then I uploaded the image:

![Upload result](/images/ictf-2023/ictf-2023-p08-62.png)

Flag: `ictf{7ruly_th3_n3x7_p1c4ss0_753433}`

## blank

![blank](/images/ictf-2023/ictf-2023-p09-70.png)

![blank challenge](/images/ictf-2023/ictf-2023-p09-71.png)

![Testing the login](/images/ictf-2023/ictf-2023-p10-78.png)

![More testing](/images/ictf-2023/ictf-2023-p10-79.png)

The login form on `blank.chal.imaginaryctf.org` turned out to be injectable —
classic union-based SQLi on the password field.

![SQLi request](/images/ictf-2023/ictf-2023-p11-86.png)

![SQLi response](/images/ictf-2023/ictf-2023-p11-87.png)

Flag: `ictf{sqli_too_powerful_9b36140a}`

## idoriot-revenge

Register the user again:

![idoriot-revenge](/images/ictf-2023/ictf-2023-p12-96.png)

![Finding the hidden param](/images/ictf-2023/ictf-2023-p12-97.png)

![Exploiting](/images/ictf-2023/ictf-2023-p13-104.png)

![Flag page](/images/ictf-2023/ictf-2023-p13-105.png)

![Flag](/images/ictf-2023/ictf-2023-p13-106.png)

Flag: `ictf{this_ch4lleng3_creator_1s_really_an_idoriot}`
