---
title: MobileHackingLab — Cyclic Scanner
published: 2026-11-05
description: Command injection in the Cyclic Scanner Android challenge from MobileHackingLab — abusing sha1sum through a malicious filename.
tags: [android, mobile, command-injection]
category: Android
draft: false
---

I will try to explain the writeup for the **Cyclic Scanner** challenge from
[MobileHackingLab](https://www.mobilehackinglab.com/).

## Analyzing AndroidManifest.xml

First I start by trying to understand the `AndroidManifest.xml` file. I found
some interesting parts in it.

![Foreground service declaration](/images/cyclic-scanner/01.png)

A **foreground service** is a service that performs work or operations that are
visible to the user and can continue executing even when the user is not
directly interacting with the app. Such a service must display a system
notification to make the user aware that it is active and using system
resources.

![MainActivity exported](/images/cyclic-scanner/02.png)

The `MainActivity` activity is defined and set as `exported="true"`, which means
the activity can be accessed from external sources. Then I start to understand
how `ScanService` works.

## How ScanService works

![ScanService code](/images/cyclic-scanner/03.png)

**1. Scans external storage:**

- Retrieves the external storage directory
  (`Environment.getExternalStorageDirectory()`)
- Iterates through all files using the file traversal utility
  (`FilesKt.walk`)
- Only scans readable files (`file.canRead() && file.isFile()`)
- Calls `ScanEngine.INSTANCE.scanFile(file)` to determine if a file is
  `SAFE` or `INFECTED`
- Outputs the file path followed by `SAFE` or `INFECTED` based on the scan
  result
- Catches `InterruptedException` and re-interrupts the thread to prevent
  unexpected termination

**2. Schedules repeated scans:**

- Uses `sendMessageDelayed()` to schedule the next scan after
  `ScanService.SCAN_INTERVAL` milliseconds — hence *cyclic* scanner

## The vulnerability

![scanFile implementation](/images/cyclic-scanner/04.png)

The method executes a command:

```console
toybox sha1sum <file_path>
```

where `<file_path>` is the absolute path of the file passed to it.

**Comparing hashes against known malware:** the calculated SHA-1 hash of the
file is then compared to a predefined list of known malware hashes stored in
`KNOWN_MALWARE_SAMPLES`.

I noticed `file.getAbsolutePath()` is directly added to the shell command — so
there is a **command injection vulnerability**. If I control a filename, the
filename itself ends up inside the shell command.

## Exploitation

Then I quickly create a file with the name `test.txt; touch asp_is_here`:

![Creating the malicious filename](/images/cyclic-scanner/05.png)

When the cyclic scan runs and hits our file, the executed command becomes:

```console
toybox sha1sum /sdcard/test.txt; touch asp_is_here
```

and the injected `touch` command runs.

![Command injection confirmed](/images/cyclic-scanner/06.png)

The challenge is solved — RCE inside the app's sandbox through a filename.
