---
layout: post
title: "Extracting Malicious Payloads from SFX Self-Extracting Installers"
date: 2021-07-10
categories: windows 7zip sfx self-extracting installers
permalink: /extracting-sfx-installer/
---

Self-extracting installers are an awesome way to distribute software because they require very little overhead and minimal configuration. Because of this, some malware threats use these SFX files to deploy components to victim systems, and malware analysts need to know how to safely unpack the components for investigation. For this example, we're going to walk through the process to unpack this malicious installer: [https://www.virustotal.com/gui/file/9d27976b21da5fc419da598ea44456a528b9fbf83f24fc5e14f697f610a5b295/detection](https://www.virustotal.com/gui/file/9d27976b21da5fc419da598ea44456a528b9fbf83f24fc5e14f697f610a5b295/detection).

## The 7zip SFX Executable Format

7zip self-extracting installers are indeed Windows Portable Executable files, but they are a specialized format to themselves. To create a SFX file, you need two or three components:

- 7zip SFX Module (from the LZMA SDK)
- Installer Configuration Script (optional)
- 7zip archive containing content

The SFX module is a minimal Windows PE file designed to execute the contents of the configuration script and extract the archive included in the created SFX file. The configuration script contains plaintext commands in configuration stanzas, and this helps creators kick off specialized installations. Finally, the archive containing content is the actual payload we want to retrieve.

These components fit together rather easily when a creator executes `copy /b 7z-module.sfx + config.txt + archive.7z installer.exe`. The SFX format assumes that all of these components are physically joined together, appended to the same file.

This means we can unpack the SFX by looking for the magic header bytes for a 7z archive to retrieve the malicious payloads inside.

## Unpacking the Malicious Content

To unpack the content of a SFX file, we can open the file in a hex editor and look for the magic bytes of a 7z archive: `37 7A BC AF 27 1C`. Once we find those magic bytes, we can select all the bytes of the file from that header to the end of the file. After selection, we can copy those bytes and paste them into a new file to obtain the malicious payload.

![Searching for 7z Magic Bytes](/assets/images/extracting-sfx-installer/searching-magic-bytes.png)

Once we've created the new payload file from the copied bytes, we can open the file from any archive tool that supports 7z.

![Opening extracted payload](/assets/images/extracting-sfx-installer/opening-extracted-payload.png)

## What About Password Protected SFXs?

The same method still works. The only difference is that our ending payload.7z archive will be password protected. If you have the password, it's trivial to extract from there. If you don't, get to cracking.

## Bonus: The Configuration Script

Since the components of the SFX are physically appended together, this also means that the configuration script can be found as plaintext inside the bytes of the SFX file. To find it, search through instances of `!@` until you find text that looks similar to this:

```txt
!@Something@!UTF-8!
...
!@SomethingEnd@!
```

![SFX Configuration Script](/assets/images/extracting-sfx-installer/configuration-script.png)
