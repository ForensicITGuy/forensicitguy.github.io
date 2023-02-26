---
layout: post
title: "NetSupport Manager RAT from a Malicious Installer"
date: 2023-02-25
categories: malware
tags: malware netsupport rar sfx detectiteasy
permalink: /netsupport-manager-malicious-installer/
---

Adversaries love to use pre-made tools for remote access and one perennial favorite is the legitimate [NetSupport Manager](https://www.netsupportmanager.com/). This post is a short and sweet look at a malicious installer that distributes NetSupport Manager to unwitting victims, allowing remote control to adversaries. If you want to follow along at home, I'm working with this file from MalwareBazaar: [https://bazaar.abuse.ch/sample/8ccff473270017f72b0910ea0404d670cc6c0ebee16977accc7cbcf137ba168b/](https://bazaar.abuse.ch/sample/8ccff473270017f72b0910ea0404d670cc6c0ebee16977accc7cbcf137ba168b/).

## Triaging the File

We can get our bearings using `file` and Detect-It-Easy.

```console
remnux@remnux:~/cases/purgatory$ file mal.exe 
mal.exe: PE32 executable (GUI) Intel 80386, for MS Windows, RAR self-extracting archive

remnux@remnux:~/cases/purgatory$ diec mal.exe 
PE32
    SFX: WinRAR(-)[-]
    Compiler: Microsoft Visual C/C++(2008 SP1)[libcmt]
    Linker: Microsoft Linker(9.0)[GUI32]
    Archive: RAR(4)[42.8%,14 files,1 dir]
```

The details from triage let us know that we're working with a WinRAR self-extracting installer file. This fact tells us a couple things to inform our next steps:

- We can't trust using import table or rich PE header hashes for pivoting and attribution
- We can likely easily obtain the installed content from the binary's overlay at the end of the file

The reason we can make these assumptions is due to the structure of WinRAR self-extracting files. The first portion of the file is a Windows WinRAR SFX module, similar to the structure of a 7-zip SFX module. After the bounds of that executable ends, a RAR archive is appended to the SFX module to complete the file. The executable code being a WinRAR SFX module means that ANY installer in the world that uses the same version of SFX module will have the same import table and rich header hashes. Malicious and legitimate. And since the archive is appended ot the end of the module we can simply dump the archive out and obtain whatever gets installed.

## Dumping the RAR Overlay and Extracting

There are a few ways we can dump that RAR archive from the file's overlay. We can use `foremost`, `binwalk`, or Detect-It-Easy. In this case, I'll opt for Detect-It-Easy. Once opening, we can go to the "Overlay" section in Detect-It-Easy, select all the overlay bytes, and right-click to dump them to a file.

![Detect-It-Easy Overlay Dump](/assets/images/netsupport-manager-malicious-installer/detectiteasy-overlay-dump.png)

By default, Detect-It-Easy wants to name the dumped files "Dump.bin" but I renamed my file to "overlay.rar". From here, we can simply use `7z` or another decompression tool to extract the content.

```console
remnux@remnux:~/cases/purgatory$ 7z x overlay.rar 
...
Extracting archive: overlay.rar
...

Everything is Ok

Folders: 1
Files: 14
Size:       5243582
Compressed: 2245282

remnux@remnux:~/cases/purgatory$ tree -a
.
├── mal.exe
├── overlay.rar
└── updatewindows23
    ├── AudioCapture.dll
    ├── client32.exe
    ├── client32.ini
    ├── HTCTL32.DLL
    ├── msvcr100.dll
    ├── nskbfltr.inf
    ├── NSM.ini
    ├── NSM.LIC
    ├── nsm_vpro.ini
    ├── pcicapi.dll
    ├── PCICHEK.DLL
    ├── PCICL32.DLL
    ├── remcmdstub.exe
    └── TCCTL32.DLL

1 directory, 16 files
```

Extraction created a folder `updatewindows23` with DLL, EXE, INI, INF, and LIC files, all part of NetSupport Manager Client.

## Examining NetSupport Manager Client

NetSupport Manager Client is a prebuilt piece of software generated with keying information from the adversary's copy of NetSupport Manager. Anyone can buy the software or obtain a free trial. To verify the software is NetSupport Manager, we can grab a hash of `client32.exe` and query Virustotal.

```console
remnux@remnux:~/cases/purgatory/updatewindows23$ sha256sum client32.exe 
18df68d1581c11130c139fa52abb74dfd098a9af698a250645d6a4a65efcbf2d  client32.exe
```

Sure enough, it's signed and legitimately from NetSupport Manager v12: [https://www.virustotal.com/gui/file/18df68d1581c11130c139fa52abb74dfd098a9af698a250645d6a4a65efcbf2d/details](https://www.virustotal.com/gui/file/18df68d1581c11130c139fa52abb74dfd098a9af698a250645d6a4a65efcbf2d/details).

Multiple files are always needed for a successful installation of the NetSupport Manager Client. These include:

- client32.exe
- client32.ini
- NSM.LIC

The `client32.exe` file may be renamed but the other two files should retain the same name as they're hardcoded in the binary. The `client32.ini` file contains the NetSupport Manager configuration and the `NSM.LIC` file contains license details for the NetSupport Manager installation. We can simply open the `client32.ini` file to view its contents with any text editor. For this post I'll cut down the contents of the INI file a bit for brevity.

```ini
[Client]
_present=1
AlwaysOnTop=0
AutoICFConfig=1
DisableChat=1
DisableChatMenu=1
DisableClientConnect=1
DisableCloseApps=1
DisableDisconnect=1
DisableLocalInventory=1
DisableManageServices=1
DisableMessage=1
DisableReplayMenu=1
DisableRequestHelp=1
HideWhenIdle=1
Protocols=3
RoomSpec=Eval
Shared=1
silent=1
SOS_Alt=0
SOS_LShift=0
SOS_RShift=0
SysTray=0
UnloadMirrorOnDisconnect=0
Usernames=*
ValidAddresses.TCP=*
...

[_License]
quiet=1
...

[HTTP]
CMPI=60
GatewayAddress=Dcejartints16[.]com:4421
GSK=GA;O@IEA9G=NCBGF;NAGFI
Port=4421
SecondaryGateway=Dcejartints17[.]com:4421
SecondaryPort=4421
...
```

The INI file contains multiple configuration options that allow NetSupport Manager operators to interact with managed (or "victim") hosts or remain hidden if they desire. The command and control configuration happens in the HTTP stanza. In this case, there are two NetSupport Manager console addresses for this client:

- `Dcejartints16[.]com`, port 4421
- `Dcejartints17[.]com`, port 4421

The LIC file contains NetSupport licensing info and may include identifying information about the adversary.

```ini
; NetSupport License File.
; Generated on 08:27 - 24/01/2014

[[Enforce]]

[_License]
control_only=0
expiry=
inactive=0
licensee=<redacted>
maxslaves=100000
os2=1
product=10
serial_no=<redacted>
shrink_wrap=0
transport=0
```

And it's just that easy to get some details from NetSupport Manager Clients when they're used for nefarious purposes.

## NetSupport From The Network Side

For this part of the post I obtained a network traffic PCAP file from the Tria.ge behavioral report for this sample: [https://tria.ge/230225-3et5gaeg4y/behavioral2](https://tria.ge/230225-3et5gaeg4y/behavioral2). The network traffic for NetSupport manager is pretty easy to spot with the right telemetry and rules. From this network traffic, multiple Suricata alerts fired:

```text
"2023-02-25T18:26:13.831422-0500 | 1:2035892:4 | ET INFO NetSupport Remote Admin Checkin | A Network Trojan was detected | 10.127.0.193:49788 -> 91.215.85.171:4421"
"2023-02-25T18:26:13.900912-0500 | 1:2035895:5 | ET INFO NetSupport Remote Admin Response | A Network Trojan was detected | 91.215.85.171:4421 -> 10.127.0.193:49788"
"2023-02-25T18:26:13.901319-0500 | 1:2035892:4 | ET INFO NetSupport Remote Admin Checkin | A Network Trojan was detected | 10.127.0.193:49788 -> 91.215.85.171:4421"
"2023-02-25T18:26:14.024660-0500 | 1:2035895:5 | ET INFO NetSupport Remote Admin Response | A Network Trojan was detected | 91.215.85.171:4421 -> 10.127.0.193:49788"
"2023-02-25T18:26:14.100691-0500 | 1:2034559:1 | ET POLICY NetSupport GeoLocation Lookup Request | Potential Corporate Privacy Violation | 10.127.0.193:49789 -> 51.142.119.24:80"
```

If you don't use Netsupport Manager as authorized remote management software in your environment and you use Suricata, consider using these ET OPEN rules:

- ET INFO NetSupport Remote Admin Checkin
- ET POLICY NetSupport GeoLocation Lookup Request
- ET INFO NetSupport Remote Admin Response

The geolocation rule is due to one specific URL visit every time NetSupport clients launch: `hxxp://geo.netsupportsoftware[.]com/location/loca.asp`. Other rules are from NetSupport's HTTP traffic. In each command and control communication, the NetSupport Manager Client uses a known User-Agent string and produces predictable HTTP traffic. In each response, the NetSupport Manager console/gateway also uses a well-known HTTP Server string to produce predictable traffic.

Client Request

```txt
POST hxxp://91.215.85[.]171/fakeurl.htm HTTP/1.1
User-Agent: NetSupport Manager/1.3
Content-Type: application/x-www-form-urlencoded
Content-Length:    22
Host: 91.215.85[.]171
Connection: Keep-Alive
```

Server Response

```txt
HTTP/1.1 200 OK
Server: NetSupport Gateway/1.7 (Windows NT)
Content-Type: application/x-www-form-urlencoded
Content-Length:    61
Connection: Keep-Alive
```

While other remote access tools can be a hassle to track down, this one should be fairly easy with the right tooling in place. That's all for tonight, thanks for reading!
