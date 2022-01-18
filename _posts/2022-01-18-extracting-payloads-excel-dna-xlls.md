---
layout: post
title: "Extracting Payloads from Excel-DNA XLL Add-Ins"
date: 2022-01-18
categories: malware xll excel-dna
permalink: /extracting-payloads-excel-dna-xlls/
---

A few different malware families have included Excel XLL add-in files as distribution mechanisms lately. These include IcedID and some commodity threats that HP's security team [documented as using Excel-DNA](https://threatresearch.ext.hp.com/how-attackers-use-xll-malware-to-infect-systems/). In this post, I'll show how you can extract payloads from XLL files created using Excel-DNA. If you want to play along at home, the sample I'm using is in MalwareBazaar here: [https://bazaar.abuse.ch/sample/876b4427b613ceebe5a4fa5a8d15e2d9473756c697db0c526dc84eb9bc7a3149/](https://bazaar.abuse.ch/sample/876b4427b613ceebe5a4fa5a8d15e2d9473756c697db0c526dc84eb9bc7a3149/)

## Triaging the File

As usual, let's make sure we're looking at a XLL file. A typical XLL file is a Windows DLL that contains particular exports. We can verify the file contents with `file`.

```console
remnux@remnux:~/cases/formbook-xll$ file balance.xll 
balance.xll: PE32 executable (DLL) (GUI) Intel 80386, for MS Windows
```

Alright, we definitely have a DLL file. Now let's take a look at the DLL exports with `pedump`.

```console
remnux@remnux:~/cases/formbook-xll$ pedump --exports balance.xll

=== EXPORTS ===

# module "Excel-Dna.xll"
# flags=0x0  ts="2106-02-07 06:28:15"  version=0.0  ord_base=1
# nFuncs=10014  nNames=10014

  ORD ENTRY_VA  NAME
    1    3e7a0  CalculationCanceled
    2    3e780  CalculationEnded
    3    3e830  DllCanUnloadNow
    4    3e840  DllGetClassObject
    5    3e8c0  DllRegisterServer
    6    3e8a0  DllUnregisterServer
    7    3e7c0  RegistrationInfo
    8    3e8e0  SetExcel12EntryPt
    9    3e7f0  SyncMacro
    a    3e770  f0

    ...

    271a    3e900  xlAddInManagerInfo12
    271b    3ea60  xlAutoClose
    271c    3ea10  xlAutoFree12
    271d    3eb60  xlAutoOpen
    271e    3ea30  xlAutoRemove
```

This DLL has a LOT of exports. I trimmed quite a few from the output so we can get the good stuff here, and it looks like we do have some exports expected for XLLs:

- xlAddInManagerInfo12
- xlAutoOpen
- xlAutoClose
- xlAutoRemove

Alrighty then, it looks like we have a XLL file! Moving on, let's learn a little bit about Excel-DNA XLL files.

## Extracting from Excel-DNA In a Nutshell

Excel-DNA is a legitimate software project that allows developers to implement .NET code in Excel Add-ins. This is achieved using a "loader" component that extracts and executes a compressed assembly. Let's take a look at the resources for this sample with `pedump`.

```console
remnux@remnux:~/cases/formbook-xll$ pedump --resources balance.xll 

=== RESOURCES ===

FILE_OFFSET    CP  LANG     SIZE  TYPE          NAME
    0x6ed38  1252     0    47104  ASSEMBLY      EXCELDNA.MANAGEDHOST
    0x7a538  1252     0   259271  ASSEMBLY_LZMA CUSTOMER
    0xb9a00  1252     0    71766  ASSEMBLY_LZMA EXCELDNA.INTEGRATION
    0xcb258  1252     0    43706  ASSEMBLY_LZMA EXCELDNA.LOADER
    0xd5d14  1252     0      530  DNA           __MAIN__
    0xd5f28  1252 0x409       64  STRING        #7
    0xd5f68  1252 0x409     3570  STRING        #8
    0xd6d5c  1252 0x409     3494  STRING        #9
    0xd7b04  1252 0x409     3080  STRING        #10
    0xd870c  1252 0x409      980  VERSION       #1
```

There are a few different resources that stand out. The ones that contain the string `EXCELDNA` in their names are likely overhead from the Excel-DNA project. I'm already suspicious of the one named `CUSTOMER`, especially with it weighing in at ~250 KiB. Let's extract that using `pedump`!

```console
remnux@remnux:~/cases/formbook-xll$ pedump --extract resource:ASSEMBLY_LZMA/CUSTOMER balance.xll > CUSTOMER.dat

remnux@remnux:~/cases/formbook-xll$ file CUSTOMER.dat 
CUSTOMER.dat: LZMA compressed data, non-streamed, size 1214464
```

Sweet, we now have a chunk of LZMA-compressed data. To decompress it, we can use `7z`.

```console
remnux@remnux:~/cases/formbook-xll$ 7z x CUSTOMER.dat

Scanning the drive for archives:
1 file, 259271 bytes (254 KiB)

Extracting archive: CUSTOMER.dat
--
Path = CUSTOMER.dat
Type = lzma

Everything is Ok

Size:       1214464
Compressed: 259271

remnux@remnux:~/cases/formbook-xll$ file CUSTOMER
CUSTOMER: PE32 executable (DLL) (console) Intel 80386 Mono/.Net assembly, for MS Windows
```

And now we have a .NET assembly we can decompile further with `ilspycmd` if desired. That's an exercise unto itself, so I'm quitting here for the day. Thanks for reading! 