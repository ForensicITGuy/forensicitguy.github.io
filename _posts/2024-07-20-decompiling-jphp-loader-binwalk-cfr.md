---
layout: post
title: "Decompiling a JPHP Loader with binwalk and cfr"
date: 2024-07-20
categories: malware
tags: malware jphp binwalk d3fck
permalink: /decompiling-jphp-loader-binwalk-cfr/
---

It's not unusual for adversaries to explore new and unusual ways to implement loader malware, and lately I've been looking at JPHP-based loader malware. This kind of loader doesn't get a lot of attention from antimalware providers, likely because of its nature as a weird hybrid language. In this post, I dive into unpacking the loader (which I suspect is "d3f@ck" loader) and statically decompiling it. If you want to follow along, I’m working with this sample in MalwareBazaar: [https://bazaar.abuse.ch/sample/94edf5396599aaa9fca9c1a6ca5d706c130ff1105f7bd1acff83aff8ad513164/](https://bazaar.abuse.ch/sample/94edf5396599aaa9fca9c1a6ca5d706c130ff1105f7bd1acff83aff8ad513164/).

## Finding a ZIP Overlay

Our first stop is to examine the initial executable we got. We can quickly do this with Detect It Easy or `diec`. 

![Detect It Easy Initial Triage](/assets/images/decompiling-jphp-loader-binwalk-cfr/detect-it-easy-initial-triage.png)

In Detect It Easy we can see the executable is a standard 32-bit binary for Windows, likely built with MinGW and GNU linker tools. At the bottom we can also see there is an overlay, meaning there is data beyond the bounds of the executable code but before the end of the file. In this case, the data appears to be a ZIP archive. We can dump that overlay into its own file before leaving Detect It Easy. In my case, I'm dumping it to disk as `overlay.zip`.

![Detect It Easy ZIP Overlay Dumping](/assets/images/decompiling-jphp-loader-binwalk-cfr/detect-it-easy-zip-overlay.png)

## Exploring the Overlay ZIP

After extracting `overlay.zip` with `7z` we can explore the contents. The directory listing gives us a bunch of interesting things to work with.

```console
$ ls -lh
total 164M
drwxrwxr-x  2 remnux remnux 4.0K Mar  9 20:07 action
drwxrwxr-x  4 remnux remnux 4.0K Mar  9 20:07 app
-rw-r--r--  1 remnux remnux 6.3K Mar  9 20:07 App.phb
-rw-r--r--  1 remnux remnux 3.8K Mar  9 20:07 Async.phb
drwxrwxr-x  3 remnux remnux 4.0K Mar  9 20:07 behaviour
drwxrwxr-x  6 remnux remnux 4.0K Mar  9 20:07 bundle
drwxrwxr-x  8 remnux remnux 4.0K Jun 14  2016 com
drwxrwxr-x  3 remnux remnux 4.0K Oct  5  2017 css
-rw-r--r--  1 remnux remnux 4.6K Mar  9 20:07 cURLFile.phb
-rw-r--r--  1 remnux remnux 8.0K Mar  9 20:07 Dialog.phb
-rw-r--r--  1 remnux remnux 2.5K Jun  5  2017 driver_property_info.properties
drwxrwxr-x  2 remnux remnux 4.0K Mar  9 20:07 facade
-rw-r--r--  1 remnux remnux  12K Mar  9 20:07 Files.phb
drwxrwxr-x  3 remnux remnux 4.0K Oct  5  2017 font
drwxrwxr-x  2 remnux remnux 4.0K Mar  9 20:07 game
-rw-r--r--  1 remnux remnux 1.5K Jun  5  2017 isc_dpb_types.properties
-rw-r--r--  1 remnux remnux 152K Jun  5  2017 isc_error_msg.properties
-rw-r--r--  1 remnux remnux  20K Jun  5  2017 isc_error_sqlstates.properties
-rw-r--r--  1 remnux remnux  244 Jun  5  2017 isc_tpb_mapping.properties
drwxrwxr-x 10 remnux remnux 4.0K Jan  7  2015 javassist
drwxrwxr-x  5 remnux remnux 4.0K Oct 24  2007 javax
-rw-r--r--  1 remnux remnux 1.1K Mar  9 20:05 jfoenix-custom.fx.css
drwxrwxr-x  2 remnux remnux 4.0K Feb  8 17:47 JPHP-INF
drwxrwxr-x  3 remnux remnux 4.0K Mar  9 20:07 JPHP-INFO
-rw-r--r--  1 remnux remnux 1.5K Aug 17  2015 LICENSE.md
drwxrwxr-x  4 remnux remnux 4.0K Mar  9 20:07 META-INF
drwxrwxr-x 14 remnux remnux 4.0K Dec 23  2016 org
-rw-rw-r--  1 remnux remnux  19M Jul 20 19:37 overlay.zip
drwxrwxr-x  7 remnux remnux 4.0K Mar  9 20:07 php
-rw-r--r--  1 remnux remnux 1.4K Aug 21  2015 README.md
-rw-r--r--  1 remnux remnux  21K Nov 23  2015 release-notes.txt
drwxrwxr-x  4 remnux remnux 4.0K Mar  9 20:07 script
drwxrwxr-x  2 remnux remnux 4.0K Mar  9 20:07 timer
drwxrwxr-x  2 remnux remnux 4.0K Jun  5  2017 translation
drwxrwxr-x  4 remnux remnux 4.0K Oct 28  2017 tray
-rw-rw-r--  1 remnux remnux  19M Mar  9 12:08 WinInstallerx64.exe
```

The `JPHP-INFO` and `JPHP-INF` folders are a good starting point, and they show that this ZIP archive was likely intended to be a Java Archive (JAR) file developed using JPHP. If we look inside the `JPHP-INF`, we'll find an entry point to the JAR so we can start analysis. Inside the `JPHP-INF` folder there are two `launcher.conf` and `.bootstrap` files. Looking at their contents gives us that entry point.

```conf
# MAIN CONFIGURATION

bootstrap.file = res://JPHP-INF/.bootstrap

fx.splash=
fx.splash.alwaysOnTop=0
```
{: file='launcher.conf'}

```php
<?php

// Generated.

use php\framework\FrameworkPackageLoader;
use php\gui\framework\Application;

$packageLoader = new FrameworkPackageLoader();
$packageLoader->register();

$app = new Application();
include 'res://.inc/jurl.phb'; 

$app->loadModules(array (
  0 => 'app\modules\AppModule',
));
$app->addStyle('/jfoenix-custom.fx.css');
$app->addStyle('/.theme/style.fx.css');
$app->launch();
```
{: file='.bootstrap'}

It looks like the entry point should be under `app\modules\AppModule`, so we can go take a look at code there.

## Decompiling JPHP code from PHB Files

Over in `app\modules` there are several files, including three that correspond with `AppModule`. They have extensions of `behaviour`, `module`, and `phb`. With a `file` command we can see the `behaviour` and `module` files are text-based and don't contain very much. Doing some extra research on PHB files will reveal they are compiled JPHP class files. 

```console
$ ls -lh
total 32K
-rw-r--r-- 1 remnux remnux   71 Feb 10 10:47 AppModule.behaviour
-rw-r--r-- 1 remnux remnux   37 Feb 10 10:47 AppModule.module
-rw-r--r-- 1 remnux remnux 4.5K Mar  9 20:07 AppModule.phb
-rw-r--r-- 1 remnux remnux   71 Mar  9 20:05 MainModule.behaviour
-rw-r--r-- 1 remnux remnux  230 Mar  9 20:05 MainModule.module
-rw-r--r-- 1 remnux remnux 5.3K Mar  9 20:07 MainModule.phb

$ file *
AppModule.behaviour:  XML 1.0 document, ASCII text, with CRLF line terminators
AppModule.module:     ASCII text
AppModule.phb:        data
MainModule.behaviour: XML 1.0 document, ASCII text, with CRLF line terminators
MainModule.module:    ASCII text
MainModule.phb:       data
```

Since JPHP is a hybrid language of PHP and Java, we should be able to decompile its intermediate bytecode to something source-like. The magic bytes showing the file type for PHB files shows that they aren't Java class files themselves that we can decompile. However, this [post](https://www.gdatasoftware.com/blog/icerat-evades-antivirus-by-using-jphp) shows we should be able to pull out Java classes from the PHB files. We can easily do automatic extraction using `binwalk`, specifying an argument to force extraction of any file types into an `_AppModule.phb.extracted` folder.

```console
$ binwalk --dd=.* AppModule.phb 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
609           0x261           Compiled Java class data, version 50.0 (Java 1.6)
2417          0x971           Compiled Java class data, version 50.0 (Java 1.6)

$ file _AppModule.phb.extracted/*
_AppModule.phb.extracted/261: compiled Java class data, version 50.0 (Java 1.6)
_AppModule.phb.extracted/971: compiled Java class data, version 50.0 (Java 1.6)
```

To get those back to source form, we can work with `cfr` and whatever text editor we want.

```console
$ cfr 261 > Class1.java

$ file Class1.java 
Class1.java: Java source, ASCII text, with very long lines
```

From here, we can rinse and repeat, decompiling all the other PHB files to source if we want.

## Finding and Decompiling the Loader Code

I won't lie, I spent a lot of time in some of these JPHP samples floundering around trying to find the malicious code. In the interest of time, I'll point the rest of the post over to a `MainForm.phb` file that was extracted from the parent ZIP file under `app/forms`.

```console
app/
├── forms
│   ├── MainForm.behaviour
│   ├── MainForm.conf
│   ├── MainForm.fxml
│   └── MainForm.phb    <=======
└── modules
    ├── AppModule.behaviour
    ├── AppModule.module
    ├── AppModule.phb
    ├── _AppModule.phb.extracted
    │   ├── 261
    │   ├── 971
    │   ├── Class1.java
    │   └── Class2.java
    ├── MainModule.behaviour
    ├── MainModule.module
    └── MainModule.phb
```

Using `binwalk` and `cfr`, we can decompile the code to two classes. 

```console
$ binwalk --dd=.* MainForm.phb

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
4287          0x10BF          Compiled Java class data, version 50.0 (Java 1.6)
14959         0x3A6F          Compiled Java class data, version 50.0 (Java 1.6)

$ cd _MainForm.phb.extracted/

$ cfr 10BF > Class1.java
$ cfr 3A6F > Class2.java
```

Inside `Class1.java` there is a mess of Java code, but the majority of the loader function resides there. I won't include the whole Java file here, but I will cover some functions and portions that show its capabilities.

## Analyzing the Loader Code

![JPHP PowerShell Windows Defender Manipulation](/assets/images/decompiling-jphp-loader-binwalk-cfr/jphp-powershell-defender-manipulation.png)

The chunk above is a bit of defense evasion code that the loader uses to exclude paths from Windows Defender scanning. In this sample, it produces a command you can see with endpoint telemetry:

`Powershell.exe -Command "& {Start-Process Powershell.exe -WindowStyle hidden -ArgumentList '-Command "Add-MpPreference -Force -ExclusionPath "C:\""' -Verb RunAs}" `

Additional parts of the code show that the loader can download and execute arbitrary executables and communicate with Telegram. The code isn't very obfuscated, but the author uses base64 encoding at select portions to obscure domains or URLs. In the case of Telegram communication, it looks like the code tries to obtain base64 encoded content from an `og:description` HTML meta tag in a Telegram channel. I presume this would be similar to how some malware uses Steam profiles or other dead-drop techniques. Alongside the Telegram URL is a Pastebin URL that has already been taken down.

![JPHP Base64 Encoded URLs](/assets/images/decompiling-jphp-loader-binwalk-cfr/jphp-base64-encoded-urls.png)

Another chunk of code appears to do status message check-ins when the loader executes.

![JPHP Status Check-Ins](/assets/images/decompiling-jphp-loader-binwalk-cfr/jphp-status-check-in.png)

Another chunk appears to have partial URLs with the domains removed. I presume those domains would be resolved by dead drop communication with the Pastebin URL (already taken down) or the Telegram profile description.

![JPHP Partial URLs for Downloading](/assets/images/decompiling-jphp-loader-binwalk-cfr/jphp-partial-urls-downloading.png)

From the code above, the loader would download an executable named `93.exe` and attempt to run it after download.

## Wait, how does the Java code execute?

You may have noticed we started with an executable but we ended up analyzing Java code, so how would the Java code execute? The executable is meant to be distributed alongside a Java Runtime Environment (JRE) executable and executed by Java as a JAR. When I found the executable in the wild it was distributed with a `v2024` folder that held the JRE material:

```console
$ tree v2024/
v2024/
├── bin
│   ├── awt.dll
│   ├── javacpl.cpl
│   ├── javacpl.exe
│   ├── java_crw_demo.dll
│   ├── java.dll
│   ├── java.exe
│   ├── javaw.exe
│   ├── javaws.exe
│   ├── JAWTAccessBridge-32.dll
│   ├── JAWTAccessBridge.dll
....
```

You can see in sandbox reports such as the [one in ANY.RUN](https://app.any.run/tasks/97f08d45-97da-484e-b2f4-1e9369e95e3b/), that the executable calls `javaws.exe -jar` and provides itself as an argument to the Java process. Because JARs are ZIP files and are typically read from back to front by Java, this operation works without causing errors.

`"C:\Users\admin\Desktop\Win.Installer.x64\v2024\bin\javaw.exe" -jar "C:\Users\admin\Desktop\Win.Installer.x64\Win Installer x64.exe"`

Thanks for reading!
