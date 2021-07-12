---
layout: post
title: "How Qbot Uses Esentutl"
date: 2021-02-01
categories: qbot malware esentutil
---

A colleague asked me a question today about the relationship between Qbot and a Windows system utility: `esentutl.exe`. It’s been sparsely documented [via tweet](https://twitter.com/redcanary/status/1334224870536712192), and I want to more fully explain why Qbot jumped into using the utility during operations.

## The WebCache

Qbot is a banking trojan, so its operators are naturally interested in obtaining data from victim hosts. The data includes internet browsing history, files opened, and much more. This data now lives within the `WebCacheV01.dat` database. In modern versions of Internet Explorer, the database uses the Microsoft Extensible Storage Engine (ESE) database format, the format famous for Exchange and Active Directory databases. As with other transactional databases, the WebCache may have multiple entries in a transaction log that get applied to the database file over time as the system allows write operations to the database. This helps improve resilience of the database and allows recoveries/rollbacks. This is where `esentutl.exe` becomes useful.

## Flushing the Data

Qbot borrowed a trick from digital forensic examiners to get victim internet history data. As [documented by SANS](https://www.sans.org/blog/ese-databases-are-dirty/) and [others](https://dfironthemountain.wordpress.com/2018/12/06/locked-file-access-using-esentutl-exe/), an examiner could get data from the `WebCacheV01.dat` file, but it would be incomplete as multiple log files may exist. This places the database in a “dirty” state. To get a complete, “clean” copy of the database, the examiner should first execute a recovery with `esentutl.exe`.

So Qbot uses a command like this:

```bat
esentutl.exe /r V01 /l"C:\Users\[REDACTED]\AppData\Local\Microsoft\Windows\WebCache" /s"C:\Users\[REDACTED]\AppData\Local\Microsoft\Windows\WebCache" /d"C:\Users\[REDACTED]\AppData\Local\Microsoft\Windows\WebCache"
```

In the command, `/r V01` indicates `esentutl.exe` will execute a recovery operation using the database log file V01. The `/l` specifies the location of log files, the `/s` specifies the location of system files (including a checkpoint file), and the `/d` specifies the location of database files. All the relevant files live in the same folder, leading to the same path appearing three times in the command. After this command executes, the data from the WebCache database log files is flushed into the `WebCacheV01.dat` database and Qbot can pick that file up for later use.

[esentutl Reference](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh875546(v=ws.11))