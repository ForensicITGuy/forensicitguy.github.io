---
layout: post
title: "RunPE and Commonplace Process Injection in Malware"
date: 2022-01-18
categories: malware runpe process-injection
permalink: /runpe-and-commonplace-injection/
---

One of my colleagues made a statement recently about how commonplace process injection has become among malware, to the point where it seems adversaries don't have to think about the injection techniques anymore. This is absolutely true as many adversaries deploying malware have begun using crypter software or services that inject their arbitrary payloads into other arbitrary processes. Today I want to show you the generic workflow around how this process happens. In this post I'll walk through how to use [CSharp-RunPE](https://github.com/NYAN-x-CAT/CSharp-RunPE) to inject [AsyncRAT](https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp) into an arbitrary process on Windows systems. This process will be similar to most of the implementations I've seen in recent malware families.

## Wait, Isn't Injection Complicated??

Eh, process injection can be extremely technical and complicated depending on how deeply you want to understand process internals. If you're simply looking to use process injection, there are multiple free and paid tools that will help you inject an arbitrary array of bytes into an arbitrary process's memory. In some of the paid products, all an adversary needs to do is check a box. In the case of free tools, sometimes a little bit of coding is needed.

All we need for this post is to understand a couple things about RunPE. First, it uses process hollowing to achieve injection. Second, we need to know the right function to call inside CSharp-RunPE for later. Keep this function definition in mind:

```cs
public static void Execute(string path, byte[] payload)
```

This will be our key for injection to "just work" without us having to dig deep into internals.

## Get CSharp-RunPE Ready

TODO compiling CSharp-RunPE and embedding into a PowerShell script

## Get AsyncRAT Ready

TODO compile AsyncRAT and embed into PowerShell script

## Make It Run

TODO System reflection assembly load,  invoke, and run

Thanks for reading!
