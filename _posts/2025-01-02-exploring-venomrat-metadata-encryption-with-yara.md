---
layout: post
title: "Exploring VenomRAT Metadata and Encryption with YARA - #100DaysOfYara"
date: 2025-01-02
categories: malware
tags: malware venomrat yara
permalink: /exploring-venomrat-metadata-encryption-with-yara/
image:
  path: /assets/images/previews/venomrat-preview.png
  alt: VenomRAT
---

It's that time of year again - 100 Days of YARA! In this post I want to walk through how I use YARA to document malware analysis findings. YARA has loads of different use cases:

- Detecting malicious file contents
- Estimating malware capabilities
- Showing how files can be similar to known documentation

My favorite use case is that last one. In my day job I often encounter malware that does not have public reporting, and I want to document the malware using VirusTotal LiveHunt YARA rules so I can find more samples in the future when they get uploaded. For this post, we'll work with this VenomRAT sample from MalwareBazaar: [https://bazaar.abuse.ch/sample/e0cc614e2c756bfe9eb3773daa8d6c0ac66a2902826f5ccbd94113e3ff69e3db/](https://bazaar.abuse.ch/sample/e0cc614e2c756bfe9eb3773daa8d6c0ac66a2902826f5ccbd94113e3ff69e3db/).

## Dumping Static Details in YARA-X

For the post, we'll work with [YARA-X](https://virustotal.github.io/yara-x/). Back in traditional YARA, we could use `yara -d` along with a minimal rule to print out what YARA observed about the file you scanned. In YARA-X, you can do this with the command `yr dump`. It outputs details from each of the YARA-X modules into a YAML format that you can view from the command line or output to a text file.

```console
$ yr dump ersyb.exe > ersyb_yara_dump.yml
```

Examining the generated YAML, we can see properties like this:

```yaml
pe:
    is_pe: true
    machine: MACHINE_I386
    subsystem: SUBSYSTEM_WINDOWS_GUI
    os_version:
        major: 4
        minor: 0
    subsystem_version:
        major: 4
        minor: 0
...
dotnet:
    is_dotnet: true
    version: "v4.0.30319"
    number_of_streams: 5
    number_of_guids: 1
    number_of_resources: 0
    number_of_classes: 0
    number_of_assembly_refs: 0
    number_of_modulerefs: 0
    number_of_user_strings: 6327
    number_of_constants: 0
    number_of_field_offsets: 0
...
```
{: file='ersyb_yara_dump.yml'}

In the case of this sample, `yr dump` provides output for the "pe" and "dotnet" YARA-X modules. If you're working with ELF, LNK, or MACH-O files, those respective modules will also show output. 

## YARA Rules Based on Version Info Metadata

Since dumping the properties of this sample produces 6500+ lines of output, I'll zoom in on some properties that might be interesting.

```yaml
...
    version_info:
        "Assembly Version": "6.0.5.0"
        "Comments": ""
        "CompanyName": ""
        "FileDescription": ""
        "FileVersion": "6.0.5"
        "InternalName": "ClientAny.exe"
        "LegalCopyright": ""
        "LegalTrademarks": ""
        "OriginalFilename": "ClientAny.exe"
        "ProductName": ""
        "ProductVersion": "6.0.5"
...
```

I like taking a look at metadata because, even though it's easily changed, adversaries often forget to change the metadata on malware right after they build it. For example, It's really common to run across AsyncRAT samples or derivatives that have "Client.exe" in file metadata or version number "0.5.8". In this case, I want create a YARA rule to look for future similar samples by version info metadata:

```yara
import "pe"

rule mal_VenomRAT_ClientAny_Metadata {
  meta:
    description = "Rule to find samples with ClientAny.exe and version 6.0.5 metadata."
    author = "Tony Lambert"
  condition:
    pe.version_info["InternalName"] == "ClientAny.exe" and
    pe.version_info["OriginalFilename"] == "ClientAny.exe" and
    pe.version_info["ProductVersion"] == "6.0.5"
}
```
{: file='mal_venomrat_rules.yar'}

To test the rule, we can run something like: `yr scan mal_venomrat_rules.yar ./`

```console
$ yr scan mal_venomrat_rules.yar ./
mal_VenomRAT_ClientAny_Metadata /home/remnux/cases/venomrat/ersyb.exe
────────────────────────
 1900 file(s) scanned in 0.2s. 1 file(s) matched.
```

From here, we can use the rule in VirusTotal LiveHunt, MalwareBazaar, or another service that allows you to do YARA hunting.

## Detecting VenomRAT based on Encryption Salt

AsyncRAT is the gift that keeps giving. It's relatively simple for adversaries to clone AsyncRAT and use it in their own derivative products. Two good examples of this are DCRat and VenomRAT. These malware families are similar enough to AsyncRAT that they often fire AsyncRAT rules.

```console
$ yr scan ~/yara/yaraforge/yara-rules-full.yar ersyb.exe
ELASTIC_Windows_Generic_Threat_Ce98C4Bc ersyb.exe
ELASTIC_Windows_Generic_Threat_2Bb6F41D ersyb.exe
ELASTIC_Windows_Trojan_Dcrat_1Aeea1Ac ersyb.exe
TELEKOM_SECURITY_Cn_Utf8_Windows_Terminal ersyb.exe
DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_References_Confidential_Data_Store ersyb.exe
DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_B64_Artifacts ersyb.exe
DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_Discordurl ersyb.exe
DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_Regkeycomb_Disablewindefender ersyb.exe
DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_WMI_Enumeratevideodevice ersyb.exe
DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_Nonewindowsua ersyb.exe
DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_Discord_Regex ersyb.exe
DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_References_VPN ersyb.exe
DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_Vaultschemaguid ersyb.exe
DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_Wirelessnetreccon ersyb.exe
DITEKSHEN_MALWARE_Win_Stormkitty ersyb.exe
DITEKSHEN_MALWARE_Win_Asyncrat ersyb.exe
DITEKSHEN_MALWARE_Win_Dlagent10 ersyb.exe
DITEKSHEN_MALWARE_Win_Unamedstealer ersyb.exe
DITEKSHEN_MALWARE_Win_Multi_Family_Infostealer ersyb.exe
DITEKSHEN_MALWARE_Win_Cyberstealer ersyb.exe
DITEKSHEN_MALWARE_Win_Arrowrat ersyb.exe
DITEKSHEN_MALWARE_Win_Venomrat ersyb.exe
───────────────────────────────
 1 file(s) scanned in 0.4s. 1 file(s) matched.
```

When cloning AsyncRAT to incorporate into other products, adversaries often just do a find/replace and switch "AsyncRAT" to whatever string they want. Like "VenomRAT". An extra step that some of the adversaries do is change the malware's encryption salt so AsyncRAT configuration extractors don't work on their RAT. In the case of VenomRAT, the code for the encryption salt looks something like:

```cs
private static readonly byte[] Salt = Encoding.ASCII.GetBytes("VenomRATByVenom");

		public Aes256(string masterKey)
		{
			if (string.IsNullOrEmpty(masterKey))
			{
				throw new ArgumentException("masterKey can not be null or empty.");
			}
			Rfc2898DeriveBytes val = new Rfc2898DeriveBytes(masterKey, Salt, 50000);
```
{: file='Aes256.cs'}

So if we want to make a more specific rule we can write something like:

```yara
import "pe"

rule mal_VenomRAT_Encryption_Salt {
  meta:
    description = "Rule to find PE files that have strings related to VenomRAT encryption."
    author = "Tony Lambert"
  strings:
    $salt = "VenomRATByVenom" ascii wide
    $errorMessage = "masterKey can not be null or empty." ascii wide
    $encryptionClass = "Rfc2898DeriveBytes" ascii wide
  condition:
    pe.is_pe and
    all of them
}
```
{: file='mal_venomrat_rules.yar'}

Yes, I know this rule isn't optimized for uber-ultra-mega-fast scanning, I'm optimizing for readability here. Combining that with the previous rule, testing would look something like:

```console
$ yr scan mal_venomrat_rules.yar ./
mal_VenomRAT_ClientAny_Metadata /home/remnux/cases/venomrat/ersyb.exe
mal_VenomRAT_Encryption_Salt /home/remnux/cases/venomrat/ersyb.exe
───────────────────────────────
 1900 file(s) scanned in 0.4s. 1 file(s) matched.
```

There's loads more to explore with this sample, but this is a good start for tonight. Thanks for reading!