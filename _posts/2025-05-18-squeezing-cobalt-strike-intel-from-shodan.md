---
layout: post
title: "Squeezing Cobalt Strike Threat Intelligence from Shodan"
date: 2025-05-18
categories: threat-intelligence
tags: threat-intelligence shodan cobaltstrike
permalink: /squeezing-cobalt-strike-intel-from-shodan/
image:
  path: /assets/images/previews/squeezing-data-shodan-preview.png
  alt: Lemony Fresh Shodan Data
---

One of my favorite Twitter accounts from the last several years was [@cobaltstrikebot](https://x.com/cobaltstrikebot), mainly because it was an awesome source of threat intelligence for Cobalt Strike beacons in the wild. The account went dark in June 2023, but its tweets are still around.

<blockquote class="twitter-tweet"><p lang="en" dir="ltr">Today&#39;s 5 most common Spawn_to values:<br>%windir%\sysnative\rundll32.exe<br>c:\windows\system32\rundll32.exe<br>%windir%\system32\rundll32.exe<br>%windir%\sysnative\gpupdate.exe<br>%windir%\sysnative\wermgr.exe</p>&mdash; cobaltstrikebot 🌻 (@cobaltstrikebot) <a href="https://twitter.com/cobaltstrikebot/status/1660775881726631940?ref_src=twsrc%5Etfw">May 22, 2023</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

In this post I'll show you how you can get similar threat intelligence on Cobalt Strike beacons for yourself using Shodan and a little bit of PowerShell. We'll focus on getting data points for beacon SpawnTo values and watermarks, specifically.

## Getting Cobalt Strike Beacon Configurations from Shodan

To get started, you'll need a Shodan "membership" account at least. This is the lowest account level at Shodan for a one-time $50 fee. I picked mine up at a discount on Black Friday sale a while ago. We need this basic membership so we can use a search filter in Shodan, `product:"Cobalt Strike"`.

When searching for Cobalt Strike servers in Shodan like this, you'll notice that Shodan queries the beacon configurations from public Cobalt Strike servers and presents the configuration as banner info for the product. 

![Shodan Cobalt Strike Product Search](/assets/images/squeezing-cobalt-strike-intel-from-shodan/shodan-cobalt-strike-results.png)
_Viewing Shodan Search Results_

The awesome part about this data being captured and presented is that we can hit the download button and get it all into a compressed JSON file for processing. So in this case, we'll get about 500 beacon configurations to parse (not all the results will parse cleanly, so it won't be the full number of results downloaded). To get the data from Shodan into a file, click "Download Results" and "Download".

If you already have the `shodan` CLI tool installed on your system with the API key entered, you can also get the results by using this command:

```console
$ shodan download beacon_data product:"Cobalt Strike"
```

![Downloading via web interface](/assets/images/squeezing-cobalt-strike-intel-from-shodan/download-results.png)
_Downloading via the web interface_

When downloading via the web interface, the file will get a goofy GUID for a name, I recommend changing it to something memorable like `beacon_data.json.gz`.

## Parsing the Cobalt Strike Configurations

This part is by far the hardest, despite the data being in JSON format. For various reasons, clean parsing of the JSON gave me lots of issues in Python, so I ended up settling on just using a combination of the `shodan` CLI tool and PowerShell for this task. To start, I [installed the `shodan` CLI tool](https://cli.shodan.io/). Once installed via `pip` or `easy_install`, you get it initialized by running:

```console
$ shodan init <API key>
```

Now that the CLI tool is initialized, we can use it to parse normalized JSON from the compressed file like this:

```console
$ shodan parse --fields cobalt_strike_beacon.x86 .\beacon_data.json.gz > beacon_data.json 
```

This extracts just the beacon configuration info, skipping the IP address, port, and other general info returned by Shodan. You can still use those data points for threat intelligence but they're atomic indicators and we're looking for some more useful intel. From here, we can jump into PowerShell:

```powershell
# Read Cobalt Strike beacon configs from JSON file
$beaconConfigs = Get-Content .\beacon_data.json |ConvertFrom-Json

$beaconSpawnTos = @()
$beaconWatermarks = @()

# For each beacon config, add SpawnTo values and watermark to arrays
foreach ($beacon in $beaconConfigs) {
  
  $beaconSpawnTos += $beacon.'post-ex.spawnto_x64'
  $beaconSpawnTos += $beacon.'post-ex.spawnto_x86'
  $beaconWatermarks += $beacon.watermark
}
```

All that processing gives us two PowerShell arrays, `$beaconSpawnTos` and `$beaconWatermarks`. To get info about those two data points, like count of SpawnTo values or watermarks, you can do something like this:

```powershell
# Sort Cobalt Strike SpawnTo values by most prevalent
$beaconSpawnTos |group | sort -Property count -Descending |ft -Property count,name

Count Name
----- ----
  269 %windir%\syswow64\rundll32.exe
  269 %windir%\sysnative\rundll32.exe
   50 %windir%\syswow64\dllhost.exe
   50 %windir%\sysnative\dllhost.exe
   29 %windir%\syswow64\gpupdate.exe
   29 %windir%\sysnative\gpupdate.exe
   15 %windir%\sysnative\runonce.exe
   15 %windir%\syswow64\runonce.exe
    7 %windir%\syswow64\RmClient.exe
    7 %windir%\sysnative\secinit.exe
    7 %windir%\syswow64\WerFault.exe
    4 %windir%\sysnative\wbem\wmiprvse.exe -Embedding
    4 %windir%\syswow64\wbem\wmiprvse.exe -Embedding
    4 %windir%\sysnative\WerFault.exe
    4 %windir%\sysnative\WUAUCLT.exe
    3 %windir%\syswow64\notepad.exe
    3 %windir%\Microsoft.NET\Framework64\v4.0.30319\vbc.exe -Embedding
    3 %windir%\Microsoft.NET\Framework\v4.0.30319\vbc.exe -Embedding
    3 c:\windows\system32\rundll32.exe
    3 c:\windows\syswow64\rundll32.exe
    3 %windir%\system32\gpupdate.exe
    3 %windir%\syswow64\svchost.exe -k wksvc
    2 %allusersprofile%\CrashReport\CrashReport.exe
    2 %allusersprofile%\CrashReport\CrashReport64.exe
    2 %windir%\sysnative\svchost.exe
    2 %windir%\sysnative\EhStorAuthn.exe
    2 %windir%\syswow64\WUAUCLT.exe
    2 %windir%\syswow64\svchost.exe
    2 %windir%\sysnative\notepad.exe
    1 %windir%\sysnative\getmac.exe /V
    1 %windir%\syswow64\DevicePairingWizard.exe
    1 %windir%\syswow64\explorer.exe
    1 %windir%\system32\notepad.exe
    1 %windir%\syswow64\dns-sd.exe
    1 %windir%\sysnative\dns-sd.exe
    1 %windir%\syswow64\grpconv.exe
    1 %allusersprofile%\Differedelic\CrashReport64.exe
    1 %windir%\syswow64\EhStorAuthn.exe
    1 %windir%\sysnative\grpconv.exe
    1 %windir%\syswow64\wusa.exe
    1 %windir%\sysnative\explorer.exe
    1 %allusersprofile%\Differedelic\CrashReport.exe
    1 %windir%\sysnative\wusa.exe
```

```powershell
# Sort Cobalt Strike watermark values by most prevalent
$beaconWatermarks |group | sort -Property count -Descending |ft -Property count,name

Count Name
----- ----
  185 987654321
  101 666666666
   31 391144938
   28 100000
   12 305419896
   12 1234567890
    7 426352781
    5 666666
    4 600000
    2 1772831429
    2 1359593325
    2 728677768
    2 6
    1 20440668
    1 330252605
    1 388888888
    1 318104477
    1 678358251
```

## Using the Beacon Data

### SpawnTo Values

As an endpoint security person, I find the SpawnTo values helpful for making detection analytics like those in Sigma. For each of the processes mentioned, you can baseline their normal activity in tools such as EDR and then use detection analytics like this in Sigma:

```yaml
title: DllHost Execution Without CommandLine Parameters
id: aca8588b-aabd-4a40-a9a5-827fb5134b5e
status: test
description: Detects dllhost.exe without any parameters as seen Cobalt Strike beacon configs
references:
    - https://www.cobaltstrike.com/help-opsec
author: Tony Lambert (@ForensicITGuy)
date: 2025-05-18
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|endswith:
            - '\dllhost.exe'
    condition: selection
falsepositives:
    - Possible, will need environment tuning
level: high
```

Some Sigma rules like this already exist in the SigmaHQ repository: [https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_rundll32_no_params.yml](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_rundll32_no_params.yml)]

### Watermark Values

Cobalt Strike watermark values provide some interesting long-term tracking data points where we can see how active certain known watermarks are. For example, the watermark `391144938` corresponds to this reporting:

- <https://www.sentinelone.com/labs/chinese-entanglement-dll-hijacking-in-the-asian-gambling-sector/>
- <https://go.recordedfuture.com/hubfs/reports/cta-2023-0808.pdf>

Some of the watermarks definitely line up with pirated Cobalt Strike, such as `987654321`. 

## Closing

This can be a starting point for bigger and better data processing, especially if you can get your hands on bigger sets of beacon configurations. Until then, I hope this helps!

@cobaltstrikebot, I hope you're doing well.