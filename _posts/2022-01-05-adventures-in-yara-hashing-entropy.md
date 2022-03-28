---
layout: post
title: "Adventures in YARA Hashing and Entropy"
date: 2022-01-05
categories: blue-team tools
categories: yara hashing entropy
permalink: /adventures-in-yara-hashing-entropy/
---

In this post I'm going to take a look at a couple of simple YARA rules that excited me during my daily analysis tasks. These rules were inspired by the #100DaysOfYARA hashtag, and if you're not following the Twitter hashtag #100DaysOfYARA go ahead and [open a new tab](https://twitter.com/search?q=%23100DaysofYARA&src=typeahead_click&f=live) so you can preload that joy for reading after this post.

## Matching on Rich Header Hash

I've talked a bit about [rich header hashes](https://forensicitguy.github.io/rich-header-hashes-with-pefile/) here before, and I love using it as a pivot point in VirusTotal. If you're not familiar, the rich header of a Windows EXE can give you information about the build environment of the binary. If you hash the clear bytes (it's XOR'd by default), you can use that hash to possibly find binaries that were built with a similar environment or tool chain. When combined with import table hashes, rich header hashes can help you pivot and find intelligence overlaps with known malware samples.

By default, there's no method included with the YARA "pe" module to query the rich header hash of a sample. That's fine, we can calculate it ourselves!

```yara
import "pe"
import  "hash"

rule sus_known_bad_rich_hash 
{
    meta:
        description = "Rule to find samples with given rich header md5 hash"
        author = "Tony Lambert"
    condition:
        hash.md5(pe.rich_signature.clear_data) == "fe5854c644d74722b56122fd4bf43115"
}
```

In this case, we're hunting for samples that match the rich header md5 hash `fe5854c644d74722b56122fd4bf43115`. Yeah, you have to know the bad rich header hash here, but this is just another hunting tool.

```
remnux@remnux:~/cases$ yara -r rich-header-rule.yar ./
sus_known_bad_rich_hash .//raccoon/maybe_raccoon.bin
```

## Matching on Resource Entropy

I occasionally run into Windows EXE malware samples that have encrypted resources attached. This is sometimes the case for binaries where shellcode is loaded from a resource or the malware otherwise has something to hide there. With YARA, we can calculate the entropy of resources and identify samples with high entropy resources.

```yara
import "pe"
import "math"

rule sus_very_high_entropy_resource
{
  meta:
    description = "check for resources with high levels of entropy"
  condition:
    for any resource in pe.resources: ( 
	math.in_range( 
		math.entropy(
		resource.offset, resource.length
        ),
        7.8, 8.0)
		)
}
```

```
remnux@remnux:~/cases$ yara -r high_entropy_resources.yar ./
sus_very_high_entropy_resource .//icedid/gigabyteI7.jpg
sus_very_high_entropy_resource .//konni/konni.scr
```

Shout-out to @greglesnewich who originally did the same thing with PE sections here: 

<blockquote class="twitter-tweet"><p lang="en" dir="ltr">We&#39;re on to day 2 of <a href="https://twitter.com/hashtag/100DaysofYARA?src=hash&amp;ref_src=twsrc%5Etfw">#100DaysofYARA</a> <br><br>Looking for super duper high entropies in .text PE sections. New rules on top of zee gist:<a href="https://t.co/CHwmpNORpw">https://t.co/CHwmpNORpw</a></p>&mdash; Greg Lesnewich (@greglesnewich) <a href="https://twitter.com/greglesnewich/status/1477644952393895948?ref_src=twsrc%5Etfw">January 2, 2022</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

Thanks for reading, and YARA on!