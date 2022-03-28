---
layout: post
title: "Getting PE Rich Header Hashes with pefile in Python"
date: 2021-09-02
categories: blue-team tools
tags: windows pefile pe rich header hash virustotal
permalink: /rich-header-hashes-with-pefile/
---

If you've performed Windows malware analysis using Python tools, you've almost certainly worked with the Python [`pefile`](https://github.com/erocarrera/pefile) library. This library allows analysts to parse, manipulate, and dump information related to Windows Portable Executable (PE) files. Given its prevalence among malware analysis tools, it can also prove useful for threat intelligence folks trying to look for data points to pivot on to find similar malware samples.

## Malware Similarity via Hashes

There are loads of resources talking about calculating hashes that allow you to pivot and find similar samples. Rather than reiterating those points, I'll just share resources talking about the ones I've used the most lately: import table and rich header hashing.

- <https://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html>
- <https://github.com/RichHeaderResearch/RichPE>
- <https://www.virusbulletin.com/virusbulletin/2020/01/vb2019-paper-rich-headers-leveraging-mysterious-artifact-pe-format/>
- <https://blog.virustotal.com/2020/11/why-is-similarity-so-relevant-when.html>
- <https://www.youtube.com/watch?v=ipPAFG8qtyg>

By the way, VirusTotal enterprise lets you search for rich header matching using the operator `rich_pe_header_hash:`, which relies on calculating the MD5 hash of the clear bytes of a rich header.

## Adding Rich Header Hashing to pefile

When I started learning about the rich header's intelligence value and how I could pivot on values in VT, I started wanting to calculate the hash value for all my samples I analyze. I knew that `pefile` supported getting import table hashes using a `get_imphash()` function so I assumed it also had functions for rich header hashing... until I found out it didn't. Several folks ([including me](https://github.com/ForensicITGuy/rhh-md5)) made their own Python scripts to calculate rich header hashes but I thought, "why not just cut out all the extra work and put it in `pefile`?"

Some programming and pull requests later, `pefile` now has rich header hashing built in with version [v2021.9.3](https://github.com/erocarrera/pefile/releases/tag/v2021.9.3)!

To give it a test run, you can use code like this:

```python
import pefile

binary = pefile.PE('thing.exe')
binary.get_rich_header_hash()
```

By default, the function uses the MD5 hashing algorithm, but you can optionally specify others as strings:

`.get_rich_header_hash( [ 'md5' | 'sha1' | 'sha256' | 'sha512' ])`

## Installing The Updated pefile

To grab the new version, you can use Python's `pip` utility:

`pip install --upgrade pefile`

Happy hashing!