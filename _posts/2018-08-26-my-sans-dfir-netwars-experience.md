---
layout: post
title: "My SANS DFIR NetWars Experience"
date: 2018-08-26
categories: SANS DFIR NetWars
permalink: /my-sans-dfir-netwars-experience/
---

At SANSFIRE 2018 in Washington, DC I had the awesome opportunity to compete in SANS DFIR NetWars with a coworker from Red Canary. This was my first experience with NetWars, and I wasn’t sure what to expect with the tournament. We heard that at SANSFIRE DFIR NetWars would allow team competition this time around, which is different from the previous individual-only competition. I went to a SANS@Night session titled “Intro to NetWars” given by Tim Medin of Red Siege Infosec fame with my coworker and our experience soon turned into a recruiting effort. We realized that we could perform Windows disk and memory forensics fairly well alongside network forensics, but neither of us could work well with smartphone, Apple forensics, or malware analysis beyond running simple static analysis tools. That said, we met a couple of awesome folks willing to team up with us for the tournament at the session.

On the Thursday night of SANSFIRE, NetWars started. The rules were simple:

- Don’t be a jerk to each other or the tournament hosts
- Use any tool for which you have a legal license (even if its proprietary to your company)

Individuals and teams of up to five were allowed to compete, and everyone was given the same evidence and questions. The evidence was distributed on USB drives the same as SANS DFIR classes, with a wide variety of evidence types. Evidence files contained Windows NTFS images, Apple HFS/APFS images, memory dumps, PCAPs, logs, malware binaries, and smartphone acquisitions. If you don’t bring any tools with you, SANS gives you a SIFT workstation VM to import into VMware Player or Workstation and all the bare minimum tools you need to answer questions. For the best experience, you’ll also need a Windows host or virtual machine. I opted for a virtual machine as I use Linux on my personal laptop. This gave me a couple of issues performance-wise and when attempting to read the evidence from USB. All the USB drives were formatted exFAT, so I had to install a couple packages to support the filesystem.

For the questions, all questions wre presented in a CTF-style portal and resembled something similar to “For the evidence file _X_, what was the created timestamp of _Y_ file in UTC?”. The questions obviously differed a bit for memory dumps, malware analysis, and network evidence, but they all required the input of some unique information that couldn’t be easily brute-forced. The tournament is designed to have 4 tiers, each level unlocking once you answer the minimal number of questions within the previous level. The questions also become more difficult as levels progress. Once you reach levels 3–4 you’ll discover that answering a single question will require multiple steps of work. For example, one question might require correlating artifacts of execution like prefetch and shim cache entries to determine times of program execution.

For the scoring, questions are worth a different amount for each level, increasing as the difficulty increases. If you answer a question incorrectly, points will be deducted from you or your team for the first two incorrect attempts. After those attempts you won’t lose any more for incorrect answers but the SANS faculty will call you out on attempting to brute-force answers. For each question there are a few hints. These hints cost you nothing and only count as a scoring mechanism in the event of a tie. If your team ties with another, the winner is decided by who used the least hints. Do not let this stop you from using hints! Each hint will help you get closer to answering the question and may even suggest tooling to assist you. If you ask SANS faculty for help during NetWars, you will be steered into hints first.

If you’re playing against veteran NetWars players, you might notice that some of their scores jump quickly early in the tournament. This is because some folks try to cheat the system a bit and save answers from their previous NetWars participation. DFIR tries to mitigate against this somewhat by rotating questions around test-bank style. Still, some players will likely have some answers saved by not all of them. In addition, you’ll notice scores jumping quickly on the second night of NetWars as many players save a copy of available questions and work on them during class on Friday. The SANS faculty are also aware of this and made notice of people working during class. By the second day, my team had already recognized we had deficiencies on the Apple forensics side, so I made another recruiting effort to find some help. That worked out well for us and we finished in second place, losing to a group of professional examiners from Stroz Friedberg. Keep in mind that you’ll be competing against some people that are DFIR pros, but don’t get discouraged.

Tips for winning:

- On a team, recruit wisely. Look for people in each discipline or at least in each of the DFIR classes
- Bring a Windows host with VMware Player/Workstation or have a Windows VM ready
- Become familiar with SIFT Workstation
- Use hints liberally, it’s better to use all hints and get right answers than use none with many wrong answers

Tips for learning:

- It’s ok not to win, aim to get better than you are
- Ask questions of your teammates
- Use all your hints and be willing to ask questions of faculty and other teams
- Be willing to answer questions for those less knowledgeable
