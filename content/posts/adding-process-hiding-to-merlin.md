---
title: "Adding Process Hiding to Merlin"
date: 2019-08-28
draft: false
tags:
    - merlin
    - ld_preload
    - RedTeam
---

Sometimes red team tools need a little bit of extra love to address certain platforms. As I researched Merlin for detection strategies on the blue team side, I noticed that it could use some extra functionality to help replicate what we see in the real world for Linux compromises.

One particular technique that fascinated me was the combination of LD_PRELOAD with libprocesshider to gain a little bit of rootkit functionality and hide processes from casual observers. This technique has been used in the wild by Rocke and Pancha Group during cryptojacking campaigns.

Once I looked through the extensible module functionality in Merlin, I realized we could fairly easily download, compile, and load libprocesshider as a shared object using /etc/ld.so.preload as long as the Merlin agent has root privileges. With the default module options, the module will hide the Merlin agent itself from observation. If you modify the options, you can choose to hide other processes executing on the system.

## Detection Notes
This wouldn’t be complete without some notes for the blue team for detection! There are a easy search/hunt you can use to find this activity- look for the modification of /etc/ld.so.preload. This file isn’t commonly modified outside security or performance monitoring applications.
