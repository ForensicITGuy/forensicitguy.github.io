---
title: "Whitelisting LD_PRELOAD for Fun and No Profit"
date: 2019-08-29
draft: false
tags: 
    - ld_preload
    - linux
    - whitelisting
    - unix
    - ld_audit
    - libpreloadvaccine
---

If you’ve been around the Linux/BSD/Solaris/Other UNIX ecosystem for a while you’ve probably heard of the fabled LD_PRELOAD trick. If you haven’t heard of it, let me introduce you to one of the longest-held, dirty security issues in UNIX…

## A Brief Look at LD_PRELOAD

![](/img/whitelisting-ld_preload-fun-no-profit/ld_preload-header.png)

LD_PRELOAD is an environment variable used by the dynamic linker on UNIX-based systems. Normally the dynamic linker follows a specified search pattern to load various dynamic libraries (shared objects on UNIX). Libraries specified using the LD_PRELOAD variable are loaded before the ones typically required by whatever command you’ll execute. It also goes one step further, libraries specified in LD_PRELOAD are loaded by commands even if their executables don’t require the preloaded binaries for operation.

This is an insanely easy way to introduce malicious code to a system. Preloaded libraries allow an adversary some extra advantages. First, an adversary has the ability to hook system calls or library calls. In at least one project, [libprocesshider](https://github.com/gianlucaborello/libprocesshider), this functionality is leveraged to taint the contents of a directory listing to hide processes. It doesn’t stop there, either. As shown in the [Zombie Ant Farm project](https://github.com/dsnezhkov/zombieant), adversaries don’t need specific information about the internals of binaries to execute their evil code. In the case of the ZAF project, it’s shown that adversaries can implement functions that execute at the load or unload of preloaded binaries. This means that adversaries can execute code by simply specifying a library is a preload and waiting for a legitimate user to execute something.

This functionality is implemented by the the dynamic linker (rtld.c source file for the geeks out there). It’s been an issue in Linux systems specifically for at least 20 years, longer in UNIX as a whole. To make matters a bit worse, this can play havoc with security tooling. First off, security tools aren’t always aware of environment variables. In the case of endpoint detection and response (EDR) tooling, environment variables aren’t even visible most of the time. In other cases, security tools may even become victims of LD_PRELOAD if they aren’t statically linked with code they need to execute.

Oh, and adversaries with root privileges can make preloads load in any process on a system by creating the file `/etc/ld.so.preload` and specifying the path of their preload library within. When done properly, adversaries can persist and evade defenses indefinitely on a system using this technique.

By the way, there’s not really an easy way to disable LD_PRELOAD - [https://security.stackexchange.com/questions/63599/is-there-any-way-to-block-ld-preload-and-ld-library-path-on-linux](https://security.stackexchange.com/questions/63599/is-there-any-way-to-block-ld-preload-and-ld-library-path-on-linux).

There are some useful abilities to LD_PRELOAD, though. It’s sometimes handy to hook functions that already exist in various applications or libraries to test or debug code. From what I can tell, this and performance monitoring are pretty much the only legitimate uses of it. Even the source and manpages say preloading shouldn’t be used long-term.

## Auditing Preload Libraries

During my day job at [Red Canary](https://redcanary.com/), I’ve spent a lot of time diving into Linux threats of various forms. LD_PRELOAD kept showing up in the form of userspace rootkits. [Azazel](https://github.com/chokepoint/azazel), [HiddenWasp](https://www.intezer.com/blog-hiddenwasp-malware-targeting-linux-systems/)/[Winnti](https://medium.com/chronicle-blog/winnti-more-than-just-windows-and-gates-e4f03436031a)/Highnoon.Linux, nation-state malware, and other threats have used LD_PRELOAD to evade defenders and persist within systems. I became really disconcerted at the lack of visibility around this threat. The closest bit of visibility I could find was implemented in osquery ([Alienvault](https://www.alienvault.com/blogs/labs-research/hunting-for-linux-library-injection-with-osquery), [Palantir](https://github.com/palantir/osquery-configuration/blob/master/Classic/Servers/Linux/osquery.conf)) and with select hunts using shell [commands](https://twitter.com/ForensicITGuy/status/1153291548978794496).

And then I read the manpage for rtld-audit- [http://man7.org/linux/man-pages/man7/rtld-audit.7.html](http://man7.org/linux/man-pages/man7/rtld-audit.7.html).

It turns out there’s an audit API exposed by the dynamic linker that may be leveraged by libraries specified in another environment variable- LD_AUDIT. In my spare time, I initially dove into this API exploring a function named `la_preinit()` which lets an audit library take actions after all libraries have been loaded but before control is passed to the executable. My hope was to implement visibility folks could use by logging preloads that have been mapped to syslog. I started out with Golang and then Rust, but neither language would compile properly for an LD_AUDIT library (although they can be used with LD_PRELOAD).

So I started learning C and test-driven development. Around this time I read the manpage for rtld-audit in more depth, noting one particular function- `la_objsearch()`. When the dynamic linker loads libraries for execution, it has to reconcile libraries requested by an ELF binary and find them on disk. When the linker searches for a particular library, it triggers the `la_objsearch()` function. The function typically returns the name a linker should use to further search for a library.

Then I read this line- **“If NULL is returned, then this pathname is ignored for further processing.”**

![](/img/whitelisting-ld_preload-fun-no-profit/curiosity-attention.jpg)

Could it be that simple? I set off to start another project around whitelisting LD_PRELOAD binaries with a simple design. I wanted to implement `la_objsearch()`, check each library loaded against the known lists of preloads (environment variable and `ld.so.preload`) and then return NULL for each preload that wasn’t also included in a known-good list. I was shocked to discover that this approach actually worked!

## Introducing libpreloadvaccine!

The result of this research and project is [libpreloadvaccine](https://github.com/ForensicITGuy/libpreloadvaccine). This tool is designed to load with every process execution, checking library loads against preload lists. If a preload search is attempted and isn’t allowed, libpreloadvaccine instructs the dynamic linker to ignore the preload. This hinders the successful execution of libraries using LD_PRELOAD.

Admittedly, this is the first version of the tool and it likely needs a bit extra work. Definitely test this before putting into production in your server farms! I’d love to see this functionality built into the dynamic linker itself, making this tool redundant. Until then, this is designed to help shore up systems against the LD_PRELOAD threat. I’m offering libpreloadvaccine to the public as open source code with a MIT License. Go forth and make the world a better place using it where you can!

Here it is in action against a module from Merlin:

![](/img/whitelisting-ld_preload-fun-no-profit/libpreloadvaccine-in-action.png)

## Installing libpreloadvaccine

To install libpreloadvaccine, first build it for your system by running `make build`. Copy the compiled shared object into the preferred library folder of your system. Then export the environment variable LD_AUDIT defining the path of your libpreloadvaccine library.

To make it persistent, add a line like this to your `/etc/profile` file:

```
export LD_AUDIT=<path to libpreloadvaccine>
```

If you want to whitelist preloads, create a space-delimited list at `/etc/libpreloadvaccine.allow`. Preload paths found in this list will be allowed for execution.

Go forth and be excellent!

![](/img/whitelisting-ld_preload-fun-no-profit/be-excellent.jpg)
