---
layout: post
title: "Decoding an Encoded Webshell Using NodeJS"
date: 2022-01-06
categories: malware webshell nodejs javascript
permalink: /decoding-webshell-using-nodejs/
---

In this post I want to walk through a process of using the NodeJS REPL (Read, Eval, Print Loop) to safely decode portions of malware during analysis. If you want to follow along at home, the sample I'm working with is here in MalwareBazaar: 

[https://bazaar.abuse.ch/sample/0ca9ca069b144ee4f9359f917c70c15015126eefa6bd60c9a2da77169f3ea122/](https://bazaar.abuse.ch/sample/0ca9ca069b144ee4f9359f917c70c15015126eefa6bd60c9a2da77169f3ea122/)

## Initial File Triage

The tags in MalwareBazaar say the sample is a webshell, but it's always possible the sample was misclassified. So, let's approach it with caution and get an idea of its contents using `file`.

```
remnux@remnux:~/cases/wso$ file wso.js 
wso.js: ASCII text, with very long lines, with no line terminators
```

It looks like we're working with a simple text file. Let's take a peek at the contents using `head` or `less`. Since all the code inside is on just one or two lines, `head` returns all the text by default. Let's just limit it to the first 100 bytes.

```
remnux@remnux:~/cases/wso$ head wso.js -c 100
document.documentElement.innerHTML=String.fromCharCode(60, 63, 112, 104, 112, 32, 10, 47, 47, 32, 83
```

In the output we can see the sample contains JavaScript that should execute in a web browser. The [`document.documentElement`](https://developer.mozilla.org/en-US/docs/Web/API/Document/documentElement) object in JavaScript allows you access properties of the standard `<html>` tag in browsers. The [`.innerHTML`](https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML) property lets you access the contents of the tag. In this case, the material returned from [`String.fromCharCode`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/fromCharCode) will be set to the contents of the document HTML tags.

## Decoding the Contents

Alright, there are a few ways we can decode JavaScript, but one of my favorites is using the NodeJS REPL. Remember how in Python you can access a console that lets you specify arbitrary commands that get evaluated? You can do the same thing with NodeJS and it works marvelously. On a system with the NodeJS runtime installed, just execute `node` or `node.exe`. I usually analyze JavaScript in Visual Studio Code and have an instance of `node` running in the terminal that is part of VSCode.

![VSCode with NodeJS REPL](/assets/images/decoding-webshell-using-nodejs/vscode-node-repl.png)

In some cases we can copy and paste code directly into the `node` interface, but this file is about 95KiB in size. If we try pasting that amount of text into the command line we're going to wait a long time for the command line to catch up and then execute. I've learned this the hard way. Instead, let's make a JS file we can execute with `node`! This will process much faster than pasting a ton of data to the command line.

We can use the [`fs.writeFileSync()`](https://nodejs.org/api/fs.html#fswritesyncfd-string-position-encoding) function to write the output of `String.fromCharCode` to a file on disk. 

```js
fs = require('fs');

page = String.fromCharCode(60, 63, 112, 104, 112, 32, ... );

fs.writeFileSync('clearpage.txt',page)
```

Now we can execute `node deobfuscate.js` or whatever else your script is named. Afterward, let's take a look at what kind of file was deobfuscated.

```
remnux@remnux:~/cases/wso$ node deobfuscate.js 

remnux@remnux:~/cases/wso$ file clearpage.txt 
clearpage.txt: PHP script, UTF-8 Unicode text, with very long lines

remnux@remnux:~/cases/wso$ head -c 25 clearpage.txt 
<?php 
// Shell Mr.Lutfie
```

Awesome, it looks like we got a PHP file so we can rename it to `clearpage.php` or something similar for further analysis. This same decoding method also works with JavaScript you might find in Windows malware executing via wscript or cscript. In those cases, the generic JavaScript code structures will be valid inside NodeJS, but Windows-specific structures like ActiveX objects will cause errors.

## Other Ways to Decode

While we're here, let's take a look at a couple of methods to verify your decoding worked properly. First, we can use a local web browser. To do this, we can disable our network connection, open Firefox, and open up the the browser developer tools to access its JavaScript console. Then we can paste in the entirety of the encoded webshell from beginning to end.

![Browser JavaScript Entry](/assets/images/decoding-webshell-using-nodejs/browser-javascript-entry.png)

After executing in the console, we can see the page attempt to render in the browser and we can grab the decoded PHP code.

![Browser PHP Rendered](/assets/images/decoding-webshell-using-nodejs/browser-php-render.png)

Finally, if you love CyberChef, you can also use it to validate your decoding. Copy all the arguments for `.fromCharCode` into CyberChef and bake using the recipe `From Charcode` setting the separator to "comma" and base to 10.

![CyberChef Decoding](/assets/images/decoding-webshell-using-nodejs/cyberchef-decoding.png)

`console.log("Thanks for reading!")`