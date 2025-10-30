---
title: RCTS-CERT Summer 2020 CTF - Forensics250 Challenge Writeup
author: vrls
date: 2020-08-06
#categories: [TOP_CATEGORIE, SUB_CATEGORIE]
tags: [rcts, cert, ctf, forensics, virtualbox, openbsd, keepass, autopsy, recovery, johntheripper, jtr, cracking, password]
image: /assets/img/posts/2020/08/c1ea80f406c4e91c7d939630f463daa0.png
---

<!-- ![image](/assets/img/posts/2020/08/c1ea80f406c4e91c7d939630f463daa0.png) -->

## Introduction

This challenge is based on **vm2.ova** file which is used by virtualization applications such as Oracle VM Virtualbox and VMWare Workstation.
Description makes reference to OpenBSD operating system. We can assume that the ova file contains a OpenBSD virtual machine.

## Analysis

Started by importing the virtual machine into our Virtualbox environment. 

![image](/assets/img/posts/2020/08/4a47a0db6e60853dedfcfdf08a5ca249.png)


When we start the virtual machine, the following command line is presented. 

![image](/assets/img/posts/2020/08/fb5c81ed3a220004b71069645f112867.png)

There is a time span of *5 seconds* that allows user to type any commands while at OpenBSD command line before it boots automatically.

We can boot the machine by pressing *ENTER*. 


![image](/assets/img/posts/2020/08/10fb15c77258a991b0028080a64fb42d.png)

The machine is now running, however, we don't have the credentials to log in.

Since we are able to pass flags at boot command line, we can force the system to boot into single user mode.

According to OpenBSD FAQ: *The basic process to regain root is to boot into single user mode, mount the / and /usr partitions and run passwd(1) to change the root password: Boot into single user mode. This part of the process varies depending on your platform. For amd64 and i386, the second stage boot loader pauses for a few seconds to give you a chance to provide parameters to the kernel. Here you can see we pass the **-s flag** to boot(8)*.

Therefore, we are able to get a *root shell* over the OpenBSD machine by typing **boot -s**. 

![image](/assets/img/posts/2020/08/09dd8c2662b96ce14928333f055c5580.png)

![image](/assets/img/posts/2020/08/8266e4bfeda1bd42d8f9794eb4ea0a13.png)

At this time we have access to the machine and ready to explore further. 

## Acquisition

While exploring the filesystem, we found two interesting files:

* **/etc/master.passwd**
* **/root/ctf.kdb**

The **master.passwd** is the BSD master password file that includes usernames, passwords and other account information. This file is equivalent to Unix **/etc/shadow**.

We obtained *root* password hashes from master file and tried to crack with *JohnTheRipper* via dictionary based attack using **rockyou.txt** wordlist, without success. These hashes are produced using the bcrypt algorithm based on Blowfish cipher and have the following form:
**$2b$\[cost]$\[22 character salt]\[31 character hash]**

Moving on to the next file **ctf.kdb**, the extension .kdb suggests it is a *KeePass Password Database file*. 

![image](/assets/img/posts/2020/08/f19c9085129709ee14d013be869df69b.png)

At this time we need to acquire the file in order to perform further analysis.

Since we are running a vanilla virtual machine, i.e., without any fancy Virtualbox Guest Additions, we cannot access the filesystem of the guest machine from our host.

There are several approaches to extract the required file. We could convert the VDI disk image to a Raw image using the following command:

```bash
$ vboxmanage clonehd "C:\Users\vrls\VirtualBox VMs\vm2\vm2-disk001.vdi" "D:\CTF\rcts_cert_summer2020\forensics-250\raw_image.img" --format raw
```

After converting the VDI to *raw_image.img* file, we could use, for example, **Autopsy** digital forensics platform to analyze and extract **ctf.kdb** file.

We could also use file craving techniques, *binwalk* to find and extract the file at a given offset, 7-zip, etc. 

![image](/assets/img/posts/2020/08/9eb9cd58b9ea5e04c890326b5c1f471f.png)

The file was successfully extracted using Autopsy software. If we try to open the password database on **KeePass** a master key input will prompt. Once again, we don't know the password. 

![image](/assets/img/posts/2020/08/602e8f042f463dc47ebfdf6a94ed5a6d.png)

## Cracking

A dictionary attack may be useful to **recover** the **kdb master key**.

We should use *keepass2john* (that is included within JTR toolkit) to convert the KeePass database to JTR compatible format

```bash
> keepass2john.exe "D:\CTF\rcts_cert_summer2020\forensics-250\ctf.kdb" > "D:\CTF\rcts_cert_summer2020\forensics-250\ctf.kdb.jtr"
```

Once we have the JTR compatible file, we are ready to start. By running the following command, it will test all the password combinations within rockyou.txt wordlist and, eventually, return the correct key.

When we were solving this challenge, [@Yanmii_is](https://twitter.com/Yanmii_is) turned up the turbo on his machine to speed up 🚀 the cracking process and retrieve the key.

```bash
john "D:\CTF\rcts_cert_summer2020\forensics-250\ctf.kdb.jtr" --wordlist="D:\Tools\Wordlists\SecLists\rockyou.txt"
```


![image](/assets/img/posts/2020/08/7afbb1602613ec52b265d7a54ad27330.png)



At this time we are able to read the KeePass database file. The file can't be directly opened in KeePass because it was created with an older 1.x version.

Instead, we should create a new 2.x database and import **ctf.kdb**.

After importing the selected file, we can read the flag, thus solving the forensics challenge :)

* **flag{keePassIsKewl}**


![image](/assets/img/posts/2020/08/586e508f161f26ce94633729ac56c602.png)


## References

* https://summer2020.ctf.cert.rcts.pt/
* https://www.openbsd.org/faq/faq8.html#LostPW
* https://en.wikipedia.org/wiki/Bcrypt
* https://www.openwall.com/john/doc/OPTIONS.shtml
* https://medium.com/@lonardogio/convert-vdi-virtualbox-to-raw-in-windows-c96bded29640
* https://bytesoverbombs.io/cracking-everything-with-john-the-ripper-d434f0f6dc1c
* https://jpdias.me/ctf/security/writeup/2020/08/06/rtcs-fccn-summer-ctf.html
