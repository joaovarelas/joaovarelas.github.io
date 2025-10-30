---
title: Red Team - Compromising Critical Infrastructure by Reversing SCADA Software
author: vrls
date: 2025-04-28
#categories: [TOP_CATEGORIE, SUB_CATEGORIE]
tags: [red, team, critical, infrastructure, scada, hmi, reversing, reverse engineering, cybersecurity, security, ics]
image: /assets/img/posts/2025/04/2bee007c2a61db5114247dd60d0d7bb86944183fc8f827385468b848a1f35a88.jpeg #og:image
permalink: /posts/2025/04/red-team-compromising-critical-infrastructure-by-reversing-scada-software/

#image:
#  src: /assets/img/posts/YYYY/MM/MD5SUMHASH.png
#  width: 350   # in pixels
#  height: 350   # in pixels
---


<!--
<meta name="twitter:card" content="summary_large_image">
<meta property="twitter:domain" content="vrls.ws">
<meta property="twitter:url" content="https://vrls.ws/posts/2025/04/red-team-compromising-critical-infrastructure-by-reversing-scada-software/">
<meta name="twitter:title" content="Red Team - Compromising Critical Infrastructure by Reversing SCADA Software">
<meta name="twitter:description" content="Personal blog about computer hacking & security">
<meta name="twitter:image" content="https://vrls.ws/assets/img/posts/2025/04/2bee007c2a61db5114247dd60d0d7bb86944183fc8f827385468b848a1f35a88.jpeg">



  <img alt="" src="/assets/img/posts/2025/04/2bee007c2a61db5114247dd60d0d7bb86944183fc8f827385468b848a1f35a88.jpeg" width="550px" height="450px" /> -->


# Introduction

Critical sectors such as energy, water, health, banking, MSP's and others are under high scrutiny in terms of security. The NIS2 Directive is pushing European organizations leadership to take a more proactive approach towards cybersecurity to avoid potential incidents.

The goal of this article is to illustrate the process of a red team engagement and how cyber attackers might operate employing diverse techniques and procedures when targeting critical infrastructure, but also to highlight the importance of having a good security posture when maintaining complex IT environments composed of corporate and industrial networks.

We have created labs to replicate target environment as much as possible and perform intrusive testing isolated from real systems avoiding severe consequences or causing unexpected behavior in production. All findings described in this article were responsibly disclosed to affected organizations, and remediation measures have been implemented to address vulnerabilities discovered during this engagement.



# Key Takeaways

Our red team assessment revealed security gaps where corporate network compromises created bridges to industrial control systems, demonstrating how modern attack vectors can bypass traditional IT/OT boundaries:

- Critical infrastructure remains vulnerable through multi-stage attack chains that connect corporate and industrial networks

- Seemingly minor misconfigurations in corporate networks (like default or misconfigured Active Directory settings) can ultimately provide pathways to reach critical OT systems

- Even security-focused industrial applications can be undermined through reverse engineering, weak privileged access and credential management

- The convergence of IT and OT networks creates significant security blind spots that determined attackers can exploit

- Effective protection requires a unified security approach spanning both corporate and industrial environments

- Following vendor security advisories and implementing manufacturer cybersecurity guidance is essential - outdated industrial control systems contain documented vulnerabilities that attackers specifically target


# Part 0x01 - Escalating Privileges in Corporate Active Directory

## Initial Access - Assumed Breach Scenario


This time we were tasked to begin a red team engagement within organization premises. Customer provided access to a regular virtual machine placed in servers network (VLAN) together with other production machines so we could mimic what an attacker *would see* and *could do* in case of a compromise (e.g., RCE exploit, webshell, etc).

It was the most realistic option, compared to starting from an isolated guest WiFi or, in contrast, from a privileged IT management network. The server was in a fair place to start as it had reasonable communication activity and could reach other corporate assets, *but not all*.

For reference, other red team members were performing an external penetration test of internet-facing assets, and a high severity issue was identified that could lead to a compromise of an internal server. In practice it was feasible to chain the external attack vector + internal vector and achieve a full attack path from internet to reach critical infrastructure, as we will see throughout this article.



## Password Spraying AD Users

Once we gained a foothold in the provided VM as a starting point and established a connection with our command and control (C2), we proxied connections and began scanning neighbors in the network looking for alive services.

In general, most frequent assets identified during scans are `physical servers`, `domain controllers`, `network devices (firewalls, switches)`, `databases`, `storage (NAS)`, `application servers` and so on. Since we started without passwords or any kind of credential, we aimed at Active Directory server first.

One way we easily identified a Domain Controller was by looking for services:
- `SMB (445)`, `LDAP (389)`, `AD-DNS (53)` and `Kerberos (88)`

When we found a host with those services enabled, we could say with confidence it was one of the Domain Controllers.

After that, we performed a quick password spray using [kerbrute](https://github.com/ropnop/kerbrute) tool against DC Kerberos service and found credentials of a user where password equaled the username, from a list of AD users that was fetched from a legacy member server using a null SMB session. This user was simply a regular domain user without special privileges and likely forgotten. Let's call it `lab.local\appuser1`.

```bash
nmap -PS -sT s-sV -p 445,389,88 --open 192.168.99.0/24
nxc smb -u '' -p '' 192.168.99.0/24 --users
kerbrute_linux_amd64 bruteforce --dc dc.lab.local -d lab.local -v userpass.txt
```

![image](/assets/img/posts/2025/04/e808f5b6a3f57af5140b1676a0f7b4dfb2202c8c27e435bc2d9b7e785d7f5cc0.png)

Having a valid domain password, we were able to enumerate Active Directory domain more deeply using tools like [BloodHound](https://github.com/SpecterOps/BloodHound) and [ADRecon](https://github.com/adrecon/ADRecon) via LDAP protocol.

Note that we were proxying these actions via provided VM using [proxychains-ng](https://github.com/rofl0r/proxychains-ng) SOCKS5, leveraging the benefits of "Living-off-the-Land" and avoiding installing things inside "compromised" machine that might risk being caught by host defenses like EDR.

BloodHound tool has multiple compatible ingestors written in `C#`, `Rust` or `Python` that fetch AD structured data and compile it into a graph representing the domain users, security groups, organizational units (OU), group policies (GPOs) and so on. During enumeration we used [BloodHound.py](https://github.com/dirkjanm/BloodHound.py) ingestor remotely. ADRecon can also be executed remotely from a non-domain joined machine using PowerShell with [RSAT](https://www.microsoft.com/pt-pt/download/details.aspx?id=45520) toolkit installed.

```bash
bloodhound-python -c All --zip -d lab.local  -u appuser1 -p appuser1 --dns-tcp -ns 192.168.99.20 -dc dc.lab.local
ADRecon.ps1 -Method LDAP -DomainController dc.lab.local -Credential lab.local\appuser1 -GenExcel C:\ADRecon-Report\
```


## Abuse of MachineAccountQuota

One thing we observed when reading enumeration outputs produced by tools above, was the parameter [ms-DS-Machine-Account-Quota](https://learn.microsoft.com/en-us/windows/win32/adschema/a-ms-ds-machineaccountquota) defaulted at `10`. It means any domain user can join up to 10 computers to domain. In other terms, an attacker is able to create computer accounts in domain (usually named as `COMPUTER$`) with a pre-defined password.

Abusing default configuration, we created a new computer object in organization domain named `ATTACKER$` with our password, using [impacket-addcomputer.py](https://github.com/fortra/impacket/blob/master/examples/addcomputer.py).

```bash
$ addcomputer.py -computer-name 'ATTACKER$' -computer-pass 'Password.123' -dc-host dc.lab.local 'lab.local/appuser1:appuser1'

    Impacket v0.13.0.dev0+20250422.104055.27bebb13 - Copyright Fortra, LLC and its affiliated companies
    [*] Successfully added machine account ATTACKER$ with password Password.123.
```



## Exploiting "WriteAccountRestrictions" DACL with RBCD

By analyzing BloodHound output carefully, we noticed there was a path to escalate from `Domain Computers` to one `Read-Only Domain Controller (RODC)` because  `Domain Computers` security group was a member of `Allowed RODC Password Replication` group and had a permission called `WriteAccountRestrictions`.

This configuration didn't seem standard. Instead, it might have happened due to a misconfiguration from a system administrator while creating and promoting a new server to (RO)DC, but root cause of this configuration was unclear.

![image](/assets/img/posts/2025/04/832c3be994e5978936446e67215674f739d74a03f0b5bac8ad92352a3c124dfd.png)

We performed the typical Kerberos Resource-Based Constrained Delegation (RBCD) attack. This involved setting the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute to the SID of our `ATTACKER$` computer account. This configuration allowed us to impersonate the `Administrator` user on the `RODC` using `ATTACKER$` credentials via `S4U2Proxy`.

```bash
$ rbcd.py -delegate-to 'RODC$' -delegate-from 'ATTACKER$' -k -action write -dc-ip 192.168.99.20 'lab.local/ATTACKER$:Password.123'
    [*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
    [*] Delegation rights modified successfully!
    [*] ATTACKER$ can now impersonate users on RODC$ via S4U2Proxy
    [*] Accounts allowed to act on behalf of other identity:
    [*] ATTACKER$ (S-1-5-21-1988370448-1183679873-2997581360-1604)

$ getST.py -spn cifs/rodc.lab.local -impersonate 'Administrator' 'lab.local/ATTACKER$:Password.123'
    [*] Getting TGT for user
    [*] Impersonating Administrator
    [*] Requesting S4U2self
    [*] Requesting S4U2Proxy
    [*] Saving ticket in Administrator@cifs_rodc.lab.local@LAB.LOCAL.ccache

$ secretsdump.py -dc-ip 192.168.99.20 -k -no-pass 'lab.local/Administrator@rodc.lab.local'
    [*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
    [*] Using the DRSUAPI method to get NTDS.DIT secrets
    Administrator:500:aad3b435b51404eeaad3b435b51404ee:71e236826b080ec3c22d7d4c31edc54e:::
    Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ab931b73c59d7e0c089c0:::
    krbtgt:502:aad3b435b51404eeaad3b435b51404ee:9fd3a549dffd8c0715d90b9814febb28:::
```

Now you may be surprised (as we were at the time) why DCSync worked on a Read-Only DC. In fact, `RODC` despite the name was not actually Read-Only. Instead, it was a regular DC and belonged to the `Domain Controllers` group. By default, a regular RODC do not cache user credentials. 

We decided to move straight into DC using Pass-the-Hash via Windows Management Instrumentation (`WMI`), placed another reverse SOCKS5 connection there and chained it. Now we could reach a lot of AD-joined computers, including  servers, desktops and even some personnel notebooks from multiple departments.

The Active Directory exploitation part is not the focus in this article, so we'll reference SpecterOps documentation [[1]](#references) that explains how this `WriteAccountRestrictions` DACL can be abused, and also a blog post from Dirk-jan [[2]](#references) covering in-depth these permissions.


```bash
nxc wmi dc.lab.local -d lab.local -u Administrator -H 71e236826b080ec3c22d7d4c31edc54e -x 'cmd'
```





# Part 0x02 - Pivoting to Restricted Network and Reversing SCADA Security

## Discovery of Valuable Assets

At this point we already had company AD domain compromised: gained domain administrator privileges, could forge Golden Tickets and gain remote access to *almost* any AD-joined server and workstation. But was that enough to demonstrate impact in our final report? Probably for cybersecurity teams, SOC, IT administrators and other technical people it would suffice.

Considering how quickly we compromised the domain (in part thanks to quality tools we used and awesome research existing out there), we still had plenty of time to continue our engagement *as far as we could*. In coordination with our customer, we decided to continue our assessment and see what would be possible to do from a domain admin standpoint.

Spending more time analyzing domain structure, types of users, groups, organizational units and computers, we compiled a shortlist of interesting targets to attack. One that caught our attention was a computer named similar to `HISTORIAN.lab.local`.

After researching this subject we found that it is common in organizations working with industrial and operational technology to have an application used for data collection & repository.

The purpose of `historian` servers is to collect, archive, and provide access to time-series data from industrial processes, essentially creating a comprehensive historical record of all operational parameters, such as power generation outputs and grid stability parameters in energy facilities, pressure readings and flow rates in oil and gas pipelines, or even chemical dosages and filter statuses in water treatment facilities.



## Credential Dumping from Historian

Login was possible into historian because we owned a privileged account, a network connection and a service running Remote Desktop Protocol `RDP`. Enumerating the system led us to find reporting software and some collected data. Some personnel actively used this server for their job duties.

We did a process dump of `lsass.exe` system process responsible for handling authentication and security in Windows. For the purpose of this article, lets consider dumping the process with [procdump64.exe](https://learn.microsoft.com/en-us/sysinternals/) tool and then parsing the dump (offline) with [mimikatz](https://github.com/gentilkiwi/mimikatz) to look for user credentials or other secrets. Following this method led us to discover a new credential: `SCADA\supplier01`.

There are several ways to dump processes. For example, it's possible to create a full memory dump with `memory acquisition` tools ([FTK Imager](https://www.exterro.com/digital-forensics-software/ftk-imager-temp), [Magnet RAM](https://www.magnetforensics.com/resources/magnet-ram-capture/)) that are used by blue teams to extract the system memory contents and then use tools to parse and analyze data from RAM dump like [volatility3](https://github.com/volatilityfoundation/volatility3). Other options include accessing virtual machines storage and grab a snapshot including the VM memory (e.g. VMware `.vmem` files) [[3]](#references).  

Note, Credential Guard [[4]](#references) and other LSA Protections [[5]](#references) were not configured in this system so it was easier to hack into Local Security Authority process.

Some techniques to attack Process Protection Light (PPL) have been released, such as [PPLdump](https://github.com/itm4n/PPLdump), [PPLKiller](https://github.com/RedCursorSecurityConsulting/PPLKiller), [Dellicious](https://github.com/jbaines-r7/dellicious) and probably other modern methods, or similar tools that abuse vulnerable legitimate drivers also known as Bring Your Own Vulnerable Driver (BYOVD) but that's out of scope.


```bash
procdump64.exe -accepteula -ma -64 lsass.exe c:\lsass.dmp
mimikatz.exe
sekurlsa::minidump c:\lsass.dmp
sekurlsa::logonPasswords
    Authentication Id : 0 ; 1927007 (00000000:001d675f)
    Session : RemoteInteractive from 2
    SID : S-1-5-21-1988370448-1183679873-2997581360-500
        ssp :
        [00000000]
        * Username : supplier01
        * Domain : SCADA
        * Password : Password.123
```


## Jumping into SCADA Server

Another important aspect to note about `HISTORIAN` server was the number of network interfaces available. This particular server was *dual-homed*: besides the connection to corporate network, it also had another IP address assigned and communicated with hosts in a different network with distinct IP range.

Network configuration was fetched using commands like `ipconfig`, `netstat` and Microsoft Sysinternals [tcpview64.exe](https://learn.microsoft.com/en-us/sysinternals/) utilities to identify established connections with a server running SCADA software.

<img alt="" src="/assets/img/posts/2025/04/095290ada74d2b2483480eb4e955384d3d202819d125a0b7f48d0c4157f4a905.png" />

<p style="text-align:center;">Picture adapted from <i>NIST SP 800-82: Guide to Operational Technology (OT) Security</i> <a href="#references">[6]</a>.</p>


Let's assume the `SCADA` server has IP address `10.1.1.10`. The user `supplier01` had Remote Desktop privileges to SCADA server and was local administrator.

After enumerating that system we found:

- SCADA project in runtime `InduSoft Web Studio`
- RDP session from an inactive user `remote.operator` *(Disconnected)*


The same user had a `Secure Viewer` process running. It was a desktop client component of InduSoft Web Studio which provides secure remote access to SCADA/HMI applications [[7]](#references). Another Thin Client was available through Internet Explorer and required ActiveX Controls and VBScript. Edge browser could be used in "compatibility mode" to run the legacy web app despite its security warnings.

Our goal at this moment was to peek into the SCADA interface. However, we couldn't run another process because the user `remote.operator` had already started it. The configured server ports were already assigned. For obvious reasons, **we couldn't stop or restart those processes in a production environment**.

Next idea was to somehow takeover the existing and inactive RDP session. Since we got privileges over the machine, we could use a know technique to hijack RDP sessions via `tscon.exe` [[8]](#references).

All we need is SYSTEM command line, either with `psexec.exe -s` or creating a service with `sc.exe` that executes the following command:

```bash
C:\Windows\system32>query user
C:\Windows\system32>sc create sesshijack binpath= "cmd.exe /k tscon TARGSESSID /dest:rdp-tcp#MYSESSIONID"
```

Once the service started, our desktop would connect to victim RDP session.

The naïve way is to open `taskmgr.exe`, right-click *disconnected* user session and click **Connect** but system requires target user password in order to successfully switch RDP console.

<img alt="" src="/assets/img/posts/2025/04/2f41b665eca3201ea13db30d967da07ce938a54661168b407d4bdd2898d5ec66.png" width="550px" height="500px" />

We avoided at all costs interfering with that system in production so `tscon` RDP hijack method was not tested this time. To access SCADA viewer running inside another user context, we needed `remote.operator` user password and started looking for it.

Our attempt using [DonPAPI](https://github.com/login-securite/DonPAPI) tool for dumping DPAPI secrets remotely revealed password for `remote.operator` saved inside a Scheduled Task configured to automatically start SCADA server at system startup.


```bash
$ donpapi collect -t 10.1.1.10 -d '.' -u supplier01 -p Password.123
    [💀] [+] DonPAPI Version 2.1.0
    [💀] [+] Output directory at /home/user/.donpapi
    [💀] [+] Loaded 1 targets
    [10.1.1.10] [+] Starting gathering credz
    [10.1.1.10] [$] [DPAPI] Got 7 masterkeys
    (...)
    [10.1.1.10] [+] Dumping User and Machine Credential Manager
    [10.1.1.10] [$] [CredMan] [SYSTEM] Domain:batch=TaskScheduler:Task:{4BCE964B-970C-4C1E-BE22-56AF28B59777} - SCADA\remote.operator:Password.123
```

After we escalated domain privileges, moved into historian server, pivoted to a restricted network, captured an operator account password and hijacked the RDP session to access the desktop. However, we were presented with nothing but a lousy `ACCESS DENIED` message.

<img alt="" src="/assets/img/posts/2025/04/3dea08d942fdff0059857a1aaf436750c053d18e68955fb1563403756280a6a7.png" width="600px" height="600px" />





## Reversing InduSoft Web Studio


InduSoft Web Studio (IWS) began as a proprietary SCADA/HMI development platform before being acquired by Wonderware in 2013 and subsequently becoming part of AVEVA portfolio after Schneider Electric's acquisition. The solution has evolved significantly, becoming one of the more widely deployed SCADA development environments in industrial applications.

The platform follows a typical architecture for modern SCADA solutions, with separate development and runtime environments. The development environment allows engineers to design custom HMI interfaces, configure tags, create scripts, and establish connections to industrial controllers (PLCs). Once developed, projects can be compiled and deployed to runtime environments that execute the actual monitoring and control functions.

Given the critical nature of critical facility we were assessing, we established a separate laboratory environment to analyze InduSoft software without risking disruption to the production system. Our lab setup included:

- Identical versions of InduSoft Web Studio to match the target environment
- A virtual machine configured to mirror the production SCADA server's operating system
- Sample project files with similar structures to those we observed in the production environment
- Network isolation to prevent any accidental connection to operational systems

An installer was found at [ICP DAS website](https://www.icpdas.com/products/Software/InduSoft/indusoft_download.htm) for the InduSoft Web Studio v8.0 & v8.1. We installed the same version in our virtual machine that allowed us to safely reverse engineer components of the software, analyze the authentication mechanisms and the rest of "Security System".



### Freezing the Time


After installing InduSoft Web Studio it ran in `Evaluation Mode`. It allows users to trial the software during 40 hours.


<img alt="" src="/assets/img/posts/2025/04/e4734de38f1e709d0f959a08db1ae64db2a4de56a8ca9d91a8bb2e51115ce93e.png" />


We did not have a license and obviously could not afford one specifically for testing its security. After all, the goal of this engagement was to uncover security holes in the critical sector organization's systems. The hypothesis we had to consider:

- Reverse InduSoft license and activation - Hard, required cryptography, hashing and bitwise operations to understand keygen.
- Uninstall/reinstall and hope counter will reset - Did not work.
- Take VM snapshot and restore it when evaluation timer is expiring - Unfeasible, we had tools inside same VM such as debugger, IDA project, etc.
- Stop the timer by patching couple bytes - **it worked!**, patched `jmp` instructions to avoid branching into specific blocks and stopped counter via `GetTickCount()` calls.

The most important modules of InduSoft Web Studio were:

- `Studio Manager.exe` - Main program that actually runs eveything (entrypoint).
    - `Studio.dll` - Main library for Web Studio GUI.
    - `UniSoft.dll` - Contains business logic components, config and project loading, APIs, multi-threading stuff.
    - `score.dll` - It might "Studio Core" or "Security Core". Handles security system, user authentication, groups, user rights, and so on.
- `RunUniReg.exe` - A wrapper for Studio Manager to load `UniReg.dll`.
    - `UniReg.dll` - Responsible for licensing, activation, key generation based on network interface MAC addr and CLSID.


This was the decompiled code view after patching clock at `UniSoft.dll` module to ensure we have enough time to perform our security testing. We observe that clock displayed on graphical interface is asynchronous to evaluation mode clock and updates every 10 to 15 seconds. After patching, it will freeze and likely never reach 00:00.

<img alt="" src="/assets/img/posts/2025/04/608fa20e3105db511eb7298a23ff008321d4c05901057494ea6c3442e6e3a7fc.png" />


<img alt="" src="/assets/img/posts/2025/04/161c1247b39883841a028a0084af6d6bdf1506a2da886ea318e78743321bf7a4.png" />



Licensing by activating a site key won't be covered here for obvious reasons but we found online some hints about how the key generation might work. I will leave here a document found on [Scribd](https://www.scribd.com/document/470894352/Installation-pdf) and reference to users posts talking about Site Codes & Activation Keys at [PLCForum](https://plcforum.uz.ua/viewtopic.php?t=28975&sid=8e6993469780a14c8c9f4f38d1e1b6e3&start=50):

<img alt="" src="/assets/img/posts/2025/04/ada63df4f6499514c49b45dc03c538d51a06c82e76d9d571a79d5d0f9a1b2d62.png" />





### Security System

InduSoft Web Studio implements a multi-layered security architecture that controls access to both development and runtime environments. 

The system manages users and groups with configurable access levels, supporting local authentication, distributed security across projects, or Active Directory domain integration [[9]](#references). 


<img alt="" src="/assets/img/posts/2025/04/5622a508307ce904978075dd0ee4eb6c44b6f550a5a8e66431e879b9e5820ed6.png" />


All security settings are stored in encrypted database files with passwords hashed and salted to protect credentials. This framework provides granular control over who can access specific application features, screens, and controls throughout the SCADA system. Database encryption is proprietary but it is possible to recover the keys and restore the contents.

Remember that it was a production server in runtime. We couldn't stop or restart services and the InduSoft project security denied modifications of database during runtime so making it difficult to modify or add new SCADA users.  


<img alt="" src="/assets/img/posts/2025/04/624dd96332e8fab14ab7fffe4c35bf542bc91bbde6359a979afe3e323dc4679d.png" />



### Dumping Hashes from Process Memory


During our red team engagement we were able to dump database sections from the system process without having to reverse engineer proprietary DB protection. We used [Process Hacker 2](https://sourceforge.net/projects/processhacker/files/processhacker2/) to scan memory for strings (usernames) and we found a config section with unencrypted database contents with several security groups, usernames and their hashes.

<img alt="" src="/assets/img/posts/2025/04/f7819e5cd6e5de5b54ee09dc579dfbcb483101e39c6a3c9544c30a5cd23ef4b1.png" />


After *beautifying* JSON parsed from memdump:

<img alt="" src="/assets/img/posts/2025/04/f643bccb07e75895cb742a372ce08994c841f8dcd5506c9c905bb0d438d803a1.png" />


We had to understand what was the type of hash and if it was a custom implementation or had additional protections such as **salting**. Note the *case sensitivity* of password field.

When debugging InduSoft with IDA Pro we placed some breakpoints at login functions, in particular `score.dll!SELogOn`. It led us to user and password comparison functions where a MD5 hash is generated with a static salt `%@tE7(` prepended to *lowercase* password. Before hashing, the whole string is encoded into `UTF-16-LE`:  

- tl;dr the password storage and authentication scheme is `MD5(UTF16LE(salt+lowercase(password)))`


<img alt="" src="/assets/img/posts/2025/04/453bb1397410306e3598c75f87792730b3a2e2373349672a63e07fbb1b679d1f.png" />



Time to setup [hashcat](https://hashcat.net/hashcat/) on our cracking machine with dedicated graphics card to break those MD5 hashes and recover plaintext passwords of SCADA users. We generated a custom wordlist with salt `%@tE7(` prepended to each line, then used hashcat mode `70` as documented in Hashcat Wiki [[10]](#references).

```bash
hashcat -m 70 -a 0 hashes.txt ~/tools/wordlists/password-wordlist.txt

    27ebfd4fa443ddda15ff6dd64f96be91:%@tE7(engineer       
    2b2f63dc665122bc867f7c94354a4af9:%@tE7(password.123
    9a288abb102206569d886fa96fc2c195:%@tE7(                   
```


## Authenticating in SCADA

After several hours of reverse engineering the software in our offline lab and cracking password hashes, we finally authenticated in `SCADA` as a privileged user with development & runtime access.  


<img alt="" src="/assets/img/posts/2025/04/f4e214d3687b0cf7104c21ab59761872466433152b06b3ae2331a743a50c348b.jpeg" />




# Conclusion

This red team engagement demonstrated the concerning reality that critical infrastructure remains vulnerable to determined attackers through a multi-stage attack chain. Starting from a simple foothold in a corporate network, we were able to progressively escalate privileges, pivot across network boundaries, and ultimately gain control over industrial control systems responsible for essential services.

Key lessons emerged from this assessment:

- Network segmentation alone is insufficient when dual-homed systems like historian servers create bridges between corporate and OT networks
- Even when specialized industrial systems provide a lot of security features, their users/customers fail to configure them properly (see [AVEVA Cybersecurity Deployment Guide](https://docs.aveva.com/bundle/cybersecurity-deployment-security-concepts/page/1510579.html))
- Default configurations in Active Directory can be exploited as initial footholds
- The complexity of modern SCADA systems creates a substantial attack surface that extends beyond just network security
- Legacy systems and development shortcuts in industrial software create opportunities for attackers to bypass access controls
- Accessibility and rapid login needs never justify weak passwords or absent MFA on critical systems - the security risks far outweigh operational convenience
- Excessive privileges common throughout the environments might indicate lack of enforcement of principle of least privilege
- Logging, monitoring, and detection capabilities are crucial across both IT and OT networks - without visibility, attackers can move freely between environments, extract credentials, and access critical systems undetected for extended periods of time 

Organizations managing critical infrastructure must adopt a defense-in-depth approach that encompasses both IT and OT security, implements proper credential management, and regularly tests security controls. 

Furthermore, the findings emphasize the importance of monitoring systems that cross network boundaries and applying mandatory (!) security updates to industrial control software - AVEVA Edge has superseded InduSoft Web Studio and there are multiple advisories by [CISA.gov](https://www.cisa.gov/news-events/cybersecurity-advisories?search_api_fulltext=indusoft&sort_by=field_release_date&url=).




# Toolset

| Tool | Description |
|------|-------------|
| **Network Discovery & Enumeration** | |
| [nmap](https://nmap.org/) | Network scanner for service discovery |
| [netexec (nxc)](https://github.com/Pennyw0rth/NetExec) | Swiss-army knife for network protocol attacks |
| [proxychains-ng](https://github.com/rofl0r/proxychains-ng) | Proxy tool for pivoting connections |
| [tcpview](https://learn.microsoft.com/en-us/sysinternals/) | Sysinternals tool for viewing TCP connections |
| **Active Directory Tools** | |
| [kerbrute](https://github.com/ropnop/kerbrute) | Tool for bruteforcing and enumerating AD users via Kerberos |
| [BloodHound](https://github.com/SpecterOps/BloodHound) | AD relationship visualization and attack path finder |
| [BloodHound.py](https://github.com/dirkjanm/BloodHound.py) | Python-based ingestor for BloodHound |
| [ADRecon](https://github.com/adrecon/ADRecon) | AD information gathering tool |
| [impacket](https://github.com/fortra/impacket) | Collection of Python scripts for network protocols |
| **Credential Access** | |
| [procdump](https://learn.microsoft.com/en-us/sysinternals/) | Sysinternals tool for dumping process memory |
| [mimikatz](https://github.com/gentilkiwi/mimikatz) | Tool for extracting plaintext passwords from memory |
| [DonPAPI](https://github.com/login-securite/DonPAPI) | Tool for extracting DPAPI secrets remotely |
| [hashcat](https://hashcat.net/hashcat/) | Advanced password recovery utility |
| **Memory Forensics** | |
| [FTK Imager](https://www.exterro.com/digital-forensics-software/ftk-imager-temp) | Commercial forensic imaging tool |
| [Magnet RAM](https://www.magnetforensics.com/resources/magnet-ram-capture/) | Commercial RAM capture tool |
| [volatility3](https://github.com/volatilityfoundation/volatility3) | Memory forensics framework |
| **Reverse Engineering** | |
| [Process Hacker 2](https://sourceforge.net/projects/processhacker/files/processhacker2/) | Advanced process monitoring and memory inspection |
| [IDA Pro](https://hex-rays.com/ida-pro/) | Professional disassembler and debugger |
| **Lateral Movement** | |
| [PsExec](https://learn.microsoft.com/en-us/sysinternals/) | Sysinternals tool for remote command execution |
| **Service Control** | |
| sc.exe | Native Windows service control utility (Built into Windows) |
| **Industrial Control Software** | |
| [InduSoft Web Studio](https://www.aveva.com/en/products/indusoft-web-studio/) | SCADA/HMI development and runtime environment |
| Secure Viewer | Thin client for InduSoft Web Studio (Part of InduSoft Web Studio) |




<a href="#" id="references"></a>

# References

- [1] SpecterOps, "WriteAccountRestrictions - DACL-Based Control," BloodHound Documentation. Available: [https://bloodhound.specterops.io/resources/edges/write-account-restrictions](https://bloodhound.specterops.io/resources/edges/write-account-restrictions)

- [2] Dirk-jan Mollema, "Abusing forgotten permissions on computer objects in Active Directory - dirkjanm.io" Security Blog, October 27, 2022. Available: [https://dirkjanm.io/abusing-forgotten-permissions-on-precreated-computer-objects-in-active-directory/](https://dirkjanm.io/abusing-forgotten-permissions-on-precreated-computer-objects-in-active-directory/)

- [3] Diverto, "Extracting passwords from hiberfil.sys and memory dumps", Information Security Warriors. November 5, 2019. Available: [https://diverto.github.io/2019/11/05/Extracting-Passwords-from-hiberfil-and-memdumps](https://diverto.github.io/2019/11/05/Extracting-Passwords-from-hiberfil-and-memdumps)

- [4] Microsoft Security Team, "Detecting and preventing LSA credential dumping attacks," Microsoft Security Blog, October 5, 2022. Available: [https://www.microsoft.com/en-us/security/blog/2022/10/05/detecting-and-preventing-lsass-credential-dumping-attacks/](https://www.microsoft.com/en-us/security/blog/2022/10/05/detecting-and-preventing-lsass-credential-dumping-attacks/)

- [5] Microsoft, "Configuring Additional LSA Protection," Windows Server Security Documentation, March 26, 2025. Available: [https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)

- [6] National Institute of Standards and Technology, "Guide to Operational Technology (OT) Security," NIST Special Publication 800-82 Revision 3, September 2023. Available: [https://csrc.nist.gov/pubs/sp/800/82/r3/final](https://csrc.nist.gov/pubs/sp/800/82/r3/final)

- [7] Helpmax, "Configuring the Thin Client", Web Studio Help. Available: [https://webstudio.helpmax.net/en/thin-clients-and-mobile-access/web/configuring-the-thin-client/](https://webstudio.helpmax.net/en/thin-clients-and-mobile-access/web/configuring-the-thin-client/)

- [8] Alexander Korznikov. A bit of security, "Passwordless RDP Session Hijacking Feature All Windows versions", March 2017. Available: [https://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html](https://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html)


- [9] Helpmax, "Project Security", Web Studio Help. Available: [https://webstudio.helpmax.net/en/project-security/](https://webstudio.helpmax.net/en/project-security/)


- [10] Hashcat, "Example Hash Modes", Hashcat Wiki. Available: [https://hashcat.net/wiki/doku.php?id=example_hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)  

- [11] AVEVA, "Cybersecurity Deployment Guide - Security Concepts". Available: [https://docs.aveva.com/bundle/cybersecurity-deployment-security-concepts/page/1510579.html](https://docs.aveva.com/bundle/cybersecurity-deployment-security-concepts/page/1510579.html)