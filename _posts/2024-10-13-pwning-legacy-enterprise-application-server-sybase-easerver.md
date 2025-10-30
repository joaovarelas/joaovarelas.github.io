---
title: Pwning a Legacy Enterprise Application Server - Sybase EAServer  
author: vrls
date: 2024-10-13  
#categories: [TOP_CATEGORIE, SUB_CATEGORIE]  
tags: [web, sybase, easerver, sap, webshell, jsp, java, pivoting, regeorg, neoregeorg, offensive, security, cybersecurity]  
image: /assets/img/posts/2024/10/0a5140b191f5a32ab25d03900a1d6b3122881205dccda363b45e6ed82385c2e0.png #og:image  
permalink: /posts/2024/10/pwning-legacy-application-server-sybase-easerver-jaguar/
#image:  
#  src: /assets/img/posts/YYYY/MM/MD5SUMHASH.png  
#  width: 350   # in pixels  
#  height: 350   # in pixels  
---

<!-- 
<meta name="twitter:card" content="summary_large_image">
<meta property="twitter:domain" content="vrls.ws">
<meta property="twitter:url" content="https://vrls.ws/posts/2024/10/pwning-legacy-application-server-sybase-easerver-jaguar/">
<meta name="twitter:title" content="Pwning a Legacy Enterprise Application Server - Sybase EAServer">
<meta name="twitter:description" content="Personal blog about computer hacking & security">
<meta name="twitter:image" content="https://vrls.ws/assets/img/posts/2024/10/0a5140b191f5a32ab25d03900a1d6b3122881205dccda363b45e6ed82385c2e0.png">



![image](/assets/img/posts/2024/10/0a5140b191f5a32ab25d03900a1d6b3122881205dccda363b45e6ed82385c2e0.png) -->

## Introduction

This article explores the process of compromising a legacy enterprise application server, EAServer. We start by gaining access to the web console by leveraging default credentials, specifically using the default user `jagadmin` with an empty password. Once we have access, we upload a specially crafted web service package that includes a web shell, ensuring compatibility with EAServer through the inclusion of configuration and definition files. This web shell enables command execution, setting the stage for further exploitation of the application server.

## Gaining Access to the Management Console

After installing the web server, the user `jagadmin` is created by default. This user can authenticate for initial server configuration and administration either using the `EAServer Manager` desktop client or through the `WebConsole`.

The Web Console can be accessed by browsing `http://server.local:8080/WebConsole/`, and it requires authentication. If the default password has not been modified by the system administrator, we can easily log in with the `jagadmin` username and an *empty* password.

![image](/assets/img/posts/2024/10/c89e5691213f15db0877acf2472ff3940a971fe9db6f26bc66e6f428146e2853.png)

## Uploading a Custom Web Shell for Code Execution

Now that we have access to the administration console, we can upload new web service applications as WAR (Web Application Archive) packages. The WAR packages typically contain a collection of Java applications, including Java classes, JAR files, JSP, and XML files.

However, this server requires the packages to have a specific format before deployment. In summary, the package should include the `web.xml` configuration and the `wsdd` definition file.

The web shell has the following structure. A template can be found [at this repository](https://github.com/joaovarelas/sybase-easerver-app):

![image](/assets/img/posts/2024/10/9561b0ad43de5ff434d044db2c354756a0435c0b03edee769833c708cd1a6ecf.png)

After packing the web shell application as a WAR file with the command `jar -cvf shell.war *`, we are ready to upload it by right-clicking on the `Web Services Collection` menu in the Web Console and then clicking `Import Collection`.

![image](/assets/img/posts/2024/10/8497e3b4d2ad70c6c20044637b0b1468b17d91e86ac184caaed3c6eb77099bf1.png)

Now we can access the application at `http://server.local:8080/webshell/index.jsp` and remotely execute commands, reading the output.

![image](/assets/img/posts/2024/10/4853ad5f371596a1384a2d3d9be2b7b064471ddcfa082719f678c2fb9cc14f55.png)

## Bonus: Connecting via RDP & Pivoting

Command execution is already possible through the web shell, but we can escalate further by compromising other servers and using them to pivot within the network. In this **LAB**, the EAServer is configured to run under a service account that has administrator privileges, allowing us to execute commands as an elevated user, such as adding a new user with a known password using the command `net user vrls MyPassword.123 /add` and placing it in the `Administrators` group:

![image](/assets/img/posts/2024/10/73857264ee2ca81b9326c87f33dbea04f4b05c54ac4cce6b6bd9ca826097b7d2.png)

An interesting method that we can leverage after compromising an exposed web server is to upload a web application that proxies our traffic to the inside network via HTTP server. There are a few tools to accomplish this, such as [reGeorg](https://github.com/sensepost/reGeorg) or [Neo-reGeorg](https://github.com/L-codes/Neo-reGeorg). These tools have been used in the past by threat groups such as APT28 and FIN13 during cyberattack campaigns to achieve persistence and perform lateral movement, as documented in [MITRE ATT&CK](https://attack.mitre.org/techniques/T1505/003/).

This is the JSP code that tunnels SOCKS over HTTP ([tunnel.tomcat.5.jsp](https://raw.githubusercontent.com/sensepost/reGeorg/refs/heads/master/tunnel.tomcat.5.jsp)):

![image](/assets/img/posts/2024/10/02330734b838c5a22be6f342abe137a86d75d53063e704f650dd43d4f12f2e80.png)

By connecting the reGeorg agent to the URL, it begins listening on a port for SOCKS5, which should be used together with proxychains and other tools. For example, we can reach the target's port `3389` to initiate a Remote Desktop session, and the traffic will be handled by the JSP reGeorg code. Other options include reaching more servers on the network to compromise and escalate privileges, depending on the red team or pentesting objectives.

![image](/assets/img/posts/2024/10/65756ddeef1ca22493742c05c27e1858d335378460b302548ba3bd2c35404734.png)

## Conclusion and Best Security Practices

- Upgrade legacy systems and ensure they are kept up to date. Isolate them from other assets while the upgrade is in progress (e.g., using VLANs or island setups).
- Change default settings, including credentials and passwords, and perform hardening.
- Adjust user and service account privileges according to the *least privilege principle*, *deny by default*, and similar practices.
- Place internet-exposed servers in a separate network security zone, such as a DMZ.
- Implement logging, monitoring, and detection solutions across hosts and networks.

## References

- [https://infocenter.sybase.com/help/index.jsp?topic=/com.sybase.infocenter.dc31727.0520/html/easws/CACEEFCH.htm](https://infocenter.sybase.com/help/index.jsp?topic=/com.sybase.infocenter.dc31727.0520/html/easws/CACEEFCH.htm)
- [https://www.rapid7.com/db/vulnerabilities/http-sybase-easerver-default-account-jagadmin/](https://www.rapid7.com/db/vulnerabilities/http-sybase-easerver-default-account-jagadmin/)
- [https://web.archive.org/web/20211025045137/https://www.rapid7.com/db/vulnerabilities/http-sybase-easerver-default-account-jagadmin/](https://web.archive.org/web/20211025045137/https://www.rapid7.com/db/vulnerabilities/http-sybase-easerver-default-account-jagadmin/)
- [https://github.com/joaovarelas/sybase-easerver-app](https://github.com/joaovarelas/sybase-easerver-app)
- [https://github.com/tennc/webshell/blob/master/fuzzdb-webshell/jsp/cmd.jsp](https://github.com/tennc/webshell/blob/master/fuzzdb-webshell/jsp/cmd.jsp)
- [https://attack.mitre.org/techniques/T1505/003/](https://attack.mitre.org/techniques/T1505/003/)
- [https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)
- [https://github.com/L-codes/Neo-reGeorg](https://github.com/L-codes/Neo-reGeorg)

