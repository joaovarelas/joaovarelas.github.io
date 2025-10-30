---
title: Bug Bounty - IDOR in domain of Alibaba Group - HackerOne
author: vrls
date: 2020-06-24
#categories: [TOP_CATEGORIE, SUB_CATEGORIE]
tags: [bug, bounty, hackerone, h1, alibaba, group, web, shop, idor, api, authorization]
image: /assets/img/posts/2020/06/d10c88f869301b1238f53cfdff8e9d7c.png
---

<!--  ![image](/assets/img/posts/2020/06/d10c88f869301b1238f53cfdff8e9d7c.png) -->

## Introduction

Some programs were made public in HackerOne bug bounty platform last month, including [Alibaba Group Bug Bounty Program](https://hackerone.com/alibaba). After having a look at their program details I've noticed they had pretty standard rewards but a huge scope to explore.

Alibaba Group is made up of private companies based in China whose businesses are focused on e-commerce, retail sales and online payment services. They also power up a search engine for purchases and cloud computing services.

The main services of this group are, just to name a few:

* Alibaba
* Alibaba Cloud aka Aliyun
* Aliexpress
* Alipay
* Taobao
* Tmall

## Scope

Their scope include Taobao assets. I decided to begin here.

As usual, started by doing some subdomain enumeration using common tools such as: **Amass**, **Sublist3r**, **Assetfinder** and **Findomain**. Also used online tools to perform passive reconaissance like **C99 Subdomain Finder**.

The scan generated an output of more than 2 MBs of subomains related to Taobao itself, that's almost *100.000 lines* of unique subdomains. 

## Exploration

By navigating a while through subdomains I've found this particular one **dianshi.taobao.com**. Since I'm not fluent in Chinese I've used Google Chrome to translate the text on this page in order to understand the context. 

![image](/assets/img/posts/2020/06/348aaed41a0630e73635d675c1e55ba5.png)

Turns out this is a cable TV service, or similar. The referenced pages are **TV Taobao**, **Watch-buy** and **Voice**. This frontend does not have anything interesting as it seems a static HTML page with some information on it.

At this point, more enumeration was performed to increase attack surface via sub directory scanning with **Gobuster**, which is pretty quick for this task together with wordlists.

This web server doesn't return a **404** status code when a page is not found, **instead it returns a 200**. This difficults finding sub directories as it will consider every word in wordlist to be a valid directory in website.

To be able to distinguish found pages from not-found pages, **Gobuster** can be configured to display *HTTP body response length* (argument **flag -l**). This way it is possible to compare response and decide whether is a valid directory or not.

By tweaking and running the tool, it found the directory **/pxb/**. 

![image](/assets/img/posts/2020/06/67971d892fee4c1c0a6f75394bbedb62.png)


The page took a little to load since it runs over *Java Spring Framework*. Having a look at the interface it is very similar to the index page, however, seems to be way more interactive and with functionality.

Quickly noticed the top right *Login/Register* and logged in via my Taobao test **user1** account. Every website from the group shares the same universal authentication mechanism. This means credentials will work everywhere within the services of Alibaba Group.

After logging in with the test account, the server displayed a page with the following error message: Your shop does not exist or is not the owner account of the shop. Does not meet user access requirements, temporarily unable to view. 

![image](/assets/img/posts/2020/06/67da38cdc9f75aff0e8271ac3478c753.png)

Unhappy with the results, decided to explore further. Test account only had permissions to read and modify its own personal details, such as full name, email, phone, etc. 



## Exploitation

To understand what was happening behind the scenes I've started **Burp Suite** to intercept and analyze HTTP requests. When editing personal details of test account, immediately observed that input verification was performed on client-side.

For example, modifying e-mail to **not_@_valid_email** in web browser would trigger a responsive error message, and modifying it in Burp repeater would successfully change it. The response in JSON format included a parameter named **unb** which was also a valid cookie with a value that represents a big integer of user ID.

At this time, created a second test account **user2** and grabbed the user ID.

By sending the same previous request while authenticated as **user1** and tampering the value of unb with the new created second account ID, modifies the user information of **user2**.

![image](/assets/img/posts/2020/06/49c7e46aaed17513f76f32940af2fbe3.png)


This can be considered a valid IDOR as the web application relies on client-side values to perform operations. An attacker is able to bypass access controls by changing the ID to anyone else ID.

Even while validating this vulnerability with success, the permission problem still persist. In order to use other features the user must be authenticated with a shop account since test accounts hadn't enough fancy permissions.

As the website relies mostly on client's browser to execute Javascript, the tool **Relative-url-extractor** revealed interesting results against the included Javascript files.

The tool returned a lot of other API endpoints that weren't used in main page. For example, the endpoints

* **/api/user/view_info**
* **/api/user/update_info**
* **/api/user/check_level**

The user ID's were not ideal to perform a brute-force because they were 13 digits long. It would be exhaustive to send a lot of requests to the server and did not want to take it down by DDoSing.

By doing a Google search with dorks, came across multiple shop user ID's. In fact, these ID's can be found within Taobao sellers page.

Requesting the **/api/user/check_level** endpoint with my test account ID results in level **200** whereas requesting with a shop user ID results in level **250**.

There was another interesting API endpoint which wasn't available to simple user accounts but appeared to work with shop accounts: **/api/order/create_order?id=**. 

![image](/assets/img/posts/2020/06/9c7a28af9c0f3efa2f9ba298c8758ede.png)

By tweaking some parameters in Burp Intruder it was possible to observe the following order history. These orders were created on behalf of privileged users (shop owners). 

![image](/assets/img/posts/2020/06/a0773a0f938651d65c38e325ba09c5b8.png)

Tampering the user ID with a shop ID value and sending a request to this endpoint will **successfully create a new order on behalf of the shop owner!**

This way it is possible to leverage the IDOR and perform other privileged operations by escalating vertically. 


## Timeline

* 2020-05-05: Reported this vulnerability to HackerOne Alibaba bug bounty program
* 2020-05-06: Triager closed as **N/A** saying that it wasn't a valid security issue
* (...)
* 2020-05-17: Added more context to report since then, but triager do not reply anymore
* 2020-05-18: Contacted Alibaba Security Team directly
* 2020-05-19: Alibaba Security Team changed status of my submission to ignored
* 2020-06-24: Public Disclosure for Transparency