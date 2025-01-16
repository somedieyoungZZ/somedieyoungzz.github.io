---
title: Gamaredon APT - Shortcut to Espionage
date: 2024-10-15 18:55:00 +0800
categories: [Malware, APT, Gamaredon, Powershell, LNK, Dropper]
tags: [Gamaredon, Russia, APT, LNK, RAT, Powershell]
---


### Introduction
![GM](https://w.wallhaven.cc/full/vq/wallhaven-vqj9q5.jpg "GM")
*Gamaredon APT Threat Actors be like*

&rarr; Gamaredon APT, also known as Primitive Bear, is a cyber espionage group linked to Russian intelligence, active since 2013. Their attacks primarily target Ukrainian government and military sectors, aligning with Russia’s geopolitical goals. Gamaredon focuses on stealing sensitive data and disrupting operations, particularly in the context of the ongoing conflict with Ukraine.

&rarr; Today, we will take a look at a series of samples attributed to this group. The first is a basic backdoor, but it employs a unique technique to drop itself onto the victim's PC.
![X](https://cdn-images-1.medium.com/v2/resize:fit:800/1*6P7CkfXxm0WFHu_k5ORblA.png "X")

### Sample 1
![VS](https://cdn-images-1.medium.com/v2/resize:fit:1200/1*b7D2DNMzwWVQQYw_4wmmGA.png "VS")

&rarr; The div id **Krf** stores the Base64 encoded payload with asterisk as delimiter.
The image tag source is invalid therefore it invokes an error and the following code is executed. 

&rarr; The div id **ltc** is taking the Base64-encoded string (stored in m3H), removing the asterisks from it, decoding it using atob(), and then executing the decoded string as JavaScript using eval().

![VS](https://cdn-images-1.medium.com/v2/resize:fit:1200/1*qzd477Kjmym0YVSrjtihyA.png "VS")

&rarr; The Javascript starts onload or as soon as the page is loaded. The script checks if the user is on a Windows based platform. It further creates an anchor to download a RAR file which is stored in **JfS** variable. The downloaded file is decoded and renamed as **Postanova.rar**.

- **It's important to note that the the script simulates a click on the link, causing the file to be downloaded without any user interaction.**

![RAR](https://cdn-images-1.medium.com/v2/resize:fit:800/1*gxpnbvwh-wM2kIh6S9FHFA.png "RAR")
![LNK](https://cdn-images-1.medium.com/v2/resize:fit:1200/1*fz5qg7JaR4AzXGJbBg1RBg.png "LNK")

&rarr; The given rar file contains a windows shortcut file(LNK) named **Postanova.lnk**. We can parse this lnk file as a json and open it in code to find some interesting things.

&rarr; The file calls powershell with hidden parameters to invoke a web request to the URL. The content of the page is piped into another powershell instance. The shortcut has a icon of shell32.dll.
![CF](https://cdn-images-1.medium.com/v2/resize:fit:1200/1*e13rPBEu4TWIC83S7U0eYg.png "CF")
![VS](https://cdn-images-1.medium.com/v2/resize:fit:800/1*ujH9XspNNzFXln1DxTLfyQ.png "VS")

&rarr; The script starts with a infinite loop that first queries the volume serial number from the logical disk and convert it into a specific format. It’s combined with the computer’s name ($PSname) and added to the POST data.

&rarr; Next up the HTTP method is called which takes a collection **$barkas**  or the **goal** object for the POST method. 
Inside this function, after sending the request, the server response is captured, and controller() is called .

![cntrl](https://cdn-images-1.medium.com/v2/resize:fit:800/1*vktmR5mLnbiVLIXlarULXw.png "cntrl")

&rarr; If the server responds with anything, the function determines how it's to be executed

- If the command starts with a **!** prefix, then it’s immediately executed with Invoke-Expression using Powershell.
	
- If it’s encoded, the **decoder()** function is called to decode the response.
	
&rarr; The **decoder()**  function XOR decodes the message using the machine’s volume serial number and returns the decoded text for execution.It starts a new job to execute the decoded text asynchronously using the **MSScriptControl** COM object.

#### C2 Emulate   
Since I waited again for the C2 to respond like I did with Kimsuky 😍 but unfortunately lighting doesn't strikes twice. We can emulate how the C2 would respond to the POST request.

- We can setup a Python server and it will respond to the powershell requests. The respond can start with a **!** to run them on Powershell directly.
![C2](https://cdn-images-1.medium.com/v2/resize:fit:800/1*nm981FALpsEzXz2xbl_pIQ.png "C2")
![C22](https://cdn-images-1.medium.com/v2/resize:fit:800/1*9VX8fRArtB08Veuo_WGrRg.png "C22")

### IOC
```
HTM 
MD5 f9162c626c891b2458179c6b3d3266ee
SHA-1 b5e4bcb722be0fd61ce8d4bd3472dac8f9db22d2
SHA-256 b3774a90a032cfb5be6cb12f0f4d8aee55d1452c1bbbbb18a056f34cdb89af1b 	
Postanova.rar 
MD5
07e3e1cde9a0dbcf9ae43271b7355f13 
Postanova.lnk
MD5 a80ac2735dd554fbdf68c13711d9a866 

think-crash-shows-circus[.]trycloudflare[.]com
```
[Virustotal](https://www.virustotal.com/gui/file/b3774a90a032cfb5be6cb12f0f4d8aee55d1452c1bbbbb18a056f34cdb89af1b/details)

[Bazaar](https://bazaar.abuse.ch/browse/tag/think-crash-shows-circus/)

Thank You for reading this till the end ❤

Discord somedieyoungzz

Twitter https://twitter.com/IdaNotPro


