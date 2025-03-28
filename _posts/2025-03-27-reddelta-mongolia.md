---
title: Mustang Panda Targeting Asia
date: 2025-3-28 18:55:00 +0800
categories: [Malware, APT, Threat Analysis]
tags: [RedDelta, PlugX, Mustung Panda, APT]
pin: true
---

### Introduction
!["X"](https://cdn-images-1.medium.com/v2/resize:fit:800/1*jzxnni4yZRsIDuQ08Z8zJg.png "X")
*Emmy's Tweet*

&rarr; While browsing for new samples to analyze, I came across this tweet from [Emmy](https://x.com/byrne_emmy12099), and it caught my attention since most of the samples he posts are DPRK-based. The replies also suggest that this sample might be a **Kimsuky** sample, potentially against the TTPs.


### Stage 1
!["VT"](https://cdn-images-1.medium.com/v2/resize:fit:1200/1*cHhP3yun92OUZaWSVOmSFA.png)

&rarr; The initial analysis of the file on VT gives it a 27/62 score (more than I ever scored in my test) and detects it as **MSC (XML)**. We can simply open the file in any code editor and find the command line parameters since we know it's malicious.

![](https://cdn-images-1.medium.com/v2/resize:fit:800/1*8mHTTlPdrWbfwC-4TJRpnA.png)

&rarr; The file name is in Mongolian and roughly translates to **Exploring the CVEDIA-RT platform in demonstrations**. More on this later, but here's our first clue that it's not a DPRK-based threat actor but something else.

&rarr; The command is a **PowerShell** script that uses the **Windows Installer COM object** to silently download and install malware. It constructs a URL **(hxxps://jpkinki[.]com/fjugm)** and sets the installation to silent mode by configuring the **UI level** to 2. The script removes any previous installations and installs the payload without user interaction.


### Stage 2
![](https://cdn-images-1.medium.com/v2/resize:fit:1200/1*-Wr4_MAbfclKCMtYLkGdaw.png)

&rarr; The **fjugm** file is a **Microsoft Installer (MSI)** file. Unlike earlier, we can't simply open the MSI file in an editor, as it contains installation data (registry entries, files, etc.). We can use **oletools** to dump any files, but for this case, we will use **msitools** to learn more about the file.
![](https://cdn-images-1.medium.com/v2/resize:fit:800/1*zO67SFEqeokk_MEJsES9gw.png)

&rarr; We use **msiextract** to list all the files and then dump them using **msidump**. We also search for strings where these files might be mentioned and discover that the files were copied to the **Local/AppData** directory.

### Stage 3

&rarr; After looking at the samples carefully, we find that the **cnmpaui.exe** is a legitimate **Canon IJ Printer Assistant Tool** binary which is vulnerable to search order hijacking. This allows it to load **PlugX** and display a decoy document.

![](https://cdn-images-1.medium.com/v2/resize:fit:800/1*NvwXJcVpcNhZmfn2aT-8Xg.png)
*Messed up the Arrows*

&rarr; The executable first attempts to load the **cnmpaui.dll** library and find the **BJMaintenanceEntryPoint** function using **GetProcAddress**.

&rarr; However, if the function is not found, the binary will proceed to load the DLL again, but using **LoadLibraryExW** and will find the **MaintenanceAppStart** function, which will be called with parameters.

![](https://cdn-images-1.medium.com/v2/resize:fit:800/1*ahhaUH_Gsy3hdDdAZ86QIQ.png)

&rarr; In the exported function, the first function we find is **FUN_100010a0**, which dynamically loads necessary API functions by calling another hashing function multiple times and storing the results in thread-specific memory (**TLS**). It also walks through the **PEB (Process Environment Block)** to gather important data and hashes it to check for certain conditions.

![](https://cdn-images-1.medium.com/v2/resize:fit:800/1*Zqvc5rGlOlHzVS6HKAW7tA.png)

&rarr; There are a lot of **anti-debugging checks** inside that are called repeatedly. The function sets up a custom exception handler to handle any unhandled errors and triggers it.

![](https://cdn-images-1.medium.com/v2/resize:fit:800/1*7rmwGdfm0CjBIbBxCrXrNg.png)

&rarr; The function **FUN_1001a4c0** implements a multi-threading mechanism by creating a new thread using **__beginthreadex**, which runs a separate function (**FUN_1001a630**). It allocates memory and stores specific values in this memory, which the new thread uses for further execution.

&rarr; The thread is then resumed with **ResumeThread**, and if any error occurs, it logs the failure. The function checks if specific modules are loaded, attempting to load them dynamically using **GetModuleHandleExW**, with Chinese strings likely representing obfuscated module names.	

![](https://cdn-images-1.medium.com/v2/resize:fit:1200/1*rTJms9ZDO1D_VpvKbvlZyQ.png)

&rarr; After patching the **PEB!BeingDebugged Flag**, we can move and find the use of **Thread-Local Storage (TLS)** to store thread-specific data, such as function pointers and configuration values. It calls **FlsAlloc** to allocate a TLS slot for each thread, keeping each thread’s data isolated and harder to detect. The malware uses the TLS index combined with the TLS base address and specific offsets to dynamically calculate where functions or critical data are located in memory. 

&rarr; The formula to reference the correct function pointer is:
**TLS + (tls_index * 0xC) + offset.** By adding the TLS index to the base address and using an offset, the malware can pinpoint the exact function pointer for that thread, making it harder to analyze, as function addresses are resolved at runtime.

![](https://cdn-images-1.medium.com/v2/resize:fit:1200/1*6bRzo3Zz_nj3L5zEmi4J1w.png)

&rarr; In this disassembly, we can see the malware dynamically loading functions, similar to how we observed in earlier code. The malware is calling system functions like **NtSetInformationProcess**, **NtQueryInformationProcess**, **NtQuerySystemInformation**, and **NtQueryVirtualMemory**. The **LoadLibrary** function is called to load **ntdll.dll**, and various **NT system calls** are used as well.

| **Outgoing DOPLUGS C2** | **Encrypted C2 Data using RC4** |
|-----------------------------|-------------------------|
| ![](https://cdn-images-1.medium.com/v2/resize:fit:800/1*n8iPzkcqceuyqRWYbtbjBw.png) | ![CMD](https://cdn-images-1.medium.com/v2/resize:fit:800/1*-IEoWndh6jndlo3dEJtlyg.png) |

![](https://cdn-images-1.medium.com/v2/resize:fit:800/1*tKTSIGBqHDHgPYvzPBuxSQ.png)
*Decoy Document*

&rarr; The document appears to describe a **CVEDIA-RT platform** used for real-time video processing and object recognition and is written in Mongolian, solidifying our case that this is indeed [**Mustang Panda**](https://go.recordedfuture.com/hubfs/reports/cta-cn-2025-0109.pdf).

![](https://cdn-images-1.medium.com/v2/resize:fit:2560/1*P7rKvAfKkbrjrOUy8Jcang.png)

&rarr; The malware also adds itself to the **autorun registry** keys and has a legitimate **Canon Printer certificate** as well.	

![](https://cdn-images-1.medium.com/v2/resize:fit:800/1*vdQ_yNJQtUq3689Pj9IpqA.png)

&rarr; Using some **Censys dorking**, I was able to find some more **C2** that deployed **PlugX**. The group also uses **Cloudflare's CDN** to proxy their **C2 traffic**.	

![](https://cdn-images-1.medium.com/v2/resize:fit:800/1*EYC6KYnFBWUY5_XPuMDK5A.jpeg)

- **Mustang Panda** (also known as **RedDelta**) has been observed conducting sustained and targeted cyber operations primarily focusing on Southeast Asia, with a notable focus on Mongolia. The group continues to refine its infection chain, leveraging advanced techniques such as DLL search order hijacking and utilizing Cloudflare CDN to obfuscate its C2 traffic. Its preferred backdoor, PlugX, is a versatile tool that provides attackers with remote access and data exfiltration capabilities.

- The use of decoy documents and multiple infection vectors, including MSI files and PowerShell scripts, further underscores the sophistication of its operations.

- As observed, the group adapts to geopolitical shifts, as seen in its targeting of the Mongolian Ministry of Defense and Taiwanese government entities

### Indicators of Compromise (IOCs)

```
fjugm.msi
2ee30e36e51f69466d6d3599e8f2d5d3

cnmpaui.dll
9f1de211941d63b57942661c4d30833d

cnmpaui.exe
0538e73fc195c3b4441721d4c60d0b96

cnmpaui.dat
0538e73fc195c3b4441721d4c60d0b96

C2

renxinguo[.]com
jpkinki[.]com

188[.]114.96.7
172[.]67.211.196

```


Thank you for reading this analysis! ❤️  
Feel free to connect with me on:  

**Discord**: `somedieyoungzz`  
**Twitter**: [@IdaNotPro](https://twitter.com/IdaNotPro)
