---
title: Tracing Silver Fox The Winos 4.0 Campaign Behind Operation Holding Hands
date: 2025-06-10 18:55:00 +0800
categories: [Malware,APT,China]
tags: [SilverFox,C2,Winos]
pin: true
---

### Introduction

→ Increasingly, malware authors are leveraging legitimate digital signatures to evade detection and raise user trust. Recently, I analyzed a backdoor sample that also uses a valid digital signature to appear benign. This particular sample stores references to key functions either within the executable’s filename or in an accompanying INI configuration file. During execution, it dynamically reads these references to perform it's tasks.

![](https://cdn-images-1.medium.com/v2/resize:fit:1200/1*9AArcAKd7QmwsHQzIm3_UA.png)

→ Today, we examine a malware sample named "給与制度改定のお知らせ.exe" (translated as Notice of Salary System Revision.exe), which was distributed through a phishing website targeting Japanese users.The stolen certificate belongs to “Sid Narayanan Ltd” and was recently signed. The following campaign has been using many different Digital Certificates.

![](https://cdn-images-1.medium.com/v2/resize:fit:800/1*aYIRni592-8kiv6yZOms4w.png)

| Debug File| Imports |
|---|---|
| ![DI](https://cdn-images-1.medium.com/v2/resize:fit:800/1*kdfp7fd6esByIOMnSLDD8w.png "DI") | ![](https://cdn-images-1.medium.com/v2/resize:fit:800/1*QbkdEHeIh313CV_MeldAkw.png) |

→ Upon opening the **"給与制度改定のお知らせ.exe"** sample in PE Studio, we observed several suspicious imports indicative of malicious behavior, including `ShellExecute`, `WriteFile`, and `LoadLibrary`. Additionally, we discovered a PDB (Program Database) path embedded in the binary: 

**D:\Workspace\HoldingHands-develop\HoldingHands-develop\Door\x64\Release\BackDoor.pdb**

This provides a strong indication that the executable functions as a backdoor.Interestingly, this particular PDB string has been observed in multiple samples associated with this campaign, hence giving the title for the blog.

### PE Analysis

![](https://cdn-images-1.medium.com/v2/resize:fit:800/1*PY6V4FBMRZMAF5Tzhk7NHw.png)

→ The code initializes a **SID (Security Identifier)** with specific values and checks whether the current process token belongs to a group associated with the **Administrators** SID. This helps to determine if it’s running with elevated privileges or not.

![](https://cdn-images-1.medium.com/v2/resize:fit:800/1*dVul1UGTJkEVHavFQuDRWw.png)

→ The malware checks if the current user has administrative privileges and retrieves the `CSIDL_LOCAL_APPDATA` directory(C:\Users\User\AppData\Local).It creates a directory named `a` within this location.It then constructs a file named `a.zip` inside this directory and obfuscates the payload data using a multi-byte transformation based on a fixed in-memory key. The obfuscated data is written to `a.zip`

![](https://cdn-images-1.medium.com/v2/resize:fit:2560/1*GV4HoTgERLfRGXQCP1Iipg.png)

→ The malware constructs a full path to `Run.exe` (`C:\Users\johndoe\AppData\Local\a\Run.exe`) and launches it via `CreateProcessW` with `CREATE_NEW_CONSOLE`, ensuring a clean startup state using a manually initialized `SHELLEXECUTEINFO` structure.

→ If the direct process launch fails or as an alternate execution path, it falls back to `ShellExecuteExA`, using the "runas" verb to relaunch itself with elevated privileges,to bypass UAC and escalate privileges.

> I was going through the disassembly and trying to figure out how the a.zip is unzipped
> 

![](https://cdn-images-1.medium.com/v2/resize:fit:800/1*RAa8w6aEE6LB3ATjm8_xNw.png)

→ The code initializes the **COM subsystem** using `CoInitialize`, then **creates an instance of a COM object** via `CoCreateInstance`to perform operations on the ZIP file.

→ It constructs a `VARIANT` containing the **full path to the ZIP archive**, wrapping it as a `BSTR`. The method `(*(__int64 (__fastcall **)(LPVOID, VARIANTARG *, __int64 *))(v4 + 72))` is called to **invoke the unzipping.**

![](https://cdn-images-1.medium.com/v2/resize:fit:800/1*47IYMBRn2NfmHZljYlOLdA.png)

![](https://cdn-images-1.medium.com/v2/resize:fit:800/1*8952kwE5fit0ywjM2FUvsg.png)

### Run.exe

![](https://cdn-images-1.medium.com/v2/resize:fit:800/1*TMb4AOezmvNPTNsASsNH1Q.png)

![](https://cdn-images-1.medium.com/v2/resize:fit:800/1*nK0_JzffBDJZbuk4wBiCCw.png)

→ Initially it gets the executable's full path using `GetModuleFileNameA` and e**xtract directory** from the path.Search for files in the same directory and skip `.,` `..` and itself.**If exactly one directory is found**, then only proceed.

![](https://cdn-images-1.medium.com/v2/resize:fit:800/1*1BSmSMhGy_hc1qdthbP6gA.png)

→ Next up, it uses the function `sub_140001000` to traverse a directory and pick up file names. In this case, it's grabbing a filename like `kernel32.dll` from a directory of dummy files. Then, it passes this name to `LoadLibrary`, pretending to load a legit system DLL.

![](https://cdn-images-1.medium.com/v2/resize:fit:800/1*uQj81aBGbLjZPF-qJhHbLg.png)

→ Combine directory + `String1` + a second string(.txt) which points to a **payload file** inside the directory. In our case it’s `dxpi.txt`.

![](https://cdn-images-1.medium.com/v2/resize:fit:800/1*Y5hCW5KGC4LM0vV7sig2Vg.png)

→ `CreateFileA`, `ReadFile`, `VirtualFree`, and other Windows APIs are resolved dynamically with `GetProcAddress`.Open the payload (`CreateFileA`) with `GENERIC_READ`.Get file size with `GetFileSizeEx`.Allocate memory dynamically with `VirtualAlloc` and read file contents into memory.

```cpp
for (i = 0; i < FileSize; i++)
    buffer[i] = (buffer[i] - key[i % 5] + 256) % 256;
```

→ Simple decryption loop using `key`which is derived from a constant (`v33`) and cast buffer to a function and execute it.

### Dynamic Analysis

![](https://cdn-images-1.medium.com/v2/resize:fit:800/1*xIeKo1tsDYQBP-II9d1oOQ.png)

![](https://cdn-images-1.medium.com/v2/resize:fit:800/1*Gq5SiWIjZoCco_bt5E4Nkw.png)

→ It reads the the payload from `dxpi.txt` in the modules directory.Read the `collalautriv.xml` file in the same directory to get the `VirtualAlloc` function name, and then get the `VirtualAlloc` function address, as shown above.

![](https://cdn-images-1.medium.com/v2/resize:fit:800/1*bScb-J4N3swMDq6xiZcJlQ.png)

→ Since we know it’s using `VirutalAlloc` we can put a breakpoint on it and find the memory address where the memory is being allocated.We can follow the memory in dump since we know it’s going to decrypted.

![](https://cdn-images-1.medium.com/v2/resize:fit:800/1*zV8CDnRA6QGzZGiHgiq_2w.png)

→ We have the decrypted payload below which will be executed in the memory.We can step over the point after the decryption to see what the payload does.

![](https://cdn-images-1.medium.com/v2/resize:fit:800/1*YcURbe3MFUozkhcIPwSasQ.png)

→ The payload starts of by using `CreateDirectoryA` to create a fake update directory in the path:

***C:\Program Files (x86)\WindowsPowerShell\Update** and creates some files in the same directory.*

![image.png](https://cdn-images-1.medium.com/v2/resize:fit:800/1*nHVFW3iIgz2hzdI-IGHaTA.png)

![](https://cdn-images-1.medium.com/v2/resize:fit:800/1*JDhRz6GTGyY1Af6R9JPkxw.png)

→ Using the same technique it reads `Settings` key and it’s corresponding value from the `TaskServer.ini` which contains some placeholder variables having windows API calls such as `VirtualAlloc`,`ExitProcess` as it’s values and allocates memory using `VirtualAlloc`.

![](https://cdn-images-1.medium.com/v2/resize:fit:800/0*YUK4-7oblWTtd4yO.png)

![](https://cdn-images-1.medium.com/v2/resize:fit:800/1*z5wmFAuLB-H-FQlB0hVzgA.png)

→ It reads the contents of the `msgDb.dat` file and allocates memory accordingly to it’s size. The contents are decoded similarly using the technique that was used earlier.

![](https://cdn-images-1.medium.com/v2/resize:fit:800/0*yjUEdW35TbFJ25jq.png)

![](https://cdn-images-1.medium.com/v2/resize:fit:800/1*VDgMny_0xbdbsKdP0RUtgw.png)

→ We can extract the shellcode using the memory dump, follow memory map and dump the shellcode.bin file on disk.

![](https://cdn-images-1.medium.com/v2/resize:fit:800/0*zDpZaw2s_xfMhjvH.png)

![image.png](https://cdn-images-1.medium.com/v2/resize:fit:800/0*9I-inPG62iN3-phS.png)

→ The malware connects to the remote server with the hardcoded IP and maintains the communication status by sending a heartbeat packets to the remote server every 1 minute.

### Conclusion

→  The *Operation Holding Hands* campaign showcases a sophisticated multi-stage infection chain. From leveraging a **stolen digital certificate** to delivering **modular payloads**, the entire setup is crafted to bypass conventional detection mechanisms. The fact that the payload is **decrypted at runtime** adds an extra layer of friction for any form of static analysis.

What makes this more elusive is the way the decrypted payload is **executed directly in memory** using `VirtualAlloc`, leaving minimal forensic artifacts behind. Combined with **API name obfuscation via config files**, **COM-based unzipping**, and fallback to **`ShellExecuteExA` for privilege escalation etc.**

→ One of the IP associated with the C2 servers has many files referring to it and upon further hunting we find the sample is maybe associated with Winos 4.0 which mainly targets [Taiwan.](http://Taiwan.Im) In one of the samples we find that it’s targetting Japan as well with the regional language checking through registry keys.The Wt

![](https://cdn-images-1.medium.com/v2/resize:fit:1200/1*cu4EhPzWV7z8YIAUInNmGQ.png)

![](https://cdn-images-1.medium.com/v2/resize:fit:1200/1*OzTPCTFza7YCEyvWyAsNsw.png)

→ We also find a Remote Access tool with the same name we found in the PDB. There’s also a chineese version of this same tool. The observation that "`HoldingHands`" might function as a backdoor aligns with the characteristics of Chinese cybercrime, a categorization further supported by the malware's certificate and the C2 being associated with Winos 4.0. This is likely a work of a Chinese Threat Actor.

→ Winos 4.0 is a memory-resident backdoor framework used in recent Chinese-language espionage campaigns.  Multiple security firms have tied Winos 4.0 to a China-linked APT sometimes called **“Silver Fox”**. In an article from [Rapid7](https://www.rapid7.com/blog/post/2025/05/22/nsis-abuse-and-srdi-shellcode-anatomy-of-the-winos-4-0-campaign/#:~:text=In%20previous%20incidents%2C%20Winos%204,locale%20settings%20for%20Chinese%20or) this has been confirmed and we found many more places that tied Winos to the Silver Fox group.

![](https://cdn-images-1.medium.com/v2/resize:fit:800/1*io-lvKO4S-uCQW4lyzjdsg.png)

### IOCs

```cpp
給与制度改定のお知らせ.exe
78dc343fe6f5d3140c9624c889148ec0
Dropped from 
hxxps[:]//jppjp[.]vip/index[.]html
154[.]205[.]139[.]223
38[.]54[.]107[.]103
38[.]54[.]50[.]212

244.exe
0b6318af44ad2e434d7cfce95e8eeba2357c226355478a6cfdfbe464d9e5e467
206[.]238.221[.]244
107[.]149.253[.]183

```

Thanks for reading this analysis! ❤️

Feel free to connect with me on:

**Discord**: `somedieyoungzz`

**Twitter**: [@IdaNotPro](https://twitter.com/IdaNotPro)

---
