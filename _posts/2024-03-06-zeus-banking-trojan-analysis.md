---
title: Zeus Banking Trojan Analysis
date: 2024-03-06 20:55:00 +0800
categories: [Malware,Zeus]
tags: [Zeus]
---
![Zeus Meme](https://i.ytimg.com/vi/JJ8qPWLbTOA/maxresdefault.jpg "Macro Enabling")

### Introduction
Banks have historically held a certain allure for the general public, making them frequent targets of physical and digital theft attempts. One prominent example of such malware is the Zeus Trojan, also known as **ZBot**. This blog series delves into the most notorious variants of **ZBot**.

#### About ZBot
**ZBot** stands as one of the most widespread banking malware strains, first emerging in 2007 to steal information from the U.S. Department of Transportation. In 2011, the source code's release led to numerous **ZBot** variants, some of the well-known ones being: 
- Zeus Gameover
- SpyEye
- Ice IX
- Carberp
- Shylock

#### Delivery Method
**ZBot** primarily employs two delivery methods:

- Drive-by Downloads: Malicious websites may trick or prompt users into clicking on links that download **ZBot**.
- Spear Phishing: **ZBot** can be injected into phishing emails and fake social media campaigns. Infected machines become part of a botnet, potentially used to distribute other malware.
 

#### TLDR;
**ZBot's primary objective is to steal your financial information and integrate your device into a larger botnet for further attacks.**

### Static Analysis

#### Initial Analysis
![Virustotal](https://cdn-images-1.medium.com/v2/resize:fit:960/1*DfJ3MQyYvj5XZSxkCe0yvg.png "Virustotal")

Firstly we will upload the sample on Virustotal and by the looks of it , it's definitely malware 😉 . The tags given in VT shows that it has many capabilities like :
- Self deletion
- Check user input
- Checks for debug
- Long sleeps
- Persistence

The threat categories is mainly given as **Trojan and Dropper**

#### PE Analysis
Let's open up the sample in our sandbox environment and try to find whether it is packed or not. We will also analyze the PE using PE Studio to find all the relevant information about the file.

![PE Studio](https://cdn-images-1.medium.com/v2/resize:fit:960/1*mKD5FQINdTFzTBT9I6-PGQ.png "PE Studio")


- File Type: The first two bytes (MZ or 4D 5A) verify it as a Windows Executable.
- Entropy: A high entropy value suggests that the binary might be packed (containing additional irrelevant data to obfuscate the real code).


![PE Studio](https://cdn-images-1.medium.com/v2/resize:fit:960/1*4cyPjbNcVAe-RN0W3QdeLg.png "PE Studio")

- Sections: A high file ratio and data section entropy further strengthen the possibility of packing.

![PE Studio](https://cdn-images-1.medium.com/v2/resize:fit:960/1*Sptu55lyJQfHFKxYolWY0g.png "PE Studio")

Looking at the import sections, we find not one or two but many suspicious imports.

Used to get data from clipboard -:
- **GetClipboardOwner**
- **GetClipboardData**
- **EnumClipboardFormats**

- **WinExec** - It is a built-in scripting function that executes a Windows command as if it was entered at the command prompt. 

Let's look at the strings using a program called **floss** that available in Flare-VM. It deobfuscates all commonly encoded strings and gives the output.

![Floss](https://cdn-images-1.medium.com/v2/resize:fit:960/1*F-6_VWLENbbnqzj4Z01iGg.png "Floss")

The strings have a very weird name followed by name of some DLL that is most probably being the name of function that is being to be called in dll. We will take a look at these functions in dynamic analysis.

I always like to run a program called **capa** which detects the capabilities of the the executable or in layman's language it gives a supposedly output of the program. It is also available in Flare-VM.

![Capa](https://cdn-images-1.medium.com/v2/resize:fit:960/1*VYB_g6R2u46fKJ_kuDqQ7A.png "Capa")

The executable is using Anti VM techniques and most probably doesn't shows it true color when ran in an virtual environment. It also resolves function which we discussed earlier.

#### Disassembly
Let's open the binary in our favorite IDA Pro and try to look for something. I'm really bad at disassembly so we will try and look for something simple for now.

![IDa](https://cdn-images-1.medium.com/v2/resize:fit:960/1*WiHNA5RglO5Gl4eU_57TvA.png "IDA")

While browsing from the entry point straight , I see a call to a function called **GetTickCount()** and as I remember reading that this function is used as a anti-debugging technique.
You can read more here at [Medium](https://medium.com/@X3non_C0der/anti-debugging-techniques-eda1868e0503)

Walking through the assembly code we can see that the function at location 40A4C3 when called first calls the Windows API function **GetTickCount** which retrieves the system uptime in milliseconds. 

The value of the register esi is decremented by 1.
There is a conditional statement which checks that if the value in esi is not zero (meaning still negative or positive).If it's not zero, the code jumps back to the beginning of the loop (loc_40A4C3), essentially restarting the loop. 

Next the least significant bit of the variable **dword_410B98** is checked if it's set to 1 or essentially bitwise AND with 1. This essentially looks like a termination condition for the loop.

 We encounter another jnz instruction and check the result of previous AND operation. Next the address of the function **AllowSetForegroundWindow** is moved into the eax and bitwise OR is performed . Further the value of eax is moved into another  variable. 
 
 
By reading the assembly we can safely assume that it's a do-while loop and opening the binary in ghidra verifies the same.
I've changed the name of the variables according to the assembly  for easier understanding.
![Ghidra](https://cdn-images-1.medium.com/v2/resize:fit:960/1*qSUrXfpJP4XcZbcLgGeUXA.png "Ghidra")
The **AllowSetForegroundWindow**  can be used to start a process in foreground given the PID.

```c++
BOOL AllowSetForegroundWindow(
  [in] DWORD dwProcessId
);
```

Looking further through the binary in IDA , I found many of the imports that were malicious in nature that we found out in PE analysis. One of them was **WinExec()** and **WriteFile**.

| WinExec() | WriteFile() |
|---|---|
| ![Alt text for image 1](https://cdn-images-1.medium.com/v2/resize:fit:1440/1*-KXQKVFlQRuS29BAZQ3deA.png) | ![Alt text for image 2](https://cdn-images-1.medium.com/v2/resize:fit:1440/1*sKtHL_Am0TQrBrqR3b0OLA.png) |

Again the assembly is simple enough. The **WinExec()** works as  function that executes a Windows command as if it was entered at the command prompt. The value of the address of the **WinExec** function is loaded into the EAX register by dereferencing (using the *->*).Next the same value of EAX is moved. The EBP here is the base pointer for the current stack frame and used to store variable in the stack and param_1 being the offset where the arguement is stored. Overall here , the **WinExec()** is being prepared to run an external program. 

The other **WriteFile()** function is also doing the same thing. The address for the **WriteFile()** is being loaded into the EAX and the address is being stored for a later use.

The binary being packed has alot of obfuscation and hence there is lot of non-sense in between the execution. After these steps we have a basic sense of what this binary is capable of doing and some of the things it will do after being executed. *The beauty of static analysis is that we're able to determine what the program is able to do even before we run it. A good static analysis can yield very efficient results*.

### Dynamic Analysis
Before running the sample I always like to configure FakeNet to simulate legitmate network service and intercept the network traffic. You can also use INetSim. Both of them come with Flare-VM.

We know that when the binary will be ran and it will most probably unpack the contents and maybe drop some executables.
We will start procmon and add filter for the process. First we will take a look at the process tree. After running the binary the first thing to notice is that the binary is deleted or removed from the place it was at in first place.

![Process Tree](https://cdn-images-1.medium.com/v2/resize:fit:960/1*vg_01d_F6R1rkMTVNvFI-A.png	 "Process Tree")


| Process Monitor | Fake Google Update |
|---|---|
| ![Alt text for image 1](https://cdn-images-1.medium.com/v2/resize:fit:1440/1*EgOkfdJheeDJK-ELEV9xeA.png ) | ![Alt text for image 2](https://cdn-images-1.medium.com/v2/resize:fit:1440/1*eoys3DSeDjMhV9cwTzRMJA.png) |

Earlier we found that the file after being ran deleted itself. Usually malware doesn't deletes itself as it may need to run the same file again for the infection vector to take place again. In our case this file is now masked as a fake Google Update. Now I quickly check for registry files as this fake binary could be used to maintain persistence. 

![Registry Key](https://cdn-images-1.medium.com/v2/resize:fit:800/1*voPrKpIommPHnsDlaAJwhQ.png "Registry Key")

When the binary is ran , a legit version of **FlashPlayer.exe** is used to unpack and drop 3 DLL files. But unfortunately at the time of making the **FlashPlayer.exe** didn't work as intended in my sandbox environment. So I manually unpacked the binary as it was packed by **aPlib** using [Github](https://github.com/herrcore/aplib-ripper) by herrcore or you can also use [Unpacme](https://www.unpac.me/) .

The dropped binary files work as a rootkit and each have some similiar working. A fake or tampered version of FlashUtil.exe is used to work a keylogger. Two others files do the same thing of setting up a socket and sending data maybe to a C2 server. They also encode data to be sent using XOR and hashes the data. All these files maintain persistence by regularly changing the registry keys.


### YARA Rules
I'm not good with YARA rules as I get confused easily on what to write and what not to write but I will try here to write something based off the analysis we just did.

```

rule ZBot_Suspicious_Binary {
  meta:
    description = "Detects potential ZBot-like malware based on common characteristicss"
    author = "somedieyoungZZ"
    date = "2024-03-05"
    reference = "http://somedieyoungzz.github.io/zeus-banking-trojan-analysis/"

  strings:
    $ magic = { 4D 5A }  # PE magic bytes
    $ suspicious_url = {
      "http*://fpdownload.macromedia.com/get/flashplayer/update/current/install/install_all_win_cab_ax_sgn.z",
      "corect.com"
    }

  imports:
    $ CreateFileA = { api("CreateFileA") }
    $ WinExec = { api("WinExec") }
    $ GetAsyncKeyState = { api("GetAsyncKeyState") }

  condition:
    all of ($magic, any of ($suspicious_url))  # Checks for PE header and suspicious URL
    any of ($ CreateFileA, $ WinExec, $ GetAsyncKeyState )  # Checks for any of the suspicious imports
}

```

We will try and analyse each of these dropped executables in our next part of the blog . Till then bai bai.
Thanks for reading the blog till the end and do give me follow on [Twitter](https://twitter.com/IdaNotPro). You can reach out to me on discord and I highly appreciate any feedback <3.









### Indicators Of Compromise (IOC)

```
SHA256  69e966e730557fde8fd84317cdef1ece00a8bb3470c0b58f3231e170168af169
SHA1    9615dca4c0e46b8a39de5428af7db060399230b2
MD5     ea039a854d20d7734c5add48f1a51c34
C2 IP   104.111.216.113
http://fpdownload.macromedia.com/get/flashplayer/update/current/install/install_all_win_cab_ax_sgn.z
```



[Virustotal](https://www.virustotal.com/gui/file/69e966e730557fde8fd84317cdef1ece00a8bb3470c0b58f3231e170168af169)


[ANY.RUN](https://app.any.run/tasks/c45986d9-4a83-4239-8c1a-585372333d0e/)



Discord somedieyoungzz

Twitter https://twitter.com/IdaNotPro