---
title: Contacto Ransomware Analysis
date: 2025-1-15 18:55:00 +0800
categories: [Malware, Ransomware, Cybersecurity]
tags: [Contacto Ransomware, File Encryption, Self-Deletion, Cryptography, Threat Analysis, Malware Analysis]
---

### Introduction
After a short break, I’m back with something new—today, we’re diving into a ransomware sample that a friend sent my way. To be honest, this is my first time reversing a ransomware sample, and I have to say, the experience was both exciting and educational. What made it even better is that the sample is quite straightforward, making it perfect for anyone new to reversing ransomware. If you’re looking to learn, this is a great place to start.

![VT](https://cdn-images-1.medium.com/v2/resize:fit:1200/1*R1QyT-iLDAcbzoIACrkF1A.png "VT")

The Contacto Ransomware is a relatively new and modern ransomware that uses advanced techniques to evade security measures. It first surfaced in early January this year, and at first glance, it appears to be a derivative or copied version of another ransomware strain.

The analysis will primarily focus on:

&rarr; **Initial Setup of the Ransomware**

&rarr; **Privilege Enabling Mechanism**

&rarr; **Persistence and Encryption**

---

### Ransomware Setup

![Main](https://cdn-images-1.medium.com/v2/resize:fit:800/1*R5qqXULrccKPCArG2D5uJA.png "Main")

&rarr; The ransomware starts by retrieving the console window handle using **`GetConsoleWindow()`** and then hides it using **`ShowWindow()`**. This prevents the user from seeing a command prompt window, keeping the ransomware's execution discreet.

&rarr; Creates a mutex (**`ContactoMutex`**) to ensure only one instance of the ransomware runs. If the mutex already exists (error 0xb7), it exits.

&rarr; Additionally, several core functions are called, which I’ve renamed for better understanding.

---

#### Enabling Privileges

![Privil](https://cdn-images-1.medium.com/v2/resize:fit:800/1*65OsSWKrIjBxE-8urvtfuA.png "Privil")

&rarr; The ransomware iterates over a list of predefined privileges and calls the **`SetPrivileges()`** function for each privilege.

&rarr; **Here's what each privilege allows**:
- **`SeDebugPrivilege`**: Enables debugging and access to other processes.  
- **`SeRestorePrivilege`**: Grants permission to restore files and directories.  
- **`SeBackupPrivilege`**: Allows bypassing file and directory permissions during backups.  
- **`SeTakeOwnershipPrivilege`**: Allows the ransomware to take ownership of files or objects.  
- **`SeAuditPrivilege`**: Enables the modification of system audit settings.  
- **`SeSecurityPrivilege`**: Allows access to sensitive security-related operations.  
- **`SeIncreaseBasePriorityPrivilege`**: Grants the ability to increase the base priority of processes.

![SetupPrivil](https://cdn-images-1.medium.com/v2/resize:fit:800/1*skPp7IW7AsQRo5KpVUk99Q.png "SetupPrivil")

&rarr; The **`SetPrivileges()`** function enables a specific privilege for the current process by opening the process token, locating the privilege by name, and then enabling it using the `AdjustTokenPrivileges` API. It assumes the ransomware is already running with administrator rights.

---

#### Ransomware Arguments

1. **`-path`**  
   Specifies the target path for encryption.

2. **`-mode`**  
   Defines the encryption mode:
   - **`full`**: Encrypts all files completely.
   - **`fast`**: Encrypts only part of each file for speed.
   - **`split`**: Encrypts files in batches or segments.
   - **`custom`**: Allows a custom encryption pattern.

3. **`-priority`**  
   Sets the ransomware's process priority for faster execution.

4. **`-skip`**  
   Specifies a number (e.g., file count or size) to skip during encryption.

5. **`-power`**  
   Defines post-encryption system actions:
   - `"restart"`: Restarts the system.
   - `"shutdown"`: Shuts down the system.

6. **`-mft`**  
   Enables Master File Table (MFT) scanning.

7. **`-console`**  
   Enables or disables console visibility.

8. **`-nomutex`**  
   Disables the mutex check.

9. **`-nonetdrive`**  
   Skips encrypting files on network drives.

10. **`-nodel`**  
    Prevents self-deletion of the ransomware executable after execution.

11. **`-nowall`**  
    Skips changing the desktop wallpaper with a ransom note.

12. **`-nologon`**  
    Disables setting a ransom note on the Windows logon screen.

13. **`-noblock`**  
    Prevents system block actions, such as disabling Task Manager, etc.

---

### Ransomware Initial Phase

![Phase](https://cdn-images-1.medium.com/v2/resize:fit:800/1*117WW4MveLC9ndqxz7Th5g.png "Phase")

After initializing and setting up its environment, the ransomware executes a series of functions to:
- Ensure persistence.
- Disable Windows Defender.
- Encrypt files on the victim's machine.

---

#### Creating Persistence

![Perst](https://cdn-images-1.medium.com/v2/resize:fit:1200/1*eWsIIZ8fKBBzS3F9gz6Ttw.png "Perst")

&rarr; The ransomware creates a fake scheduled task named **`Windows Update BETA`** with SYSTEM privileges to run on every startup.

&rarr; Writes an empty DLL called **`MNCS.DLL`**, acting as a marker.

---

#### Disabling Security Features

| **Defender Registry Keys** | **Defender Disabling** |
|-----------------------------|-------------------------|
| ![Reg](https://cdn-images-1.medium.com/v2/resize:fit:800/1*Ns9JZAFbmf4PDyhVkXUIWQ.png "Reg") | ![CMD](https://cdn-images-1.medium.com/v2/resize:fit:800/1*oTuy6NtJfof8KV-jjnGbDA.png "CMD") |

&rarr; The ransomware manipulates registry keys such as **`DisableAntiSpyware`** and **`DisableRealtimeMonitoring`** under Windows Defender policies to turn off real-time protection.

&rarr; Deletes **Volume Shadow Copies** using `vssadmin` and backup catalogs using `wbadmin`.

&rarr; Clears event logs twice: once using **`ClearEventLogW`** and again using **`wevtutil`** commands.

#### Emptying Recyle Bin
!["ERC"](https://cdn-images-1.medium.com/v2/resize:fit:800/1*VOquX3f8iEPYZyZM4KQHNA.png "ECR")

&rarr; The function starts by calling **`SHEmptyRecycleBinW`** to empty the Recycle Bin for the current user.
&rarr; : It then loops through a predefined list of drive letters and uses **`GetDriveTypeW`** to check if the drive is a fixed drive (type 3) and then finds deleted files might still be stored on each drive and delete them recursively. It’s essentially trying to ensure that no recoverable files are left on the computer.

#### Mount Volumes
!["MV"](https://cdn-images-1.medium.com/v2/resize:fit:800/1*6KwCq0QPFRHL8QokZW-13Q.png "MV")

&rarr; The MountVolumes function works to enumerate, check, and handle mounted volumes on the system. It attempts to mount unmounted volumes and associate them with drive letters.


### Encryption
#### Threading
&rarr; Before we understand how the encryption is done. it's important to understand how the ransomware sets up multithreaded file encryption across the system. It's essentially the bread and butter of every ransomware so it's important to understand. I'll be going through the code in small snippets to understand better.
!["TH1"](https://cdn-images-1.medium.com/v2/resize:fit:800/1*XYERsY1zZZ1CxFhSvm8vFA.png "TH1")

&rarr; The function determines the number of processors and sets up twice that number of threads for optimal multithreaded encryption.
Here we can see that **`[eax+eax]`** refers to the doubling of threads.
!["TH2](https://cdn-images-1.medium.com/v2/resize:fit:800/1*j8dvrgSBeZE186_CnnKaFQ.png "TH2")

&rarr; This part allocates memory for thread handles and creates multiple worker threads using CreateThread. Each thread runs a worker function called **`StartAddress`**.

&rarr; The function uses an **`IOCP`** (CreateIoCompletionPort) for communication between the main thread and worker threads. It waits for worker threads to complete their encryption tasks.In the end it logs a message indicating encryption completion, resets the system's thread execution state, and cleans up resources like the IOCP handle etc.

!["Flow"](https://cdn-images-1.medium.com/v2/resize:fit:800/1*NkkYDb7q65DwPTUUMs4yPQ.png "Flow")
*Threading Model Used In Ransomware*

#### Start Address
!["Prio"](https://cdn-images-1.medium.com/v2/resize:fit:800/1*i4TyEGGx4gcOZ6xSTunnBQ.png "Prio")
&rarr; To write about a large function like this, we will focus on breaking it into logical sections based on the flow of the function and highlight key operations only. The function starts by increasing the thread priority to ensure smooth processing and resolves the full path of the targeted directory.
!["MFT"](https://cdn-images-1.medium.com/v2/resize:fit:800/1*hxGQ6s6cM0gPK_GFIL4Wuw.png "MFT")
&rarr; The function attempts to open the MFT and enumerate files directly. If this fails, it falls back to the Win32 API for file enumeration. The code further tries to do many things like heap creation, file enumeration again etc until it lands on the main code responsible which sends the file for encryption.

!["ENC"](https://cdn-images-1.medium.com/v2/resize:fit:800/1*amBcTqhjbE1ot91Fj61Tyg.png "ENC")
&rarr; The function enumerates files using FindFirstFileW and checks if the file size is greater than zero using **`nFileSizeHigh`**
&rarr; **`SetFilePermissions`** is called to modify the file's access control list (ACL), ensuring the ransomware has sufficient permissions to manipulate the file.

&rarr; **`EnsureFileAccessibility`** handles access errors like **`ACCESS_DENIED`** or **`SHARING_VIOLATION`**, retrying or resolving conflicts to ensure exclusive access.

&rarr; If accessible, the file undergoes encryption **`(EncryptFile)`** and a global counter **`(_DAT_0044ee38)`** is incremented to track the number of encrypted files.
#### Encrypt File
!["EC"](https://cdn-images-1.medium.com/v2/resize:fit:800/1*HibQjWiatMRR0_EqVFQyVg.png "EC")

&rarr; The function renames the file specified in **`param_1`** to include the **`.Contacto`** extension using **`MoveFileExW`**. If renaming fails, it logs an error and exits.Opens the renamed file with **`CreateFileW`** and retrieves its size using **`GetFileSizeEx`**. If the file size is zero or invalid, the handle is closed, and the function exits.

&rarr; Based on the **`ransomware_mode_var`**, the function determines how to encrypt the file as discusses earlier above.


| **Encryption** | **Crypt Function** |
|-----------------------------|-------------------------|
| !["ENC3"](https://cdn-images-1.medium.com/v2/resize:fit:800/1*Cj7fvEYHb3IRH3y0XHh1kw.png "ENC3") | ![CMD](https://cdn-images-1.medium.com/v2/resize:fit:800/1*ZiVSJMBPAzAifUA8Y2v3fQ.png "CMD") |

To understand more about this topic of encryption I'd suggest read [this](https://blog.csdn.net/msvcer/article/details/11363). Wonderful article written from 2004

&rarr; The function **`CryptFunctions`** is invoked to generate random cryptographic keys using either:

- **`bcrypt.dll`** for modern, secure algorithms.
- **`advapi32.dll`** as a fallback, utilizing legacy APIs like **`CryptAcquireContextW`** and **`CryptGenRandom`**

&rarr; Two sets of keys are generated:

   - One key **`(auStack_2c)`** with 32 bytes for initializing the encryption process.
   - Another key derived from a smaller segment (8 bytes) for further operations.		
   

&rarr; The function **`EncryptDataChunk`** applies cryptographic transformations and is the core cryptographic function. It combines the keys generated above with predefined constants like **`DAT_004465f4`** and **`DAT_00441954`**

**NOTE**


**If you go through the code you will find that instead of encrypting the entire file, the ransomware encrypts only parts of the file (header, footer, or random segments) to save time while still rendering files unusable even when the mode is full encryption(XD)**

#### Wallpaper Change
!["WP"](https://cdn-images-1.medium.com/v2/resize:fit:1200/1*6ixpyYhBTQHxIK0Jucotvw.png "WP")

&rarr; The function uses **`GetDeviceCaps()`	** to retrieve display parameters and dynamically creates a compatible bitmap using **`CreateCompatibleBitmap()`**

&rarr; It writes the ransom note text ("Contacto Ransomware..." message) onto the bitmap using **`DrawTextW()`** and renders it with a custom Arial font created via **`CreateFontW()`**


!["END"](https://cdn-images-1.medium.com/v2/resize:fit:1200/1*Gd4tN6jQ520JXs_HpWPjqA.png "END")

&rarr; In the end the malware deletes the scheduled task it created earlier and cleans up by self deleting and clearing all the logs again.

!["NOTE"](https://cdn-images-1.medium.com/v2/resize:fit:1200/1*s9kHUmHAVewe1BsIifNs8w.png "NOTE")
*Ransom Note*
!["WP"](https://cdn-images-1.medium.com/v2/resize:fit:1200/1*VfFDIyx94sXHPtt-U1GMpQ.png "WP")
*Changed Wallpaper*

### Encryption Process Overview

1. **Dynamic Key Generation**  
   - The encryption process begins with the generation of two cryptographic keys:  
     - **Primary Key (32 bytes):** Generated through a hybrid RNG (Random Number Generator) utilizing system entropy and a pseudo-random number generator (PRNG) seeded with unique initialization vectors.  
     - **Secondary Key (8 bytes):** Derived from a cascading hash-based PRNG, ensuring no predictable patterns.  

2. **Chunk-Based Data Transformation**  
   - File data is processed in **adaptive chunk sizes**, dynamically adjusted based on file size and system resources.  
   - Each chunk undergoes a **multi-stage XOR operation** with the keys, interspersed with bitwise rotations and modular arithmetic to introduce non-linear transformations.  

3. **Key Evolution with SHA-256**  
   - Both keys are hashed using **iterative SHA-256 rounds**, producing intermediate digests that are integrated into the encryption stream.  
   - The process includes salt values embedded in the binary, ensuring per-file uniqueness.

4. **Layered Obfuscation**  
   - The encryption algorithm applies a layered obfuscation strategy by utilizing:  
     - **Key Whitening:** Keys are XORed with pre-defined constants before every operation to mask their actual values.  
     - **Permutation Steps:** Each chunk undergoes byte-level shuffling based on a precomputed permutation matrix.  

5. **Pipeline Optimization for Speed**  
   - The encryption leverages **multi-threaded I/O queues**, allowing concurrent processing of multiple files.  
   - A **low-level custom instruction set** ensures efficient utilization of CPU caches, speeding up large file encryption.


---

### Indicators of Compromise (IOCs)

```
MD5
f36c5298b988e68aa15f72223a445e6d
SHA-1
c4f497b7fac36733f445f3f72c392ea7cadcde8c
SHA-256
7ec702b0b999799eb6de4c960814ab46c004536c42085e2cf77a516c4b6ed4e3 
```

- [Virustotal](https://www.virustotal.com/gui/file/7ec702b0b999799eb6de4c960814ab46c004536c42085e2cf77a516c4b6ed4e3/details)

!["TY"](https://y.yarn.co/e0cb8107-ddd0-4591-9f09-8ea3556b3f3b_text.gif "TY")

Thank you for reading this analysis! ❤️  
Feel free to connect with me on:  
**Discord**: `somedieyoungzz`  
**Twitter**: [@IdaNotPro](https://twitter.com/IdaNotPro)
