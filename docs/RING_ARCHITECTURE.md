# CPU Ring Architecture Deep Dive

## Understanding x86/x64 Privilege Levels

This document provides an in-depth exploration of CPU privilege rings and their implications for DRM bypass techniques.

---

## Table of Contents

1. [Ring Model Overview](#ring-model-overview)
2. [Ring -2: System Management Mode](#ring--2-system-management-mode)
3. [Ring -1: Hypervisor Mode](#ring--1-hypervisor-mode)
4. [Ring 0: Kernel Mode](#ring-0-kernel-mode)
5. [Ring 1-2: Historical Use](#ring-1-2-historical-use)
6. [Ring 3: User Mode](#ring-3-user-mode)
7. [Ring Transitions and Performance](#ring-transitions-and-performance)
8. [Security Boundaries](#security-boundaries)

---

## Ring Model Overview

The x86/x64 architecture implements a hierarchical protection model where code executes at different privilege levels. Modern systems effectively use 4 levels (though x86 defines 4 hardware rings):

```
           ┌─────────────────────────────────────┐
           │   Ring -2 (SMM/UEFI Firmware)       │
           │   • BIOS/UEFI runtime services      │
           │   • System Management Interrupts    │
           │   • Firmware-level security         │
           └─────────────┬───────────────────────┘
                         │ SMI Handler Entry
           ┌─────────────▼───────────────────────┐
           │   Ring -1 (VMX Root / SVM Host)     │
           │   • Hypervisor control plane        │
           │   • Virtual machine monitoring      │
           │   • Hardware instruction intercept  │
           └─────────────┬───────────────────────┘
                         │ VMCALL / VMMCALL
           ┌─────────────▼───────────────────────┐
           │   Ring 0 (Kernel Mode)              │
           │   • Operating system kernel         │
           │   • Device drivers                  │
           │   • Memory management               │
           └─────────────┬───────────────────────┘
                         │ System Call (syscall/sysenter)
           ┌─────────────▼───────────────────────┐
           │   Ring 1-2 (Unused in modern OS)    │
           │   • Reserved for OS services        │
           │   • Not used by Windows/Linux       │
           └─────────────┬───────────────────────┘
                         │ (Conceptual transition)
           ┌─────────────▼───────────────────────┐
           │   Ring 3 (User Mode)                │
           │   • Application execution           │
           │   • Game processes                  │
           │   • DLL injection                   │
           └─────────────────────────────────────┘
```

---

## Ring -2: System Management Mode

### What is SMM?

System Management Mode (SMM) is a special-purpose CPU mode used for low-level system management functions. It operates **completely outside the normal operating system** and has unrestricted access to all hardware.

### Technical Characteristics

| Property | Value |
|----------|-------|
| **Entry Method** | System Management Interrupt (SMI) - typically triggered by hardware |
| **Memory Space** | SMRAM (System Management RAM) - hidden from OS, only accessible in SMM |
| **Execution Context** | Completely isolated from OS - interrupts disabled, paging disabled |
| **Typical Uses** | Power management, USB legacy emulation, firmware updates, thermal management |
| **Security Level** | Highest - can bypass all OS protections, tamper with boot process |

### UEFI Firmware Context

Modern UEFI firmware operates in a similar privilege level during boot:

```c
// UEFI boot flow (pseudo-code)
void UEFIBootSequence() {
    // Phase 1: SEC (Security) - CPU initialization
    InitializeCPU();
    
    // Phase 2: PEI (Pre-EFI Initialization)
    InitializeMemory();
    
    // Phase 3: DXE (Driver Execution Environment)
    LoadUEFIDrivers();  // ← EfiGuard loads here
    
    // Phase 4: BDS (Boot Device Selection)
    FindBootDevice();
    
    // Phase 5: TSL (Transient System Load)
    LoadOSBootLoader();
    
    // Phase 6: RT (Runtime)
    ExitBootServices();  // ← EfiGuard hooks this
}
```

### EfiGuard's Ring -2 Capabilities

**What EfiGuard Can Do**:
1. **Patch kernel code before OS loads** - Modify Windows loader (bootmgfw.efi) to disable security checks
2. **Manipulate UEFI variables** - Change boot configuration data (BCD) to disable protections
3. **Hook boot services** - Intercept firmware functions to inject patches during boot
4. **Persist across reboots** - Remains active as long as it's in the EFI System Partition

**Patch Targets**:
```c
// Pseudocode from EfiGuard decompilation
void PatchWindowsLoader() {
    // Locate ntoskrnl.exe in bootmgr
    PVOID ntoskrnl = FindNtoskrnl(bootmgr);
    
    // Patch 1: Disable Driver Signature Enforcement (DSE)
    // Target: g_CiOptions global variable in CI.dll
    PBYTE ciOptions = FindPattern(ntoskrnl, "\x48\x8B\x05\x00\x00\x00\x00");
    *ciOptions = 0x00;  // Set to 0 = DSE disabled
    
    // Patch 2: Disable PatchGuard initialization
    // Target: KiFilterFiberContext function
    PBYTE pgInit = FindPattern(ntoskrnl, "\x48\x89\x5C\x24\x08\x57\x48");
    *pgInit = 0xC3;  // RET instruction = skip initialization
    
    // Patch 3: Enable kernel debugging
    // Target: KdDebuggerEnabled flag
    PBYTE kdFlag = FindPattern(ntoskrnl, "\x0F\xB6\x05\x00\x00\x00\x00");
    *(kdFlag + 3) = 0x01;  // Set to 1 = debugging enabled
}
```

### Security Implications

**Extreme Risk Factors**:
- ❌ **Bypasses Secure Boot** - Firmware can no longer be trusted
- ❌ **Persists across OS reinstall** - Must reflash firmware or clear EFI partition to remove
- ❌ **Invisible to OS** - Cannot be detected by Windows security tools
- ❌ **Breaks BitLocker** - Disabling Secure Boot invalidates encryption keys
- ❌ **BIOS/UEFI corruption risk** - Incorrect patches can brick the motherboard

---

## Ring -1: Hypervisor Mode

### AMD SVM (Secure Virtual Machine)

**Architecture Overview**:
```
┌──────────────────────────────────────────────────────┐
│  SVM Host Mode (Ring -1)                             │
│  ┌────────────────────────────────────────────────┐  │
│  │  Hypervisor Code (SimpleSvm.sys)               │  │
│  │  • Handles VM-Exits                            │  │
│  │  • Intercepts privileged instructions         │  │
│  │  • Manages VMCB (Virtual Machine Control Block)│ │
│  └────────────────────────────────────────────────┘  │
└───────────────────┬──────────────────────────────────┘
                    │ VMRUN instruction
                    │ VM-Exit on intercept
┌───────────────────▼──────────────────────────────────┐
│  SVM Guest Mode (Ring 0/3)                           │
│  ┌────────────────────────────────────────────────┐  │
│  │  Windows Kernel + Game Process                 │  │
│  │  • Executes normally                           │  │
│  │  │  Thinks it's running on real hardware       │  │
│  │  • CPUID instruction → VM-Exit                 │  │
│  └────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────┘
```

**VMCB Structure** (Virtual Machine Control Block):
```c
typedef struct _VMCB {
    // Control Area (offset 0x000)
    UINT16 InterceptCr;          // CR read/write intercepts
    UINT16 InterceptDr;          // Debug register intercepts
    UINT32 InterceptException;   // Exception intercepts (bitmap)
    UINT32 InterceptMisc1;       // Misc intercepts (INTR, NMI, SMI)
    UINT32 InterceptMisc2;       // Misc intercepts (INVLPG, CPUID, etc.)
    
    // Intercept flags for DRM bypass
    UINT8  InterceptCPUID : 1;   // Set to 1 = trap CPUID
    UINT8  InterceptRDTSC : 1;   // Set to 1 = trap RDTSC
    UINT8  InterceptRDPMC : 1;   // Set to 1 = trap RDPMC
    UINT8  InterceptMSR : 1;     // Set to 1 = trap MSR access
    
    // Nested Page Tables (NPT) - memory virtualization
    UINT64 NptCr3;               // Guest physical → host physical mapping
    
    // Guest state save area (offset 0x400)
    UINT64 GuestRIP;
    UINT64 GuestRSP;
    UINT64 GuestRAX;
    // ... other GPRs
    
} VMCB, *PVMCB;
```

**SimpleSvm.sys Implementation**:
```c
// Actual decompiled code structure
NTSTATUS SimpleSvmVmExitHandler(PVMCB vmcb) {
    UINT64 exitCode = vmcb->ExitCode;
    
    switch (exitCode) {
        case VMEXIT_CPUID:
            HandleCPUIDExit(vmcb);
            break;
            
        case VMEXIT_MSR:
            HandleMSRExit(vmcb);
            break;
            
        case VMEXIT_RDTSC:
            HandleRDTSCExit(vmcb);
            break;
            
        case VMEXIT_XSETBV:
            HandleXSETBVExit(vmcb);
            break;
            
        default:
            // Pass through to guest
            break;
    }
    
    // Resume guest execution
    __svm_vmrun(vmcb);
    
    return STATUS_SUCCESS;
}
```

### Intel VMX (Virtual Machine Extensions)

**VMCS Structure** (Virtual Machine Control Structure):
```c
// VMCS fields (partial list - full spec has 100+ fields)
enum VMCSField {
    // Guest state fields
    GUEST_RIP = 0x681E,
    GUEST_RSP = 0x681C,
    GUEST_RFLAGS = 0x6820,
    GUEST_CR0 = 0x6800,
    GUEST_CR3 = 0x6802,
    GUEST_CR4 = 0x6804,
    
    // Host state fields (hypervisor)
    HOST_RIP = 0x6C16,
    HOST_RSP = 0x6C14,
    HOST_CR3 = 0x6C02,
    
    // Execution control fields
    CPU_BASED_VM_EXEC_CONTROL = 0x4002,  // Primary controls
    SECONDARY_VM_EXEC_CONTROL = 0x401E,  // Secondary controls
    
    // VM-Exit control fields
    VM_EXIT_CONTROLS = 0x400C,
    VM_EXIT_REASON = 0x4402,
    
    // EPT (Extended Page Tables)
    EPT_POINTER = 0x201A,
};

// VM execution control bits for DRM bypass
#define CPU_BASED_HLT_EXITING           (1 << 7)
#define CPU_BASED_CPUID_EXITING         (1 << 10)
#define CPU_BASED_RDTSC_EXITING         (1 << 12)
#define CPU_BASED_MSR_EXITING           (1 << 28)

#define SECONDARY_ENABLE_EPT            (1 << 1)
#define SECONDARY_ENABLE_RDTSCP         (1 << 3)
#define SECONDARY_ENABLE_XSAVES         (1 << 20)
```

**HyperDbg VM-Exit Handler**:
```c
// From hyperhv.dll decompilation (762 functions)
void VmExitHandler() {
    UINT32 exitReason;
    __vmx_vmread(VM_EXIT_REASON, &exitReason);
    
    switch (exitReason & 0xFFFF) {
        case EXIT_REASON_CPUID:
            DispatchCPUID();
            break;
            
        case EXIT_REASON_RDTSC:
            DispatchRDTSC();
            break;
            
        case EXIT_REASON_RDPMC:
            DispatchRDPMC();
            break;
            
        case EXIT_REASON_MSR_READ:
            DispatchMSRRead();
            break;
            
        case EXIT_REASON_MSR_WRITE:
            DispatchMSRWrite();
            break;
            
        case EXIT_REASON_EPT_VIOLATION:
            DispatchEPTViolation();
            break;
            
        case EXIT_REASON_XSETBV:
            DispatchXSETBV();
            break;
    }
    
    // Advance guest RIP past intercepted instruction
    AdvanceGuestRIP();
    
    // Resume VM execution
    __vmx_vmresume();
}
```

### Extended Page Tables (EPT) - Memory Virtualization

EPT provides hardware-assisted memory virtualization, allowing the hypervisor to:
- Create multiple views of the same physical memory
- Hide code modifications from integrity checks
- Implement split-TLB attacks

**EPT Translation Hierarchy**:
```
Guest Virtual Address (GVA)
         │
         │ Guest Page Tables (controlled by OS)
         ▼
Guest Physical Address (GPA)
         │
         │ EPT (controlled by hypervisor)
         ▼
Host Physical Address (HPA)
```

**Split-TLB Attack** (bypassing code integrity checks):
```c
// Configure EPT to show different memory for execute vs. read
void SetupSplitTLB(PVOID codeAddress, PVOID fakeCode, PVOID realCode) {
    EPT_ENTRY *eptEntry = GetEPTEntry(codeAddress);
    
    // Set execute-only permission (no read/write)
    eptEntry->ExecuteAccess = 1;
    eptEntry->ReadAccess = 0;
    eptEntry->WriteAccess = 0;
    eptEntry->PhysicalAddress = VirtToPhys(realCode) >> 12;
    
    // Create second EPT entry for read access
    EPT_ENTRY *readEntry = AllocateEPTEntry();
    readEntry->ExecuteAccess = 0;
    readEntry->ReadAccess = 1;
    readEntry->WriteAccess = 0;
    readEntry->PhysicalAddress = VirtToPhys(fakeCode) >> 12;
    
    // Result: Game executes patched code but integrity check reads original
}
```

### Performance Impact

| Operation | Without Hypervisor | With Hypervisor | Overhead |
|-----------|-------------------|-----------------|----------|
| **Normal Instructions** | ~1 cycle | ~1 cycle | 0% |
| **CPUID** | ~30 cycles | ~3000 cycles | 100x slower |
| **RDTSC** | ~20 cycles | ~2500 cycles | 125x slower |
| **MSR Read/Write** | ~50 cycles | ~3500 cycles | 70x slower |
| **Memory Access** (EPT enabled) | ~4 cycles | ~8 cycles | 100% |
| **Average Game** | N/A | N/A | 2-5% FPS loss |

**Why is VM-Exit Expensive?**
```
1. CPU saves guest state to VMCS/VMCB      (~500 cycles)
2. Switch to hypervisor context            (~300 cycles)
3. Execute VM-exit handler code            (~1000+ cycles)
4. Modify guest state if needed            (~500 cycles)
5. Restore guest state from VMCS/VMCB      (~500 cycles)
6. Resume guest execution (VMRESUME/VMRUN) (~200 cycles)

Total: ~3000 cycles minimum per VM-exit
```

---

## Ring 0: Kernel Mode

### Windows Kernel Architecture

```
┌─────────────────────────────────────────────────────┐
│  User Mode (Ring 3)                                 │
│  ┌───────────────────────────────────────────────┐  │
│  │  Application (Game.exe)                       │  │
│  │  • Call NtQuerySystemInformation()            │  │
│  └───────────────────┬───────────────────────────┘  │
└────────────────────┬─┴─────────────────────────────┘
                     │ syscall/sysenter
┌────────────────────▼───────────────────────────────┐
│  Kernel Mode (Ring 0)                              │
│  ┌─────────────────────────────────────────────┐   │
│  │  System Service Dispatcher                  │   │
│  │  • Validates parameters                     │   │
│  │  • Calls kernel function                    │   │
│  └──────────────────┬──────────────────────────┘   │
│  ┌──────────────────▼──────────────────────────┐   │
│  │  NT Kernel (ntoskrnl.exe)                   │   │
│  │  • NtQuerySystemInformation()               │   │
│  │  • Kernel data structures                   │   │
│  └──────────────────┬──────────────────────────┘   │
│  ┌──────────────────▼──────────────────────────┐   │
│  │  Device Drivers (SimpleSvm.sys)             │   │
│  │  • IoCreateDevice()                         │   │
│  │  • IRP handling                             │   │
│  │  • Hardware access                          │   │
│  └─────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────┘
```

### KUSER_SHARED_DATA Structure

**Address**: `0x7FFE0000` (mapped read-only in user mode, read-write in kernel)

```c
typedef struct _KUSER_SHARED_DATA {
    // Offset 0x000
    ULONG TickCountLowDeprecated;
    ULONG TickCountMultiplier;
    
    // Offset 0x008
    KSYSTEM_TIME InterruptTime;      // Used for timing attacks
    KSYSTEM_TIME SystemTime;         // Current system time
    KSYSTEM_TIME TimeZoneBias;
    
    // Offset 0x014
    ULONG BootId;                    // Increments on each boot
    
    // Offset 0x02D4
    BOOLEAN KdDebuggerEnabled;       // Kernel debugger flag
    BOOLEAN KdDebuggerNotPresent;
    
    // Offset 0x320
    ULONG TickCountLow;              // 32-bit tick count
    ULONG TickCountHigh;             // High part for 64-bit
    
    // Offset 0x340
    ULONG Cookie;                    // Security cookie
    
    // Other fields...
    ULONG NtMajorVersion;
    ULONG NtMinorVersion;
    ULONG NtBuildNumber;
    
} KUSER_SHARED_DATA, *PKUSER_SHARED_DATA;
```

**Spoofing Strategy**:
```c
// Kernel driver continuously updates KUSER to hide emulation
void KUSERSpoofLoop(ULONG gameProcessId) {
    // Map KUSER_SHARED_DATA with write permissions
    PHYSICAL_ADDRESS physAddr = {.QuadPart = 0x7FFE0000};
    PVOID kuser = MmMapIoSpace(physAddr, 0x1000, MmNonCached);
    
    LARGE_INTEGER startTime;
    KeQuerySystemTime(&startTime);
    
    while (IsGameRunning(gameProcessId)) {
        PKUSER_SHARED_DATA kuserData = (PKUSER_SHARED_DATA)kuser;
        
        // 1. Spoof time to prevent timing-based detection
        LARGE_INTEGER currentTime;
        KeQuerySystemTime(&currentTime);
        ULONGLONG elapsed = currentTime.QuadPart - startTime.QuadPart;
        
        kuserData->SystemTime.High1Time = (ULONG)(elapsed >> 32);
        kuserData->SystemTime.LowPart = (ULONG)elapsed;
        kuserData->SystemTime.High2Time = kuserData->SystemTime.High1Time;
        
        // 2. Hide debugger
        kuserData->KdDebuggerEnabled = FALSE;
        kuserData->KdDebuggerNotPresent = TRUE;
        
        // 3. Consistent tick count
        ULONG fakeTicks = (ULONG)(elapsed / 10000);  // Convert 100ns to ms
        kuserData->TickCountLow = fakeTicks;
        kuserData->TickCountHigh = 0;
        
        // Update every millisecond
        LARGE_INTEGER interval = {.QuadPart = -10000};  // 1ms
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }
    
    MmUnmapIoSpace(kuser, 0x1000);
}
```

### Kernel Callbacks for Process Monitoring

```c
// Register process creation callback
NTSTATUS RegisterProcessMonitor() {
    return PsSetCreateProcessNotifyRoutineEx(
        ProcessNotifyCallback,
        FALSE  // FALSE = register, TRUE = unregister
    );
}

void ProcessNotifyCallback(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo
) {
    if (CreateInfo != NULL) {
        // Process is being created
        PUNICODE_STRING imageName = CreateInfo->ImageFileName;
        
        // Check if this is the target game
        if (wcsstr(imageName->Buffer, L"ResidentEvil.exe")) {
            // Store PID for KUSER spoofing
            g_TargetGamePID = (ULONG)(ULONG_PTR)ProcessId;
            
            // Start spoofing thread
            HANDLE threadHandle;
            PsCreateSystemThread(
                &threadHandle,
                THREAD_ALL_ACCESS,
                NULL,
                NULL,
                NULL,
                KUSERSpoofLoop,
                (PVOID)g_TargetGamePID
            );
        }
    } else {
        // Process is exiting
        if ((ULONG)(ULONG_PTR)ProcessId == g_TargetGamePID) {
            g_TargetGamePID = 0;  // Stop spoofing
        }
    }
}
```

### Driver Signature Enforcement (DSE)

**How DSE Works**:
```c
// Kernel function: MmLoadSystemImage (simplified)
NTSTATUS MmLoadSystemImage(PUNICODE_STRING FileName) {
    // 1. Load PE file into memory
    PVOID imageBase = LoadPEImage(FileName);
    
    // 2. Check if DSE is enabled
    if (g_CiOptions & CI_VALIDATE_IMAGE_SIGNATURE) {
        // 3. Verify digital signature
        NTSTATUS status = CiValidateImageHeader(imageBase);
        
        if (!NT_SUCCESS(status)) {
            // Signature invalid - refuse to load
            return STATUS_INVALID_IMAGE_HASH;
        }
    }
    
    // 4. Signature valid or DSE disabled - load driver
    return ProcessDriverLoad(imageBase);
}
```

**g_CiOptions Values**:
```c
// ci.dll global variable (Code Integrity Options)
#define CI_NONE                      0x00  // No checks
#define CI_VALIDATE_IMAGE_SIGNATURE  0x01  // Standard DSE
#define CI_FORCE_INTEGRITY           0x02  // Enhanced verification
#define CI_AUDIT_MODE                0x04  // Log violations only
#define CI_UMCI_ENABLED              0x08  // User-Mode CI
#define CI_WHQL_ENFORCEMENT          0x10  // Require WHQL
#define CI_HYPERVISOR_ENFORCEMENT    0x20  // HVCI enabled

// Typical value: 0x06 (validate + force)
// Bypassed value: 0x00 (all checks disabled)
```

**EfiGuard's DSE Bypass**:
```c
// Patch applied during UEFI boot
void EfiGuardDisableDSE(PVOID ntoskrnl) {
    // Find g_CiOptions variable via pattern scan
    PBYTE pattern = "\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0";
    PBYTE ciOptionsRef = FindPattern(ntoskrnl, pattern, sizeof(pattern) - 1);
    
    // Calculate actual address (RIP-relative addressing)
    LONG offset = *(PLONG)(ciOptionsRef + 3);
    PBYTE ciOptionsAddr = ciOptionsRef + 7 + offset;
    
    // Set to 0 (disable all checks)
    *(PULONG)ciOptionsAddr = 0x00;
}
```

---

## Ring 1-2: Historical Use

Rings 1 and 2 were designed for operating system services in the original x86 architecture but are **unused by modern operating systems**:

- **Ring 1**: Originally intended for OS services (device drivers in early Unix)
- **Ring 2**: Originally intended for less privileged OS code

**Why Unused?**
- Most modern OSes use only Ring 0 (kernel) and Ring 3 (user)
- Performance: Extra ring transitions add overhead
- Complexity: Managing 4 privilege levels is unnecessarily complex
- Hardware: x86-64 long mode encourages 2-level model

**Exception**: Some research hypervisors experimented with Ring 1 for para-virtualization:
```
Ring 0: Hypervisor
Ring 1: Guest kernel (knows it's virtualized)
Ring 3: Guest applications
```

---

## Ring 3: User Mode

### Application Execution Environment

```c
// User-mode restrictions
void UserModeCapabilities() {
    // ✓ Can do:
    VirtualAlloc(...);           // Allocate memory in own process
    CreateThread(...);           // Create threads in own process
    LoadLibrary(...);            // Load DLLs into own process
    
    // ✗ Cannot do:
    __readmsr(0x1A0);            // Privileged instruction → #GP exception
    __writecr3(newPageTable);    // Privileged register → #GP exception
    PhysicalMemoryAccess(0x0);   // No direct hardware access
    
    // ⚠ Can do with limitations:
    VirtualProtect(code, PAGE_EXECUTE_READWRITE);  // Modify own code
    SetThreadContext(thread, &ctx);                // Modify own threads
    DebugActiveProcess(pid);                       // If has privileges
}
```

### DLL Injection Techniques

**1. DLL Hijacking / Search Order Hijacking**:
```c
// Game loads version.dll from its directory before System32
// Place malicious version.dll in game folder:

// version.dll (proxy DLL)
#pragma comment(linker, "/export:GetFileVersionInfoA=C:\\Windows\\System32\\version.GetFileVersionInfoA")
#pragma comment(linker, "/export:GetFileVersionInfoW=C:\\Windows\\System32\\version.GetFileVersionInfoW")
// ... forward all exports

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Inject payload before forwarding to real DLL
        LoadLibrary("lightemu.dll");
    }
    return TRUE;
}
```

**2. IAT (Import Address Table) Hooking**:
```c
void HookIAT(HMODULE module, const char *dllName, const char *funcName, PVOID hookFunc) {
    // Get PE headers
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)module;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)module + dosHeader->e_lfanew);
    
    // Get import directory
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(
        (PBYTE)module + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
    );
    
    // Find target DLL
    while (importDesc->Name) {
        const char *importDllName = (const char *)((PBYTE)module + importDesc->Name);
        
        if (_stricmp(importDllName, dllName) == 0) {
            // Found target DLL - enumerate imported functions
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((PBYTE)module + importDesc->FirstThunk);
            PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)((PBYTE)module + importDesc->OriginalFirstThunk);
            
            while (thunk->u1.Function) {
                PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)module + origThunk->u1.AddressOfData);
                
                if (strcmp(importByName->Name, funcName) == 0) {
                    // Found target function - replace IAT entry
                    DWORD oldProtect;
                    VirtualProtect(&thunk->u1.Function, sizeof(PVOID), PAGE_READWRITE, &oldProtect);
                    thunk->u1.Function = (ULONG_PTR)hookFunc;
                    VirtualProtect(&thunk->u1.Function, sizeof(PVOID), oldProtect, &oldProtect);
                    
                    return;
                }
                
                thunk++;
                origThunk++;
            }
        }
        
        importDesc++;
    }
}
```

**3. Inline Hooking / Detours**:
```c
// Hook by replacing function prologue with JMP to hook
void InlineHook(PVOID targetFunc, PVOID hookFunc, PVOID *originalFunc) {
    // Allocate trampoline
    PBYTE trampoline = VirtualAlloc(NULL, 16, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    
    // Copy original prologue (5+ bytes)
    memcpy(trampoline, targetFunc, 12);
    
    // Add JMP back to original function (+12 bytes)
    trampoline[12] = 0xE9;  // JMP rel32
    *(PDWORD)(trampoline + 13) = (DWORD)((PBYTE)targetFunc + 12 - (trampoline + 17));
    
    // Replace original function with JMP to hook
    DWORD oldProtect;
    VirtualProtect(targetFunc, 12, PAGE_EXECUTE_READWRITE, &oldProtect);
    
    ((PBYTE)targetFunc)[0] = 0xE9;  // JMP rel32
    *(PDWORD)((PBYTE)targetFunc + 1) = (DWORD)((PBYTE)hookFunc - (PBYTE)targetFunc - 5);
    
    // Fill remaining bytes with NOP
    memset((PBYTE)targetFunc + 5, 0x90, 7);
    
    VirtualProtect(targetFunc, 12, oldProtect, &oldProtect);
    
    *originalFunc = trampoline;
}
```

### Vectored Exception Handler (VEH)

Used to catch and emulate privileged instructions that would normally crash:

```c
LONG CALLBACK VEHHandler(PEXCEPTION_POINTERS exc) {
    if (exc->ExceptionRecord->ExceptionCode == EXCEPTION_PRIV_INSTRUCTION) {
        PBYTE rip = (PBYTE)exc->ContextRecord->Rip;
        
        // Decode instruction
        if (rip[0] == 0x0F && rip[1] == 0xA2) {
            // CPUID instruction (0F A2)
            UINT32 leaf = (UINT32)exc->ContextRecord->Rax;
            UINT32 subleaf = (UINT32)exc->ContextRecord->Rcx;
            
            UINT32 eax, ebx, ecx, edx;
            EmulateCPUID(leaf, subleaf, &eax, &ebx, &ecx, &edx);
            
            exc->ContextRecord->Rax = eax;
            exc->ContextRecord->Rbx = ebx;
            exc->ContextRecord->Rcx = ecx;
            exc->ContextRecord->Rdx = edx;
            exc->ContextRecord->Rip += 2;  // Skip CPUID
            
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    
    return EXCEPTION_CONTINUE_SEARCH;
}

// Register VEH
AddVectoredExceptionHandler(1, VEHHandler);
```

---

## Ring Transitions and Performance

### Transition Costs

| Transition | Mechanism | Typical Cost | Use Case |
|-----------|-----------|--------------|----------|
| Ring 3 → Ring 0 | `syscall` / `sysenter` | ~50-100 cycles | System call (file I/O, memory allocation) |
| Ring 0 → Ring -1 | VM-Exit (VMEXIT) | ~1000-3000 cycles | CPUID, RDTSC, MSR access in hypervisor |
| Ring -1 → Ring 0 | VM-Resume (VMRESUME) | ~500 cycles | Return from hypervisor |
| Ring 0 → Ring -2 | SMI (System Management Interrupt) | ~5000+ cycles | Firmware operation, rarely used |

**Why Are VM-Exits So Expensive?**

```
Normal Ring 3 → Ring 0 System Call:
1. Save user registers                    ( ~20 cycles)
2. Switch to kernel stack                 ( ~10 cycles)
3. Lookup system call in SSDT             ( ~15 cycles)
4. Execute kernel function                (varies)
5. Restore user context                   ( ~15 cycles)
Total: ~60-100 cycles

Ring 0 → Ring -1 VM-Exit:
1. CPU detects intercept condition        ( ~50 cycles)
2. Save VMCS/VMCB guest state             (~500 cycles)
3. Load VMCS/VMCB host state              (~300 cycles)
4. Execute hypervisor handler             (~1000+ cycles)
5. Modify guest state if needed           (~200 cycles)
6. Save VMCS/VMCB host state              (~200 cycles)
7. Restore VMCS/VMCB guest state          (~400 cycles)
8. Resume guest (VMRESUME/VMRUN)          (~200 cycles)
Total: ~2800-3000 cycles minimum
```

---

## Security Boundaries

### Attack Surface Per Ring

```
┌─────────────────────────────────────────────────────┐
│  Ring -2: UEFI/SMM                                  │
│  Attack Surface:                                    │
│  • Firmware vulnerabilities                         │
│  • SMM code injection                               │
│  • UEFI bootkit installation                        │
│  • NVRAM variable manipulation                      │
│  Defense: TPM attestation, UEFI Secure Boot         │
└─────────────────┬───────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────┐
│  Ring -1: Hypervisor                                │
│  Attack Surface:                                    │
│  • VM-Exit handler bugs (exploitable from Ring 0)   │
│  • EPT misconfiguration (memory corruption)         │
│  • VMCS/VMCB state corruption                       │
│  • Nested virtualization escape                     │
│  Defense: Hypervisor code audit, VBS/HVCI           │
└─────────────────┬───────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────┐
│  Ring 0: Kernel                                     │
│  Attack Surface:                                    │
│  • Driver vulnerabilities (arbitrary write)         │
│  • Kernel pool overflow                             │
│  • PatchGuard bypass attempts                       │
│  • Kernel structure corruption                      │
│  Defense: PatchGuard, DSE, HVCI, KASLR              │
└─────────────────┬───────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────┐
│  Ring 3: User Mode                                  │
│  Attack Surface:                                    │
│  • DLL injection                                    │
│  • API hooking                                      │
│  • Memory corruption (buffer overflow)              │
│  • Process hollowing                                │
│  Defense: DEP, ASLR, CFG, ACG, CIG                  │
└─────────────────────────────────────────────────────┘
```

### Windows Security Features by Ring

| Feature | Ring | Purpose | Bypass Requirement |
|---------|------|---------|-------------------|
| **ASLR** | Ring 3 | Randomize memory layout | Memory leak to find base addresses |
| **DEP/NX** | Ring 3/0 | Prevent data execution | ROP chains or VirtualProtect |
| **CFG** | Ring 3 | Control flow guard | Valid call target or overwrite |
| **DSE** | Ring 0 | Driver signature check | Ring -2 patch or UEFI variable |
| **PatchGuard** | Ring 0 | Kernel integrity | Ring -2 disable before OS load |
| **HVCI** | Ring -1 | Code integrity via hypervisor | Disable VBS entirely |
| **Secure Boot** | Ring -2 | Boot chain verification | UEFI firmware modification |

---

## Conclusion

Understanding the CPU privilege ring model is essential for analyzing DRM bypass techniques:

- **Ring -2 (UEFI/SMM)**: Ultimate control, highest risk, difficult to implement
- **Ring -1 (Hypervisor)**: Powerful interception, complex, compatibility issues
- **Ring 0 (Kernel)**: Broad system access, moderate risk, requires DSE bypass
- **Ring 3 (User Mode)**: Limited but safe, portable, easiest to detect

Each ring level offers different trade-offs between power, complexity, detection risk, and system stability. Modern DRM bypass often requires coordination across multiple rings to achieve comprehensive evasion.

---

*This document is part of academic research on computer security and should not be used for illegal purposes.*
