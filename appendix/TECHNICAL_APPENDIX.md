# Technical Appendix

## A. CPU Instruction Reference

### A.1 CPUID Instruction Details

**Opcode**: `0F A2`  
**Privilege**: Ring 3 (user mode)  
**Interception**: Can be trapped by hypervisor (VMX/SVM)

**Usage**:
```nasm
mov eax, leaf        ; Set leaf number
mov ecx, subleaf     ; Set subleaf (if applicable)
cpuid                ; Execute
; Results in EAX, EBX, ECX, EDX
```

**Important Leaves for DRM Detection**:

| Leaf | Subleaf | Function | EAX | EBX | ECX | EDX |
|------|---------|----------|-----|-----|-----|-----|
| 0x00000000 | 0 | Max Standard Leaf | Max leaf | "Genu" | "ineI" | "ntel" |
| 0x00000001 | 0 | Processor Info | Family/Model/Stepping | Brand/CLFLUSH | Feature flags | Feature flags |
| 0x00000007 | 0 | Extended Features | Max subleaf | BMI/AVX2/... | ... | ... |
| 0x40000000 | 0 | Hypervisor Info | Max HV leaf | "KVMK" | "VMKV" | "M\0\0\0" |
| 0x80000000 | 0 | Max Extended Leaf | Max leaf | Reserved | Reserved | Reserved |
| 0x80000001 | 0 | Extended Info | ... | ... | LAHF/LZCNT | SYSCALL/NX |

**CPUID Leaf 0x01 Bit Flags** (ECX register):

```c
#define CPUID_FEAT_ECX_SSE3         (1 << 0)
#define CPUID_FEAT_ECX_PCLMUL       (1 << 1)
#define CPUID_FEAT_ECX_DTES64       (1 << 2)
#define CPUID_FEAT_ECX_MONITOR      (1 << 3)
#define CPUID_FEAT_ECX_DS_CPL       (1 << 4)
#define CPUID_FEAT_ECX_VMX          (1 << 5)   // Intel VT-x support
#define CPUID_FEAT_ECX_SMX          (1 << 6)
#define CPUID_FEAT_ECX_EST          (1 << 7)
#define CPUID_FEAT_ECX_TM2          (1 << 8)
#define CPUID_FEAT_ECX_SSSE3        (1 << 9)
#define CPUID_FEAT_ECX_CID          (1 << 10)
#define CPUID_FEAT_ECX_FMA          (1 << 12)
#define CPUID_FEAT_ECX_CX16         (1 << 13)
#define CPUID_FEAT_ECX_ETPRD        (1 << 14)
#define CPUID_FEAT_ECX_PDCM         (1 << 15)
#define CPUID_FEAT_ECX_PCIDE        (1 << 17)
#define CPUID_FEAT_ECX_DCA          (1 << 18)
#define CPUID_FEAT_ECX_SSE4_1       (1 << 19)
#define CPUID_FEAT_ECX_SSE4_2       (1 << 20)
#define CPUID_FEAT_ECX_x2APIC       (1 << 21)
#define CPUID_FEAT_ECX_MOVBE        (1 << 22)
#define CPUID_FEAT_ECX_POPCNT       (1 << 23)
#define CPUID_FEAT_ECX_AES          (1 << 25)
#define CPUID_FEAT_ECX_XSAVE        (1 << 26)
#define CPUID_FEAT_ECX_OSXSAVE      (1 << 27)
#define CPUID_FEAT_ECX_AVX          (1 << 28)
#define CPUID_FEAT_ECX_F16C         (1 << 29)
#define CPUID_FEAT_ECX_RDRAND       (1 << 30)
#define CPUID_FEAT_ECX_HYPERVISOR   (1 << 31)  // Running in VM
```

---

### A.2 RDTSC/RDTSCP Instructions

**RDTSC Opcode**: `0F 31`  
**RDTSCP Opcode**: `0F 01 F9`

**Difference**:
- **RDTSC**: Reads Time Stamp Counter (TSC)
- **RDTSCP**: RDTSC + Processor ID (in ECX)

**Usage**:
```nasm
rdtsc           ; Read TSC
; EDX:EAX = 64-bit timestamp

rdtscp          ; Read TSC + CPU ID
; EDX:EAX = 64-bit timestamp
; ECX = Processor ID
```

**Timing Attack Example**:
```c
// Measure instruction execution time
uint64_t start, end;
uint32_t aux;

start = __rdtscp(&aux);
// ... code to measure ...
end = __rdtscp(&aux);

uint64_t cycles = end - start;

// If running in hypervisor, cycles will be much higher due to VM-exits
if (cycles > 1000) {
    // Possible hypervisor detected
}
```

---

### A.3 XGETBV Instruction

**Opcode**: `0F 01 D0`  
**Privilege**: Ring 3 (if CR4.OSXSAVE = 1)

**Purpose**: Read extended control register (XCR)

**Usage**:
```nasm
xor ecx, ecx    ; ECX = 0 (XCR0)
xgetbv          ; Read XCR0
; EDX:EAX = XCR0 value
```

**XCR0 Bits** (Extended Feature Enable):

```c
#define XCR0_X87         (1 << 0)   // x87 FPU state
#define XCR0_SSE         (1 << 1)   // SSE state (XMM registers)
#define XCR0_AVX         (1 << 2)   // AVX state (YMM registers)
#define XCR0_BNDREG      (1 << 3)   // MPX bounds registers
#define XCR0_BNDCSR      (1 << 4)   // MPX BNDCFGU and BNDSTATUS
#define XCR0_OPMASK      (1 << 5)   // AVX-512 opmask registers (k0-k7)
#define XCR0_ZMM_HI256   (1 << 6)   // AVX-512 upper 256 bits of ZMM0-15
#define XCR0_HI16_ZMM    (1 << 7)   // AVX-512 upper 512 bits of ZMM16-31
#define XCR0_PKRU        (1 << 9)   // Protection Key Rights Register
```

**Denuvo Check**:
```c
// Verify AVX support matches CPUID claim
uint32_t eax, ebx, ecx, edx;
__cpuid(1, eax, ebx, ecx, edx);

bool cpuid_avx = (ecx & (1 << 28)) != 0;
bool cpuid_osxsave = (ecx & (1 << 27)) != 0;

if (cpuid_avx && cpuid_osxsave) {
    uint64_t xcr0 = _xgetbv(0);
    bool xgetbv_avx = (xcr0 & 0x06) == 0x06;  // XCR0[1:2] = 11b
    
    if (!xgetbv_avx) {
        // Inconsistency detected - possible emulation
    }
}
```

---

## B. Hypervisor Detection Techniques

### B.1 CPUID-Based Detection

```c
bool DetectHypervisor_CPUID() {
    uint32_t eax, ebx, ecx, edx;
    
    // Method 1: Check hypervisor bit (CPUID.01H:ECX[31])
    __cpuid(1, eax, ebx, ecx, edx);
    if (ecx & (1 << 31)) {
        return true;  // Hypervisor present
    }
    
    // Method 2: Check CPUID leaf 0x40000000
    __cpuid(0x40000000, eax, ebx, ecx, edx);
    if (eax >= 0x40000000) {
        // Read hypervisor vendor string
        char vendor[13];
        *(uint32_t*)(vendor + 0) = ebx;
        *(uint32_t*)(vendor + 4) = ecx;
        *(uint32_t*)(vendor + 8) = edx;
        vendor[12] = '\0';
        
        // Known hypervisor signatures:
        // "KVMKVMKVM\0\0\0" - KVM
        // "Microsoft Hv" - Hyper-V
        // "VMwareVMware" - VMware
        // "XenVMMXenVMM" - Xen
        
        return true;
    }
    
    return false;
}
```

---

### B.2 Timing-Based Detection

```c
bool DetectHypervisor_Timing() {
    const int SAMPLES = 100;
    uint64_t timings[SAMPLES];
    
    // Measure RDTSC execution time
    for (int i = 0; i < SAMPLES; i++) {
        uint32_t aux;
        uint64_t start = __rdtscp(&aux);
        __rdtscp(&aux);  // Measure RDTSC itself
        uint64_t end = __rdtscp(&aux);
        
        timings[i] = end - start;
    }
    
    // Calculate average
    uint64_t sum = 0;
    for (int i = 0; i < SAMPLES; i++) {
        sum += timings[i];
    }
    uint64_t average = sum / SAMPLES;
    
    // On bare metal: ~20-40 cycles
    // In hypervisor: ~2000-4000 cycles (due to VM-exit overhead)
    if (average > 500) {
        return true;  // Likely in hypervisor
    }
    
    // Check for outliers (VM-exits)
    int outliers = 0;
    for (int i = 0; i < SAMPLES; i++) {
        if (timings[i] > average * 10) {
            outliers++;
        }
    }
    
    // More than 10% outliers suggests VM-exits
    if (outliers > SAMPLES / 10) {
        return true;
    }
    
    return false;
}
```

---

### B.3 MSR-Based Detection

```c
// Requires Ring 0 (kernel driver)
bool DetectHypervisor_MSR() {
    uint64_t msr_value;
    
    // Read IA32_FEATURE_CONTROL (MSR 0x3A)
    // Bit 0: Lock bit
    // Bit 2: Enable VMX outside SMX
    msr_value = __readmsr(0x3A);
    
    bool vmx_locked = (msr_value & 0x01) != 0;
    bool vmx_enabled = (msr_value & 0x04) != 0;
    
    if (vmx_locked && vmx_enabled) {
        // VMX is enabled and locked - possible hypervisor
        return true;
    }
    
    // Read IA32_VMX_BASIC (MSR 0x480)
    // Only accessible if VMX is supported
    __try {
        msr_value = __readmsr(0x480);
        // If we can read this, VMX is supported
        // Check VMCS revision ID (bits 30:0)
        uint32_t vmcs_revision = (uint32_t)(msr_value & 0x7FFFFFFF);
        if (vmcs_revision != 0) {
            return true;  // VMX capability detected
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        // Exception reading MSR - VMX not supported
    }
    
    return false;
}
```

---

## C. Extended Page Tables (EPT) Deep Dive

### C.1 EPT Translation Hierarchy

**4-Level Page Table Structure**:

```
Guest Virtual Address (48-bit):
┌─────────┬─────────┬─────────┬─────────┬──────────────┐
│ PML4 (9)│ PDPT (9)│  PD (9) │  PT (9) │  Offset (12) │
└─────────┴─────────┴─────────┴─────────┴──────────────┘

Guest Physical Address:
         ↓
┌─────────────────────────────────────┐
│  Guest Page Tables (managed by OS)  │
└─────────────────────────────────────┘
         ↓
EPT Translation:
┌─────────┬─────────┬─────────┬─────────┬──────────────┐
│ EPT-PML4│ EPT-PDPT│ EPT-PD  │ EPT-PT  │  Offset (12) │
└─────────┴─────────┴─────────┴─────────┴──────────────┘
         ↓
Host Physical Address
```

**EPT Entry Structure** (64-bit):

```c
typedef union _EPT_ENTRY {
    uint64_t raw;
    struct {
        uint64_t read_access : 1;        // Bit 0
        uint64_t write_access : 1;       // Bit 1
        uint64_t execute_access : 1;     // Bit 2
        uint64_t memory_type : 3;        // Bits 3-5 (0=UC, 6=WB)
        uint64_t ignore_pat : 1;         // Bit 6
        uint64_t large_page : 1;         // Bit 7 (1=2MB/1GB page)
        uint64_t accessed : 1;           // Bit 8
        uint64_t dirty : 1;              // Bit 9
        uint64_t user_execute : 1;       // Bit 10
        uint64_t reserved1 : 1;          // Bit 11
        uint64_t physaddr : 40;          // Bits 12-51 (4KB aligned)
        uint64_t reserved2 : 11;         // Bits 52-62
        uint64_t suppress_ve : 1;        // Bit 63
    };
} EPT_ENTRY;
```

---

### C.2 Split-TLB Attack Implementation

**Concept**: Create different views of the same physical page for execute vs. read

```c
// Setup split TLB for code integrity bypass
void SetupSplitTLB(PVOID code_addr, PVOID original_code, PVOID patched_code) {
    // Get EPT entry for code page
    EPT_ENTRY *ept_entry = WalkEPT(code_addr);
    
    // Create two physical page mappings
    uint64_t original_phys = VirtToPhys(original_code);
    uint64_t patched_phys = VirtToPhys(patched_code);
    
    // Configure execute-only mapping (no read/write)
    ept_entry->read_access = 0;
    ept_entry->write_access = 0;
    ept_entry->execute_access = 1;
    ept_entry->physaddr = patched_phys >> 12;
    
    // Create second EPT entry for read access (in separate EPT structure)
    EPT_ENTRY *read_entry = AllocateEPTEntry();
    read_entry->read_access = 1;
    read_entry->write_access = 0;
    read_entry->execute_access = 0;
    read_entry->physaddr = original_phys >> 12;
    
    // When game reads memory for integrity check, it sees original code
    // When game executes code, CPU fetches from patched code
    // This bypasses CRC/SHA checks on code sections
}
```

**EPT Violation Handler**:

```c
void HandleEPTViolation(GUEST_STATE *guest) {
    uint64_t gpa = __vmx_vmread(GUEST_PHYSICAL_ADDRESS);
    uint64_t exit_qualification = __vmx_vmread(EXIT_QUALIFICATION);
    
    // Parse exit qualification
    bool read_violation = (exit_qualification & 0x01) != 0;
    bool write_violation = (exit_qualification & 0x02) != 0;
    bool exec_violation = (exit_qualification & 0x04) != 0;
    
    if (exec_violation && !read_violation) {
        // Execute attempt on non-executable page
        // Switch to execute-only EPT mapping
        SwitchToExecuteEPT(gpa);
    }
    else if (read_violation && !exec_violation) {
        // Read attempt on execute-only page
        // Switch to read-only EPT mapping
        SwitchToReadEPT(gpa);
    }
    
    // Resume guest
}
```

---

## D. KUSER_SHARED_DATA Structure Deep Dive

**Address**: `0x7FFE0000` (fixed on all x64 Windows)

**Full Structure** (partial):

```c
typedef struct _KSYSTEM_TIME {
    ULONG LowPart;
    LONG High1Time;
    LONG High2Time;
} KSYSTEM_TIME;

typedef struct _KUSER_SHARED_DATA {
    // 0x000
    ULONG TickCountLowDeprecated;
    ULONG TickCountMultiplier;
    
    // 0x008
    volatile KSYSTEM_TIME InterruptTime;
    
    // 0x014
    volatile KSYSTEM_TIME SystemTime;
    
    // 0x020
    volatile KSYSTEM_TIME TimeZoneBias;
    
    // 0x02C
    USHORT ImageNumberLow;
    USHORT ImageNumberHigh;
    
    // 0x030
    WCHAR NtSystemRoot[260];
    
    // 0x238
    ULONG MaxStdioHandle;
    ULONG PageSize;
    
    // 0x240
    ULONG AllocationGranularity;
    USHORT MinimumUserModeAddress;
    USHORT MaximumUserModeAddress;
    
    // 0x248
    ULONG_PTR ActiveProcessorMask;
    ULONG NumberOfProcessors;
    
    // 0x250
    ULONG NtProductType;
    BOOLEAN ProductTypeIsValid;
    BOOLEAN Reserved0[1];
    USHORT NativeProcessorArchitecture;
    
    // 0x254
    ULONG NtMajorVersion;
    ULONG NtMinorVersion;
    
    // 0x25C
    BOOLEAN ProcessorFeatures[64];
    
    // 0x29C
    ULONG Reserved1;
    ULONG Reserved3;
    
    // 0x2A4
    volatile ULONG TimeUpdateLock;
    
    // 0x2A8
    ULONGLONG Reserved4;
    
    // 0x2B0
    ULONGLONG Reserved5;
    
    // 0x2B8
    ULONGLONG Reserved6;
    
    // 0x2C0
    union {
        KSYSTEM_TIME TickCount;
        volatile ULONG64 TickCountQuad;
        struct {
            ULONG ReservedTickCountOverlay[3];
            ULONG TickCountPad[1];
        };
    };
    
    // 0x2D0
    ULONG Cookie;
    ULONG CookiePad;
    
    // 0x2D4
    volatile BOOLEAN KdDebuggerEnabled;
    union {
        BOOLEAN KdDebuggerNotPresent;
        BOOLEAN Reserved8[3];
    };
    
    // 0x2D8
    ULONG SharedDataFlags;
    
    // ... many more fields ...
    
    // 0x320
    ULONG TickCountLow;
    ULONG TickCountHigh;
    
} KUSER_SHARED_DATA, *PKUSER_SHARED_DATA;
```

**Spoofing Strategy**:

```c
// Kernel driver continuously updates shared data
void SpoofKUSER() {
    PKUSER_SHARED_DATA kuser = (PKUSER_SHARED_DATA)0x7FFE0000;
    
    // Start time reference
    LARGE_INTEGER boot_time;
    KeQuerySystemTime(&boot_time);
    
    while (true) {
        // Calculate elapsed time
        LARGE_INTEGER current_time;
        KeQuerySystemTime(&current_time);
        
        ULONGLONG elapsed_100ns = current_time.QuadPart - boot_time.QuadPart;
        
        // Update SystemTime (fake it advancing normally)
        kuser->SystemTime.LowPart = (ULONG)elapsed_100ns;
        kuser->SystemTime.High1Time = (LONG)(elapsed_100ns >> 32);
        kuser->SystemTime.High2Time = kuser->SystemTime.High1Time;
        
        // Update InterruptTime (must match SystemTime for consistency)
        kuser->InterruptTime = kuser->SystemTime;
        
        // Update TickCount (milliseconds since boot)
        ULONGLONG ticks = elapsed_100ns / 10000;  // Convert to ms
        kuser->TickCount.LowPart = (ULONG)ticks;
        kuser->TickCount.High1Time = (LONG)(ticks >> 32);
        kuser->TickCount.High2Time = kuser->TickCount.High1Time;
        
        kuser->TickCountLow = (ULONG)ticks;
        kuser->TickCountHigh = (ULONG)(ticks >> 32);
        
        // Hide debugger
        kuser->KdDebuggerEnabled = FALSE;
        kuser->KdDebuggerNotPresent = TRUE;
        
        // Update every 1ms
        LARGE_INTEGER interval;
        interval.QuadPart = -10000;  // 1ms in 100ns units
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }
}
```

---

## E. Steam Emulation (Goldberg)

### E.1 Steamworks API Surface

**Key Interfaces**:

| Interface | Purpose | Common Functions |
|-----------|---------|------------------|
| **ISteamClient** | Client lifecycle | CreateSteamPipe, ConnectToGlobalUser |
| **ISteamUser** | User authentication | GetSteamID, BLoggedOn, GetAuthSessionTicket |
| **ISteamFriends** | Social features | GetPersonaName, GetFriendCount |
| **ISteamUtils** | Utilities | GetAppID, GetServerRealTime |
| **ISteamApps** | App management | BIsSubscribed, BIsDlcInstalled |
| **ISteamUserStats** | Achievements/Stats | GetAchievement, SetStat |
| **ISteamRemoteStorage** | Cloud saves | FileWrite, FileRead |
| **ISteamNetworking** | P2P networking | SendP2PPacket, AcceptP2PSessionWithUser |

---

### E.2 Configuration Files

**steam_appid.txt**:
```
3764200
```

**configs.main.ini**:
```ini
[main]
# Steam AppId
appid = 3764200

# Language
language = english

# Account name
account_name = Player

# Listen port for Steam callbacks
listen_port = 47584

# Enable offline mode
offline = 1

# Disable overlay
disable_overlay = 1
```

**steam_interfaces.txt**:
```
SteamClient020
SteamUser021
SteamFriends017
SteamUtils010
SteamMatchMaking009
SteamUserStats012
SteamApps008
SteamNetworking006
SteamRemoteStorage014
SteamScreenshots003
SteamHTTP003
SteamController008
SteamUGC018
SteamAppList001
SteamMusic001
SteamMusicRemote001
SteamHTMLSurface005
SteamInventory003
SteamVideo002
SteamParentalSettings001
SteamInput006
SteamParties002
SteamRemotePlay001
SteamUser020
```

---

*This appendix provides additional technical details for researchers and developers working with virtualization-based security bypass techniques.*
