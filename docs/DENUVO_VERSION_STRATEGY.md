# Denuvo Version Targeting Strategy & Modern Research Approaches

> **Research Note**: This document consolidates community feedback, architectural critique, and modern research directions for effective DRM analysis focus.

---

## Table of Contents

- [Version Targeting Rationale](#version-targeting-rationale)
- [Why Hypervisor is Essential for v15+](#why-hypervisor-is-essential-for-v15)
- [Environmental Preconditions & Limitations](#environmental-preconditions--limitations)
- [Virtualized Execution as a Research Primitive](#virtualized-execution-as-a-research-primitive)
- [Binary Differential Analysis Methodology](#binary-differential-analysis-methodology)
- [Cross-Platform Research Limitations](#cross-platform-research-limitations)
- [Protocol Bridge Analysis](#protocol-bridge-analysis)
- [Breakpoint Strategy Taxonomy](#breakpoint-strategy-taxonomy)
- [OEP Recovery Research](#oep-recovery-research)
- [CPUID / HWID / Syscall Extraction Tools](#cpuid--hwid--syscall-extraction-tools)
- [Referenced Open-Source Projects](#referenced-open-source-projects)

---

## Version Targeting Rationale

A key strategic observation in the research community is that **not all Denuvo versions are equally worth studying**. Allocating significant research effort toward older Denuvo versions (v1–v8, roughly 2014–2018) carries diminishing returns for several reasons:

| Factor | Older Versions (v1–v8) | Modern Versions (v12–v17+) |
|--------|------------------------|---------------------------|
| **Active game library** | Mostly end-of-life titles, abandoned or nearing license expiry | Current AAA releases actively played |
| **Denuvo license lifecycle** | Publishers often let licenses lapse → DRM removed officially | Active, frequently renewed licenses |
| **Protection complexity** | Earlier VM architectures, simpler MBA layers | Deeply nested MBA, anti-hypervisor, anti-VBS checks |
| **Community value** | Low — many already cracked or officially unprotected | High — represents the actual research frontier |
| **Transferability of findings** | Limited to that specific version | Foundational understanding applies forward |

**Conclusion**: Effective research effort should concentrate on **Denuvo v12 and above**, with particular emphasis on **v15+** which powers the majority of current major releases. Understanding the architecture of older versions remains useful for building foundational knowledge, but should not be the *endpoint* of a research project.

---

## Why Hypervisor is Essential for v15+

Modern Denuvo versions (v15+) have significantly hardened their detection of Ring 0 and Ring 3 analysis environments. The hypervisor (Ring -1) layer is not just one option among many — it is increasingly the *minimum viable privilege level* for meaningful analysis of current protection schemes.

### Detection Mechanisms in v15+ That Rule Out Lower Rings

**Against Ring 0 (Kernel Driver) approaches:**
- Active scanning for unsigned or anomalous kernel modules
- Timing-based checks that detect kernel-hook latency
- Integration with anti-cheat stacks that have their own kernel presence (e.g., Kernel Anti-Cheat callbacks)
- HVCI enforcement on modern Windows 11 systems blocks unsigned kernel code injection

**Against Ring 3 (User-Mode) approaches:**
- IAT integrity checks at runtime
- Redundant API resolution through direct syscalls (bypasses all user-mode hooks)
- Thread stack scanning to detect injected DLLs
- Guard page / TLS callback monitoring

**Why Ring -1 (Hypervisor) changes the equation:**
- The hypervisor operates *below* the OS; the guest OS and all its processes — including Denuvo — run inside the VM
- CPUID and MSR reads from the guest can be transparently intercepted and modified
- Extended Page Tables (EPT) allow memory views to differ between host and guest, enabling shadow-page research
- Execution is observed at hardware level before any software-level anti-analysis code runs

### The HV-PlugNPlay Reference Architecture

The project [HV-PlugNPlay](https://github.com/jcnnik/HV-PlugNPlay) is a publicly studied example of a minimal hypervisor framework designed for plug-and-play extensibility in research contexts. Its architectural characteristics include:

- **Minimal VMX setup**: Initializes VMCS with only the fields required for the target use case, reducing detectable hypervisor fingerprint
- **VM-exit handler dispatch**: Clean routing of VM exits (CPUID, RDMSR, WRMSR, EPT violations) to registered handler modules
- **No persistent kernel presence**: Designed to be loaded transiently, reducing exposure window

From a research standpoint this architecture is valuable because it demonstrates how to build a *targeted* hypervisor rather than a general-purpose one — reducing complexity and the attack surface that DRM can use to detect the hypervisor's presence.

---

## Environmental Preconditions & Limitations

A critical limitation of all current hypervisor-based research approaches is the **required environmental setup**. This is not a minor inconvenience — it represents a fundamental constraint that limits practical applicability:

### Required Conditions for Hypervisor-Based Analysis

| Requirement | Details | Challenge |
|-------------|---------|-----------|
| **BIOS/UEFI settings** | VT-x/AMD-V must be enabled; Secure Boot often needs disabling | Most consumer systems ship with secure boot on; some cannot disable it |
| **Test Signing Mode** | Windows requires test signing mode (`bcdedit /set testsigning on`) for unsigned hypervisor drivers | Detectable via `NtQuerySystemInformation`, `IsDebuggerPresent`-family checks, and direct KUSER_SHARED_DATA inspection |
| **HVCI / VBS disabled** | Virtualization-Based Security and HVCI block loading of unsigned Ring -1 code | Increasingly enabled by default on Windows 11 OEM systems |
| **No nested virtualization** | Running the research hypervisor inside an existing VM (e.g., VirtualBox/VMware) typically requires nested virtualization support | Performance degradation; additional detection surface |
| **Specific CPU generation** | Some VMX features (EPT, unrestricted guest, VMFUNC) required for advanced techniques are only in Intel Haswell+ or AMD Zen+ | Older hardware may not expose required MSR bits |

### The Test Mode Detection Problem

Test mode is particularly problematic because it is **observable from within Ring 3**. Denuvo v12+ is known to check for test signing mode as part of its environment integrity assessment. Detection vectors include:

- `NtQuerySystemInformation(SystemKernelDebuggerInformation)` — returns debug state
- Direct read of `KUSER_SHARED_DATA + 0x2D4` (TestRetailFlags field)  
- Checking for the test mode watermark presence via Desktop Window Manager hooks
- Certificate chain validation — self-signed test certificates produce a different chain than production WHQL signatures

This means a naive hypervisor loaded via test mode may cause the target application to alter its behaviour, observe a different code path, or refuse to run — invalidating the research environment before meaningful data is collected.

---

## Virtualized Execution as a Research Primitive

A conceptually powerful approach — and one that addresses the test mode problem at its root — is to **execute the target application inside a virtualized environment where the application itself performs the decryption**, producing clean code that can then be observed and extracted.

### The Core Idea

Denuvo's protection model relies on:
1. Encrypting sections of the game's executable code
2. Decrypting sections on-demand at runtime using hardware-bound keys
3. Re-encrypting after the section is no longer needed (in some versions)

If the virtualized environment is sufficiently transparent — i.e., the application cannot distinguish "real hardware" from the emulated view — it will proceed through its normal decryption routine. At that point, the decrypted code exists in memory and can be observed.

### Research Flow

```
┌─────────────────────────────────────────────┐
│  1. Establish transparent VM environment    │
│     - Spoof CPUID to match physical host    │
│     - Present authentic hardware MSRs       │
│     - Pass-through HWID sources faithfully  │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│  2. Launch target application inside VM     │
│     - DRM runs, validates environment       │
│     - Proceeds with normal decryption       │
│     - Decrypted code lands in guest memory  │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│  3. Observe from hypervisor layer           │
│     - EPT-based monitoring of write ops     │
│     - Track which pages transition from     │
│       encrypted → executable                │
│     - Capture page contents at execution    │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│  4. Reconstruct clean binary                │
│     - Assemble captured pages into PE       │
│     - Resolve remaining stubs / trampolines │
│     - Validate against known import table   │
└─────────────────────────────────────────────┘
```

### Why Transparency is Hard

Achieving a truly transparent VM is a significant research challenge. Known detection vectors that Denuvo and similar systems check:

- **CPUID leaf 0x40000000**: Hypervisor presence bit and vendor string (e.g., "VMwareVMware", "KVMKVMKVM", "Microsoft Hv")
- **RDTSC timing**: VM exits introduce measurable latency; timing two consecutive RDTSC calls reveals virtualization
- **MSR 0x3B** (IA32_TSC_ADJUST): Hypervisor may modify this; inconsistency is detectable
- **APIC timer calibration**: Virtual APIC timers drift differently from hardware
- **Cache topology**: `CPUID EAX=4` cache topology may not match expected physical layout
- **SIDT/SGDT**: On some hypervisors, interrupt descriptor table base differs from bare metal

Addressing all of these simultaneously — while maintaining a stable research environment — is a non-trivial systems engineering problem and represents an active area of academic research.

---

## Binary Differential Analysis Methodology

Once clean code has been obtained (or when studying DLC/feature gating specifically), **binary differential analysis** is a powerful technique for understanding what the DRM layer adds or modifies.

### DLC vs. Base Version Comparison

A practically useful research approach is to acquire two versions of the same title:
1. **Base version** (no DLC or specific feature)
2. **DLC/full version** (with the feature enabled)

By comparing the two binaries, it becomes possible to isolate exactly which code paths and data are gated by the DRM layer. This is valuable because:

- DLC gating often involves relatively small additions to the executable — making diffs tractable
- The memory map difference reveals what additional data the stack loads when execution reaches the EXE module boundary
- Structural differences in import tables, resource sections, or overlay data indicate where the DRM-enforced content is stored

### Tooling for Binary Comparison

The [kvc repository](https://github.com/wesmar/kvc) provides tooling specifically suited for binary code comparison tasks. Relevant capabilities include:

- **Structural diff**: Compare PE section layouts between two binaries
- **Function-level matching**: Identify identical, similar, and new functions across versions
- **Byte-level delta**: Produce minimal patch sets representing the differences
- **Call graph diff**: Visualize how control flow changes between versions

### Practical Workflow

```
Step 1: Obtain both binaries (base and DLC version)
         │
         ▼
Step 2: Normalize load addresses (rebase to same VA if needed)
         │
         ▼
Step 3: Run structural section diff
         → Identify new/modified sections
         → Note size deltas in .text, .data, .rdata
         │
         ▼
Step 4: Function-level diff in disassembler (Ghidra / BN)
         → Export function lists from both
         → Match by hash or name
         → Isolate unmatched (new) functions
         │
         ▼
Step 5: Trace call paths from new functions back to known entry
         → Understand how DLC code is reached
         → Identify branch conditions that gate access
         │
         ▼
Step 6: Examine stack loading at EXE module boundary
         → What additional .pak / encrypted blobs are mapped?
         → What decryption keys are derived?
```

---

## Cross-Platform Research Limitations

A significant architectural weakness of hypervisor-based research is its **near-exclusive dependence on Windows and specific x86 hardware configurations**.

### Platform Coverage Analysis

| Platform | Hypervisor Research Feasibility | Notes |
|----------|--------------------------------|-------|
| **Windows 10/11 x64** | High | Native VMX/SVM support; most tooling targets this |
| **Linux x86_64** | Low | KVM available but Denuvo titles rarely run natively; Wine/Proton adds layers that complicate analysis |
| **macOS (Intel)** | Very Low | Hypervisor entitlement required; SIP restrictions; Denuvo has no native macOS presence |
| **macOS (Apple Silicon)** | Minimal | ARMv8 architecture; no x86 VMX; translation layer (Rosetta) invalidates native analysis |
| **Steam Deck (SteamOS)** | Low | Proton/Wine translation; hypervisor setup complex; limited RE tooling for this environment |

### The Linux/macOS Gap

This cross-platform limitation is not merely a tooling inconvenience — it represents a fundamental research constraint. Specifically:

- **Linux**: Many security researchers prefer Linux tooling ecosystems (radare2, pwndbg, QEMU/KVM). However, because Denuvo-protected titles do not run natively on Linux, all Linux-based analysis must go through a compatibility layer (Proton/Wine). This compatibility layer itself introduces artifacts that can confound analysis results — making it unclear whether observed behaviour is from Denuvo, the game, or the translation layer.

- **macOS**: Denuvo has no production macOS deployment at the time of writing, making it a non-target. However, from a broader DRM research standpoint, the macOS Hypervisor framework (`Hypervisor.framework`) offers interesting academic study opportunities for understanding how Apple restricts hypervisor access to user-space processes via entitlements.

### Research Implication

Any hypervisor-based DRM research framework that seeks broad applicability should treat **Linux compatibility as a first-class concern** rather than an afterthought. A research environment that only functions under specific Windows + BIOS conditions has limited reproducibility and peer review potential.

---

## Protocol Bridge Analysis

An underexplored research vector is the **protocol bridge between Denuvo and the Windows kernel/OS infrastructure**. Rather than attempting to intercept at the hypervisor level, placing analysis points at these protocol bridges may be more tractable in certain scenarios.

### What is a Protocol Bridge in This Context?

Denuvo must, at some point, interact with real hardware and OS services to perform its functions:
- **License validation**: Requires network I/O (TCP/TLS to Denuvo servers) or local token file access
- **Hardware fingerprinting**: Requires kernel-level queries (WMI, registry, CPUID, volume serial numbers)
- **Anti-debug checks**: Requires OS API calls that have kernel entry points
- **Time-based checks**: Requires access to high-resolution timers

Each of these interactions crosses a boundary (user ↔ kernel, process ↔ driver, application ↔ network stack) that represents a **observable protocol bridge**.

### Breakpoint Placement Strategy at Bridges

Rather than generic instruction-level tracing, targeted breakpoints at bridge points can yield high-value information with lower noise:

```
Bridge Type          │ Placement Point                    │ Observable Data
─────────────────────┼────────────────────────────────────┼──────────────────────────
Network bridge       │ WSASend/WSARecv, ssl_write/read     │ License request/response
Registry bridge      │ NtQueryKey, NtEnumerateValueKey     │ HW ID sources queried
Volume bridge        │ NtQueryVolumeInformationFile        │ Serial number queries
WMI bridge           │ IWbemServices::ExecQuery            │ Hardware property reads  
CPUID bridge         │ __cpuid() call sites in binary      │ Which leaves are checked
Timer bridge         │ NtQueryPerformanceCounter           │ Timing check patterns
Syscall bridge       │ SSDT entries for above calls        │ All of the above at once
```

### Virtual Breakpoints

Virtual breakpoints (implemented via EPT permission manipulation rather than INT3) are particularly valuable at bridge points because:
- They do not modify the target instruction stream (undetectable by checksum integrity checks)
- They fire at the hardware level before any software anti-debug can respond
- They can be made conditional on register state, allowing filtering to relevant invocations only

---

## Breakpoint Strategy Taxonomy

For reference, a complete taxonomy of breakpoint types relevant to DRM research:

### Software Breakpoints
- **INT3 (0xCC)**: Replaces target byte; detectable via checksum; triggers debug exception
- **INT1 (0xF1)**: Alternate single-step trap; less commonly detected than INT3

### Hardware Breakpoints
- **DR0–DR3 debug registers**: Up to 4 simultaneous breakpoints; execute, read, write, or I/O access
- **Limitation**: DR registers are accessible to the process itself — Denuvo actively checks them

### Hypervisor-Level Breakpoints
- **EPT breakpoints**: Set page to no-execute; VM exit fires on execution attempt; completely transparent to guest
- **MMIO traps**: Intercept memory-mapped I/O for device simulation

### Library Breakpoints
- Set at the entry point of a specific imported library function
- Useful for: `CreateFileW`, `RegQueryValueExW`, `DeviceIoControl`, `WinHttpSend`
- Detectable if the IAT has been resolved via direct syscalls (Denuvo v12+ does this for sensitive calls)

### Volume Breakpoints (I/O Breakpoints)
- Trigger on access to a specific physical disk sector or volume region
- Implemented via storage driver filter or hypervisor EPT on MMIO-mapped storage controller
- Useful for studying license token file access patterns

### Syscall Breakpoints
- Set at SSDT entries in the kernel; fire for every invocation of the syscall from any process
- Effective for capturing hardware query patterns without per-call hooking overhead

---

## OEP Recovery Research

Finding the **Original Entry Point (OEP)** of a protected binary remains a foundational challenge regardless of which analysis layer is used.

### Why OEP Matters

Denuvo's protection inserts a stub that runs first and performs:
1. Environment integrity checks
2. License validation
3. Decryption of protected code sections
4. Transfer of control to the real game code (OEP)

If OEP can be identified and execution captured at that point, the decrypted game code is fully present in memory and in a valid executable state.

### OEP Finding Approaches

| Approach | Description | Reliability vs. v15+ |
|----------|-------------|---------------------|
| **Import table reconstruction** | Locate calls to `GetProcAddress` post-decryption to find IAT rebuild | Medium — IAT may be rebuilt incrementally |
| **Stack unwind analysis** | Denuvo stub preserves original stack frame; OEP is a return target | Medium — stack cookies complicate this |
| **Heap spray timing** | OEP execution triggers allocation patterns measurable from hypervisor | Low — timing-dependent |
| **TLS callback analysis** | Check if OEP is invoked from a TLS callback chain | High — TLS callbacks are structurally predictable |
| **Exception handler pivot** | OEP is sometimes transferred to via SEH or VEH chain manipulation | Medium |
| **EPT write-then-execute monitoring** | Monitor page transitions; OEP page will be written (decrypted) then executed | High — hardware-level, non-invasive |

The EPT write-then-execute pattern is considered the most robust approach for modern Denuvo versions: the first execution of a previously write-only page is a strong indicator of OEP or a near-OEP location.

---

## CPUID / HWID / Syscall Extraction Tools

Accurate extraction of what hardware identifiers and syscalls a DRM system queries is essential baseline information for any research effort. Two notable open-source projects address this:

### mojtabafalleh/emulator

Repository: [https://github.com/mojtabafalleh/emulator](https://github.com/mojtabafalleh/emulator)

This emulator framework is designed to instrument and extract:
- **CPUID leaf responses**: Captures which CPUID leaves the target queries and what values it receives, enabling researchers to understand what CPU information Denuvo uses for environment validation
- **HWID sources**: Tracks hardware identifier collection — volume serials, MAC addresses, TPM data, SMBios strings
- **Syscall sequences**: Records the raw syscall numbers invoked, independently of the symbol names, which is important for analysis of direct-syscall patterns that bypass API-level hooks
- **Fingerprint assembly**: Observes how individual hardware data points are combined into the final hardware fingerprint that Denuvo uses for license binding

**Research value**: Provides a ground-truth baseline for what hardware data Denuvo actually reads, which is prerequisite information for building a spoofing or transparency layer.

### mojtabafalleh/emudbg

Repository: [https://github.com/mojtabafalleh/emudbg](https://github.com/mojtabafalleh/emudbg)

A companion debugging interface to the emulator above, providing:
- **Interactive inspection** of emulated state during execution
- **Breakpoint support** within the emulation context
- **Memory dump utilities** for capturing decrypted regions
- **Trace logging** of instruction sequences through critical code paths

**Research value**: Enables step-through analysis of DRM code within the emulator environment — particularly useful for tracing the fingerprint assembly logic and understanding conditional branches in the license validation path.

### Relationship Between the Two Projects

```
┌──────────────────────────────────────────────────┐
│             mojtabafalleh/emulator               │
│  Core emulation engine                           │
│  - CPU state management                          │
│  - CPUID/MSR interception                        │
│  - HWID source tracking                          │
│  - Syscall sequence recording                    │
└──────────────────────┬───────────────────────────┘
                       │ exposes debug API
                       ▼
┌──────────────────────────────────────────────────┐
│             mojtabafalleh/emudbg                 │
│  Debug frontend                                  │
│  - Interactive breakpoints                       │
│  - State inspection                              │
│  - Trace visualization                           │
│  - Memory capture                                │
└──────────────────────────────────────────────────┘
```

---

## Referenced Open-Source Projects

A consolidated reference table of externally cited projects relevant to this research direction:

| Project | URL | Primary Research Value |
|---------|-----|----------------------|
| **HV-PlugNPlay** | https://github.com/jcnnik/HV-PlugNPlay | Minimal hypervisor reference architecture for plug-and-play research extension |
| **kvc** | https://github.com/wesmar/kvc | Binary code comparison tool for differential analysis between game versions |
| **mojtabafalleh/emulator** | https://github.com/mojtabafalleh/emulator | CPUID, HWID, fingerprint, and syscall extraction framework |
| **mojtabafalleh/emudbg** | https://github.com/mojtabafalleh/emudbg | Debug interface for the above emulator |
| **HyperDbg** | https://github.com/HyperDbg/HyperDbg | Full-featured hypervisor-based debugger |
| **SimpleSvm** | https://github.com/tandasat/SimpleSvm | Minimal AMD-SVM hypervisor reference |

---

### Further Reading

- **Denuvo Analysis Blog**: [connorjaydunn.github.io/blog/posts/denuvo-analysis/](https://connorjaydunn.github.io/blog/posts/denuvo-analysis/) — Detailed technical walkthrough of Denuvo internals, protection layer structure, and observed anti-analysis techniques

---

*This document represents community research observations and architectural analysis. All referenced projects are open-source and publicly available. For educational and research use only.*
