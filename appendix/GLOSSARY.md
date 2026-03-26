# Glossary of Technical Terms

**Quick reference for DRM bypass and virtualization terminology.**

## CPU & Virtualization
- **CPUID**: Processor identification instruction
- **RDTSC**: Read timestamp counter for timing
- **EPT/NPT**: Extended/Nested Page Tables (memory virtualization)
- **VMX/SVM**: Intel/AMD virtualization extensions
- **VM-Exit**: Guest-to-hypervisor transition
- **MSR**: Model-Specific Register (Ring 0 only)

## Windows Security
- **DSE**: Driver Signature Enforcement
- **PatchGuard**: Kernel Patch Protection
- **VBS**: Virtualization-Based Security
- **HVCI**: Hypervisor-Protected Code Integrity
- **KUSER_SHARED_DATA**: Kernel shared memory at 0x7FFE0000

## DRM Terms
- **Denuvo**: Anti-tamper protection system
- **MBA**: Mutated Bytecode Architecture (Denuvo VM)
- **Hardware Fingerprinting**: Unique machine ID generation
- **License Token**: Hardware-bound activation file

## Reverse Engineering
- **IAT Hooking**: Import Address Table interception
- **VEH**: Vectored Exception Handler
- **Inline Patching**: Direct code modification
- **Trampoline**: Hook preservation stub
- **OEP**: Original Entry Point — the real entry point of an executable before any protection stub runs
- **EPT Breakpoint**: Hypervisor-level breakpoint set by removing page execute permissions; transparent to guest
- **Protocol Bridge**: An observable OS boundary that DRM must cross (network, registry, volume, WMI, syscall)
- **Binary Differential Analysis**: Comparing two versions of a binary to isolate added/changed code regions
- **Volume Breakpoint**: Breakpoint triggered by access to a specific disk sector or volume region
- **Library Breakpoint**: Breakpoint placed at the entry of a specific imported library function
- **Syscall Breakpoint**: Hook placed at a kernel SSDT entry; fires for all invocations of that syscall
- **Direct Syscall**: Invoking a kernel syscall by number directly, bypassing all API-layer hooks
- **HWID Fingerprint**: Composite unique identifier assembled from multiple hardware sources
- **VM Transparency**: The degree to which a hypervisor environment is indistinguishable from bare metal
- **RDTSC Drift**: Measurable timing difference in `RDTSC` reads caused by VM-exit latency

*Full details in TECHNICAL_APPENDIX.md and DENUVO_VERSION_STRATEGY.md*
