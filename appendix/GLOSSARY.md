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

*Full details in TECHNICAL_APPENDIX.md*
