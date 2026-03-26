# Repository Structure

This document describes the organization of the Hypervisor-Based DRM Bypass Research repository.

---

## Directory Layout

```
hypervisor-drm-research/
├── README.md                           # Main documentation and project overview
├── LICENSE                             # MIT license with educational disclaimer
├── STRUCTURE.md                        # This file - repository organization
│
├── docs/                               # Detailed technical documentation
│   ├── RING_ARCHITECTURE.md           # CPU privilege ring deep dive
│   ├── COMPARISON_MATRIX.md           # Bypass technique comparison tables
│   └── USER_MODE_EMULATOR.md          # User-mode emulator implementation guide
│
├── diagrams/                           # Technical architecture diagrams (SVG)
│   ├── drm_fingerprint_sources.svg    # Hardware fingerprinting attack surface
│   ├── drm_hypervisor_arms_race.svg   # Detection vs. evasion timeline
│   ├── ept_address_translation.svg    # EPT memory virtualization
│   └── vm_exit_entry_cycle.svg        # VM-Exit/VM-Entry flow
│
└── appendix/                           # Additional technical references
    └── TECHNICAL_APPENDIX.md          # CPU instructions, EPT details, KUSER structure
```

---

## File Descriptions

### Root Directory

| File | Size | Description |
|------|------|-------------|
| **README.md** | ~80 KB | Comprehensive project overview, executive summary, technical implementation details, architecture diagrams, security implications, alternative approaches, and references |
| **LICENSE** | ~4 KB | MIT license with educational use disclaimer, legal notices, and attribution guidelines |
| **STRUCTURE.md** | This file | Repository organization and navigation guide |

---

### `/docs` - Technical Documentation

#### RING_ARCHITECTURE.md (~70 KB)
**CPU Privilege Ring Deep Dive**

Content:
- Ring -2 (SMM/UEFI): System Management Mode, UEFI firmware context, EfiGuard capabilities
- Ring -1 (Hypervisor): AMD SVM and Intel VMX architecture, VMCB/VMCS structures, interception handlers
- Ring 0 (Kernel): Windows kernel architecture, KUSER_SHARED_DATA, kernel callbacks, DSE bypass
- Ring 1-2 (Historical): Unused rings in modern OS
- Ring 3 (User Mode): Application execution, DLL injection techniques, IAT/inline hooking, VEH
- Ring transitions and performance costs
- Security boundaries and attack surface analysis

Target Audience: Researchers studying hardware virtualization and OS security

---

#### COMPARISON_MATRIX.md (~50 KB)
**DRM Bypass Technique Comparison**

Content:
- Approach comparison overview (UEFI bootkit, hypervisor, kernel driver, user-mode)
- Technical capability matrices (instruction interception, OS-level coverage)
- Denuvo version effectiveness timeline (v1-v19, 2014-2026)
- Platform compatibility (Windows versions, security features, CPU architectures)
- Detection risk analysis by anti-cheat system
- Implementation complexity estimates (development time, skill requirements, code metrics)
- Cost-benefit analysis (resources, maintenance burden, risk vs. reward)
- Recommended approaches by use case

Target Audience: Security researchers evaluating bypass methodologies

---

#### USER_MODE_EMULATOR.md (~65 KB)
**User-Mode Emulator Implementation Guide**

Content:
- Strategic rationale (why user-mode vs. hypervisor)
- Architecture overview (component hierarchy, execution flow)
- Implementation phases:
  - Phase 1: Reverse engineering the target game
  - Phase 2: Emulator components (proxy DLL, API hooking, instruction patching, VEH, PEB unlinking)
  - Phase 3: Integration and deployment
- Performance considerations and optimization
- Detection evasion techniques
- Limitations vs. hypervisor approach
- Future directions (DBT, AI-assisted RE, signed kernel drivers)

Target Audience: Developers implementing DRM bypass tools, security researchers

---

### `/diagrams` - Technical Visualizations (SVG)

| File | Size | Description |
|------|------|-------------|
| **drm_fingerprint_sources.svg** | ~21 KB | Visual map of hardware fingerprinting sources used by DRM systems |
| **drm_hypervisor_arms_race.svg** | ~37 KB | Timeline showing evolution of DRM detection vs. hypervisor evasion (2014-2026) |
| **ept_address_translation.svg** | ~21 KB | Extended Page Tables (EPT) 4-level translation hierarchy diagram |
| **vm_exit_entry_cycle.svg** | ~17 KB | VM-Exit and VM-Entry instruction interception lifecycle |

**Format**: All diagrams are in SVG (Scalable Vector Graphics) format for maximum quality and editability.

**Usage**: Can be viewed in any modern web browser or vector graphics editor (Inkscape, Adobe Illustrator).

---

### `/appendix` - Technical References

#### TECHNICAL_APPENDIX.md (~45 KB)
**Low-Level Technical Reference**

Content:
- Appendix A: CPU Instruction Reference
  - CPUID instruction details (opcodes, important leaves, bit flags)
  - RDTSC/RDTSCP timing instructions
  - XGETBV extended control register
- Appendix B: Hypervisor Detection Techniques
  - CPUID-based detection
  - Timing-based detection
  - MSR-based detection
- Appendix C: Extended Page Tables (EPT) Deep Dive
  - EPT translation hierarchy (4-level page tables)
  - EPT entry structure (64-bit format)
  - Split-TLB attack implementation
- Appendix D: KUSER_SHARED_DATA Structure
  - Complete structure definition
  - Spoofing strategy
- Appendix E: Steam Emulation (Goldberg)
  - Steamworks API surface
  - Configuration file formats

Target Audience: Low-level systems programmers, kernel developers

---

## Navigation Guide

### For Quick Overview
Start with: **README.md** → Read Executive Summary and Table of Contents

### For Understanding CPU Rings
Read: **docs/RING_ARCHITECTURE.md** → Explains privilege levels and capabilities at each ring

### For Comparing Approaches
Read: **docs/COMPARISON_MATRIX.md** → Comprehensive comparison tables for decision-making

### For Implementation Details
Read: **docs/USER_MODE_EMULATOR.md** → Step-by-step guide with code examples

### For Low-Level Details
Read: **appendix/TECHNICAL_APPENDIX.md** → CPU instruction reference, EPT details, structures

### For Visual Learning
View: **diagrams/*.svg** → Architecture diagrams and flowcharts

---

## Document Conventions

### Code Examples
- C/C++ for kernel-mode and system programming
- Assembly (NASM syntax) for low-level operations
- Python for automation scripts
- Batch/PowerShell for Windows utilities

### Naming Conventions
- **Ring -2/-1/0/3**: CPU privilege levels
- **EPT/NPT**: Extended/Nested Page Tables
- **VMX/SVM**: Intel VT-x / AMD-V virtualization
- **VMCS/VMCB**: Virtual Machine Control Structure/Block
- **IAT/EAT**: Import/Export Address Table
- **VEH**: Vectored Exception Handler
- **DSE**: Driver Signature Enforcement
- **PatchGuard**: Windows Kernel Patch Protection
- **KUSER**: Kernel User Shared Data

### Diagram Conventions
- **Green boxes**: User-level components
- **Yellow boxes**: Kernel-level components
- **Red boxes**: Hypervisor/firmware components
- **Arrows**: Data flow or control flow
- **Dashed lines**: Optional or conditional paths

---

## File Sizes

Total repository size: **~400 KB** (excluding Git metadata)

Breakdown:
- Documentation (Markdown): ~310 KB
- Diagrams (SVG): ~96 KB
- License: ~4 KB

---

## Update History

- **2026-03-25**: Initial repository structure created
  - Added comprehensive README with technical analysis
  - Created ring architecture deep dive
  - Added comparison matrices for different approaches
  - Included user-mode emulator implementation guide
  - Added SVG diagrams from original research
  - Created technical appendix with low-level details

---

## Contributing

When adding new content, follow this structure:

1. **Documentation** → Place in `/docs` if it's a complete guide
2. **Diagrams** → Place in `/diagrams` as SVG format
3. **Reference Material** → Place in `/appendix` if it's supplementary
4. **Update this file** → Add new files to the directory layout above

---

## License

All content in this repository is licensed under the MIT License with Educational Use provisions.  
See [LICENSE](../LICENSE) for full details.

---

*Repository maintained for academic and security research purposes only.*
