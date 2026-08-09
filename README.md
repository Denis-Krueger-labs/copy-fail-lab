# Copy Fail Lab

> Controlled reproduction, detection, and mitigation of **CVE-2026-31431 (Copy Fail)** in an isolated Linux kernel research environment.

<p align="center">

![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04%20LTS-E95420?style=flat-square&logo=ubuntu&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-Kernel%20Research-9d4dff?style=flat-square&logo=linux&logoColor=white)
![Proxmox](https://img.shields.io/badge/Proxmox-VE-E57000?style=flat-square&logo=proxmox&logoColor=white)
![Detection](https://img.shields.io/badge/Detection-MORI-9d4dff?style=flat-square)
![Status](https://img.shields.io/badge/Status-Vendor%20Patch%20Validation-9d4dff?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-4b4453?style=flat-square)

</p>

---

## Overview

This repository documents a controlled security research project investigating
**CVE-2026-31431**, commonly referred to as **Copy Fail**.

The vulnerability affects the Linux kernel and can be abused by an
unprivileged local user to modify page-cache-backed data associated with a
privileged executable, ultimately resulting in local privilege escalation.

The objective of this project is not simply to execute a public proof of
concept.

Instead, the laboratory follows the vulnerability through its complete
defensive lifecycle:

```text
research
   ↓
baseline
   ↓
vulnerable kernel reconstruction
   ↓
controlled reproduction
   ↓
observable system effect
   ↓
custom detection
   ↓
signature comparison
   ↓
custom compensating control
   ↓
vendor remediation
   ↓
final retest
```

Every phase is documented with command output, screenshots, cryptographic
hashes, configuration files, and reproducible evidence.

---

## Project Objectives

- Build an isolated Linux kernel research environment
- Establish and preserve a clean reference baseline
- Reconstruct a historically vulnerable Ubuntu kernel
- Understand the Copy Fail exploitation chain
- Reproduce the vulnerability using an unprivileged user
- Validate privilege escalation without persistence or unrelated post-exploitation
- Investigate the page-cache-visible modification caused by the exploit
- Identify useful defensive observables
- Build a custom integrity detector
- Compare integrity-based detection with exact-sample YARA detection
- Build and test a custom compensating control
- Measure the compatibility impact of that control
- Apply the vendor remediation
- Repeat the experiment against the patched system
- Produce a reproducible technical report and presentation

---

# Research Progress

```text
████████████████████  Vulnerability Research
████████████████████  Clean Reference Baseline
████████████████████  Vulnerable Kernel Reconstruction
████████████████████  Vulnerability Analysis
████████████████████  Controlled Reproduction
████████████████████  Privilege Escalation Validation
████████████████████  MORI Integrity Detection
████████████████████  YARA Detection Comparison
████████████████████  MORI Guard Compensating Control
░░░░░░░░░░░░░░░░░░░░  Vendor Patch Validation
░░░░░░░░░░░░░░░░░░░░  Final Retest
░░░░░░░░░░░░░░░░░░░░  Final Report / Presentation
```

---

# Lab Environment

The experiment is performed inside an isolated Proxmox laboratory behind an
OPNsense firewall.

| Component | Configuration |
|-----------|---------------|
| Hypervisor | Proxmox VE |
| Guest OS | Ubuntu Server 24.04 LTS |
| Virtualization | KVM / QEMU |
| Reference System | Patched Ubuntu reference VM |
| Vulnerable System | `copyfail-vuln` |
| Vulnerable Kernel | `6.8.0-116-generic` |
| Unprivileged Test User | `labuser` |
| Research / Administration User | `researcher` |
| Network | Isolated OPNsense laboratory |
| Snapshots | Used before destructive or state-changing phases |

A dedicated snapshot preserves the validated vulnerable system before vendor
remediation:

```text
pre-vendor-patch-mori-guard
```

---

# Vulnerability Reproduction

The vulnerable system was reconstructed using the historical Ubuntu
`6.8.0-116-generic` kernel.

The public Copy Fail proof of concept was executed as the deliberately
unprivileged `labuser`.

Before exploitation:

```text
uid=1001(labuser)
```

The privileged target `/usr/bin/su` had the known-good SHA-256 value:

```text
c74311fe5636b7d7f9a56239fa8adeeab12ba86fe7d41b91afa85bf9bbdae78b
```

Successful reproduction resulted in:

```text
uid=0(root)
```

while the page-cache-visible representation of `/usr/bin/su` changed.

A direct read of the backing ext4 filesystem continued to return the original
file hash, demonstrating that the observed modification was not equivalent to
a conventional persistent file write.

Rebooting the vulnerable system restored the original VFS-visible file state.

The experiment deliberately stopped after proving local privilege escalation.
No persistence, credential theft, reverse shell, or unrelated post-exploitation
activity was performed.

---

# MORI Monitor

To investigate defensive visibility, the project introduces **MORI Monitor**,
a small integrity watcher for privileged executables.

```text
 /\_/\
( •.• )   MORI: privileged binaries look normal.
 > ^ <
```

MORI maintains a protected known-good SHA-256 baseline for accessible
root-owned SUID executables and periodically compares their current
VFS-visible contents against that baseline.

During a successful Copy Fail attempt, MORI observed the modification of
`/usr/bin/su`:

```text
 /\_/\
( Ò.Ó )   MORI: INTEGRITY VIOLATION.
 > ^ <
```

The detector identified the security-relevant effect without depending on:

- the proof-of-concept filename
- the exploit's own file hash
- a specific process name
- the exploit source code

MORI Monitor is a **detection mechanism only**. It does not prevent the
vulnerability from being exploited.

---

# YARA Comparison

A small YARA experiment was added to contrast exact-sample identification with
integrity-based detection.

An exact-hash YARA rule successfully identified the known laboratory copy of
the Copy Fail proof of concept.

Original sample:

```text
SHA-256:
d401e7d1c00605749d6c617ace73ab20a762b72e41c2e1590331596e38219a61

Result:
MATCH
```

A private test copy was then modified by appending a single trailing newline.

```text
731 bytes → 732 bytes
```

No exploit logic was changed and the modified sample was not executed.

The new SHA-256 became:

```text
a567d09b15f6e4440e70c9f2aa8edec8ed59f53301952df05c719aa3911687f9
```

The exact-hash YARA rule no longer matched.

This does **not** demonstrate a limitation of YARA as a whole. YARA can use
strings, byte patterns, structural properties, and more generalized
conditions.

The experiment instead demonstrates the difference between:

```text
exact artifact identification
        vs.
security-relevant effect detection
```

---

# MORI Guard

The project also implements a custom compensating control called
**MORI Guard**.

MORI Guard prevents the vulnerable `algif_aead` kernel interface from being
loaded through normal `modprobe` resolution while the vulnerable kernel is
intentionally retained for laboratory testing.

```text
            ⁺‧₊˚ ཐི⋆♱⋆ཋྀ ˚₊‧⁺

 /\_/\
( Ò.Ó )   MORI GUARD
 > ^ <

One of my trusted moths has informed me
that you are touching my binaries.

I do not share my binaries.
They are mine.

Begone.
You are scaring the moths.
```

The control redirects requests for `algif_aead` through a custom blocker:

```text
install algif_aead /usr/local/sbin/mori-block-algif-aead
```

During the mitigated Copy Fail retest:

```text
kernel:               6.8.0-116-generic
attacker:             uid=1001(labuser)
algif_aead:           blocked
PoC result:           failure
privilege escalation: none
/usr/bin/su:          unchanged
MORI integrity alert: none
```

The same proof of concept that previously produced a root shell was therefore
unable to complete its exploitation chain.

MORI Guard is explicitly treated as a **compensating control**, not as a fix
for the underlying kernel defect.

---

## Compatibility Impact

Blocking `algif_aead` also prevents legitimate applications from using that
kernel interface.

A benign unprivileged AF_ALG AEAD bind was tested while MORI Guard was active.

Result:

```text
EXPECTED: benign AEAD bind failed while MORI Guard is active
```

This demonstrates the primary tradeoff of the compensating control:

```text
reduced attack surface
        ↕
reduced functionality
```

The vendor kernel patch remains the preferred remediation.

---

# Repository Structure

```text
copy-fail-lab/
│
├── evidence/
│   ├── 00-baseline/
│   │
│   ├── 01-vulnerability-validation/
│   │
│   ├── 02-reproduction/
│   │
│   ├── 03-detection/
│   │   └── yara-comparison/
│   │
│   ├── 04-custom-mitigation/
│   │
│   ├── 05-patched/                 # upcoming
│   │
│   └── 06-final-retest/            # upcoming
│
├── report/
│   ├── main.tex
│   │
│   └── sections/
│       ├── 01-research.tex
│       ├── 02-lab-setup.tex
│       ├── 03-clean-baseline.tex
│       ├── 04-vulnerability-analysis.tex
│       └── ...
│
├── references/
│
└── README.md
```

Evidence directories contain combinations of:

```text
README.md
PUBLIC-SHA256SUMS.txt
artifacts/
screenshots/
```

where appropriate.

---

# Evidence Integrity

Evidence is preserved using a simple chain-of-custody workflow:

```text
collect raw evidence
        ↓
hash raw evidence
        ↓
preserve private original
        ↓
create sanitized public copy
        ↓
hash public evidence
        ↓
generate PUBLIC-SHA256SUMS.txt
        ↓
commit
```

Public evidence is reviewed for infrastructure-specific or sensitive
information before publication.

Exact internal network addressing, machine identifiers, credentials, tokens,
and other unnecessary environmental details are not intentionally published.

The proof-of-concept itself is also not redistributed in this repository.

---

# Research Methodology

The project follows an experiment-driven approach.

Each phase attempts to answer four questions:

```text
Why is this test being performed?

What exactly is being tested?

What was observed?

What does the observation mean?
```

Evidence and interpretation are kept separate wherever possible.

Observed behavior is documented directly, while explanations that depend on
kernel implementation details are validated against upstream or vendor
sources before being treated as conclusions.

---

# Defensive Layers

The project deliberately distinguishes between several defensive mechanisms.

| Layer | Purpose |
|------|---------|
| YARA exact-sample rule | Identify a known artifact |
| MORI Monitor | Detect integrity changes to privileged targets |
| MORI Guard | Prevent access to the tested vulnerable interface |
| Vendor kernel update | Correct the underlying vulnerability |

These mechanisms are complementary rather than interchangeable.

---

# Learning Goals

This project focuses on practical understanding of:

- Linux kernel security
- Local privilege escalation
- AF_ALG and kernel crypto interfaces
- Page cache behavior
- SUID attack surface
- Vulnerability reproduction
- Security research methodology
- Integrity monitoring
- Detection engineering
- Signature-based detection
- Compensating controls
- Defense in depth
- Vendor remediation
- Evidence preservation
- Reproducible technical documentation

The goal is to understand the vulnerability and its defensive implications
rather than treating a public exploit as a black box.

---

# Safety and Scope

All experiments are performed:

- inside an isolated virtual laboratory
- against systems owned and controlled by the author
- using a deliberately created unprivileged test account
- exclusively for security research and educational purposes

Privilege escalation is considered proven once the controlled test user
obtains root identity.

No persistence, credential harvesting, lateral movement, reverse shells, or
unauthorized targets are involved.

---

# Current Status

Completed:

```text
✓ vulnerability research
✓ clean reference baseline
✓ vulnerable kernel reconstruction
✓ controlled Copy Fail reproduction
✓ root validation
✓ page-cache / backing-filesystem comparison
✓ privileged target analysis
✓ MORI Monitor
✓ live Copy Fail detection
✓ YARA exact-sample comparison
✓ MORI Guard
✓ blocked Copy Fail retest
✓ compensating-control compatibility test
```

Current phase:

```text
→ vendor remediation
```

Next:

```text
vendor-patched kernel
        ↓
repeat controlled test
        ↓
compare vulnerable / mitigated / patched behavior
        ↓
final report
        ↓
technical presentation
```

---

# Related Work

This laboratory forms part of a broader security research and home-lab
environment and is being developed as the practical component of a
cybersecurity final project.

---

## License

Released under the MIT License.

Research artifacts, third-party software, vulnerability information, and
referenced external material remain subject to their respective licenses and
terms.
