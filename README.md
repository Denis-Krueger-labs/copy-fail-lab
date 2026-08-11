# Copy Fail Lab

> Controlled reproduction, detection, behavioral correlation, compensating control development, and vendor-patch validation for **CVE-2026-31431 (Copy Fail)** in an isolated Linux kernel research environment.

<p align="center">

![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04%20LTS-E95420?style=flat-square&logo=ubuntu&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-Kernel%20Research-9d4dff?style=flat-square&logo=linux&logoColor=white)
![Proxmox](https://img.shields.io/badge/Proxmox-VE-E57000?style=flat-square&logo=proxmox&logoColor=white)
![Detection](https://img.shields.io/badge/Detection-MORI-9d4dff?style=flat-square)
![Mitigation](https://img.shields.io/badge/MORI-v2.7-9d4dff?style=flat-square)
![Status](https://img.shields.io/badge/Status-Final%20Report-9d4dff?style=flat-square)

</p>

---

## Overview

This repository documents a controlled security research project investigating **CVE-2026-31431**, commonly referred to as **Copy Fail**.

The vulnerability affects the Linux kernel and can be abused by an unprivileged local user to modify page-cache-visible data associated with a privileged executable, ultimately resulting in local privilege escalation.

The objective of this project is not simply to execute a public proof of concept.

Instead, the laboratory follows the vulnerability through a complete defensive lifecycle:

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
broad compensating control
   ↓
compatibility analysis
   ↓
behavioral correlation
   ↓
shadow policy
   ↓
selective enforcement
   ↓
MORI regression testing
   ↓
MORI v2.7 lifecycle fix
   ↓
vendor remediation
   ↓
independent patched-kernel retest
   ↓
evidence freeze
   ↓
final report / presentation
```

Every phase is documented with command output, screenshots, cryptographic hashes, configuration files, implementation checkpoints, and reproducible evidence.

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
- Build and test an initial compensating control
- Measure the compatibility impact of that control
- Develop a more selective behavior-based compensating control
- Validate correlation logic using positive and negative controls
- Introduce shadow enforcement before active denial
- Enforce the selected behavior using BPF LSM
- Add structured deny telemetry
- Regression-test the compensating control
- Correct the discovered MORI correlation-lifecycle weakness
- Apply the vendor remediation
- Repeat the experiment against the patched system with MORI isolated
- Verify benign AF_ALG functionality remains available
- Preserve and verify the final evidence packages
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
████████████████████  MORI Guard v1
████████████████████  Compatibility Analysis
████████████████████  MORI v2 Behavioral Correlation
████████████████████  MORI v2 Shadow Policy
████████████████████  MORI v2 Selective Enforcement
████████████████████  Structured Deny Telemetry
████████████████████  MORI v2.7 Regression Fix
████████████████████  Vendor Patch Validation
████████████████████  Final Retest
░░░░░░░░░░░░░░░░░░░░  Final Report / Presentation
```

---

# Lab Environment

The experiment is performed inside an isolated Proxmox laboratory behind an OPNsense firewall.

| Component | Configuration |
|---|---|
| Hypervisor | Proxmox VE |
| Guest OS | Ubuntu Server 24.04 LTS |
| Virtualization | KVM / QEMU |
| Reference System | Patched Ubuntu reference VM |
| Vulnerable System | `copyfail-vuln` |
| Vulnerable Kernel | `6.8.0-116-generic` |
| Vendor-patched validation kernel | `6.8.0-137-generic` |
| Vendor kernel package version | `6.8.0-137.137` |
| Unprivileged Test User | `labuser` |
| Research / Administration User | `researcher` |
| Network | Isolated OPNsense laboratory |
| Snapshots | Used before destructive or state-changing phases |

A dedicated snapshot preserves the validated vulnerable system before vendor remediation:

```text
pre-vendor-patch-mori-guard
```

---

# Vulnerability Reproduction

The vulnerable system was reconstructed using the historical Ubuntu `6.8.0-116-generic` kernel.

The public Copy Fail proof of concept was executed as the deliberately unprivileged `labuser`.

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

while the VFS-visible representation of `/usr/bin/su` changed.

A direct read of the backing ext4 filesystem continued to return the original file hash, demonstrating that the observed modification was not equivalent to a conventional persistent file write.

Rebooting the vulnerable system restored the original VFS-visible file state.

The experiment deliberately stopped after proving local privilege escalation.

No persistence, credential theft, reverse shell, lateral movement, or unrelated post-exploitation activity was performed.

---

# MORI Monitor

To investigate defensive visibility, the project introduces **MORI Monitor**, an integrity watcher for privileged executables.

```text
 /\_/\
( •.• )   MORI: privileged binaries look normal.
 > ^ <
```

MORI maintains a protected known-good SHA-256 baseline for accessible root-owned SUID executables and periodically compares their current VFS-visible contents against that baseline.

During a successful Copy Fail attempt, MORI observed the modification of `/usr/bin/su`:

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

MORI Monitor is a **detection mechanism only**.

It does not prevent the vulnerability from being exploited.

---

# YARA Comparison

A small YARA experiment was added to contrast exact-sample identification with integrity-based detection.

An exact-hash YARA rule successfully identified the known laboratory copy of the Copy Fail proof of concept.

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

This does **not** demonstrate a limitation of YARA as a whole.

YARA can use strings, byte patterns, structural properties, and generalized conditions.

The experiment instead demonstrates the difference between:

```text
exact artifact identification
        vs.
security-relevant effect detection
```

---

# MORI Guard v1

The first custom compensating control is **MORI Guard v1**.

It prevents the vulnerable `algif_aead` kernel interface from being loaded through normal `modprobe` resolution while the vulnerable kernel is intentionally retained for laboratory testing.

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

The same proof of concept that previously produced a root shell was therefore unable to complete its exploitation chain.

MORI Guard v1 is explicitly treated as a **compensating control**, not as a fix for the underlying kernel defect.

---

## MORI Guard v1 Compatibility Impact

Blocking `algif_aead` also prevents legitimate applications from using that kernel interface.

A benign unprivileged AF_ALG AEAD bind was tested while MORI Guard v1 was active.

Result:

```text
EXPECTED: benign AEAD bind failed while MORI Guard is active
```

The result established the central limitation of v1:

```text
Copy Fail path blocked
        +
benign AEAD functionality blocked
```

The negative compatibility result motivated development of MORI v2.

---

# MORI v2

**MORI v2** explores whether Copy Fail-relevant behavior can be observed, correlated, and selectively denied without disabling AF_ALG AEAD entirely.

The implementation combines:

```text
BPF LSM
    +
fentry tracing
    +
BPF state maps
    +
userspace trust validation
    +
ring-buffer telemetry
```

The current validated research build is:

```text
MORI v2.7
```

---

## From False Positive to Selective Control

The first MORI v2 observer monitored non-root reads of root-owned SUID executables.

It immediately discovered a false positive:

```text
MORI Monitor
      |
      | periodic integrity hashing
      v
root-owned SUID read
      |
      v
MORI v2 alert
```

MORI had, effectively, detected herself.

Instead of suppressing the event using a hard-coded PID, UID, or process name, the trust model was developed incrementally.

The final monitor exemption verifies:

- dedicated service cgroup membership
- expected monitor path
- exact process argv entry
- root ownership
- regular-file status
- absence of group/world write permission
- known-good SHA-256

If trust verification fails, MORI still attaches but leaves the trust map empty.

---

# MORI v2 Behavioral Signals

The research control correlates several independently observable signals.

## AF_ALG AEAD Activity

A BPF LSM program attached to:

```text
lsm/socket_bind
```

observes AF_ALG socket-bind attempts whose algorithm type is:

```text
aead
```

Benign unprivileged:

```text
gcm(aes)
```

use was confirmed to remain functional when MORI Guard v1 was disabled and MORI v2 was operating.

## SUID-to-Pipe Splice Activity

A tracing program attached to:

```text
fentry/do_splice
```

observes splice activity involving:

```text
root-owned SUID file
        |
        v
pipe
```

The splice signal alone is **not** classified as malicious.

## Privileged-File Read

A BPF LSM program attached to:

```text
lsm/file_permission
```

observes non-root reads of root-owned SUID files.

---

# Cross-Hook Correlation

MORI uses BPF maps to share state between the independent programs.

```text
lsm/socket_bind
        |
        v
   aead_state


fentry/do_splice
        |
        v
 splice_state


       both
        |
        v
lsm/file_permission
        |
        v
 correlation decision
```

Testing demonstrated that state written by the `fentry/do_splice` program was visible to the `file_permission` LSM hook during the same splice operation.

A controlled combined test produced:

```text
AEAD-ARM
SPLICE-ARM
TRIPLE-CORRELATED
```

while the individual benign operations still succeeded.

---

# MORI v2 Shadow Policy

Before enabling active enforcement, the combined policy was operated in shadow mode.

A matching event produced:

```text
WOULD-DENY-AEAD-SPLICE-SUID
```

while preserving the original LSM return value.

Negative controls demonstrated:

```text
AEAD only
    -> no WOULD-DENY

SUID -> pipe splice only
    -> no WOULD-DENY

AEAD + SUID -> pipe splice + privileged read
    -> WOULD-DENY
```

All operations remained permitted during the shadow-policy stage.

---

# MORI v2 Selective Enforcement

After the shadow-policy behavior was validated, MORI v2 was changed to return:

```text
-EPERM
```

when the selected correlated condition was reached.

A controlled enforcement test produced:

```text
aead_bind=success
splice=blocked errno=1 message=Operation not permitted
```

with the matching kernel sequence:

```text
AEAD-ARM
SPLICE-ARM
DENY-AEAD-SPLICE-SUID
```

The resulting tested policy boundary is:

```text
AEAD activity only
    -> allowed

SUID -> pipe splice only
    -> allowed

recent AEAD activity
    +
root-owned SUID -> pipe splice
    +
matching privileged-file read
    -> denied with EPERM
```

This is **behavior-based correlation**, not attacker-intent detection.

---

# Structured Deny Telemetry

MORI v2.6.1 introduced a BPF ring buffer for structured deny events.

A deny event contains:

```text
timestamp
TGID
UID
event type
```

The security decision and telemetry path are deliberately independent.

```text
policy match
      |
      +----> -EPERM
      |
      `----> ring-buffer event
```

Failure of userspace telemetry does not weaken enforcement.

An end-to-end test demonstrated matching:

```text
kernel:
DENY-AEAD-SPLICE-SUID

MORI userspace:
MORI event: DENY tgid=<TGID> uid=1001

test process:
splice=blocked errno=1
```

---

# Judgment Cat

MORI v2.6.2 added an optional attacker-facing notification layer.

When a deny event is received, MORI attempts to locate an interactive terminal for the originating process through:

```text
/proc/<tgid>/fd/
```

Candidate descriptors are independently opened and verified using:

```text
isatty()
```

before any message is written.

If no interactive terminal exists, notification is skipped.

Notification failure does not change enforcement.

The message is:

```text
 /\_/\
( Ò.Ó )
 > ^ <

MORI: no.
MORI: bad.
MORI: I'm disappointed in you.
```

The ASCII cat is presentation.

The actual security mechanism remains the BPF LSM `EPERM` decision.

---

# MORI v2.7 Lifecycle Regression Fix

Additional regression testing of v2.6.2 identified a same-TGID timing/lifecycle weakness in the experimental correlation model.

The test sequence demonstrated that correlation state could expire before the later protected operation in the tested delayed sequence.

The issue was retained as evidence rather than hidden, and a v2.7 lifecycle correction was developed and regression-tested.

The final v2.7 validation demonstrated:

```text
cross-TGID activity
    -> remains isolated

tested same-TGID expiry sequence
    -> no longer bypasses the selected enforcement path

final Python CopyFail PoC
    -> denied

independent C CopyFail PoC
    -> denied

post-test privileged target validation
    -> clean
```

The final v2.7 source and build artifacts were frozen and independently hashed after validation.

---

# MORI v2 Development Progression

```text
v2.1
SUID-read observation
        |
        v
v2.1.1
trusted monitor filtering
        |
        v
v2.1.2
authenticated monitor trust
        |
        v
v2.2
AF_ALG AEAD observation
        |
        v
v2.3
same-process temporal correlation
        |
        v
v2.4
splice observation
cross-hook correlation
triple correlation
        |
        v
v2.5
shadow WOULD-DENY policy
negative controls
        |
        v
v2.6
actual EPERM enforcement
        |
        v
v2.6.1
structured ring-buffer telemetry
        |
        v
v2.6.2
attacker-facing TTY notification
        |
        v
v2.7
correlation lifecycle regression fix
final Python + independent C validation
artifact freeze + provenance
```

---

# MORI v2 Limitations

MORI v2 remains an experimental research control.

Important limitations include:

- correlation windows and lifecycle rules are specific to the tested research design
- AEAD state is keyed at process/TGID scope
- splice state is keyed at process/TGID scope
- process-level correlation does not establish precise thread-level causality
- `socket_bind` observes an AEAD bind attempt before successful completion is independently known
- SUID-to-pipe splice activity is not inherently malicious
- legitimate software reproducing the same correlated sequence may be denied
- the control was designed around the behavior investigated in this Copy Fail laboratory
- the validation scope is limited to the tested environment and PoC implementations

MORI v2 is therefore not presented as a universal Linux exploit-prevention system.

The vendor kernel remediation remains the preferred fix.

---

# Phase 05 — Vendor Patch Validation

After MORI v2.7 validation was completed, the laboratory moved to the vendor-remediated kernel.

The purpose of Phase 05 was to answer a separate question:

> Does the vendor-remediated kernel prevent the previously reproduced Copy Fail behavior without relying on MORI, while preserving the benign AF_ALG functionality exercised by the laboratory?

The patched validation environment used:

```text
Linux:   6.8.0-137-generic
Package: linux-image-6.8.0-137-generic
Version: 6.8.0-137.137
```

Before active retesting, MORI was explicitly isolated from the enforcement path.

Validation confirmed:

```text
MORI process:           absent
MORI integrity service: inactive
MORI BPF pins:          absent
```

Benign AF_ALG AEAD functionality remained operational:

```text
socket(AF_ALG):                 PASS
bind(("aead", "gcm(aes)")):     PASS
accept():                       PASS
```

The Python Copy Fail PoC and an independently compiled C implementation were then tested against the patched kernel.

For both tested implementations:

```text
unauthorized privilege transition: not observed
/usr/bin/su integrity:              preserved
normal su authentication:           preserved
```

The baseline and final SHA-256 of `/usr/bin/su` matched:

```text
c74311fe5636b7d7f9a56239fa8adeeab12ba86fe7d41b91afa85bf9bbdae78b
```

The Phase 05 evidence package contains 5 machine-readable text artifacts and 13 screenshots. All 18 evidence objects were verified against `PUBLIC-SHA256SUMS.txt`.

See:

[`evidence/05-vendor-patch-validation/README.md`](evidence/05-vendor-patch-validation/README.md)

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
│   │   ├── artifacts/                  # MORI Guard v1
│   │   ├── screenshots/                # MORI Guard v1 + final v2.7 validation evidence
│   │   └── mori-v2/
│   │       ├── artifacts/
│   │       │   ├── checkpoints/
│   │       │   │   ├── v2.2.0/
│   │       │   │   ├── v2.3.0/
│   │       │   │   ├── v2.4-splice-probe/
│   │       │   │   ├── v2.4.0/
│   │       │   │   ├── v2.5.0/
│   │       │   │   ├── v2.6.0/
│   │       │   │   ├── v2.6.1/
│   │       │   │   └── v2.6.2/
│   │       │   └── current/
│   │       │       ├── build/
│   │       │       ├── source/
│   │       │       ├── PROVENANCE.txt
│   │       │       └── PROVENANCE.sha256
│   │       ├── screenshots/
│   │       ├── PUBLIC-SHA256SUMS.txt
│   │       └── README.md
│   │
│   └── 05-vendor-patch-validation/
│       ├── artifacts/
│       ├── screenshots/
│       ├── PUBLIC-SHA256SUMS.txt
│       └── README.md
│
├── report/
│   ├── main.tex
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

---

# MORI v2 Evidence Package

The MORI v2 package preserves historical implementation checkpoints for:

```text
v2.2.0
v2.3.0
v2.4-splice-probe
v2.4.0
v2.5.0
v2.6.0
v2.6.1
v2.6.2
```

The currently validated MORI v2.7 implementation is preserved under:

```text
evidence/04-custom-mitigation/mori-v2/artifacts/current/
```

The current package separates:

```text
source/
build/
PROVENANCE.txt
PROVENANCE.sha256
```

The tested v2.7 executable is:

```text
mori_observer.v2.7
```

with SHA-256:

```text
7fe7b609b90e164f3ae4a9c025363399a8a63bf2a4338db2ecc62cfd2682d039
```

The provenance record itself was independently verified after transfer into the repository.

---

# Phase 05 Evidence Package

The vendor-patch validation package contains:

```text
Raw text artifacts:  5
Screenshots:        13
Total evidence:     18
```

The evidence manifest covers the raw artifacts and screenshots while intentionally excluding the editable README.

The complete package is documented at:

[`evidence/05-vendor-patch-validation/`](evidence/05-vendor-patch-validation/)

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
verify manifest
        ↓
commit
```

Public evidence is reviewed for infrastructure-specific or sensitive information before publication.

Exact internal network addressing, machine identifiers, credentials, tokens, and other unnecessary environmental details are not intentionally published.

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

The project deliberately preserves:

- failed experiments
- false positives
- compatibility failures
- negative controls
- intermediate implementation checkpoints
- discovered weaknesses in the custom control
- regression tests for subsequent fixes

rather than only publishing successful final results.

Observed behavior is documented directly, while explanations that depend on kernel implementation details are validated against upstream or vendor sources before being treated as conclusions.

---

# Defensive Layers

The project deliberately distinguishes between several defensive mechanisms.

| Layer | Purpose |
|---|---|
| YARA exact-sample rule | Identify the known laboratory artifact |
| MORI Monitor | Detect integrity changes to privileged targets |
| MORI Guard v1 | Broadly restrict access to the tested vulnerable interface |
| MORI v2.7 | Correlate Copy Fail-relevant behavior and selectively deny the tested combination |
| Vendor kernel update | Correct the underlying vulnerability in the validated long-term remediation path |

These mechanisms are complementary rather than interchangeable.

The final laboratory progression is:

```text
detect
  ↓
broadly mitigate
  ↓
measure compatibility cost
  ↓
build selective compensating control
  ↓
regression-test the control
  ↓
apply vendor remediation
  ↓
validate patched behavior independently
```

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
- eBPF
- BPF LSM
- BTF / CO-RE
- fentry tracing
- cross-program BPF state
- behavioral correlation
- temporal state and lifecycle design
- regression testing
- shadow enforcement
- compensating controls
- compatibility testing
- structured security telemetry
- defense in depth
- vendor remediation
- evidence preservation
- reproducible technical documentation

The goal is to understand the vulnerability and its defensive implications rather than treating a public exploit as a black box.

---

# Safety and Scope

All experiments are performed:

- inside an isolated virtual laboratory
- against systems owned and controlled by the author
- using deliberately created unprivileged test accounts
- exclusively for security research and educational purposes

Privilege escalation is considered proven once the controlled test user obtains root identity.

No persistence, credential harvesting, lateral movement, reverse shells, or unauthorized targets are involved.

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

✓ MORI Guard v1
✓ blocked Copy Fail retest
✓ MORI Guard compatibility analysis

✓ MORI v2 SUID observation
✓ MORI self-false-positive analysis
✓ authenticated monitor trust
✓ AF_ALG AEAD observation
✓ benign AEAD compatibility validation
✓ splice observation
✓ cross-hook BPF state sharing
✓ temporal correlation
✓ triple correlation
✓ shadow policy
✓ AEAD-only negative control
✓ splice-only negative control
✓ selective EPERM enforcement
✓ structured ring-buffer telemetry
✓ attacker-facing TTY notification

✓ MORI v2.6.2 regression validation
✓ same-TGID expiry weakness reproduced
✓ MORI v2.7 lifecycle correction
✓ cross-TGID isolation validation
✓ final Python PoC denied under MORI v2.7
✓ independent C PoC denied under MORI v2.7
✓ MORI v2.7 source/build artifacts frozen
✓ MORI v2.7 provenance verified

✓ vendor-patched kernel identified
✓ MORI isolated from vendor-patch validation
✓ benign AF_ALG AEAD control passed
✓ Python Copy Fail retest failed to reproduce privilege escalation
✓ independent C Copy Fail retest failed to reproduce privilege escalation
✓ final /usr/bin/su integrity preserved
✓ Phase 05 evidence package verified 18/18
```

Current phase:

```text
→ final technical report
```

Next:

```text
final report
      ↓
technical presentation
      ↓
publication-ready repository review
```

---

# Related Work

This laboratory forms part of a broader security research and home-lab environment and is being developed as the practical component of a cybersecurity final project.
