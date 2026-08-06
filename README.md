# Copy Fail Lab

> A documented reproduction, analysis, and mitigation study of the Linux kernel **Copy Fail** vulnerability inside an isolated Proxmox home lab.

<p align="center">

![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04%20LTS-E95420?style=flat-square&logo=ubuntu&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-Kernel%20Research-9d4dff?style=flat-square&logo=linux&logoColor=white)
![Proxmox](https://img.shields.io/badge/Proxmox-VE-E57000?style=flat-square&logo=proxmox&logoColor=white)
![Status](https://img.shields.io/badge/Status-In%20Progress-9d4dff?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-4b4453?style=flat-square)

</p>

---

## Overview

This repository documents the complete lifecycle of reproducing the **Copy Fail** Linux kernel vulnerability inside a controlled virtual laboratory.

Rather than simply executing a public exploit, the objective is to understand **why** the vulnerability exists, how it can be reproduced safely, how privilege escalation occurs, and how applying vendor patches changes the system's behavior.

Every step is documented to make the research reproducible and educational.

---

## Objectives

- Build an isolated Linux kernel research environment
- Establish a reproducible baseline
- Document every configuration step
- Understand the underlying vulnerability
- Reproduce the privilege escalation
- Validate exploit success
- Apply vendor patches
- Verify mitigation
- Produce a technical presentation

---

## Research Progress

```text
██████████░░░░░░░░░░  Clean Baseline
░░░░░░░░░░░░░░░░░░░░  Vulnerable Kernel
░░░░░░░░░░░░░░░░░░░░  Vulnerability Analysis
░░░░░░░░░░░░░░░░░░░░  Exploit Reproduction
░░░░░░░░░░░░░░░░░░░░  Root Validation
░░░░░░░░░░░░░░░░░░░░  Mitigation
░░░░░░░░░░░░░░░░░░░░  Documentation
░░░░░░░░░░░░░░░░░░░░  Final Presentation
```

---

# Lab Environment

| Component | Configuration |
|-----------|---------------|
| Hypervisor | Proxmox VE |
| Guest OS | Ubuntu Server 24.04 LTS |
| Hostname | copyfail01 |
| User | researcher |
| Network | Isolated OPNsense laboratory |
| Virtualization | KVM |
| Snapshots | Used throughout research |

---

# Repository Structure

```text
copy-fail-lab/

├── docs/
│   ├── 01-research.md
│   ├── 02-lab-setup.md
│   ├── 03-clean-baseline.md
│   ├── 04-vulnerability-analysis.md
│   ├── 05-reproduction.md
│   ├── 06-mitigation.md
│   └── 07-lessons-learned.md
│
├── evidence/
│   ├── screenshots/
│   ├── command-output/
│   ├── hashes/
│   └── logs/
│
├── presentation/
│   ├── slides/
│   ├── diagrams/
│   └── script.md
│
├── references/
│   ├── advisories.md
│   └── papers.md
│
└── README.md
```

---

# Documentation

| Step | Description |
|------|-------------|
| 01 | Vulnerability research |
| 02 | Building the lab |
| 03 | Baseline documentation |
| 04 | Understanding Copy Fail |
| 05 | Reproducing the vulnerability |
| 06 | Applying vendor fixes |
| 07 | Lessons learned |

---

# Learning Goals

This project focuses on understanding

- Linux kernel internals
- Privilege escalation
- Vulnerability validation
- Security research methodology
- Defensive mitigation
- Reproducible documentation
- Responsible experimentation

rather than treating public exploits as black boxes.

---

# Safety

All experiments are performed

- inside an isolated virtual network
- on systems owned by the author
- exclusively for educational purposes

No unauthorized systems were targeted during this research.

---

# Related Projects

- Home Lab
- Active Directory Lab
- Security Research Collection
- Harvard CS50 Cybersecurity Final Project

---

# Current Status

The laboratory has been deployed and the initial Ubuntu installation has been completed.

The next phase is documenting the clean baseline before intentionally reproducing the vulnerability.

---

## License

Released under the MIT License.
