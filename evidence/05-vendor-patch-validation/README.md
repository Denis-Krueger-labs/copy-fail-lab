# Phase 05  Vendor Patch Validation

## Objective

Phase 05 validates the vendor-remediated Ubuntu kernel against the CopyFail proof-of-concept paths used throughout this laboratory.

The purpose of this phase is deliberately narrower than the custom mitigation work in Phase 04:

- confirm that the patched kernel no longer exhibits the previously reproduced CopyFail privilege-escalation behavior,
- demonstrate that the result is independent of MORI,
- verify that benign AF_ALG AEAD functionality remains available,
- confirm that the controlled SUID target remains intact before and after retesting,
- preserve provenance for the independent C PoC used as a second implementation path.

The conclusions in this directory apply to the tested environment and the tested PoC implementations. They are not intended as a universal statement about every possible variant of the vulnerability.

---

## Test Environment

| Property | Value |
|---|---|
| Operating system | Ubuntu 24.04.2 LTS |
| Kernel | Linux 6.8.0-137-generic |
| Kernel package | linux-image-6.8.0-137-generic |
| Package version | 6.8.0-137.137 |
| Primary SUID target | /usr/bin/su |
| Primary test identity | researcher |
| Secondary test identity | labuser |
| Custom mitigation | MORI isolated from the active enforcement path |

Baseline SHA-256 of `/usr/bin/su`:

`c74311fe5636b7d7f9a56239fa8adeeab12ba86fe7d41b91afa85bf9bbdae78b`

The target retained its expected ownership and SUID mode during final validation:

`-rwsr-xr-x 1 root root 55680 ... /usr/bin/su`

---

## Evidence Integrity

This phase contains two complementary evidence classes:

1. **Machine-readable artifacts** in `artifacts/`
2. **Visual terminal evidence** in `screenshots/`

`PUBLIC-SHA256SUMS.txt` records SHA-256 digests for the evidence objects contained in those directories.

The README is intentionally excluded from the evidence manifest so that documentation can be improved without changing the integrity state of the captured evidence.

At the time the Phase 05 package was frozen, the manifest covered:

- 5 text artifacts
- 13 screenshots
- 18 evidence objects total

All 18 manifest entries were successfully re-verified after transfer into the repository.

---

## 1. Baseline Capture

The patched environment was documented before active retesting.

The baseline establishes:

- host and kernel identity,
- unprivileged test identities,
- `/usr/bin/su` ownership and SUID permissions,
- the baseline `/usr/bin/su` SHA-256 digest,
- the state of the test environment before the vendor-patch validation sequence.

Primary artifact:

- `artifacts/phase05-pre-patch.txt`

Visual evidence:

- `screenshots/00-vendor-patch-baseline.png`
- `screenshots/01-vendor-patch-baseline-hash.png`

---

## 2. MORI Isolation

The vendor patch was evaluated independently of the custom compensating control developed in Phase 04.

Before the CopyFail retests, validation confirmed that MORI was absent from the active enforcement path:

- no active MORI enforcement process,
- MORI integrity service inactive,
- no active MORI BPF pins associated with the control.

This separation is important because it prevents a successful MORI denial from being mistaken for vendor-patch behavior.

Primary artifact:

- `artifacts/phase05-vendor-patch-isolation.txt`

Visual evidence:

- `screenshots/02-mori-enforcement-isolated.png`

---

## 3. Vendor Kernel Identification

The running test environment used:

- kernel `6.8.0-137-generic`
- Ubuntu kernel package version `6.8.0-137.137`

Visual evidence:

- `screenshots/03-vendor-kernel-package-version.png`

This identifies the exact kernel state used for the validation sequence.

---

## 4. AF_ALG Availability and Benign Control

The patched environment was tested to ensure that the observed mitigation was not simply caused by removal of the affected AF_ALG functionality.

The `algif_aead` functionality remained present, and the benign control successfully completed the expected unprivileged AEAD lifecycle:

| Operation | Result |
|---|---|
| `socket(AF_ALG)` | PASS |
| AEAD `bind()` | PASS |
| `accept()` | PASS |

The controlled SUID target retained its baseline SHA-256 digest after the benign control.

Primary artifact:

- `artifacts/phase05-patched-aead-control.txt`

Visual evidence:

- `screenshots/04-algif-aead-module-state.png`
- `screenshots/05-benign-aead-control-pass.png`
- `screenshots/06-benign-aead-control-hash.png`

### Interpretation

The tested remediation preserved the benign AF_ALG AEAD behavior exercised by the laboratory control. The observed CopyFail failure therefore cannot be explained by wholesale removal of the tested subsystem.

---

## 5. Python CopyFail Retest

The Python CopyFail PoC was executed against the patched kernel after MORI had been isolated.

The intended unauthorized privilege transition was not observed.

Execution of `/usr/bin/su` reached the normal authentication boundary and returned:

`su: Authentication failure`

Post-test validation showed that:

- the `researcher` identity remained unprivileged,
- `/usr/bin/su` remained owned by `root:root`,
- the SUID permission remained present,
- the target retained its baseline SHA-256 digest.

Visual evidence:

- `screenshots/07-python-poc-provenance-and-denial.png`
- `screenshots/08-post-python-target-integrity.png`

The successful Python retest was captured interactively in the screenshots. No retrospective raw execution transcript was created for this run.

---

## 6. Independent C CopyFail Retest

A separately compiled C implementation was used as an additional regression path.

### Source provenance

Source:

`/home/labuser/copyfail-c-test/exploit.c`

SHA-256:

`e1dec1348c0d43ab47d8f992d9a0336216fd37ff83e6fa1d9e39a80890fbd165`

### Binary provenance

Binary:

`/home/labuser/copyfail-c-test/copyfail-c`

SHA-256:

`3b2605dc5e820f40645f682385194469f9189cbb65ee99153b52aedf45be5706`

Compiler:

`gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0`

The binary hash captured in provenance matches the binary used during the recorded retest.

Primary artifact:

- `artifacts/phase05-independent-c-poc-provenance.txt`

Visual evidence:

- `screenshots/09-pre-c-poc-target-integrity.png`
- `screenshots/10-independent-c-poc-provenance.png`
- `screenshots/11-independent-c-poc-denied.png`

### Result

The independent C PoC did not produce the intended unauthorized privilege transition.

The target again reached its ordinary authentication boundary rather than yielding elevated access.

The interactive C execution is preserved in the screenshot evidence. No retrospective raw execution transcript was manufactured after the test.

---

## 7. Final Target Validation

After the Python and C retests, `/usr/bin/su` was validated again.

Final SHA-256:

`c74311fe5636b7d7f9a56239fa8adeeab12ba86fe7d41b91afa85bf9bbdae78b`

This matches the Phase 05 baseline.

The target also retained:

- root ownership,
- expected SUID permissions,
- normal execution behavior,
- normal authentication enforcement.

Primary artifact:

- `artifacts/phase05-final-target-validation.txt`

Visual evidence:

- `screenshots/12-post-c-poc-integrity-auth-control.png`

The final `su` invocation reached authentication and rejected the unprivileged attempt normally.

---

## Evidence Map

| ID | Evidence | Purpose |
|---|---|---|
| 00 | `00-vendor-patch-baseline.png` | Patched environment baseline |
| 01 | `01-vendor-patch-baseline-hash.png` | Baseline record integrity |
| 02 | `02-mori-enforcement-isolated.png` | Demonstrates MORI isolation |
| 03 | `03-vendor-kernel-package-version.png` | Identifies tested vendor kernel package |
| 04 | `04-algif-aead-module-state.png` | Confirms AF_ALG AEAD availability |
| 05 | `05-benign-aead-control-pass.png` | Demonstrates benign AEAD functionality |
| 06 | `06-benign-aead-control-hash.png` | Benign-control record integrity |
| 07 | `07-python-poc-provenance-and-denial.png` | Python PoC retest and denied privilege transition |
| 08 | `08-post-python-target-integrity.png` | Post-Python SUID target validation |
| 09 | `09-pre-c-poc-target-integrity.png` | C PoC pre-test target state |
| 10 | `10-independent-c-poc-provenance.png` | Independent C source, binary and compiler provenance |
| 11 | `11-independent-c-poc-denied.png` | Independent C PoC retest result |
| 12 | `12-post-c-poc-integrity-auth-control.png` | Final target integrity and authentication control |

---

## Raw Artifact Map

| Artifact | Purpose |
|---|---|
| `phase05-pre-patch.txt` | Environment and target baseline |
| `phase05-vendor-patch-isolation.txt` | Vendor-kernel identity and MORI isolation record |
| `phase05-patched-aead-control.txt` | Benign AF_ALG AEAD regression control |
| `phase05-independent-c-poc-provenance.txt` | Independent C source/binary/compiler provenance |
| `phase05-final-target-validation.txt` | Final SUID target integrity validation |

---

## Results Summary

| Validation question | Result |
|---|---|
| Was MORI active during vendor-patch validation? | No |
| Was the tested vendor kernel identified? | Yes |
| Did benign AF_ALG AEAD functionality remain available? | Yes |
| Did the Python CopyFail PoC produce the previous unauthorized privilege transition? | No |
| Did the independent C CopyFail PoC produce the previous unauthorized privilege transition? | No |
| Did `/usr/bin/su` retain its baseline SHA-256? | Yes |
| Did `/usr/bin/su` retain its expected SUID state? | Yes |
| Did ordinary `su` authentication remain enforced? | Yes |

---

## Conclusion

Within the tested Ubuntu `6.8.0-137-generic` environment and against the Python and independent C CopyFail PoC implementations used in this laboratory, the previously reproduced unauthorized privilege-escalation behavior was no longer observed.

This result was reproduced while MORI was absent from the active enforcement path.

At the same time, the tested benign AF_ALG AEAD lifecycle remained operational, and `/usr/bin/su` retained its baseline integrity throughout the final validation sequence.

The vendor-remediated kernel therefore represents the preferred long-term remediation demonstrated by this laboratory.

MORI v2.7 remains documented in Phase 04 as a compensating control for environments in which the vulnerable kernel must temporarily be retained.

---

## Relationship to Phase 04

Phase 04 and Phase 05 answer different security-engineering questions:

**Phase 04  Custom Mitigation**

Can a compensating control detect and selectively prevent the reproduced CopyFail attack chain while the vulnerable environment is retained?

**Phase 05  Vendor Patch Validation**

Does the vendor-remediated kernel prevent the previously reproduced behavior without relying on MORI, while preserving the benign AF_ALG functionality exercised by the laboratory?

Together, the two phases document the transition from temporary compensating control to preferred vendor remediation.
