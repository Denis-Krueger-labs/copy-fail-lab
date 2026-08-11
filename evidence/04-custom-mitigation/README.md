# 04 — Custom Mitigation: MORI

This evidence set documents the development, regression testing, and final
validation of MORI, an eBPF-based compensating control developed for the
CopyFail laboratory environment.

The final tested candidate is MORI v2.7.

## Final Candidate

Frozen executable:

`artifacts/mori-v2.7/build/mori_observer.v2.7`

SHA-256:

`7fe7b609b90e164f3ae4a9c025363399a8a63bf2a4338db2ecc62cfd2682d039`

The final candidate was not rebuilt between the final Python PoC test and the
independent C PoC test.

## Frozen v2.7 Artifacts

| Artifact | SHA-256 |
|---|---|
| `source/mori_observer.bpf.c` | `05e0a387ce084d2aef121351c9af7907f85696307d9f08ccdf6d9191f91a035d` |
| `build/mori_observer.bpf.o` | `b3723e4f9815611512696a2ccd5516e37450490453063e05f644ce0a4e70f5a7` |
| `source/mori_observer.c` | `2ee01194b488e757dd4c1062a4123aec8aac5c5cbd74767ebc3a938f886939e6` |
| `build/mori_observer.skel.h` | `5cd82d2cc061e6b5fdbf2d59c563ebcdaa54e5dae3a97f0ff0dda6fd0200fd73` |
| `build/mori_observer.v2.7` | `7fe7b609b90e164f3ae4a9c025363399a8a63bf2a4338db2ecc62cfd2682d039` |
| `build/vmlinux.h` | `9afb58909604112dc7a303acef1e12ccd1edd6e3a066bb81fef69278a267af9a` |

The original Linux-generated artifact manifest is preserved at:

`artifacts/mori-v2.7/SHA256SUMS.txt`

The transferred Windows repository copy was independently checked against that
manifest and all entries verified successfully.

## Final Validation Summary

MORI v2.7 was tested against two independently implemented CopyFail test cases.

### Python PoC

Observed MORI lifecycle:

- AEAD activity observed
- AF_ALG accept observed
- splice state armed
- SUID-target correlation reached
- dangerous splice denied
- splice state disarmed
- AEAD state released
- attacker-facing notification delivered

Result:

- exploit operation returned `EPERM`
- `/usr/bin/su` remained byte-identical to baseline
- `labuser` remained UID 1001
- privilege escalation failed

### Independent C PoC

Repository commit:

`ba3f503b1497350a2df3a89fab0427b4f868fe59`

Source SHA-256:

`e1dec1348c0d43ab47d8f992d9a0336216fd37ff83e6fa1d9e39a80890fbd165`

Binary SHA-256:

`3b2605dc5e820f40645f682385194469f9189cbb65ee99153b52aedf45be5706`

Observed MORI lifecycle:

- AEAD activity observed
- AF_ALG accept observed
- splice state armed
- SUID-target correlation reached
- `DENY-AEAD-SPLICE-SUID` emitted
- splice state disarmed
- AEAD state released

Result:

- C PoC failed on its first attempted write
- `/usr/bin/su` remained byte-identical to baseline
- `labuser` remained UID 1001
- privilege escalation failed

## Regression Testing

The final candidate was also tested for control correctness rather than only
attack blocking.

The regression suite covered:

- ordinary socket activity not producing false AEAD accept telemetry
- tracked AF_ALG AEAD bind/accept lifecycle remaining observable
- cross-TGID isolation
- same-TGID state expiry behavior
- expiry-bypass regression
- alternate SUID targets
- multi-target SUID sweep
- post-test target integrity

Earlier v2.6.2 and intermediate v2.7 screenshots are intentionally retained.
They document discovered false positives and lifecycle defects as well as the
subsequent corrections.

## Screenshot Index

| ID | Evidence |
|---|---|
| 39 | MORI v2.6.2 pre-PoC validation |
| 40 | v2.6.2 active before real Python PoC |
| 41 | real Python CopyFail PoC blocked |
| 42 | post-PoC integrity validation |
| 43 | independent C PoC pre-test state |
| 44 | independent C PoC denied |
| 45 | C PoC post-test validation |
| 46 | alternate SUID target baseline (`fusermount3`) |
| 47 | SUID-target sweep denial |
| 48 | post-sweep integrity, 10/10 targets unchanged |
| 49 | cross-TGID isolation, unrelated splice allowed |
| 50 | same-TGID expiry bypass reproduced |
| 51 | intermediate v2.7 lifecycle regression, splice still allowed |
| 52 | v2.7 expiry-bypass regression fixed |
| 53 | frozen v2.7 Python PoC denial |
| 54 | frozen v2.7 Python post-test validation |
| 55 | frozen v2.7 independent C PoC denial and post-validation |
| 56 | independent C PoC provenance |

## Target Integrity

Known-good `/usr/bin/su` SHA-256 used during final validation:

`c74311fe5636b7d7f9a56239fa8adeeab12ba86fe7d41b91afa85bf9bbdae78b`

The same digest was observed after both final PoC executions.

## PoC Distribution

The exploit PoC source and executable used for validation are not redistributed
as part of this repository evidence set.

Instead, provenance is preserved through repository commit identifiers,
cryptographic hashes, screenshots, execution output, and target-integrity
validation.

## Interpretation

The evidence supports the narrower claim that the frozen MORI v2.7 candidate
successfully prevented the tested CopyFail exploitation paths in this
laboratory environment while preserving the benign behaviors exercised by the
regression suite.

It should not be interpreted as proof that MORI prevents every possible
variation of the vulnerability or as a replacement for an upstream kernel fix.
