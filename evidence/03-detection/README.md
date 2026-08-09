# 03 — Detection

This directory contains the threat-surface analysis, detector implementation,
and experimental evidence for the custom Copy Fail detection control.

The goal of this phase was not to detect a specific exploit filename or PoC
implementation. Instead, the detector monitors the integrity of privileged
executables that could represent useful privilege-escalation targets.

## Threat Model

The tested attacker begins as an unprivileged local user:

```text
uid=1001(labuser)
```

The observed attack path is:

```text
Unprivileged local user
        |
        v
Vulnerable kernel
        |
        v
AF_ALG / algif_aead
        |
        v
pipe + splice + vulnerable AEAD operation
        |
        v
Cached view of privileged executable modified
        |
        v
Setuid-root executable launched
        |
        v
Root privilege boundary crossed
```

The protected asset is therefore not only `/usr/bin/su`, but the host's
privileged execution boundary.

## Privileged Target Discovery

The lab system contained 13 root-owned SUID files on the tested filesystem.

From the `labuser` account:

- 12 were readable and executable.
- `/usr/lib/dbus-1.0/dbus-daemon-launch-helper` was readable but not executable.
- `/usr/bin/su` was experimentally demonstrated as a working Copy Fail target.
- The remaining reachable SUID executables are treated as candidate privileged
  targets and were not individually claimed to be exploitable.

The inventory also records executables using Linux file capabilities. These are
treated as a separate privileged-execution surface and are not included in the
initial SUID integrity baseline.

## Known-Good Baseline

A SHA-256 baseline was generated for the 12 root-owned SUID executables that
were both readable and executable by `labuser`.

The baseline is stored as:

```text
artifacts/02-suid-known-good.tsv
```

Baseline file SHA-256:

```text
c5ebe8afe16326aea860317b153981a43e57f3d462c3e1d03d3d1bbe5d951e74
```

The operational copy was moved to:

```text
/etc/copyfail-detector/suid-known-good.tsv
```

and placed under root ownership.

A separate tamper-resistance test confirmed that `labuser` could read the
baseline but could not modify it.

## MORI Integrity Monitor

MORI is a small Python integrity monitor created for this experiment.

```text
 /\_/\
( •.• )   MORI: privileged binaries look normal.
 > ^ <
```

The monitor:

1. Loads the protected known-good baseline.
2. Reads each monitored executable through the normal filesystem interface.
3. Calculates its current SHA-256 hash.
4. Compares the result with the expected hash.
5. Generates an alert when the observed value differs.
6. Tracks alert state to avoid continuously repeating identical alerts.

The check interval used during the experiment was:

```text
0.25 seconds
```

The implementation is available under:

```text
detector/mori_integrity_watch.py
detector/mori-integrity.service
```

SHA-256 of the tested Python implementation:

```text
20a5d690db4d2afcd4aa8b6746b9575c1d1813db290b1aa1e8a6437dd68488e5
```

## Service Deployment

MORI was deployed as a systemd service.

The service uses systemd hardening including:

```text
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
```

The monitor therefore does not require administrative privileges merely to
perform integrity checking.

Output is written to the system journal.

## Copy Fail Detection Test

With MORI running, the Copy Fail PoC was executed again from the unprivileged
`labuser` account.

Before exploitation, `/usr/bin/su` matched its known-good baseline:

```text
c74311fe5636b7d7f9a56239fa8adeeab12ba86fe7d41b91afa85bf9bbdae78b
```

During exploitation, MORI observed:

```text
expected=c74311fe5636b7d7f9a56239fa8adeeab12ba86fe7d41b91afa85bf9bbdae78b
observed=44900c631391f0d60eb6d271b8374a08dc1d9be76e403390d27a91ed5f179be9
```

and generated:

```text
 /\_/\
( Ò.Ó )   MORI: INTEGRITY VIOLATION.
 > ^ <
```

The exploit simultaneously succeeded in obtaining a UID 0 shell.

This demonstrates that MORI successfully detected the integrity violation, but
did not prevent exploitation.

## Detection vs. Prevention

MORI, in this phase, is a **detection control**.

```text
Copy Fail
    |
    v
Integrity corruption
    |
    +----> MORI detects hash mismatch
    |
    v
Privileged execution can still occur
```

The detector therefore provides visibility into exploitation but does not
remove the vulnerable kernel path.

Prevention is evaluated separately in the custom mitigation phase.

## Evidence Overview

| ID | Evidence | Purpose |
|---|---|---|
| 00 | `00-privileged-target-surface.txt` | Records the root-owned SUID inventory, file capabilities, hashes, package ownership, and mount state. |
| 01 | `01-suid-accessibility.txt` | Records which SUID targets are readable and executable by the unprivileged test user. |
| 02 | `02-suid-known-good.tsv` | Contains the known-good SHA-256 baseline for the 12 monitored privileged executables. |
| 03 | `03-protected-baseline-state.txt` | Records the protected root-owned baseline deployment. |
| 04 | `04-mori-copyfail-detection.txt` | Contains the real journal event generated when MORI detected Copy Fail. |
| 07 | `07-mori-service-status.txt` | Records the deployed systemd service state. |

## Screenshots

The screenshot sequence documents the experiment visually:

```text
00  SUID target surface
01  SUID accessibility from labuser
02  known-good SUID baseline
03  fusermount3 /usr merge verification
04  protected baseline
05  baseline tamper attempt denied
06a MORI watcher source, part 1
06b MORI watcher source, part 2
07  MORI standalone clean state
09  MORI systemd service active
10  MORI system-service clean state
11  MORI detects Copy Fail
12  MORI detection with root-shell confirmation
```

Screenshot number `08` is intentionally absent because the originally planned
controlled-alert test was not captured. The evidence sequence preserves the
actual experimental record rather than retroactively renumbering it.

## Directory Layout

```text
03-detection/
├── README.md
├── PUBLIC-SHA256SUMS
├── artifacts/
│   ├── 00-privileged-target-surface.txt
│   ├── 01-suid-accessibility.txt
│   ├── 02-suid-known-good.tsv
│   ├── 03-protected-baseline-state.txt
│   ├── 04-mori-copyfail-detection.txt
│   └── 07-mori-service-status.txt
├── detector/
│   ├── mori_integrity_watch.py
│   └── mori-integrity.service
└── screenshots/
    ├── 00-suid-target-surface.png
    ├── 01-suid-accessibility.png
    ├── 02-suid-known-good-baseline.png
    ├── 03-fusermount3-usrmerge-verification.png
    ├── 04-protected-baseline.png
    ├── 05-baseline-tamper-denied.png
    ├── 06a-mori-integrity-watcher-poc-part1.png
    ├── 06b-mori-integrity-watcher-poc-part2.png
    ├── 07-mori-integrity-monitor-baseline.png
    ├── 09-mori-systemd-service-active.png
    ├── 10-mori-system-service-clean-state.png
    ├── 11-mori-detects-copyfail.png
    └── 12-mori-detection-with-root-confirmation.png
```

## Integrity

`PUBLIC-SHA256SUMS` contains SHA-256 hashes for the public evidence,
screenshots, detector implementation, service definition, and README.

The final public directory was verified against the manifest after assembly.

## Scope

All testing was performed exclusively inside the isolated, user-controlled
Copy Fail laboratory environment.

The detection experiment used the previously established privilege-escalation
reproduction only to observe whether the custom monitor identified the
resulting integrity violation.

No persistence, credential collection, lateral movement, or unrelated
post-exploitation activity was performed.