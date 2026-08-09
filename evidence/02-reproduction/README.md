# 02 Vulnerability Reproduction

This directory contains evidence from the controlled reproduction of
CVE-2026-31431 ("Copy Fail") in the isolated Copy Fail lab environment.

The reproduction was performed using an unprivileged test account on the
historically vulnerable Ubuntu kernel `6.8.0-116-generic`.

The evidence is ordered chronologically from the clean pre-exploitation state,
through privilege escalation and the resulting modified mounted-file view, to
comparison with the backing filesystem and recovery after rebooting into the
same vulnerable kernel.

## Experimental Sequence

A preliminary reproduction was performed before the final evidence run.

During that preliminary investigation, additional observations were made,
including cache-drop tests and direct comparison between the mounted filesystem
view and the underlying ext4 filesystem.

Before preserving the final reproduction evidence, the VM was rebooted into
the same vulnerable kernel:

```text
6.8.0-116-generic
```

The reboot restored the normal mounted view of `/usr/bin/su` to its original
known-good SHA-256 value.

The preserved reproduction run therefore began again from a clean observable
state on the same vulnerable kernel rather than continuing from the preliminary
experiment.

This separation is important because it prevents observations from the
preliminary run from being confused with the preserved reproduction sequence.

## Evidence Overview

| ID | Evidence | Purpose |
|---|---|---|
| 01 | `01-pre-exploit-state` | Establishes the vulnerable kernel, unprivileged test user, and original `/usr/bin/su` hash before exploitation. |
| 02 | `02-algif-aead-loaded.png` | Confirms that the AF_ALG AEAD interface required for the reproduction is available and loaded. |
| 03 | `03-privilege-escalation-success.png` | Shows execution of the PoC followed by a shell with UID 0 and the changed mounted-view hash of `/usr/bin/su`. |
| 04 | intentionally omitted | A screenshot containing the complete PoC source was removed from the public evidence package. |
| 05 | `05-post-exploit-state` | Shows that after leaving the privileged shell the test account is again UID 1001 while the changed `/usr/bin/su` hash remains observable. |
| 06 | `06-page-cache-vs-backing-filesystem` | Compares the mounted/VFS view of `/usr/bin/su` with a direct read from the backing ext4 filesystem. The two views produce different hashes. |
| 07 | `07-reboot-restores-original-file` | Demonstrates that after rebooting into the same vulnerable kernel, the normal mounted view of `/usr/bin/su` returns to its original hash. |

The numbering intentionally retains the missing `04` position so that the
remaining filenames continue to correspond to the original experimental
sequence.

## Reproduction Result

Before exploitation, the test account was unprivileged:

```text
uid=1001(labuser)
```

The target `/usr/bin/su` was owned by root and retained its normal SUID
permissions.

Its known-good SHA-256 value was:

```text
c74311fe5636b7d7f9a56239fa8adeeab12ba86fe7d41b91afa85bf9bbdae78b
```

The Copy Fail proof of concept was then executed from the unprivileged account.

Successful privilege escalation was demonstrated by the resulting shell:

```text
uid=0(root)
```

No persistence or unrelated post-exploitation activity was performed.

After exploitation, the SHA-256 value observed through the normal mounted/VFS
view of `/usr/bin/su` changed to:

```text
44900c631391f0d60eb6d271b8374a08dc1d9be76e403390d27a91ed5f179be9
```

After leaving the privileged shell, `labuser` again operated as UID 1001 while
the modified mounted-view hash remained observable.

## Direct Backing-Filesystem Comparison

To distinguish the normal mounted-file view from a direct read of the backing
ext4 filesystem, the following command was used:

```bash
sudo debugfs -R 'cat /usr/bin/su' \
  /dev/mapper/ubuntu--vg-ubuntu--lv 2>/dev/null \
  | sha256sum
```

The normal mounted/VFS view produced:

```text
44900c631391f0d60eb6d271b8374a08dc1d9be76e403390d27a91ed5f179be9
```

The direct ext4 read produced:

```text
c74311fe5636b7d7f9a56239fa8adeeab12ba86fe7d41b91afa85bf9bbdae78b
```

This demonstrates that, during the experiment, the data observed through the
mounted filesystem differed from the data returned by the direct backing
filesystem read.

No stronger conclusion about the internal kernel state is inferred from this
comparison alone.

## Cache-Drop Observation

During the preliminary investigation, cache-drop operations were also tested.

Dropping caches with values `1` and `3` did not restore the original mounted
view during the experiment.

This is retained as an experimental observation only. No causal explanation is
inferred from that result without additional kernel-level evidence.

## Reboot Recovery

After the preserved reproduction run, the system was rebooted again into the
same vulnerable kernel:

```text
6.8.0-116-generic
```

After reboot, the normal mounted view of `/usr/bin/su` again produced the
original known-good SHA-256 value:

```text
c74311fe5636b7d7f9a56239fa8adeeab12ba86fe7d41b91afa85bf9bbdae78b
```

The recovery therefore did not depend on upgrading to a patched kernel.

The evidence records only the observed result: rebooting into the same
vulnerable kernel restored the original mounted-file hash.

## Important Hashes

Original `/usr/bin/su`:

```text
c74311fe5636b7d7f9a56239fa8adeeab12ba86fe7d41b91afa85bf9bbdae78b
```

Observed modified mounted/VFS view:

```text
44900c631391f0d60eb6d271b8374a08dc1d9be76e403390d27a91ed5f179be9
```

Local PoC representation:

```text
SHA-256: d401e7d1c00605749d6c617ace73ab20a762b72e41c2e1590331596e38219a61
Size: 731 bytes
```

The locally obtained representation differed from the separately recorded
732-byte representation by a trailing newline.

The proof-of-concept source itself is not redistributed in this public
evidence package.

## Proof-of-Concept Handling

The proof of concept was used only inside the isolated laboratory environment
for controlled reproduction.

A screenshot that displayed the complete PoC source was intentionally removed
from the public evidence package.

Evidence ID `04` therefore remains intentionally absent.

The public repository retains hashes, execution results, environmental state,
and other experimental observations without redistributing the complete exploit
source.

## Integrity

`PUBLIC-SHA256SUMS` contains SHA-256 hashes for every public artifact,
screenshot, and this README included in the reproduction evidence package,
excluding the manifest itself.

The manifest is regenerated after changes to the public package and verified
before publication.

## Directory Layout

```text
02-reproduction/
├── PUBLIC-SHA256SUMS
├── README.md
├── artifacts/
│   ├── 01-pre-exploit-state.txt
│   ├── 05-post-exploit-state.txt
│   ├── 06-page-cache-vs-backing-filesystem.txt
│   ├── 07-reboot-restores-original-file.txt
│   └── copyfail-confirmed-vulnerable-state.txt
└── screenshots/
    ├── 01-pre-exploit-state.png
    ├── 02-algif-aead-loaded.png
    ├── 03-privilege-escalation-success.png
    ├── 05-post-exploit-state.png
    ├── 06-page-cache-vs-backing-filesystem.png
    └── 07-reboot-restores-original-file.png
```

Screenshot `04-copy-fail-poc-source.png` is intentionally absent because it
contained the complete proof-of-concept source.

## Scope

The reproduction was performed exclusively inside an isolated,
user-controlled laboratory environment.

The experiment was limited to demonstrating and observing the local privilege
escalation.

No persistence, credential collection, lateral movement, reverse shell,
credential theft, or unrelated post-exploitation activity was performed.

Successful privilege escalation was demonstrated only through the resulting
UID 0 shell and associated experimental observations.