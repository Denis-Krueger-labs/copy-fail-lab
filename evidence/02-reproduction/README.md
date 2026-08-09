\# 02 Vulnerability Reproduction



This directory contains evidence from the controlled reproduction of

CVE-2026-31431 in the isolated Copy Fail lab environment.



The reproduction was performed using an unprivileged test account on the

historically vulnerable Ubuntu kernel `6.8.0-116-generic`.



The evidence is ordered chronologically from the clean pre-exploitation

state through privilege escalation, observation of the modified mounted

file view, and recovery after rebooting into the same vulnerable kernel.



\## Evidence Overview



| ID | Evidence | Purpose |

|---|---|---|

| 01 | `01-pre-exploit-state` | Establishes the vulnerable kernel, unprivileged test user, and original `/usr/bin/su` hash before exploitation. |

| 02 | `02-algif-aead-loaded.png` | Confirms that the AF\_ALG AEAD interface required for the reproduction is available and loaded. |

| 03 | `03-privilege-escalation-success.png` | Shows execution of the PoC followed by a shell with UID 0 and the changed mounted-view hash of `/usr/bin/su`. |

| 04 | `04-copy-fail-poc-source.png` | Records the exact local PoC representation used during the experiment together with its local hash and size. |

| 05 | `05-post-exploit-state` | Shows that after leaving the privileged shell the test account is again UID 1001 while the changed `/usr/bin/su` hash remains observable. |

| 06 | `06-page-cache-vs-backing-filesystem` | Compares the mounted/VFS view of `/usr/bin/su` with a direct read from the backing ext4 filesystem. The two views produce different hashes. |

| 07 | `07-reboot-restores-original-file` | Demonstrates that after rebooting into the same vulnerable kernel, the normal mounted view of `/usr/bin/su` returns to its original hash. |



\## Important Hashes



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



The local PoC representation differed from the published representation

only by the final newline.



\## Integrity



`PUBLIC-SHA256SUMS` contains SHA-256 hashes for every public artifact and

screenshot in this directory.



The repository copy was verified against this manifest after transfer.



\## Directory Layout



```text

02-reproduction/

├── PUBLIC-SHA256SUMS

├── artifacts/

│   ├── 01-pre-exploit-state.txt

│   ├── 05-post-exploit-state.txt

│   ├── 06-page-cache-vs-backing-filesystem.txt

│   ├── 07-reboot-restores-original-file.txt

│   └── copyfail-confirmed-vulnerable-state.txt

└── screenshots/

&#x20;   ├── 01-pre-exploit-state.png

&#x20;   ├── 02-algif-aead-loaded.png

&#x20;   ├── 03-privilege-escalation-success.png

&#x20;   ├── 04-copy-fail-poc-source.png

&#x20;   ├── 05-post-exploit-state.png

&#x20;   ├── 06-page-cache-vs-backing-filesystem.png

&#x20;   └── 07-reboot-restores-original-file.png

```



\## Scope



The reproduction was performed exclusively inside an isolated,

user-controlled laboratory environment.



No persistence, credential collection, lateral movement, or unrelated

post-exploitation activity was performed. Successful privilege escalation

was demonstrated only through the resulting UID 0 shell and associated

experimental observations.

