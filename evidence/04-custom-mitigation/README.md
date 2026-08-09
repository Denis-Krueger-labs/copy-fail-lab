# Custom Mitigation Evidence

This directory contains evidence for the custom compensating control tested
against CVE-2026-31431 ("Copy Fail").

## Objective

The mitigation experiment tests whether access to the vulnerable
`algif_aead` kernel interface can be prevented while deliberately retaining
the vulnerable `6.8.0-116-generic` kernel.

The control does not patch the underlying kernel vulnerability. Instead, it
uses a `modprobe` install override to prevent `algif_aead` from being loaded.

## MORI Guard

The control consists of:

- `/etc/modprobe.d/mori-copyfail-guard.conf`
- `/usr/local/sbin/mori-block-algif-aead`

Requests to load `algif_aead` are redirected to the MORI Guard blocker.

The blocker records the denied request in the system journal and returns a
failure status.

The tested blocker also produces a deliberately visible denial message:

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

The message is cosmetic. The actual control decision is the failed
`algif_aead` module-load request.

## Test Result

The same Copy Fail proof of concept that previously produced a root shell was
executed again as the unprivileged `labuser`.

During the mitigated test:

- the system remained on kernel `6.8.0-116-generic`;
- `algif_aead` was not loaded;
- the proof of concept terminated with an error;
- `labuser` remained unprivileged;
- `/usr/bin/su` retained its known-good SHA-256 value;
- MORI Guard recorded the denied module-load request; and
- MORI Monitor recorded no integrity violation during the blocked attempt.

The protected target retained the known-good SHA-256 value:

```text
c74311fe5636b7d7f9a56239fa8adeeab12ba86fe7d41b91afa85bf9bbdae78b
```

The proof of concept failed before privilege escalation could occur.

This demonstrates that the compensating control interrupted the tested
exploit chain before the privileged executable was modified.

## Control Boundary

MORI Guard, in this initial implementation, blocks the availability of the
`algif_aead` interface through normal `modprobe` resolution.

Its purpose is therefore narrower than replacing the vulnerable kernel, but
broader than recognizing one particular exploit sample.

The tested control does not depend on:

- the proof-of-concept filename;
- the proof-of-concept SHA-256 value;
- the exploit source code; or
- the specific `/usr/bin/su` payload used during reproduction.

Instead, it removes one kernel interface required by the tested Copy Fail
exploit chain.

However, this also means the control cannot distinguish malicious use of that
interface from legitimate use.

## Compatibility Impact

A benign unprivileged AF_ALG AEAD bind was tested while MORI Guard was active.

The benign test attempted to bind:

```text
AF_ALG
type: aead
algorithm: gcm(aes)
```

Result:

```text
EXPECTED: benign AEAD bind failed while MORI Guard is active
exception=FileNotFoundError
errno=2
message=No such file or directory
```

The benign operation therefore failed as well.

This demonstrates an important limitation of the initial control:
MORI Guard does not distinguish malicious Copy Fail activity from legitimate
applications that require the `algif_aead` interface.

The practical tradeoff is:

```text
reduced attack surface
        ↕
reduced functionality
```

## Experimental Limitation and Follow-Up

The initial MORI Guard implementation successfully interrupted the tested
Copy Fail exploitation chain.

However, the compatibility test also produced a valuable negative result:
the control blocked benign AF_ALG AEAD functionality.

The initial implementation therefore did **not** provide selective mitigation.

Functionally, its security effect is comparable to disabling the affected
kernel module, while adding explicit denial logging and experimental
visibility.

In simplified form:

```text
MORI Guard v1
    |
    +-- exploit-related AEAD use --> DENY
    |
    `-- benign AEAD use ----------> DENY
                                      ^
                                      |
                                   too broad
```

This result is retained as part of the experiment rather than hidden as an
implementation failure.

It motivates a second, more selective MORI Guard design.

The follow-up question becomes:

> Can the exploit-relevant behavior be blocked while legitimate AF_ALG AEAD
> functionality remains available?

A successful follow-up control should therefore satisfy both conditions:

```text
benign AEAD operation
        |
        `--> ALLOW

exploit-relevant behavior chain
        |
        `--> DENY
```

The second design is evaluated separately so that the evidence for this
initial broad control remains historically intact.

## Relationship to MORI Monitor

MORI Guard and MORI Monitor serve different purposes.

MORI Monitor detects the consequence observed during successful exploitation:

```text
privileged executable changes
        |
        v
known-good hash mismatch
        |
        v
MORI integrity alert
```

MORI Guard attempts to interrupt the exploitation path before that consequence
occurs:

```text
Copy Fail attempt
        |
        v
algif_aead requested
        |
        v
MORI Guard denies load
        |
        v
exploit chain interrupted
```

During the blocked test, MORI Monitor generated no integrity violation because
`/usr/bin/su` remained unchanged.

This is expected behavior and does not indicate a failure of the monitor.

## Relationship to Vendor Mitigation

MORI Guard is a **compensating control**, not a correction for the underlying
kernel defect.

The initial implementation deliberately follows the same general defensive
idea as disabling the affected `algif_aead` functionality: make the vulnerable
interface unavailable while the vulnerable kernel remains installed.

The custom implementation adds:

- explicit denial logging;
- a reproducible laboratory control;
- observable control activation; and
- direct comparison with MORI Monitor.

It does not remove the underlying vulnerability from the kernel.

Vendor remediation remains the preferred long-term fix.

## Evidence

The `artifacts/` directory contains textual evidence and copies of the tested
control configuration.

The `screenshots/` directory contains visual evidence from the mitigation
experiment.

The evidence sequence documents:

```text
00  MORI Guard configuration
01  direct algif_aead module-load denial
02  MORI Guard denial message
03  clean pre-attempt state
04  Copy Fail attempt blocked
05  corresponding MORI Guard journal event
06  post-attempt verification
07  tested blocker implementation
```

The artifacts preserve:

- the deployed `modprobe` override;
- the tested blocker script;
- the real denial journal event;
- the post-attempt integrity state;
- the deployed control state;
- the benign AEAD compatibility test;
- the final blocked Copy Fail retest; and
- the corresponding MORI Guard and MORI Monitor journal output.

## Proof-of-Concept Handling

The original proof-of-concept source is not redistributed in this evidence
package.

The public retest artifact preserves the traceback and execution result while
intentionally omitting proof-of-concept source lines.

This retains the experimental result without publishing another copy of the
exploit source.

## Integrity

`PUBLIC-SHA256SUMS.txt` provides SHA-256 hashes for every file included in
this public evidence package except the manifest itself.

The public package is regenerated and re-verified whenever published evidence
or documentation changes.

## Scope

All mitigation testing was performed exclusively inside the isolated,
user-controlled Copy Fail laboratory.

The deliberately vulnerable kernel was retained specifically so that the
custom control could be evaluated against the same environment and proof of
concept used during the successful reproduction phase.

No persistence, credential collection, lateral movement, reverse shells, or
unrelated post-exploitation activity was performed.