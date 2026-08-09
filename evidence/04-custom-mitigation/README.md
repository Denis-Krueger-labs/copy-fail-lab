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

This demonstrates that the compensating control interrupted the tested
exploit chain before the privileged executable was modified.

## Compatibility Impact

A benign unprivileged AF_ALG AEAD bind was also tested while MORI Guard was
active.

The benign operation failed as well.

This demonstrates an important limitation of the control: MORI Guard does not
distinguish malicious Copy Fail activity from legitimate applications that
require the `algif_aead` interface. It therefore reduces attack surface at the
cost of disabling that functionality.

## Evidence

The `artifacts/` directory contains textual evidence and copies of the tested
control configuration.

The `screenshots/` directory contains visual evidence from the mitigation
experiment.

The original proof-of-concept source is not redistributed. The public retest
artifact preserves the traceback and execution result while intentionally
omitting proof-of-concept source lines.

`PUBLIC-SHA256SUMS.txt` provides SHA-256 hashes for every file included in
this public evidence package except the manifest itself.
