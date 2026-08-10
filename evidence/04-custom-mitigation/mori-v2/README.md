# MORI v2 — Correlated eBPF/LSM Compensating Control

MORI v2 is the second-generation experimental compensating control developed during the Copy Fail research lab.

It was created after MORI Guard v1 successfully blocked the tested Copy Fail path by disabling access to `algif_aead`, but also prevented legitimate AF_ALG AEAD use. MORI v2 therefore explored whether exploit-relevant behavior could be observed, correlated, and selectively denied while preserving individual benign operations.

## Scope

The implementation was developed and evaluated on the intentionally vulnerable Copy Fail research VM.

MORI v2 is not presented as a replacement for the vendor security update and does not claim to identify attacker intent.

The final policy operates on an experimentally derived combination of observable behavior:

1. recent AF_ALG AEAD activity by a non-root process,
2. a root-owned SUID file being spliced into a pipe by that process,
3. the corresponding privileged-file read permission check.

Individual signals are insufficient to trigger enforcement.

The final enforcement action is an LSM denial returning `EPERM`.

## Development progression

### v2.1 — Initial privileged-file observation

The first prototype observed non-root reads of root-owned SUID files through the BPF LSM `file_permission` hook.

This immediately exposed a false positive: the existing MORI integrity monitor itself periodically reads the protected SUID binaries and therefore triggered MORI v2.

Evidence:

- `00-mori-v2-identifies-mori-monitor-process.png`
- `01-mori-v2-false-positive-mori-monitor.png`
- `02-mori-monitor-service-context.png`

### v2.1.1 — Trusted monitor filtering

A `trusted_tgids` BPF map was introduced.

The userspace loader populated the map using processes found in the dedicated `mori-integrity.service` cgroup. Reads originating from the trusted monitor were suppressed while untrusted SUID reads remained observable.

Evidence:

- `03-mori-v2-1-1-trusted-monitor-loaded.png`
- `04-mori-v2-1-1-trusted-monitor-suppressed.png`
- `05-mori-v2-1-1-untrusted-suid-read-detected.png`
- `06-mori-v2-1-1-implementation-hashes.png`

### v2.1.2 — Authenticated monitor trust

TGID membership alone was considered insufficient for the trust decision.

The loader was extended to verify:

- expected monitor path,
- regular-file status,
- root ownership,
- absence of group/world write permissions,
- expected SHA-256 digest,
- presence of the expected monitor path as an exact argv entry for the process in the service cgroup.

Trust failure leaves the map empty rather than preventing MORI from attaching.

A deliberate monitor-file modification caused trust to be refused and made the monitor visible to the observer again. Restoring the known-good file restored the exemption.

Evidence:

- `07-mori-v2-1-2-monitor-trust-verified.png`
- `08-mori-v2-1-2-verified-monitor-suppressed.png`
- `09-mori-v2-1-2-untrusted-suid-read-detected.png`
- `10-mori-v2-1-2-tampered-monitor-trust-refused.png`
- `11-mori-v2-1-2-refused-monitor-becomes-visible.png`
- `12-mori-v2-1-2-restored-monitor-trust-recovered.png`
- `13-mori-v2-1-2-final-artifact-hashes.png`

### v2.2 — AF_ALG AEAD observation

A BPF LSM `socket_bind` program was added.

The observer identifies AF_ALG socket-bind attempts whose algorithm type is `aead`.

The first compatibility experiment was performed while MORI Guard v1 was still active. MORI v2 observed the AEAD bind attempt, but the operation itself failed because v1 intentionally prevented `algif_aead` from loading.

For the subsequent compatibility test, v1 was temporarily disabled and `algif_aead` was loaded. A non-root `gcm(aes)` AF_ALG AEAD bind then succeeded while remaining observable by MORI v2.

An `AEAD-ARM` event therefore represents an observed AEAD bind attempt. Successful completion must be established separately from userspace evidence.

Evidence:

- `14-mori-v2-2-aead-bind-attempt-observed.png`
- `15-mori-v2-2-v1-guard-intercepts-algif-aead.png`
- `16-mori-v2-2-benign-aead-bind-preserved.png`
- `17-mori-v2-2-final-artifact-hashes.png`

### v2.3 — Same-process temporal correlation

An `aead_state` BPF map was added.

The map records the timestamp of recent AEAD activity by TGID. A ten-second correlation interval was used experimentally; this interval is not a claim that activity within ten seconds is inherently malicious.

A SUID read by the same TGID within the experimental window produces a correlated event.

Negative controls showed that:

- the correlation expires,
- an ordinary SUID read without recent AEAD activity is not classified as correlated.

Evidence:

- `18-mori-v2-3-ktime-helper-verifier-probe.png`
- `19-mori-v2-3-same-tgid-aead-suid-correlation.png`
- `20-mori-v2-3-correlation-window-expires.png`
- `21-mori-v2-3-suid-only-negative-control.png`
- `22-mori-v2-3-final-artifact-hashes.png`

### v2.4 — Splice observation and cross-hook correlation

A disposable `fentry/do_splice` probe was first used to establish whether splice activity could be observed on the vulnerable kernel.

The probe distinguished ordinary file-to-pipe splice activity from a root-owned SUID-file-to-pipe splice. The latter is not considered malicious by itself.

The validated splice logic was then integrated into MORI.

A `splice_state` map allowed the `fentry/do_splice` program to share state with the `file_permission` LSM program.

Testing demonstrated that state written by the tracing program was visible to the LSM hook during the same splice operation.

MORI could then correlate:

- recent AEAD activity,
- SUID-to-pipe splice activity,
- SUID read activity,

for the same TGID.

All tests remained observation-only at this stage.

Evidence:

- `23-mori-v2-4-benign-file-pipe-splice-observed.png`
- `24-mori-v2-4-suid-file-pipe-splice-observed.png`
- `25-mori-v2-4-splice-probe-hashes.png`
- `26-mori-v2-4-cross-hook-splice-state-correlation.png`
- `27-mori-v2-4-aead-splice-suid-triple-correlation.png`
- `28-mori-v2-4-final-artifact-hashes.png`

### v2.5 — Shadow policy

The triple-correlation condition was converted into a shadow enforcement decision.

When all required signals were present, MORI emitted:

`WOULD-DENY-AEAD-SPLICE-SUID`

but preserved the original LSM return value.

Negative controls demonstrated:

- AEAD alone did not reach the shadow deny condition,
- SUID-to-pipe splice activity alone did not reach the shadow deny condition,
- the combined behavior did reach the shadow deny condition,
- all tested operations remained permitted because enforcement was still disabled.

Evidence:

- `29-mori-v2-5-shadow-policy-would-deny.png`
- `30-mori-v2-5-aead-only-negative-control.png`
- `31-mori-v2-5-splice-only-negative-control.png`
- `32-mori-v2-5-final-artifact-hashes.png`

### v2.6 — Selective enforcement

The validated shadow decision was converted to an actual LSM denial.

When the correlated condition was reached, MORI returned `-EPERM`.

The controlled test demonstrated:

- AF_ALG AEAD bind succeeded,
- the correlated SUID-to-pipe splice was denied,
- userspace received `errno=1` / `Operation not permitted`,
- MORI emitted the matching deny event.

Evidence:

- `33-mori-v2-6-selective-enforcement-blocks-correlated-splice.png`
- `34-mori-v2-6-final-artifact-hashes.png`

### v2.6.1 — Structured deny telemetry

A BPF ring buffer was added.

On a policy denial, the kernel program emits a structured event containing:

- timestamp,
- TGID,
- UID,
- event type.

Event delivery is best-effort and is deliberately independent of enforcement. Failure of userspace telemetry does not change the `EPERM` decision.

End-to-end testing demonstrated matching:

- kernel deny telemetry,
- ring-buffer delivery,
- userspace MORI event handling,
- attacker-side `EPERM`.

Evidence:

- `35-mori-v2-6-1-ring-buffer-deny-event-delivery.png`
- `36-mori-v2-6-1-final-artifact-hashes.png`

### v2.6.2 — Attacker-facing notification

The userspace telemetry handler was extended with an optional attacker-facing notification.

For a denied TGID, MORI attempts to locate an interactive process terminal through `/proc/<tgid>/fd/`.

A descriptor is independently opened and checked with `isatty()` before notification. If no suitable terminal exists, notification is skipped.

Notification failure does not alter enforcement.

The final message is intentionally cosmetic:

```text
 /\_/\
( Ò.Ó )
 > ^ <

MORI: no.
MORI: bad.
MORI: I'm disappointed in you.
```

The actual security mechanism remains the BPF LSM `EPERM` decision.

Evidence:

- `37a-mori-v2-6-2-attacker-facing-judgment-cat.png`
- `37b-mori-v2-6-2-attacker-facing-judgment-cat.png`
- `38-mori-v2-6-2-final-artifact-hashes.png`

## Final policy boundary

The tested policy can be summarized as:

```text
AEAD activity only
    -> allowed

root-owned SUID -> pipe splice only
    -> allowed

recent AEAD activity
    +
root-owned SUID -> pipe splice
    +
matching privileged-file read
    -> denied with EPERM
```

This is behavior-based correlation, not attacker-intent detection.

## Important limitations

The current implementation remains an experimental research control.

The ten-second correlation windows are experimental.

AEAD state is keyed by TGID and therefore represents process-level correlation.

The splice prototype also uses TGID-based state and is not intended to establish precise thread-local causality in multithreaded applications.

The `socket_bind` LSM hook observes an AEAD bind attempt before successful protocol completion is independently known.

Root-owned SUID-to-pipe splice activity is not inherently malicious.

The final policy can therefore produce false positives for legitimate software that performs the same correlated sequence.

MORI is a compensating control developed for this research environment and should not be interpreted as a substitute for installing the vendor security update.

## Preserved artifacts

Historical full implementation checkpoints are preserved for:

- v2.2.0
- v2.3.0
- v2.4-splice-probe
- v2.4.0
- v2.5.0
- v2.6.0
- v2.6.1
- v2.6.2

The final v2.6.2 build is also preserved separately under `artifacts/final/`.

Earlier v2.1.x development is represented through the preserved screenshot and hash evidence rather than complete checkpoint directories.

## Integrity

`PUBLIC-SHA256SUMS.txt` contains SHA-256 hashes for the packaged implementation artifacts and screenshots.

Current package inventory:

```text
Artifacts:   45
Screenshots: 40
Total:       85

Manifest verification:
Verified: 85
Failed:    0
```
