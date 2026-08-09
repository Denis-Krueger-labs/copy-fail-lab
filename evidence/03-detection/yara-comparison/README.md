# YARA Exact-Sample Comparison

This experiment compares an exact-sample YARA rule with the integrity-based
detection approach used by MORI Monitor.

## Objective

The goal is not to evaluate YARA as a whole.

Instead, this experiment demonstrates the limitation of using an exact file
hash as a detection signature for a known proof-of-concept sample.

## Rule

The test rule uses YARA's `hash` module and matches the SHA-256 value of the
known Copy Fail proof of concept used in the laboratory.

Known sample SHA-256:

`d401e7d1c00605749d6c617ace73ab20a762b72e41c2e1590331596e38219a61`

## Original Sample Test

The original laboratory copy of the proof of concept was scanned without
executing it.

Result:

`CopyFail_Known_PoC_Exact_Hash` matched successfully.

## Harmless Variant Test

A private copy of the same sample was modified by appending one trailing
newline.

No exploit logic was changed and the variant was not executed.

The file size changed from 731 bytes to 732 bytes, producing a different
SHA-256 value.

The exact-hash YARA rule no longer matched the modified sample.

## Interpretation

The experiment demonstrates that an exact-sample signature reliably
identifies the specific artifact for which it was created, but does not
generalize across even trivial byte-level variations.

This is not a limitation of YARA as a whole. More generalized YARA rules can
use strings, byte sequences, structural properties, and other conditions.

The comparison instead illustrates the difference between identifying a
known artifact and detecting a security-relevant system effect.

MORI Monitor does not depend on the proof-of-concept filename or exact file
contents. It monitors the integrity of protected privileged executables and
alerts when those targets deviate from their known-good state.

## Evidence

The original proof-of-concept and the modified private variant are not
redistributed in this repository.

The artifacts contain the YARA rule, hashes, environment information, and
scan results only.
