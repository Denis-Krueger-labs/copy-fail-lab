#!/bin/sh

TAG="mori-guard"

logger -t "$TAG" \
    "control=mori-guard action=DENY module=algif_aead reason=CVE-2026-31431"

message='
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
'

# Show the message when stderr is connected to the requesting process.
printf '%s\n' "$message" >&2

# Preserve the same message in the system journal.
printf '%s\n' "$message" | logger -t "$TAG"

exit 1
