import "hash"

rule CopyFail_Known_PoC_Exact_Hash
{
    meta:
        description = "Exact-sample comparison rule for the known Copy Fail PoC"
        cve = "CVE-2026-31431"
        purpose = "Laboratory comparison with integrity-based detection"

    condition:
        filesize > 0 and
        hash.sha256(0, filesize) ==
        "d401e7d1c00605749d6c617ace73ab20a762b72e41c2e1590331596e38219a61"
}
