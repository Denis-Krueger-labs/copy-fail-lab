#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define MORI_S_ISUID   0004000
#define MORI_MAY_READ  0x00000004

/*
 * MORI v2.1.1
 *
 * Observation-only prototype.
 *
 * Detects non-root reads of root-owned SUID files while allowing
 * userspace to mark selected TGIDs as trusted integrity-monitor
 * processes.
 */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32);
    __type(key, __u32);
    __type(value, __u8);
} trusted_tgids SEC(".maps");

/*
 * MORI v2.5.0 short-lived correlation state.
 *
 * Key:   process TGID
 * Value: timestamp of the most recent observed AF_ALG AEAD bind
 *
 * Ten seconds is an experimental correlation window, not a claim
 * that activity inside this interval is inherently malicious.
 */
#define MORI_AEAD_WINDOW_NS (10ULL * 1000000000ULL)

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} aead_state SEC(".maps");

/*
 * MORI v2.5.0 short-lived splice state.
 *
 * Key:   process TGID
 * Value: timestamp of the most recent root-owned SUID -> pipe splice
 *
 * Ten seconds is an experimental observation window.
 */
#define MORI_SPLICE_WINDOW_NS (10ULL * 1000000000ULL)

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} splice_state SEC(".maps");

SEC("lsm/file_permission")
int BPF_PROG(mori_suid_observer,
             struct file *file,
             int mask,
             int ret)
{
    struct inode *inode;
    __u64 uid_gid;
    __u64 pid_tgid;
    __u32 uid;
    __u32 owner;
    __u32 tgid;
    __u16 mode;
    __u8 *trusted;
    __u64 *aead_seen;
    __u64 *splice_seen;
    __u64 now;
    int aead_recent = 0;
    int splice_recent = 0;

    /* Preserve previous LSM decisions. */
    if (ret != 0)
        return ret;

    if (!file)
        return ret;

    uid_gid = bpf_get_current_uid_gid();
    uid = (__u32)uid_gid;

    /* Root is not interesting for this preliminary signal. */
    if (uid == 0)
        return ret;

    /* Only READ permission checks. */
    if (!(mask & MORI_MAY_READ))
        return ret;

    inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return ret;

    owner = BPF_CORE_READ(inode, i_uid.val);
    mode = BPF_CORE_READ(inode, i_mode);

    /* Only root-owned SUID files. */
    if (owner != 0)
        return ret;

    if (!(mode & MORI_S_ISUID))
        return ret;

    pid_tgid = bpf_get_current_pid_tgid();
    tgid = pid_tgid >> 32;

    /*
     * Userspace controls which TGIDs are trusted.
     * Suppress only this READ-SUID observation.
     */
    trusted = bpf_map_lookup_elem(&trusted_tgids, &tgid);

    if (trusted && *trusted)
        return ret;

    /*
     * Evaluate both short-lived behavioral states.
     */
    now = bpf_ktime_get_ns();

    aead_seen = bpf_map_lookup_elem(&aead_state, &tgid);

    if (aead_seen) {
        if (now >= *aead_seen &&
            now - *aead_seen <= MORI_AEAD_WINDOW_NS) {
            aead_recent = 1;
        } else {
            bpf_map_delete_elem(&aead_state, &tgid);
        }
    }

    splice_seen = bpf_map_lookup_elem(&splice_state, &tgid);

    if (splice_seen) {
        if (now >= *splice_seen &&
            now - *splice_seen <= MORI_SPLICE_WINDOW_NS) {
            splice_recent = 1;
        } else {
            bpf_map_delete_elem(&splice_state, &tgid);
        }
    }

    if (aead_recent && splice_recent) {
        /*
         * MORI v2.5.0 shadow policy.
         *
         * This is the point at which enforcement would deny the
         * operation. For now, record the decision and preserve the
         * original access result unchanged.
         */
        bpf_printk(
            "MORI v2.5.0 WOULD-DENY-AEAD-SPLICE-SUID tgid=%u uid=%u",
            tgid,
            uid
        );

        return ret;
    }

    if (aead_recent) {
        bpf_printk(
            "MORI v2.5.0 CORRELATED-AEAD-SUID tgid=%u uid=%u",
            tgid,
            uid
        );

        return ret;
    }

    if (splice_recent) {
        bpf_printk(
            "MORI v2.5.0 CORRELATED-SPLICE-SUID tgid=%u uid=%u",
            tgid,
            uid
        );

        return ret;
    }

    bpf_printk(
        "MORI v2.5.0 READ-SUID tgid=%u uid=%u mask=%d",
        tgid,
        uid,
        mask
    );

    /* Observation only. */
    return ret;
}

char LICENSE[] SEC("license") = "GPL";

/*
 * MORI v2.5.0
 *
 * AF_ALG AEAD observation prototype.
 *
 * This is deliberately observation-only.
 * AF_ALG and AEAD are legitimate kernel crypto interfaces and are
 * not considered malicious by themselves.
 */

#define MORI_AF_ALG 38

static __always_inline int mori_sockaddr_type_is_aead(
    struct sockaddr *address,
    int addrlen)
{
    /*
     * struct sockaddr_alg begins with:
     *
     *   __u16 salg_family;
     *   __u8  salg_type[14];
     *
     * struct sockaddr exposes the same first sixteen bytes as:
     *
     *   sa_family_t sa_family;
     *   char        sa_data_min[14];
     *
     * Require the complete fixed-size type field to be present before
     * examining it.
     */
    if (addrlen < 16)
        return 0;

    return address->sa_data_min[0] == 'a' &&
           address->sa_data_min[1] == 'e' &&
           address->sa_data_min[2] == 'a' &&
           address->sa_data_min[3] == 'd' &&
           address->sa_data_min[4] == '\0';
}

SEC("lsm/socket_bind")
int BPF_PROG(mori_socket_bind_observer,
             struct socket *sock,
             struct sockaddr *address,
             int addrlen,
             int ret)
{
    __u64 uid_gid;
    __u64 pid_tgid;
    __u32 uid;
    __u32 tgid;
    __u64 now;
    int state_err;
    sa_family_t family;

    (void)sock;

    /* Preserve any decision made by an earlier LSM program. */
    if (ret != 0)
        return ret;

    if (!address)
        return ret;

    /*
     * The family field is available directly through the BTF-typed
     * LSM hook argument.
     */
    family = address->sa_family;

    if (family != MORI_AF_ALG)
        return ret;

    uid_gid = bpf_get_current_uid_gid();
    uid = (__u32)uid_gid;

    pid_tgid = bpf_get_current_pid_tgid();
    tgid = pid_tgid >> 32;

    if (mori_sockaddr_type_is_aead(address, addrlen)) {
        now = bpf_ktime_get_ns();

        state_err = bpf_map_update_elem(
            &aead_state,
            &tgid,
            &now,
            BPF_ANY
        );

        if (state_err == 0) {
            bpf_printk(
                "MORI v2.5.0 AEAD-ARM tgid=%u uid=%u len=%d",
                tgid,
                uid,
                addrlen
            );
        } else {
            bpf_printk(
                "MORI v2.5.0 AEAD-STATE-FAIL tgid=%u uid=%u",
                tgid,
                uid
            );
        }
    } else {
        bpf_printk(
            "MORI v2.5.0 AF_ALG-OTHER tgid=%u uid=%u len=%d",
            tgid,
            uid,
            addrlen
        );
    }

    /* Observation only. */
    return ret;
}


/*
 * MORI v2.5.0
 *
 * Root-owned SUID -> pipe splice observation.
 * Observation only.
 */

#define MORI_S_IFMT   00170000
#define MORI_S_IFIFO  0010000

SEC("fentry/do_splice")
int BPF_PROG(mori_splice_observer,
             struct file *in,
             loff_t *off_in,
             struct file *out,
             loff_t *off_out,
             size_t len,
             unsigned int flags)
{
    struct inode *in_inode;
    struct inode *out_inode;
    __u64 pid_tgid;
    __u64 uid_gid;
    __u64 now;
    __u32 tgid;
    __u32 uid;
    __u32 in_owner;
    __u16 in_mode;
    __u16 out_mode;
    int state_err;

    (void)off_in;
    (void)off_out;
    (void)flags;

    if (!in || !out)
        return 0;

    uid_gid = bpf_get_current_uid_gid();
    uid = (__u32)uid_gid;

    /* Our LPE-relevant observation concerns non-root callers. */
    if (uid == 0)
        return 0;

    in_inode = BPF_CORE_READ(in, f_inode);
    out_inode = BPF_CORE_READ(out, f_inode);

    if (!in_inode || !out_inode)
        return 0;

    in_owner = BPF_CORE_READ(in_inode, i_uid.val);
    in_mode = BPF_CORE_READ(in_inode, i_mode);
    out_mode = BPF_CORE_READ(out_inode, i_mode);

    if (in_owner != 0)
        return 0;

    if (!(in_mode & MORI_S_ISUID))
        return 0;

    if ((out_mode & MORI_S_IFMT) != MORI_S_IFIFO)
        return 0;

    pid_tgid = bpf_get_current_pid_tgid();
    tgid = pid_tgid >> 32;
    now = bpf_ktime_get_ns();

    state_err = bpf_map_update_elem(
        &splice_state,
        &tgid,
        &now,
        BPF_ANY
    );

    if (state_err == 0) {
        bpf_printk(
            "MORI v2.5.0 SPLICE-ARM tgid=%u uid=%u len=%lu",
            tgid,
            uid,
            len
        );
    } else {
        bpf_printk(
            "MORI v2.5.0 SPLICE-STATE-FAIL tgid=%u uid=%u",
            tgid,
            uid
        );
    }

    return 0;
}
