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

    bpf_printk(
        "MORI v2.1.2 READ-SUID tgid=%u uid=%u mask=%d",
        tgid,
        uid,
        mask
    );

    /* Observation only. */
    return ret;
}

char LICENSE[] SEC("license") = "GPL";

/*
 * MORI v2.2.0
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
        bpf_printk(
            "MORI v2.2.0 AF_ALG-AEAD tgid=%u uid=%u len=%d",
            tgid,
            uid,
            addrlen
        );
    } else {
        bpf_printk(
            "MORI v2.2.0 AF_ALG-OTHER tgid=%u uid=%u len=%d",
            tgid,
            uid,
            addrlen
        );
    }

    /* Observation only. */
    return ret;
}
