#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define MORI_S_ISUID   0004000
#define MORI_MAY_READ  0x00000004

#define MORI_S_IFMT    00170000
#define MORI_S_IFIFO   0010000

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
 * MORI v2.7 lifecycle-aware AEAD state.
 *
 * AF_ALG AEAD sockets are tracked by socket lifetime rather than by
 * an attacker-controllable time window.
 *
 * Parent/listening socket:
 *     MORI_AEAD_CANDIDATE
 *
 * Accepted operation socket:
 *     MORI_AEAD_ACTIVE
 */

#define MORI_AEAD_CANDIDATE 1
#define MORI_AEAD_ACTIVE    2

struct mori_aead_socket_state {
    __u32 owner_tgid;
    __u8 state;
    __u8 counted;
    __u16 reserved;
};

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 0);
    __type(key, int);
    __type(value, struct mori_aead_socket_state);
} aead_socket_state SEC(".maps");

/*
 * Number of currently active AEAD operation sockets associated with a
 * TGID. This is what enforcement will consult.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} active_aead_tgids SEC(".maps");

/*
 * MORI v2.7 transient splice state.
 *
 * Keyed by TID, not TGID. The state will exist only while that exact
 * thread is executing the relevant do_splice() operation.
 *
 * It will be armed at fentry/do_splice and removed at fexit/do_splice.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} splice_active_tids SEC(".maps");

/*
 * MORI v2.7 structured deny telemetry.
 *
 * Enforcement must not depend on event delivery. If the ring buffer is
 * full or userspace is unavailable, the LSM decision still returns EPERM.
 */
enum mori_event_type {
    MORI_EVENT_DENY = 1,
};

struct mori_event {
    __u64 timestamp_ns;
    __u32 tgid;
    __u32 uid;
    __u32 type;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

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
    __u32 tid;
    __u16 mode;
    __u8 *trusted;
    __u32 *active_aead;
    __u8 *splice_active;

    /* Preserve previous LSM decisions. */
    if (ret != 0)
        return ret;

    if (!file)
        return ret;

    uid_gid = bpf_get_current_uid_gid();
    uid = (__u32)uid_gid;

    if (uid == 0)
        return ret;

    if (!(mask & MORI_MAY_READ))
        return ret;

    inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return ret;

    owner = BPF_CORE_READ(inode, i_uid.val);
    mode = BPF_CORE_READ(inode, i_mode);

    if (owner != 0)
        return ret;

    if (!(mode & MORI_S_ISUID))
        return ret;

    pid_tgid = bpf_get_current_pid_tgid();
    tgid = pid_tgid >> 32;
    tid = (__u32)pid_tgid;

    /*
     * Trusted MORI Monitor processes may perform ordinary SUID reads.
     */
    trusted = bpf_map_lookup_elem(&trusted_tgids, &tgid);
    if (trusted && *trusted)
        return ret;

    /*
     * v2.7 enforcement is lifecycle/state based:
     *
     * active_aead_tgids[TGID] > 0
     *     this process owns a live relevant AEAD operation socket
     *
     * splice_active_tids[TID] == 1
     *     this exact thread is currently inside a root-SUID -> pipe
     *     splice operation
     */
    active_aead =
        bpf_map_lookup_elem(&active_aead_tgids, &tgid);

    splice_active =
        bpf_map_lookup_elem(&splice_active_tids, &tid);

    if (active_aead && *active_aead > 0 &&
        splice_active && *splice_active) {
        struct mori_event *event;
        __u64 now;

        /*
         * Time remains useful for telemetry, but no longer decides
         * whether enforcement occurs.
         */
        now = bpf_ktime_get_ns();

        event = bpf_ringbuf_reserve(
            &events,
            sizeof(*event),
            0
        );

        if (event) {
            event->timestamp_ns = now;
            event->tgid = tgid;
            event->uid = uid;
            event->type = MORI_EVENT_DENY;
            bpf_ringbuf_submit(event, 0);
        }

        bpf_printk(
            "MORI v2.7 DENY-AEAD-SPLICE-SUID tgid=%u tid=%u uid=%u",
            tgid,
            tid,
            uid
        );

        return -1; /* -EPERM */
    }

    if (active_aead && *active_aead > 0) {
        bpf_printk(
            "MORI v2.7 ACTIVE-AEAD-SUID tgid=%u tid=%u uid=%u",
            tgid,
            tid,
            uid
        );

        return ret;
    }

    if (splice_active && *splice_active) {
        bpf_printk(
            "MORI v2.7 ACTIVE-SPLICE-SUID tgid=%u tid=%u uid=%u",
            tgid,
            tid,
            uid
        );

        return ret;
    }

    bpf_printk(
        "MORI v2.7 READ-SUID tgid=%u tid=%u uid=%u mask=%d",
        tgid,
        tid,
        uid,
        mask
    );

    return ret;
}

char LICENSE[] SEC("license") = "GPL";

/*
 * MORI v2.7
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

/*
 * MORI v2.7 AF_ALG AEAD lifecycle tracking.
 *
 * socket_bind:
 *     mark the bound AF_ALG AEAD socket as a candidate.
 *
 * socket_accept:
 *     propagate candidate state to the accepted operation socket and
 *     increment the owning TGID's active AEAD count.
 *
 * sock_release:
 *     decrement the count when an active operation socket is released.
 */

static __always_inline int mori_active_aead_inc(__u32 tgid)
{
    __u32 one = 1;
    __u32 *count;

    count = bpf_map_lookup_elem(&active_aead_tgids, &tgid);
    if (!count)
        return bpf_map_update_elem(
            &active_aead_tgids,
            &tgid,
            &one,
            BPF_NOEXIST
        );

    __sync_fetch_and_add(count, 1);
    return 0;
}

static __always_inline void mori_active_aead_dec(__u32 tgid)
{
    __u32 *count;

    count = bpf_map_lookup_elem(&active_aead_tgids, &tgid);
    if (!count)
        return;

    /*
     * Keep zero-valued TGID entries rather than racing a concurrent
     * increment against deletion. Enforcement checks count > 0.
     */
    if (*count > 0)
        __sync_fetch_and_add(count, (__u32)-1);
}

SEC("lsm/socket_bind")
int BPF_PROG(mori_socket_bind_observer,
             struct socket *sock,
             struct sockaddr *address,
             int addrlen,
             int ret)
{
    struct sock *sk;
    struct mori_aead_socket_state init = {};
    struct mori_aead_socket_state *state;
    __u64 uid_gid;
    __u64 pid_tgid;
    __u32 uid;
    __u32 tgid;
    sa_family_t family;
    int state_err;

    if (ret != 0)
        return ret;

    if (!sock || !address)
        return ret;

    family = address->sa_family;
    if (family != MORI_AF_ALG)
        return ret;

    if (!mori_sockaddr_type_is_aead(address, addrlen))
        return ret;

    sk = sock->sk;
    if (!sk)
        return ret;

    pid_tgid = bpf_get_current_pid_tgid();
    tgid = pid_tgid >> 32;

    uid_gid = bpf_get_current_uid_gid();
    uid = (__u32)uid_gid;

    init.owner_tgid = tgid;
    init.state = MORI_AEAD_CANDIDATE;
    init.counted = 0;

    state = bpf_sk_storage_get(
        &aead_socket_state,
        sk,
        &init,
        BPF_LOCAL_STORAGE_GET_F_CREATE
    );

    if (!state) {
        bpf_printk(
            "MORI v2.7 AEAD-CANDIDATE-FAIL tgid=%u uid=%u",
            tgid,
            uid
        );
        return ret;
    }

    state->owner_tgid = tgid;

    if (!state->counted) {
        state_err = mori_active_aead_inc(tgid);

        if (state_err != 0) {
            bpf_printk(
                "MORI v2.7 AEAD-ACTIVE-COUNT-FAIL tgid=%u uid=%u",
                tgid,
                uid
            );
            return ret;
        }

        state->counted = 1;
    }

    state->state = MORI_AEAD_ACTIVE;

    bpf_printk(
        "MORI v2.7 AEAD-ACTIVE tgid=%u uid=%u len=%d",
        tgid,
        uid,
        addrlen
    );

    return ret;
}

SEC("lsm/socket_accept")
int BPF_PROG(mori_socket_accept_observer,
             struct socket *sock,
             struct socket *newsock,
             int ret)
{
    struct sock *parent_sk;
    struct mori_aead_socket_state *state;
    __u64 pid_tgid;
    __u32 tgid;

    if (ret != 0)
        return ret;

    if (!sock || !newsock)
        return ret;

    parent_sk = sock->sk;
    if (!parent_sk)
        return ret;

    state = bpf_sk_storage_get(
        &aead_socket_state,
        parent_sk,
        0,
        0
    );

    /*
     * Ignore ordinary socket accepts completely.
     * Telemetry is emitted only when the parent socket is one of
     * MORI's tracked AF_ALG AEAD sockets.
     */
    if (!state)
        return ret;

    if (state->state != MORI_AEAD_ACTIVE)
        return ret;

    pid_tgid = bpf_get_current_pid_tgid();
    tgid = pid_tgid >> 32;

    bpf_printk(
        "MORI v2.7 AEAD-ACCEPT-OBSERVED tgid=%u",
        tgid
    );

    return ret;
}

SEC("fentry/__sock_release")
int BPF_PROG(mori_sock_release_observer,
             struct socket *sock,
             struct inode *inode)
{
    (void)inode;
    struct sock *sk;
    struct mori_aead_socket_state *state;
    __u32 owner_tgid;

    if (!sock)
        return 0;

    sk = sock->sk;
    if (!sk)
        return 0;

    state = bpf_sk_storage_get(
        &aead_socket_state,
        sk,
        0,
        0
    );

    if (!state)
        return 0;

    if (state->state != MORI_AEAD_ACTIVE || !state->counted)
        return 0;

    owner_tgid = state->owner_tgid;

    mori_active_aead_dec(owner_tgid);

    /*
     * Mark uncounted before kernel socket teardown. Socket-local
     * storage itself is automatically destroyed with the socket.
     */
    state->counted = 0;

    bpf_printk(
        "MORI v2.7 AEAD-RELEASE tgid=%u",
        owner_tgid
    );

    return 0;
}

/*
 * MORI v2.7 root-owned SUID -> pipe splice lifecycle tracking.
 */

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
    __u32 tid;
    __u32 tgid;
    __u32 uid;
    __u32 in_owner;
    __u16 in_mode;
    __u16 out_mode;
    __u8 one = 1;
    int state_err;

    (void)off_in;
    (void)off_out;
    (void)flags;

    if (!in || !out)
        return 0;

    uid_gid = bpf_get_current_uid_gid();
    uid = (__u32)uid_gid;

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
    tid = (__u32)pid_tgid;

    /*
     * v2.7: this state exists only for the lifetime of this exact
     * do_splice() invocation. No temporal grace window is involved.
     */
    state_err = bpf_map_update_elem(
        &splice_active_tids,
        &tid,
        &one,
        BPF_ANY
    );

    if (state_err == 0) {
        bpf_printk(
            "MORI v2.7 SPLICE-ARM tgid=%u tid=%u uid=%u len=%lu",
            tgid,
            tid,
            uid,
            len
        );
    } else {
        bpf_printk(
            "MORI v2.7 SPLICE-STATE-FAIL tgid=%u tid=%u uid=%u",
            tgid,
            tid,
            uid
        );
    }

    return 0;
}

SEC("fexit/do_splice")
int BPF_PROG(mori_splice_exit,
             struct file *in,
             loff_t *off_in,
             struct file *out,
             loff_t *off_out,
             size_t len,
             unsigned int flags,
             ssize_t ret)
{
    __u64 pid_tgid;
    __u32 tgid;
    __u32 tid;
    int deleted;

    (void)in;
    (void)off_in;
    (void)out;
    (void)off_out;
    (void)len;
    (void)flags;

    pid_tgid = bpf_get_current_pid_tgid();
    tgid = pid_tgid >> 32;
    tid = (__u32)pid_tgid;

    deleted = bpf_map_delete_elem(
        &splice_active_tids,
        &tid
    );

    /*
     * Log only when this invocation actually carried MORI splice
     * state. ret is telemetry, not part of the enforcement decision.
     */
    if (deleted == 0) {
        bpf_printk(
            "MORI v2.7 SPLICE-DISARM tgid=%u tid=%u ret=%ld",
            tgid,
            tid,
            (long)ret
        );
    }

    return 0;
}
