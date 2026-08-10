#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MORI_S_IFMT   00170000
#define MORI_S_IFIFO  0010000
#define MORI_S_ISUID  0004000

SEC("fentry/do_splice")
int BPF_PROG(mori_splice_probe,
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
    __u32 tgid;
    __u32 uid;
    __u32 in_owner;
    __u16 in_mode;
    __u16 out_mode;

    (void)off_in;
    (void)off_out;
    (void)flags;

    if (!in || !out)
        return 0;

    in_inode = BPF_CORE_READ(in, f_inode);
    out_inode = BPF_CORE_READ(out, f_inode);

    if (!in_inode || !out_inode)
        return 0;

    in_owner = BPF_CORE_READ(in_inode, i_uid.val);
    in_mode = BPF_CORE_READ(in_inode, i_mode);
    out_mode = BPF_CORE_READ(out_inode, i_mode);

    pid_tgid = bpf_get_current_pid_tgid();
    tgid = pid_tgid >> 32;

    uid_gid = bpf_get_current_uid_gid();
    uid = (__u32)uid_gid;

    /*
     * First prototype:
     * identify a root-owned SUID input file being spliced to a pipe.
     *
     * Observation only.
     */
    if (in_owner == 0 &&
        (in_mode & MORI_S_ISUID) &&
        ((out_mode & MORI_S_IFMT) == MORI_S_IFIFO)) {

        bpf_printk(
            "MORI SPLICE-SUID-PIPE tgid=%u uid=%u len=%lu",
            tgid,
            uid,
            len
        );
    } else {
        bpf_printk(
            "MORI SPLICE-OTHER tgid=%u uid=%u len=%lu",
            tgid,
            uid,
            len
        );
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
