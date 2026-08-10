#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "mori_observer.skel.h"

#define MORI_MONITOR_PATH \
    "/usr/local/lib/copyfail-detector/mori_integrity_watch.py"

#define MORI_CGROUP_PROCS \
    "/sys/fs/cgroup/system.slice/mori-integrity.service/cgroup.procs"

#define MORI_MAX_TRUSTED_TGIDS 32

static const unsigned char expected_monitor_sha256[32] = {
    0x20, 0xa5, 0xd6, 0x90, 0xdb, 0x4d, 0x2a, 0xfc,
    0xd4, 0xaa, 0x8b, 0x67, 0x46, 0xb9, 0x57, 0x5c,
    0x1d, 0x18, 0x13, 0xdb, 0x29, 0x0b, 0x1a, 0xa1,
    0xe8, 0xa6, 0x43, 0x7d, 0xd6, 0x84, 0x88, 0xe5
};

static volatile sig_atomic_t exiting = 0;

static void handle_signal(int sig)
{
    (void)sig;
    exiting = 1;
}

static void print_digest(FILE *stream,
                         const unsigned char *digest,
                         unsigned int len)
{
    unsigned int i;

    for (i = 0; i < len; i++)
        fprintf(stream, "%02x", digest[i]);
}

static int sha256_file(const char *path, unsigned char digest[32])
{
    EVP_MD_CTX *ctx = NULL;
    FILE *fp = NULL;
    unsigned char buffer[4096];
    unsigned int digest_len = 0;
    size_t n;
    int ret = -1;

    fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr,
                "MORI: failed to open monitor for hashing: %s\n",
                strerror(errno));
        goto out;
    }

    ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fprintf(stderr,
                "MORI: failed to allocate SHA-256 context\n");
        goto out;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        fprintf(stderr,
                "MORI: failed to initialize SHA-256\n");
        goto out;
    }

    while ((n = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
        if (EVP_DigestUpdate(ctx, buffer, n) != 1) {
            fprintf(stderr,
                    "MORI: SHA-256 update failed\n");
            goto out;
        }
    }

    if (ferror(fp)) {
        fprintf(stderr,
                "MORI: failed while reading monitor file\n");
        goto out;
    }

    if (EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1) {
        fprintf(stderr,
                "MORI: SHA-256 finalization failed\n");
        goto out;
    }

    if (digest_len != 32) {
        fprintf(stderr,
                "MORI: unexpected SHA-256 length: %u\n",
                digest_len);
        goto out;
    }

    ret = 0;

out:
    EVP_MD_CTX_free(ctx);

    if (fp)
        fclose(fp);

    return ret;
}

static int verify_monitor_file(void)
{
    struct stat st;
    unsigned char observed[32];

    if (stat(MORI_MONITOR_PATH, &st) != 0) {
        fprintf(stderr,
                "MORI: failed to stat monitor: %s\n",
                strerror(errno));
        return -1;
    }

    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr,
                "MORI: trust refused: monitor is not a regular file\n");
        return -1;
    }

    if (st.st_uid != 0) {
        fprintf(stderr,
                "MORI: trust refused: monitor is not root-owned\n");
        return -1;
    }

    if (st.st_mode & (S_IWGRP | S_IWOTH)) {
        fprintf(stderr,
                "MORI: trust refused: monitor is group/world writable\n");
        return -1;
    }

    if (sha256_file(MORI_MONITOR_PATH, observed) != 0)
        return -1;

    if (memcmp(observed,
               expected_monitor_sha256,
               sizeof(expected_monitor_sha256)) != 0) {

        fprintf(stderr,
                "MORI: trust refused: monitor SHA-256 mismatch\n");

        fprintf(stderr, "MORI: expected: ");
        print_digest(stderr,
                     expected_monitor_sha256,
                     sizeof(expected_monitor_sha256));
        fprintf(stderr, "\n");

        fprintf(stderr, "MORI: observed: ");
        print_digest(stderr, observed, sizeof(observed));
        fprintf(stderr, "\n");

        return -1;
    }

    printf("MORI: monitor ownership and permissions verified.\n");
    printf("MORI: monitor SHA-256 verified: ");
    print_digest(stdout, observed, sizeof(observed));
    printf("\n");

    return 0;
}

static int process_runs_expected_monitor(uint32_t tgid)
{
    char proc_path[64];
    char cmdline[4096];
    FILE *fp;
    size_t n;
    size_t pos = 0;

    snprintf(proc_path,
             sizeof(proc_path),
             "/proc/%u/cmdline",
             tgid);

    fp = fopen(proc_path, "rb");
    if (!fp)
        return 0;

    n = fread(cmdline, 1, sizeof(cmdline) - 1, fp);
    fclose(fp);

    if (n == 0)
        return 0;

    cmdline[n] = '\0';

    /*
     * /proc/<pid>/cmdline is NUL-separated.
     * Compare complete argv entries rather than substring matching.
     */
    while (pos < n) {
        size_t remaining = n - pos;
        size_t len = strnlen(&cmdline[pos], remaining);

        if (len == remaining)
            break;

        if (strcmp(&cmdline[pos], MORI_MONITOR_PATH) == 0)
            return 1;

        pos += len + 1;
    }

    return 0;
}

static int populate_trusted_tgids(struct mori_observer_bpf *skel)
{
    uint32_t candidates[MORI_MAX_TRUSTED_TGIDS];
    uint8_t trusted = 1;
    uint32_t tgid;
    FILE *fp;
    int map_fd;
    int count = 0;
    int i;

    map_fd = bpf_map__fd(skel->maps.trusted_tgids);
    if (map_fd < 0) {
        fprintf(stderr,
                "MORI: failed to obtain trusted_tgids map FD\n");
        return -1;
    }

    fp = fopen(MORI_CGROUP_PROCS, "r");
    if (!fp) {
        fprintf(stderr,
                "MORI: failed to open %s: %s\n",
                MORI_CGROUP_PROCS,
                strerror(errno));
        return -1;
    }

    while (fscanf(fp, "%u", &tgid) == 1) {
        if (!process_runs_expected_monitor(tgid)) {
            fprintf(stderr,
                    "MORI: TGID %u is in service cgroup but "
                    "does not run the expected monitor; skipping\n",
                    tgid);
            continue;
        }

        if (count >= MORI_MAX_TRUSTED_TGIDS) {
            fprintf(stderr,
                    "MORI: too many trusted monitor processes\n");
            fclose(fp);
            return -1;
        }

        candidates[count++] = tgid;
    }

    fclose(fp);

    if (count == 0) {
        fprintf(stderr,
                "MORI: no verified monitor process found\n");
        return -1;
    }

    /*
     * Only update the BPF map after all userspace identity checks
     * have completed.
     */
    for (i = 0; i < count; i++) {
        if (bpf_map_update_elem(
                map_fd,
                &candidates[i],
                &trusted,
                BPF_ANY) != 0) {

            int j;

            fprintf(stderr,
                    "MORI: failed to trust TGID %u: %s\n",
                    candidates[i],
                    strerror(errno));

            /*
             * Roll back any entries inserted during this attempt.
             */
            for (j = 0; j < i; j++)
                bpf_map_delete_elem(map_fd, &candidates[j]);

            return -1;
        }
    }

    for (i = 0; i < count; i++)
        printf("MORI: trusted verified monitor TGID %u\n",
               candidates[i]);

    return 0;
}

int main(void)
{
    struct mori_observer_bpf *skel;
    int trust_granted = 0;
    int err;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    skel = mori_observer_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr,
                "MORI: failed to open/load BPF object\n");
        return 1;
    }

    /*
     * Trust is optional.
     *
     * Verification failure does NOT prevent the observer from
     * attaching. It simply leaves the trust map empty.
     */
    if (verify_monitor_file() == 0) {
        if (populate_trusted_tgids(skel) == 0)
            trust_granted = 1;
    }

    if (!trust_granted) {
        fprintf(stderr,
                "MORI: WARNING: monitor trust was not granted.\n");
        fprintf(stderr,
                "MORI: attaching with an empty trust map.\n");
    }

    err = mori_observer_bpf__attach(skel);
    if (err) {
        fprintf(stderr,
                "MORI: failed to attach BPF program: %d\n",
                err);
        mori_observer_bpf__destroy(skel);
        return 1;
    }

    printf("MORI v2.3.0 observer attached.\n");

    if (trust_granted)
        printf("Verified MORI Monitor reads are suppressed.\n");
    else
        printf("No monitor exemption is active.\n");

    printf("Observation only. No access decisions are modified.\n");
    printf("Press Ctrl-C to stop.\n");

    while (!exiting)
        sleep(1);

    mori_observer_bpf__destroy(skel);

    printf("\nMORI observer detached.\n");

    return 0;
}
