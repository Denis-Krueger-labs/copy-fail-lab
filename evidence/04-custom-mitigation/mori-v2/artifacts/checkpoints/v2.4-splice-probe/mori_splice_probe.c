#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "mori_splice_probe.skel.h"

static volatile sig_atomic_t exiting = 0;

static void handle_signal(int sig)
{
    (void)sig;
    exiting = 1;
}

int main(void)
{
    struct mori_splice_probe_bpf *skel;
    int err;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    skel = mori_splice_probe_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr,
                "MORI: splice fentry verifier probe FAILED\n");
        return 1;
    }

    printf("MORI: splice fentry verifier probe PASSED\n");

    err = mori_splice_probe_bpf__attach(skel);
    if (err) {
        fprintf(stderr,
                "MORI: splice fentry attach FAILED: %d\n",
                err);
        mori_splice_probe_bpf__destroy(skel);
        return 1;
    }

    printf("MORI: fentry/do_splice attached.\n");
    printf("Observation only. Press Ctrl-C to stop.\n");

    while (!exiting)
        sleep(1);

    mori_splice_probe_bpf__destroy(skel);
    return 0;
}
