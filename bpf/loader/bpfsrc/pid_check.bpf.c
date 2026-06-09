// SPDX-License-Identifier: GPL-2.0
//
// pid_check.bpf.c — WSL2 BPF-visible PID detection probe
//
// This minimal BPF program attaches as a kprobe on __sys_connect.
// When triggered, it captures the current process's TGID, TID, and comm
// from the kernel's perspective via bpf_get_current_pid_tgid() and
// bpf_get_current_comm(). The result is sent to userspace via a ring buffer.
//
// On WSL2, bpf_get_current_pid_tgid() returns a DIFFERENT PID than what
// userspace sees via getpid() / /proc. This probe is used to detect the
// BPF-visible PID so that the PID filter map can be populated correctly.
//
// Build (run from project root E:/Work/kyanos):
//
//   clang -g -O2 -target bpf \
//     -D__TARGET_ARCH_x86_64 \
//     -I./vmlinux/x86/ \
//     -I./.output/ \
//     -c bpf/loader/bpfsrc/pid_check.bpf.c \
//     -o bpf/loader/pid_check.bpf.o
//
// The compiled .o is embedded into the Go binary via //go:embed in
// wsl2_loader.go and loaded at runtime using cilium/ebpf's
// LoadCollectionSpecFromReader().
//
// NOTE: The vmlinux header path (vmlinux/x86/vmlinux_601.h) is relative
// to the project root. CO-RE relocations are resolved at load time using
// the running kernel's BTF, so the .o is portable across kernel versions.

#include "vmlinux_601.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8192);
} dbg_rb SEC(".maps");

// Capture ALL connect calls, record tgid, tid and comm
SEC("kprobe/__sys_connect")
int BPF_KPROBE(kprobe_all_connect) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    // Also get the comm (process name)
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    struct {
        u32 tgid;
        u32 tid;
        char comm[16];
    } *evt;

    evt = bpf_ringbuf_reserve(&dbg_rb, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->tgid = tgid;
    evt->tid = tid;
    bpf_probe_read_kernel_str(evt->comm, sizeof(evt->comm), comm);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
