#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct event_t {
    u32  pid;
    u32  uid;
    char comm[16];
    u64  write_len;
    u64  fd;
    u8   sample[512];
};


#define MIN_WRITE_BYTES 512

static __always_inline void handle_write(struct trace_event_raw_sys_enter *ctx)
{
    u64 write_len = (u64)ctx->args[2];
    if (write_len < MIN_WRITE_BYTES)
        return;

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;

    e->pid       = bpf_get_current_pid_tgid() >> 32;
    e->uid       = (u32)bpf_get_current_uid_gid();
    e->write_len = write_len;
    e->fd        = (u64)ctx->args[0];
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    
    __builtin_memset(e->sample, 0, sizeof(e->sample));


    void *buf = (void *)ctx->args[1];
    bpf_probe_read_user(e->sample, sizeof(e->sample), buf);

    bpf_ringbuf_submit(e, 0);
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_write(struct trace_event_raw_sys_enter *ctx) {
    handle_write(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pwrite64")
int trace_pwrite64(struct trace_event_raw_sys_enter *ctx) {
    handle_write(ctx);
    return 0;
}
