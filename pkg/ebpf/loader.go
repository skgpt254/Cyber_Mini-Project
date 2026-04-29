// Package ebpf documents the eBPF kernel-space component of eRDS and provides
// shared constants that must stay in sync between the C probe and the Go agent.
//
// The kernel probe (bpf/monitor.bpf.c) is attached to the
// tracepoint/syscalls/sys_enter_write hook.  It fires on every write(2) system
// call system-wide and pushes an event_t record into a BPF_MAP_TYPE_RINGBUF.
//
// Key design decisions:
//   - Ring buffer (not perf buffer): zero-copy, no per-CPU fragmentation.
//   - CO-RE (Compile Once – Run Everywhere): the .bpf.c file uses vmlinux.h so
//     it carries no runtime kernel header dependency.
//   - 128-byte sample: enough for Shannon entropy to converge while keeping the
//     per-event ring buffer cost minimal (160 bytes total including metadata).
//   - Minimum write size filter (16 bytes): drops stdout/log noise in-kernel
//     before the ring buffer is touched, reducing user-space CPU load.
package ebpf

const (
        // MinWriteBytes is the minimum write(2) payload size (in bytes) that the
        // eBPF probe will forward to user space.  Writes smaller than this are
        // dropped inside the kernel.  Must match MIN_WRITE_BYTES in monitor.bpf.c.
        MinWriteBytes = 16

        // SampleSize is the number of bytes captured from the write buffer by the
        // eBPF probe.  Must match sizeof(event_t.sample) in monitor.bpf.c.
        SampleSize = 128

        // RingBufSize is the ring buffer capacity in bytes (16 MiB).
        // Must match max_entries in the BPF_MAP_TYPE_RINGBUF definition.
        RingBufSize = 1 << 24
)
