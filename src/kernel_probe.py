#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KernelPulse-eBPF: Real-time kernel-level syscall monitor.
Author: Sala Blanca Operator
"""

from bcc import BPF
import sys

bpf_source = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[256];
};

BPF_PERF_OUTPUT(events);

int trace_execve(struct pt_regs *ctx, const char __user *filename) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user(&data.filename, sizeof(data.filename), (void *)filename);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

b = None

def imprimir_evento(cpu, data, size):
    evento = b["events"].event(data)
    print(
        f"[ALERTA KERNEL] PID: {evento.pid} | UID: {evento.uid} | "
        f"Proceso: {evento.comm.decode('utf-8', 'ignore')} | "
        f"Binario: {evento.filename.decode('utf-8', 'ignore')}",
        flush=True,
    )

def main():
    global b
    print("=== KERNELPULSE-eBPF ACTIVE MONITOR ===", flush=True)
    print("[*] Compilando e inyectando sonda en el Kernel...", flush=True)

    b = BPF(text=bpf_source)
    b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="trace_execve")

    print("[+] Sonda activa. Monitoreando llamadas al sistema en tiempo real. Presiona Ctrl+C para salir.\n", flush=True)
    b["events"].open_perf_buffer(imprimir_evento)

    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\n[-] Desconectando sonda del kernel y limpiando registros...", flush=True)
        sys.exit(0)

if __name__ == "__main__":
    main()
