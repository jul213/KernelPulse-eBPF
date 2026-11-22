#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KernelPulse-eBPF: Real-time kernel-level execve monitor via raw_tracepoint.
Author: Sala Blanca Operator
"""

from bcc import BPF
import os
import sys

bpf_source = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <asm/unistd_64.h>

struct data_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[256];
};

BPF_PERF_OUTPUT(events);

RAW_TRACEPOINT_PROBE(sys_enter) {
    unsigned long syscall_id = ctx->args[1];
    if (syscall_id != __NR_execve) {
        return 0;
    }

    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
    const char __user *filename_ptr = NULL;

    /* En x86_64, el primer argumento de una syscall (filename) viaja en di */
    bpf_probe_read_kernel(&filename_ptr, sizeof(filename_ptr), &regs->di);

    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    if (filename_ptr != NULL) {
        bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename_ptr);
    }

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

b = None

def imprimir_evento(cpu, data, size):
    evento = b["events"].event(data)
    binario = evento.filename.decode("utf-8", "ignore") or "<desconocido>"
    proceso = evento.comm.decode("utf-8", "ignore")
    print(
        f"[ALERTA KERNEL] PID: {evento.pid} | UID: {evento.uid} | "
        f"Proceso: {proceso} | Binario: {binario}",
        flush=True,
    )

def main():
    global b
    print("=== KERNELPULSE-eBPF ACTIVE MONITOR ===", flush=True)
    print("[*] Compilando e inyectando sonda (raw_tracepoint/sys_enter)...", flush=True)

    b = BPF(text=bpf_source)

    print("[+] Sonda activa. Monitoreando llamadas al sistema en tiempo real. Presiona Ctrl+C para salir.\n", flush=True)
    b["events"].open_perf_buffer(imprimir_evento)

    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\n[-] Desconectando sonda del kernel y limpiando registros...", flush=True)
        os._exit(0)

if __name__ == "__main__":
    main()
