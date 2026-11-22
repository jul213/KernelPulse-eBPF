#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KernelPulse-eBPF: Real-time kernel-level syscall monitor via tracepoint.
Author: Sala Blanca Operator
"""

from bcc import BPF
import os
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

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), args->filename);

    events.perf_submit(args, &data, sizeof(data));
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
    print("[*] Compilando e inyectando sonda (tracepoint syscalls:sys_enter_execve)...", flush=True)

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
