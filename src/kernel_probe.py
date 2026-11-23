#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KernelPulse-eBPF: Real-time kernel-level execve monitor & path risk classifier.
Hook: raw_tracepoint/sys_enter filtered by __NR_execve.
"""

from bcc import BPF
import argparse
import datetime
import json
import os
import sys

RUTAS_CRITICAS = ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/shm/")
PREFIJOS_SISTEMA_ROOT = ("/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/", "/vscode/", "/proc/")

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

    /* En arquitectura x86_64 ABI de syscalls, el 1er argumento (filename) reside en di */
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
log_handle = None
solo_alertas = False


def clasificar_evento(uid: int, binario: str) -> tuple[str, str]:
    if binario.startswith(RUTAS_CRITICAS):
        return ("CRITICO", "Ejecucion desde ruta temporal/volatil de alto riesgo")
    if uid == 0 and binario != "<desconocido>" and not binario.startswith(PREFIJOS_SISTEMA_ROOT):
        return ("PRIVILEGIO", "Proceso root ejecutando binario fuera de rutas estandar")
    return ("INFO", "Ejecucion observada")


def manejar_evento(cpu, data, size):
    evento = b["eventso"].event(data)
    binario = evento.filename.decode("utf-8", "ignore") or "<desconocido>"
    proceso = evento.comm.decode("utf-8", "ignore")
    pid = int(evento.pid)
    uid = int(evento.uid)

    severidad, motivo = clasificar_evento(uid, binario)
    if solo_alertas and severidad == "INFO":
        return

    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    print(
        f"[{severidad}] {ts} | PID: {pid} | UID: {uid} | "
        f"Proceso: {proceso} | Binario: {binario} | Motivo: {motivo}",
        flush=True,
    )

    if log_handle is not None:
        registro = {
            "timestamp_utc": ts,
            "severidad": severidad,
            "pid": pid,
            "uid": uid,
            "proceso": proceso,
            "binario": binario,
            "motivo": motivo,
        }
        log_handle.write(json.dumps(registro, ensure_ascii=False) + "\n")
        log_handle.flush()


def parse_args():
    parser = argparse.ArgumentParser(description="KernelPulse-eBPF execve security monitor")
    parser.add_argument(
        "--solo-alertas",
        action="store_true",
        help="Muestra y registra unicamente eventos CRITICO o PRIVILEGIO",
    )
    parser.add_argument(
        "--log-file",
        type=str,
        default=None,
        help="Ruta opcional para guardar eventos en formato JSON Lines (.jsonl)",
    )
    return parser.parse_args()


def main():
    global b, log_handle, solo_alertas
    args = parse_args()
    solo_alertas = args.solo_alertas

    if args.log_file:
        log_handle = open(args.log_file, "a", encoding="utf-8")

    print("=== KERNELPULSE-eBPF ACTIVE MONITOR ===", flush=True)
    print("[*] Compilando e inyectando sonda (raw_tracepoint/sys_enter -> __NR_execve)...", flush=True)

    b = BPF(text=bpf_source)
    b["events"].open_perf_buffer(manejar_evento)

    print("[+] Sonda activa. Ctrl+C para desconectar.\n", flush=True)

    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\n[-] Desconectando sonda del kernel y cerrando recursos...", flush=True)
        if log_handle is not None:
            log_handle.close()
        os._exit(0)


if __name__ == "__main__":
    main()
