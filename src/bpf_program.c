#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

struct data_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[256];

};

BPF_PERF_OUTPUT(events);

int trace_execve(struct pt_regs *ctx, const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp) {
    struct data_t data = {};
    
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // Copiar el nombre del binario ejecutado desde el espacio de usuario al kernel
    bpf_probe_read_user(&data.filename, sizeof(data.filename), (void *)filename);

    // Enviar evento al canal de usuario
    events.perf_submit(ctx, &data, sizeof(data));
    
    return 0;
}