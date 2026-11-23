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

    /* En x86_64, el primer argumento de la syscall (filename) viaja en el registro di */
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