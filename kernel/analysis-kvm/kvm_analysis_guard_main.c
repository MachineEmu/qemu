// SPDX-License-Identifier: GPL-2.0
/*
 * Lab-only KVM companion module scaffold for the unifi-qemu malware-analysis
 * profile. Low-level KVM hooks stay in C; target policy and timing state live
 * in Rust.
 */

#include <linux/init.h>
#include <linux/debugfs.h>
#include <linux/kprobes.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/timekeeping.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/atomic.h>
#include <generated/utsrelease.h>

#if defined(CONFIG_X86)
#include <asm/cpufeature.h>
#include <asm/msr.h>
#endif

extern void analysis_kvm_policy_configure(bool enable, int target_tgid,
                                          bool hyperv_fast_mode,
                                          u32 tsc_floor_ns);
extern bool analysis_kvm_target_enabled(int tgid);
extern u64 analysis_kvm_adjust_tsc(int tgid, u64 raw_tsc, u64 host_tsc);
extern void analysis_kvm_record_exit(int tgid, u32 reason);
extern void analysis_kvm_record_exit_timing(int tgid, u32 reason, u64 delta_ns);
extern void analysis_kvm_policy_reset(void);

struct analysis_kvm_stats {
    bool lab_enable;
    int target_tgid;
    bool hyperv_fast_mode;
    u32 tsc_floor_ns;
    u64 exits_observed;
    u64 exit_timing_observed;
    u64 exit_ns_total;
    u64 exit_ns_max;
    u64 exit_ns_ewma;
    u64 rdtsc_observed;
    u64 rdtsc_adjusted;
    u64 last_guest_tsc;
    u64 last_host_tsc;
};

extern void analysis_kvm_snapshot_stats(struct analysis_kvm_stats *out);

static bool lab_enable;
module_param(lab_enable, bool, 0600);
MODULE_PARM_DESC(lab_enable,
    "Enable lab-only KVM analysis mitigations. Default: false.");

static int target_tgid = -1;
module_param(target_tgid, int, 0600);
MODULE_PARM_DESC(target_tgid,
    "Optional qemu-system process tgid allowlist. -1 means no target selected.");

static uint tsc_floor_ns = 0;
module_param(tsc_floor_ns, uint, 0600);
MODULE_PARM_DESC(tsc_floor_ns,
    "Reserved timing floor for future RDTSC/RDTSCP smoothing backend.");

static bool hyperv_fast_mode;
module_param(hyperv_fast_mode, bool, 0600);
MODULE_PARM_DESC(hyperv_fast_mode,
    "Records that the target VM is using kvm=off plus Hyper-V enlightenments.");

static bool hook_exits;
module_param(hook_exits, bool, 0600);
MODULE_PARM_DESC(hook_exits,
    "Register target-gated KVM exit timing probes. Default: false.");

static bool hook_tsc;
module_param(hook_tsc, bool, 0600);
MODULE_PARM_DESC(hook_tsc,
    "Register target-gated KVM TSC read probes. Default: false.");

static atomic64_t exit_probe_hits = ATOMIC64_INIT(0);
static atomic64_t tsc_probe_hits = ATOMIC64_INIT(0);
static struct dentry *debugfs_root;

struct exit_probe_data {
    int tgid;
    u64 start_ns;
};

struct tsc_probe_data {
    int tgid;
    u64 host_tsc;
};

static int exit_entry(struct kretprobe_instance *ri, struct pt_regs *regs);
static int exit_return(struct kretprobe_instance *ri, struct pt_regs *regs);
static int tsc_entry(struct kretprobe_instance *ri, struct pt_regs *regs);
static int tsc_return(struct kretprobe_instance *ri, struct pt_regs *regs);

static struct kretprobe vmx_exit_retprobe = {
    .kp.symbol_name = "vmx_handle_exit",
    .entry_handler = exit_entry,
    .handler = exit_return,
    .data_size = sizeof(struct exit_probe_data),
    .maxactive = 64,
};

static struct kretprobe svm_exit_retprobe = {
    .kp.symbol_name = "svm_handle_exit",
    .entry_handler = exit_entry,
    .handler = exit_return,
    .data_size = sizeof(struct exit_probe_data),
    .maxactive = 64,
};

static struct kretprobe kvm_read_l1_tsc_retprobe = {
    .kp.symbol_name = "kvm_read_l1_tsc",
    .entry_handler = tsc_entry,
    .handler = tsc_return,
    .data_size = sizeof(struct tsc_probe_data),
    .maxactive = 256,
};

static bool vmx_exit_retprobe_registered;
static bool svm_exit_retprobe_registered;
static bool kvm_read_l1_tsc_retprobe_registered;

static int exit_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct exit_probe_data *data = (struct exit_probe_data *)ri->data;
    int tgid = task_tgid_nr(current);

    if (!analysis_kvm_target_enabled(tgid)) {
        return 1;
    }

    atomic64_inc(&exit_probe_hits);
    data->tgid = tgid;
    data->start_ns = ktime_get_mono_fast_ns();
    return 0;
}

static int exit_return(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct exit_probe_data *data = (struct exit_probe_data *)ri->data;
    u64 stop_ns;
    u64 delta_ns;

    if (data->tgid < 1 || data->start_ns == 0) {
        return 0;
    }

    stop_ns = ktime_get_mono_fast_ns();
    delta_ns = stop_ns >= data->start_ns ? stop_ns - data->start_ns : 0;
    analysis_kvm_record_exit_timing(data->tgid, 0, delta_ns);
    return 0;
}

static int tsc_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct tsc_probe_data *data = (struct tsc_probe_data *)ri->data;
    int tgid = task_tgid_nr(current);

    if (!analysis_kvm_target_enabled(tgid)) {
        return 1;
    }

    atomic64_inc(&tsc_probe_hits);
    data->tgid = tgid;
    data->host_tsc = regs_get_kernel_argument(regs, 1);
    return 0;
}

static int tsc_return(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct tsc_probe_data *data = (struct tsc_probe_data *)ri->data;
    u64 raw_tsc;
    u64 adjusted_tsc;

    if (data->tgid < 1) {
        return 0;
    }

    raw_tsc = regs_return_value(regs);
    adjusted_tsc = analysis_kvm_adjust_tsc(data->tgid, raw_tsc, data->host_tsc);
    if (adjusted_tsc != raw_tsc) {
        regs_set_return_value(regs, adjusted_tsc);
    }
    return 0;
}

static void unregister_exit_probes(void)
{
    if (vmx_exit_retprobe_registered) {
        unregister_kretprobe(&vmx_exit_retprobe);
        vmx_exit_retprobe_registered = false;
    }
    if (svm_exit_retprobe_registered) {
        unregister_kretprobe(&svm_exit_retprobe);
        svm_exit_retprobe_registered = false;
    }
}

static void unregister_tsc_probe(void)
{
    if (kvm_read_l1_tsc_retprobe_registered) {
        unregister_kretprobe(&kvm_read_l1_tsc_retprobe);
        kvm_read_l1_tsc_retprobe_registered = false;
    }
}

static void register_exit_probes(void)
{
    int ret;

    if (!hook_exits) {
        pr_info("kvm_analysis_guard: KVM exit timing probes disabled; set hook_exits=1 to observe target exits\n");
        return;
    }

    ret = register_kretprobe(&vmx_exit_retprobe);
    if (ret) {
        pr_info("kvm_analysis_guard: vmx_handle_exit retprobe unavailable: %d\n",
                ret);
    } else {
        vmx_exit_retprobe_registered = true;
        pr_info("kvm_analysis_guard: vmx_handle_exit retprobe registered\n");
    }

    ret = register_kretprobe(&svm_exit_retprobe);
    if (ret) {
        pr_info("kvm_analysis_guard: svm_handle_exit retprobe unavailable: %d\n",
                ret);
    } else {
        svm_exit_retprobe_registered = true;
        pr_info("kvm_analysis_guard: svm_handle_exit retprobe registered\n");
    }
}

static void register_tsc_probe(void)
{
    int ret;

    if (!hook_tsc) {
        pr_info("kvm_analysis_guard: KVM TSC read probe disabled; set hook_tsc=1 to observe KVM TSC reads\n");
        return;
    }

    ret = register_kretprobe(&kvm_read_l1_tsc_retprobe);
    if (ret) {
        pr_info("kvm_analysis_guard: kvm_read_l1_tsc retprobe unavailable: %d\n",
                ret);
    } else {
        kvm_read_l1_tsc_retprobe_registered = true;
        pr_info("kvm_analysis_guard: kvm_read_l1_tsc retprobe registered\n");
    }
}

static int stats_show(struct seq_file *m, void *v)
{
    struct analysis_kvm_stats stats;

    analysis_kvm_snapshot_stats(&stats);

    seq_printf(m, "lab_enable: %u\n", stats.lab_enable);
    seq_printf(m, "target_tgid: %d\n", stats.target_tgid);
    seq_printf(m, "hyperv_fast_mode: %u\n", stats.hyperv_fast_mode);
    seq_printf(m, "tsc_floor_ns: %u\n", stats.tsc_floor_ns);
    seq_printf(m, "exit_probe_hits: %lld\n", atomic64_read(&exit_probe_hits));
    seq_printf(m, "tsc_probe_hits: %lld\n", atomic64_read(&tsc_probe_hits));
    seq_printf(m, "exits_observed: %llu\n", stats.exits_observed);
    seq_printf(m, "exit_timing_observed: %llu\n", stats.exit_timing_observed);
    seq_printf(m, "exit_ns_total: %llu\n", stats.exit_ns_total);
    seq_printf(m, "exit_ns_max: %llu\n", stats.exit_ns_max);
    seq_printf(m, "exit_ns_ewma: %llu\n", stats.exit_ns_ewma);
    seq_printf(m, "rdtsc_observed: %llu\n", stats.rdtsc_observed);
    seq_printf(m, "rdtsc_adjusted: %llu\n", stats.rdtsc_adjusted);
    seq_printf(m, "last_guest_tsc: %llu\n", stats.last_guest_tsc);
    seq_printf(m, "last_host_tsc: %llu\n", stats.last_host_tsc);

    return 0;
}

static int stats_open(struct inode *inode, struct file *file)
{
    return single_open(file, stats_show, inode->i_private);
}

static const struct file_operations stats_fops = {
    .owner = THIS_MODULE,
    .open = stats_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

static void init_debugfs(void)
{
    debugfs_root = debugfs_create_dir("kvm_analysis_guard", NULL);
    if (IS_ERR_OR_NULL(debugfs_root)) {
        pr_info("kvm_analysis_guard: debugfs unavailable\n");
        debugfs_root = NULL;
        return;
    }

    debugfs_create_file("stats", 0400, debugfs_root, NULL, &stats_fops);
}

static int __init kvm_analysis_guard_init(void)
{
    pr_info("kvm_analysis_guard: loading for kernel %s\n", UTS_RELEASE);

    analysis_kvm_policy_configure(lab_enable, target_tgid, hyperv_fast_mode,
                                  tsc_floor_ns);
    atomic64_set(&exit_probe_hits, 0);
    atomic64_set(&tsc_probe_hits, 0);
    init_debugfs();

    if (!lab_enable) {
        pr_info("kvm_analysis_guard: inactive; set lab_enable=1 to arm lab-only controls\n");
        return 0;
    }

    if (target_tgid < 1) {
        pr_warn("kvm_analysis_guard: lab_enable=1 without target_tgid; refusing active backend\n");
        return 0;
    }

#if defined(CONFIG_X86)
    if (!boot_cpu_has(X86_FEATURE_TSC)) {
        pr_warn("kvm_analysis_guard: host CPU has no TSC feature\n");
    }
    if (!boot_cpu_has(X86_FEATURE_CONSTANT_TSC)) {
        pr_warn("kvm_analysis_guard: host CPU lacks constant_tsc; timing smoothing would be noisy\n");
    }
#else
    pr_warn("kvm_analysis_guard: non-x86 build; no KVM timing backend available\n");
#endif

    if (!analysis_kvm_target_enabled(target_tgid)) {
        pr_warn("kvm_analysis_guard: Rust policy did not arm target_tgid=%d\n",
                target_tgid);
        return 0;
    }

    /*
     * Exercise the Rust policy path without changing guest-visible behavior.
     * Active KVM hooks will call these functions once the hook backend lands.
     */
    (void)analysis_kvm_adjust_tsc(target_tgid, 0, 0);
    analysis_kvm_record_exit(target_tgid, 0);
    register_exit_probes();
    register_tsc_probe();

    pr_info("kvm_analysis_guard: armed for tgid=%d hyperv_fast_mode=%d tsc_floor_ns=%u hook_exits=%d hook_tsc=%d\n",
            target_tgid, hyperv_fast_mode, tsc_floor_ns, hook_exits, hook_tsc);
    return 0;
}

static void __exit kvm_analysis_guard_exit(void)
{
    unregister_exit_probes();
    unregister_tsc_probe();
    debugfs_remove_recursive(debugfs_root);
    analysis_kvm_policy_reset();
    pr_info("kvm_analysis_guard: unloaded\n");
}

module_init(kvm_analysis_guard_init);
module_exit(kvm_analysis_guard_exit);

MODULE_DESCRIPTION("Lab-only KVM analysis guard scaffold for unifi-qemu");
MODULE_AUTHOR("unifi-qemu contributors");
MODULE_LICENSE("GPL");
