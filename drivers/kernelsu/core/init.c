#include <linux/export.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/jiffies.h>
#include <linux/kmod.h>

#include "policy/allowlist.h"
#include "policy/app_profile.h"
#include "policy/feature.h"
#include "klog.h" // IWYU pragma: keep
#include "manager/manager_identity.h"
#include "manager/manager_observer.h"
#include "manager/throne_tracker.h"
#include "hook/hook_manager.h"
#include "runtime/ksud.h"
#include "runtime/ksud_boot.h"
#include "supercall/supercall.h"
#include "ksu.h"
#include "feature/sulog.h"
#include "infra/file_wrapper.h"
#include "selinux/selinux.h"
#include "feature/selinux_hide.h"
#include "feature/adb_root.h"

extern void __init ksu_lsm_hook_init(void);
extern int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr,
				void *argv, void *envp, int *flags);
extern int ksu_handle_execveat_ksud(int *fd, struct filename **filename_ptr,
			    void *argv, void *envp, int *flags);
int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv,
		void *envp, int *flags)
{
	ksu_handle_execveat_ksud(fd, filename_ptr, argv, envp, flags);
	return ksu_handle_execveat_sucompat(fd, filename_ptr, argv, envp,
					    flags);
}

#if defined(CONFIG_STACKPROTECTOR) &&                                          \
    (defined(CONFIG_ARM64) && defined(MODULE) &&                               \
     !defined(CONFIG_STACKPROTECTOR_PER_TASK))
#include <linux/stackprotector.h>
#include <linux/random.h>
unsigned long __stack_chk_guard __ro_after_init
    __attribute__((visibility("hidden")));

__attribute__((no_stack_protector)) void __init ksu_setup_stack_chk_guard()
{
    unsigned long canary;
    get_random_bytes(&canary, sizeof(canary));
    canary ^= LINUX_VERSION_CODE;
    canary &= CANARY_MASK;
    __stack_chk_guard = canary;
}

__attribute__((naked)) int __init ksu_init_early(void)
{
    asm("mov x19, x30;\n"
        "bl ksu_setup_stack_chk_guard;\n"
        "mov x30, x19;\n"
        "b kernelsu_init;\n");
}
#define NEED_OWN_STACKPROTECTOR 1
#else
#define NEED_OWN_STACKPROTECTOR 0
#endif

struct cred *ksu_cred;
bool ksu_late_loaded;

/*
 * Manual hook boot work: retry track_throne, trigger boot events,
 * and spawn ksud for module mounting since init.rc injection
 * doesn't work without kprobes.
 */
static struct delayed_work ksu_boot_delayed_work;
static struct delayed_work ksu_spawn_ksud_delayed;
static int ksu_boot_retry_count;

#define KSU_BOOT_RETRY_MAX 30
#define KSU_BOOT_RETRY_DELAY msecs_to_jiffies(2000)
#define KSU_KSUD_DELAY msecs_to_jiffies(8000)

static void ksu_spawn_ksud_func(struct work_struct *work)
{
	char *envp[] = {
		"HOME=/",
		"PATH=/sbin:/bin:/system/bin:/vendor/bin",
		NULL
	};
	char *argv_postfs[] = {
		KSUD_PATH, "post-fs-data", NULL
	};
	char *argv_bootcompl[] = {
		KSUD_PATH, "boot-completed", NULL
	};
	int ret;

	pr_info("manual hook: spawning ksud post-fs-data...\n");
	ret = call_usermodehelper(KSUD_PATH, argv_postfs, envp, UMH_WAIT_EXEC);
	pr_info("manual hook: ksud post-fs-data ret=%d\n", ret);

	pr_info("manual hook: spawning ksud boot-completed...\n");
	ret = call_usermodehelper(KSUD_PATH, argv_bootcompl, envp, UMH_WAIT_EXEC);
	pr_info("manual hook: ksud boot-completed ret=%d\n", ret);
}

static void ksu_boot_retry_func(struct work_struct *work)
{
	if (ksu_is_manager_appid_valid()) {
		pr_info("manual hook: manager already found\n");
		return;
	}

	ksu_boot_retry_count++;
	pr_info("manual hook: boot retry %d/%d, tracking throne...\n",
		ksu_boot_retry_count, KSU_BOOT_RETRY_MAX);

	track_throne(false);

	if (ksu_is_manager_appid_valid()) {
		pr_info("manual hook: manager found! uid=%d\n",
			ksu_get_manager_appid());
		if (!ksu_boot_completed) {
			ksu_boot_completed = true;
			on_boot_completed();
		}
		return;
	}

	if (ksu_boot_retry_count < KSU_BOOT_RETRY_MAX) {
		schedule_delayed_work(&ksu_boot_delayed_work, KSU_BOOT_RETRY_DELAY);
	} else {
		pr_warn("manual hook: gave up retrying after %d attempts\n",
			KSU_BOOT_RETRY_MAX);
	}
}

static void ksu_boot_delayed_func(struct work_struct *work)
{
	ksu_boot_retry_func(NULL);
}

int __init kernelsu_init(void)
{
#ifdef MODULE
	ksu_late_loaded = (current->pid != 1);
#else
	ksu_late_loaded = false;
#endif

#ifdef CONFIG_KSU_DEBUG
	pr_alert("*************************************************************");
	pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
	pr_alert("**                                                         **");
	pr_alert("**         You are running KernelSU in DEBUG mode          **");
	pr_alert("**                                                         **");
	pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
	pr_alert("*************************************************************");
#endif

    ksu_cred = prepare_creds();
    if (!ksu_cred) {
        pr_err("prepare cred failed!\n");
    }

	ksu_feature_init();
	ksu_sulog_init();
	ksu_supercalls_init();

	if (ksu_late_loaded) {
		pr_info("late load mode, skipping kprobe hooks\n");

		apply_kernelsu_rules();
		cache_sid();
		ksu_selinux_hide_init();
		setup_ksu_cred();

		escape_to_root_for_init();

		ksu_allowlist_init();
		ksu_load_allow_list();

		ksu_syscall_hook_manager_init();

		ksu_throne_tracker_init();
		ksu_observer_init();
		ksu_file_wrapper_init();

		ksu_boot_completed = true;
		track_throne(false);

		if (!getenforce()) {
			pr_info("Permissive SELinux, enforcing\n");
			setenforce(true);
		}

	} else {
		ksu_syscall_hook_manager_init();
		ksu_lsm_hook_init();
		ksu_adb_root_init();
		ksu_selinux_hide_init();

		ksu_allowlist_init();
		ksu_load_allow_list();

		ksu_throne_tracker_init();
		ksu_observer_init();

		ksu_ksud_init();
		ksu_file_wrapper_init();

		ksu_boot_completed = true;
		track_throne(false);

		/*
		 * Manual hook mode: init.rc injection doesn't work
		 * without kprobes, so ksud never runs at boot.
		 * We need to:
		 * 1. Retry track_throne to find the manager
		 * 2. Spawn ksud directly for module mounting
		 */
#ifndef KSU_KPROBES_HOOK
		ksu_boot_retry_count = 0;
		INIT_DELAYED_WORK(&ksu_boot_delayed_work, ksu_boot_delayed_func);
		INIT_DELAYED_WORK(&ksu_spawn_ksud_delayed, ksu_spawn_ksud_func);
		pr_info("manual hook: scheduling boot retry and ksud spawn\n");
		schedule_delayed_work(&ksu_boot_delayed_work, KSU_BOOT_RETRY_DELAY);
		schedule_delayed_work(&ksu_spawn_ksud_delayed, KSU_KSUD_DELAY);
#endif
	}

#ifdef MODULE
#ifndef CONFIG_KSU_DEBUG
	kobject_del(&THIS_MODULE->mkobj.kobj);
#endif
#endif
	return 0;
}

void __exit kernelsu_exit(void)
{
	ksu_syscall_hook_manager_exit();
	ksu_supercalls_exit();

	if (!ksu_late_loaded)
		ksu_ksud_exit();

#ifndef KSU_KPROBES_HOOK
	cancel_delayed_work_sync(&ksu_boot_delayed_work);
	cancel_delayed_work_sync(&ksu_spawn_ksud_delayed);
#endif

	synchronize_rcu();

	ksu_observer_exit();
	ksu_throne_tracker_exit();
	ksu_allowlist_exit();
	ksu_sulog_exit();
	ksu_adb_root_exit();
	ksu_feature_exit();

	if (ksu_cred) {
		put_cred(ksu_cred);
	}
}

#if NEED_OWN_STACKPROTECTOR
module_init(ksu_init_early);
#else
module_init(kernelsu_init);
#endif
module_exit(kernelsu_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("weishu");
MODULE_DESCRIPTION("Android KernelSU");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
