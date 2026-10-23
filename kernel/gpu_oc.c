// SPDX-License-Identifier: GPL-2.0-only
/*
 * gpu_oc.c - MT6768 (OPPO A38 / Helio G85) GPU OPP table overclock injection.
 *
 * GPU DVFS on this platform is driven by the closed-source vendor module
 * mtk_gpufreq_mt6768.ko (MediaTek gpufreq v2_legacy).  At driver probe it
 * copies a static table into a heap allocated working table, then applies
 * per-chip efuse signed voltages on top.  Stock maximum is 1.0 GHz.
 *
 * We wait for the module to probe, then locate the working table: the module
 * keeps a pointer to it in .bss (verified by decoding
 * __gpufreq_get_fgpu_by_idx, which reads *(u32 *)(table + idx * 24)), and
 * the table itself may also live in the module .bss.  Both are found by the
 * frequency signature of the stock table and patched in place.
 *
 * Working table entry (24 bytes, verified against the module binary and
 * /proc/gpufreqv2/gpu_working_opp_table):
 *
 *	struct gpufreq_opp {
 *		u32 freq;	+0   kHz
 *		u32 volt;	+4   uV, efuse signed
 *		u32 vsram;	+8   uV
 *		u32 posdiv;	+12  1 or 2
 *		u32 margin;	+16  uV
 *		u32 power;	+20  mW, computed by the driver
 *	};
 *
 * The top OPPs are rewritten so the GPU reaches 1.4 GHz (the MFG PLL was
 * verified to lock 1.4 GHz on this platform):
 *
 *	idx0  1000 MHz -> 1400 MHz @ 1.1875 V (vsram 1.125 V)
 *	idx1   975 MHz -> 1300 MHz @ 1.1250 V (vsram 1.125 V)
 *	idx2   950 MHz -> 1200 MHz @ 1.0625 V (vsram 1.125 V)
 *	idx3   925 MHz -> 1100 MHz @ 1.0000 V (vsram 1.100 V)
 *	idx4   900 MHz -> 1000 MHz (keeps the efuse voltage of the old idx0)
 *
 * Everything from idx5 down is left untouched, so idle and mid clocks keep
 * their stock efuse signed voltages.  Boot parameter "gpufreq_oc=off"
 * disables the injection.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/math64.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/notifier.h>
#include <linux/sysfs.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>

#define GPUOC_MODULE		"mtk_gpufreq_mt6768"
#define GPUOC_ENTRIES		32
#define GPUOC_ENTRY_SIZE	24

/* stock table anchors (kHz), see gpuoc_table_match() */
#define STOCK_F0	1000000
#define STOCK_F1	975000
#define STOCK_F2	950000
#define STOCK_F3	925000
#define STOCK_F4	900000
#define STOCK_F12	690000
#define STOCK_F31	299000

/* new top OPPs (absolute values, post-efuse domain)
 * NOTE: the table stores voltages in units of 10 uV (87500 == 0.875 V) */
#define OC0_FREQ	1400000
#define OC0_VOLT	118750		/* 1.1875 V */
#define OC0_VSRAM	112500		/* 1.125 V */
#define OC1_FREQ	1300000
#define OC1_VOLT	112500		/* 1.125 V */
#define OC2_FREQ	1200000
#define OC2_VOLT	106250		/* 1.0625 V */
#define OC3_FREQ	1100000
#define OC3_VOLT	100000		/* 1.0 V */
#define OC_VSRAM_CAP	112500
#define OC_MARGIN	1875

/* sanity window for OPP voltages (MT6358 vgpu/vsram, 10 uV units) */
#define GPUOC_VOLT_MIN	50000		/* 0.5 V */
#define GPUOC_VOLT_MAX	129222		/* 1.2922 V */

/* retry budget: 150 * 200ms = 30s after the module finishes loading */
#define GPUOC_MAX_TRIES	150
#define GPUOC_RETRY_MS	200
#define GPUOC_MAX_TABLES 4

struct gpuoc_opp {
	u32 freq;
	u32 volt;
	u32 vsram;
	u32 posdiv;
	u32 margin;
	u32 power;
};

static bool gpuoc_disable;
static int __init gpuoc_off_setup(char *s)
{
	gpuoc_disable = true;
	return 1;
}
__setup("gpufreq_oc=off", gpuoc_off_setup);

struct gpuoc_ctx {
	struct module *mod;
	unsigned int tries;
	bool done;
	bool notifier_fired;
	unsigned int patched;
	struct delayed_work work;
};

static struct gpuoc_ctx gpuoc;

/*
 * The stock table is identified by its frequency ladder and posdiv split
 * (1 above 743 MHz, 2 below).  This is unique inside the module and survives
 * efuse voltage adjustments, which only touch volt/vsram.
 */
static bool gpuoc_table_match(const struct gpuoc_opp *t)
{
	unsigned int i;

	if (t[0].freq != STOCK_F0 || t[1].freq != STOCK_F1 ||
	    t[2].freq != STOCK_F2 || t[3].freq != STOCK_F3 ||
	    t[4].freq != STOCK_F4 || t[12].freq != STOCK_F12 ||
	    t[31].freq != STOCK_F31)
		return false;

	if (t[0].posdiv != 1 || t[1].posdiv != 1 ||
	    t[12].posdiv != 2 || t[31].posdiv != 2)
		return false;

	for (i = 0; i < GPUOC_ENTRIES; i++) {
		if (t[i].freq < STOCK_F31 || t[i].freq > STOCK_F0)
			return false;
		if (t[i].volt < GPUOC_VOLT_MIN || t[i].volt > GPUOC_VOLT_MAX)
			return false;
		if (t[i].vsram < GPUOC_VOLT_MIN || t[i].vsram > GPUOC_VOLT_MAX)
			return false;
		if (t[i].posdiv != 1 && t[i].posdiv != 2)
			return false;
		if (i && t[i].freq >= t[i - 1].freq)
			return false;
	}

	return true;
}

/* fault tolerant read: never take an oops on a bad pointer candidate */
static bool gpuoc_read_safe(const void *src, void *dst, size_t len)
{
	return copy_from_kernel_nofault(dst, src, len) == 0;
}

static bool gpuoc_target_is_module(const void *p, const struct module *mod)
{
	enum mod_mem_type type;

	for (type = 0; type < MOD_MEM_NUM_TYPES; type++) {
		unsigned long base = (unsigned long)mod->mem[type].base;

		if (base && (unsigned long)p - base < mod->mem[type].size)
			return true;
	}

	return false;
}

/*
 * Reject pointer targets that are not backed by RAM.  The vendor module
 * keeps ioremap'ed pointers (e.g. MFGCFG @ 0x13000000) in .bss; reading
 * those while the MFG power domain is down trips a hardware DEVAPC
 * protection fault, which the vendor devapc driver treats as a BUG().
 * Device mappings have no RAM struct page behind them, so they never
 * pass this check.
 */
static bool gpuoc_target_is_ram(const void *p)
{
	struct page *page;

	if (is_vmalloc_addr(p)) {
		page = vmalloc_to_page(p);
		return page && pfn_valid(page_to_pfn(page));
	}

	return virt_addr_valid(p);
}

static u32 gpuoc_scale_power(u32 p0, u32 f0, u32 v0, u32 f, u32 v)
{
	u64 num, den;

	if (!p0 || !f0 || !v0)
		return 0;

	/* P ~ f * V^2, evaluated stepwise so u64 never overflows */
	num = (u64)p0 * (f / 1000) * v;
	den = (u64)(f0 / 1000) * v0;

	return (u32)div64_u64(num * v, den * v0);
}

static void gpuoc_patch_table(struct gpuoc_opp *t)
{
	static const struct {
		u32 freq, volt, vsram;
	} oc[4] = {
		{ OC0_FREQ, OC0_VOLT, OC0_VSRAM },
		{ OC1_FREQ, OC1_VOLT, OC_VSRAM_CAP },
		{ OC2_FREQ, OC2_VOLT, OC_VSRAM_CAP },
		{ OC3_FREQ, OC3_VOLT, 110000 },
	};
	struct gpuoc_opp one_g = t[0];
	unsigned int i;

	/*
	 * idx4 becomes the old 1 GHz point with its efuse signed voltage,
	 * keeping a known good step between the OC range and the stock curve.
	 */
	t[4].freq = one_g.freq;
	t[4].volt = one_g.volt;
	t[4].vsram = one_g.vsram;
	t[4].posdiv = one_g.posdiv;
	t[4].margin = one_g.margin;
	t[4].power = one_g.power;

	for (i = 0; i < 4; i++) {
		t[i].freq = oc[i].freq;
		t[i].volt = oc[i].volt;
		t[i].vsram = oc[i].vsram;
		t[i].posdiv = 1;
		t[i].margin = OC_MARGIN;
		t[i].power = gpuoc_scale_power(one_g.power, one_g.freq,
					       one_g.volt, oc[i].freq,
					       oc[i].volt);
	}
}

/*
 * The working table is either a .bss array or heap memory referenced from a
 * module .bss pointer (the latter is what the stock module actually does).
 * Scan the module's writable memory for both shapes and patch every match,
 * writing through pointers only after confirming they reference RAM and a
 * fault tolerant validation of the full table.
 */
static bool gpuoc_table_probe(const void *p, struct gpuoc_opp *snapshot)
{
	u32 freq0;

	/* cheap probe first: never pull a full table through a bad pointer */
	if (!gpuoc_read_safe(p, &freq0, sizeof(freq0)) || freq0 != STOCK_F0)
		return false;
	if (!gpuoc_read_safe(p, snapshot, sizeof(snapshot)))
		return false;

	return gpuoc_table_match(snapshot);
}

static unsigned int gpuoc_scan_module(struct module *mod)
{
	unsigned long base, end, addr, last = 0;
	unsigned int patched = 0;
	struct gpuoc_opp snapshot[GPUOC_ENTRIES];

	base = (unsigned long)mod->mem[MOD_DATA].base;
	end = base + mod->mem[MOD_DATA].size;
	if (!base)
		return 0;

	for (addr = base;
	     addr + GPUOC_ENTRY_SIZE * GPUOC_ENTRIES <= end && patched < GPUOC_MAX_TABLES;
	     addr += 4) {
		u64 maybe_ptr;
		void *target;

		/* direct hit: the table lives inside the module memory */
		if (addr % 8 == 0 &&
		    gpuoc_table_probe((void *)addr, snapshot)) {
			gpuoc_patch_table((void *)addr);
			last = addr;
			patched++;
			continue;
		}

		if (addr % 8 || addr == last)
			continue;

		/* pointer hit: .bss holds a reference to the heap table */
		if (!gpuoc_read_safe((void *)addr, &maybe_ptr, sizeof(maybe_ptr)))
			continue;
		if ((maybe_ptr & (sizeof(void *) - 1)) ||
		    maybe_ptr < 0xffff800000000000ULL)
			continue;

		target = (void *)(unsigned long)maybe_ptr;
		if (gpuoc_target_is_module(target, mod))
			continue;
		if (!gpuoc_target_is_ram(target))
			continue;

		if (!gpuoc_table_probe(target, snapshot))
			continue;

		gpuoc_patch_table(target);
		last = (unsigned long)target;
		patched++;
	}

	return patched;
}

static void gpuoc_workfn(struct work_struct *work)
{
	struct delayed_work *dw = to_delayed_work(work);
	struct module *mod = gpuoc.mod;
	unsigned int patched;

	if (gpuoc.done || !mod)
		return;

	if (mod->state != MODULE_STATE_LIVE) {
		if (++gpuoc.tries < GPUOC_MAX_TRIES)
			schedule_delayed_work(dw, msecs_to_jiffies(GPUOC_RETRY_MS));
		else
			gpuoc.done = true;
		return;
	}

	if (!try_module_get(mod)) {
		gpuoc.done = true;
		return;
	}

	patched = gpuoc_scan_module(mod);
	module_put(mod);
	gpuoc.patched = patched;

	if (patched) {
		pr_info("GPU OC applied: %u table(s) patched, top OPP %u kHz @ %u uV\n",
			patched, OC0_FREQ, OC0_VOLT);
		gpuoc.done = true;
		return;
	}

	if (++gpuoc.tries < GPUOC_MAX_TRIES) {
		schedule_delayed_work(dw, msecs_to_jiffies(GPUOC_RETRY_MS));
	} else {
		gpuoc.done = true;
		pr_warn("GPU OC: working OPP table not found, giving up (module layout changed?)\n");
	}
}

static int gpuoc_module_notify(struct notifier_block *nb, unsigned long action,
			       void *data)
{
	struct module *mod = data;

	if (gpuoc_disable || action != MODULE_STATE_COMING)
		return NOTIFY_DONE;

	if (strcmp(mod->name, GPUOC_MODULE))
		return NOTIFY_DONE;

	gpuoc.mod = mod;
	gpuoc.tries = 0;
	gpuoc.done = false;
	gpuoc.notifier_fired = true;
	schedule_delayed_work(&gpuoc.work, msecs_to_jiffies(500));

	pr_info("watching %s for its working OPP table\n", GPUOC_MODULE);

	return NOTIFY_DONE;
}

static ssize_t gpuoc_status_show(struct kobject *kobj, struct kobj_attribute *attr,
				 char *buf)
{
	return sysfs_emit(buf,
			  "notifier_fired=%d tries=%u done=%d tables_patched=%u\n",
			  gpuoc.notifier_fired, gpuoc.tries, gpuoc.done,
			  gpuoc.patched);
}
static struct kobj_attribute gpuoc_status_attr =
	__ATTR(status, 0444, gpuoc_status_show, NULL);
static struct kobject *gpuoc_kobj;

static struct notifier_block gpuoc_nb = {
	.notifier_call = gpuoc_module_notify,
};

static int __init gpu_oc_init(void)
{
	if (gpuoc_disable) {
		pr_info("disabled by kernel cmdline\n");
		return 0;
	}

	gpuoc_kobj = kobject_create_and_add("gpu_oc", kernel_kobj);
	if (!gpuoc_kobj || sysfs_create_file(gpuoc_kobj, &gpuoc_status_attr.attr))
		pr_warn("failed to create /sys/kernel/gpu_oc/status\n");

	INIT_DELAYED_WORK(&gpuoc.work, gpuoc_workfn);

	return register_module_notifier(&gpuoc_nb);
}
late_initcall(gpu_oc_init);
