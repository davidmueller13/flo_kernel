/*
 * arch/arm/kernel/topology.c
 *
 * Copyright (C) 2011 Linaro Limited.
 * Written by: Vincent Guittot
 *
 * based on arch/sh/kernel/topology.c
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 */

#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/init.h>
#include <linux/percpu.h>
#include <linux/node.h>
#include <linux/nodemask.h>
#include <linux/of.h>
#include <linux/sched.h>
#include <linux/cpumask.h>
#include <linux/cpuset.h>
#include <linux/notifier.h>
uuuuu
#ifdef CONFIG_DEBUG_FS
#include <linux/debugfs.h>
#include <linux/uaccess.h>	/* for copy_from_user */
#endif
#include <asm/cputype.h>
#include <asm/topology.h>

#define ARM_FAMILY_MASK 0xFF0FFFF0

#define MPIDR_SMP_BITMASK (0x3 << 30)
#define MPIDR_SMP_VALUE (0x2 << 30)

struct cpu_capacity {
	unsigned long hwid;
	unsigned long capacity;
};

struct cpu_capacity *cpu_capacity;

unsigned long middle_capacity = 1;
/*
 * Iterate all CPUs' descriptor in DT and compute the efficiency
 * (as per table_efficiency). Also calculate a middle efficiency
 * as close as possible to  (max{eff_i} - min{eff_i}) / 2
 * This is later used to scale the cpu_power field such that an
 * 'average' CPU is of middle power. Also see the comments near
 * table_efficiency[] and update_cpu_power().
 */
static void __init parse_dt_topology(void)
{
	struct cpu_efficiency *cpu_eff;
	struct device_node *cn = NULL;
	unsigned long min_capacity = (unsigned long)(-1);
	unsigned long max_capacity = 0;
	unsigned long capacity = 0;
	int alloc_size, cpu = 0;

	alloc_size = nr_cpu_ids * sizeof(struct cpu_capacity);
	cpu_capacity = (struct cpu_capacity *)kzalloc(alloc_size, GFP_NOWAIT);

	while ((cn = of_find_node_by_type(cn, "cpu"))) {
		const u32 *rate, *reg;
		int len;

		if (cpu >= num_possible_cpus())
			break;

		for (cpu_eff = table_efficiency; cpu_eff->compatible; cpu_eff++)
			if (of_device_is_compatible(cn, cpu_eff->compatible))
				break;

		if (cpu_eff->compatible == NULL)
			continue;

		rate = of_get_property(cn, "clock-frequency", &len);
		if (!rate || len != 4) {
			pr_err("%s missing clock-frequency property\n",
				cn->full_name);
			continue;
		}

		reg = of_get_property(cn, "reg", &len);
		if (!reg || len != 4) {
			pr_err("%s missing reg property\n", cn->full_name);
			continue;
		}

		capacity = ((be32_to_cpup(rate)) >> 20) * cpu_eff->efficiency;

		/* Save min capacity of the system */
		if (capacity < min_capacity)
			min_capacity = capacity;

		/* Save max capacity of the system */
		if (capacity > max_capacity)
			max_capacity = capacity;

		cpu_capacity[cpu].capacity = capacity;
		cpu_capacity[cpu++].hwid = be32_to_cpup(reg);
	}

	if (cpu < num_possible_cpus())
		cpu_capacity[cpu].hwid = (unsigned long)(-1);

	/* If min and max capacities are equals, we bypass the update of the
	 * cpu_scale because all CPUs have the same capacity. Otherwise, we
	 * compute a middle_capacity factor that will ensure that the capacity
	 * of an 'average' CPU of the system will be as close as possible to
	 * SCHED_POWER_SCALE, which is the default value, but with the
	 * constraint explained near table_efficiency[].
	 */
	if (min_capacity == max_capacity)
		cpu_capacity[0].hwid = (unsigned long)(-1);
	else if (4*max_capacity < (3*(max_capacity + min_capacity)))
		middle_capacity = (min_capacity + max_capacity)
				>> (SCHED_POWER_SHIFT+1);
	else
		middle_capacity = ((max_capacity / 3)
				>> (SCHED_POWER_SHIFT-1)) + 1;

}

/*
 * Look for a customed capacity of a CPU in the cpu_capacity table during the
 * boot. The update of all CPUs is in O(n^2) for heteregeneous system but the
 * function returns directly for SMP system.
 */
void update_cpu_power(unsigned int cpu, unsigned long hwid)
{
	unsigned int idx = 0;

	/* look for the cpu's hwid in the cpu capacity table */
	for (idx = 0; idx < num_possible_cpus(); idx++) {
		if (cpu_capacity[idx].hwid == hwid)
			break;

		if (cpu_capacity[idx].hwid == -1)
			return;
	}

	if (idx == num_possible_cpus())
		return;

	set_power_scale(cpu, cpu_capacity[idx].capacity / middle_capacity);

	printk(KERN_INFO "CPU%u: update cpu_power %lu\n",
		cpu, arch_scale_freq_power(NULL, cpu));
}

#else
static inline void parse_dt_topology(void) {}
static inline void update_cpu_power(unsigned int cpuid, unsigned int mpidr) {}
#endif

 /*
 * cpu topology table
 */
struct cputopo_arm cpu_topology[NR_CPUS];

/*
 * cpu power scale management
 * a per cpu data structure should be better because each cpu is mainly
 * using its own cpu_power even it's not always true because of
 * nohz_idle_balance
 */

static DEFINE_PER_CPU(unsigned int, cpu_scale);

/*
 * cpu topology mask update management
 */

static unsigned int prev_sched_mc_power_savings = 0;
static unsigned int prev_sched_smt_power_savings = 0;

ATOMIC_NOTIFIER_HEAD(topology_update_notifier_list);

/*
 * Update the cpu power of the scheduler
 */
unsigned long arch_scale_freq_power(struct sched_domain *sd, int cpu)
{
	return per_cpu(cpu_scale, cpu);
}

void set_power_scale(unsigned int cpu, unsigned int power)
{
	per_cpu(cpu_scale, cpu) = power;
}

int topology_register_notifier(struct notifier_block *nb)
{

	return atomic_notifier_chain_register(
				&topology_update_notifier_list, nb);
}

int topology_unregister_notifier(struct notifier_block *nb)
{

	return atomic_notifier_chain_unregister(
				&topology_update_notifier_list, nb);
}

/*
 * sched_domain flag configuration
 */
/* TODO add a config flag for this function */
int arch_sd_sibling_asym_packing(void)
{
	if (sched_smt_power_savings || sched_mc_power_savings)
		return SD_ASYM_PACKING;
	return 0;
}

/*
 * default topology function
 */
const struct cpumask *cpu_coregroup_mask(int cpu)
{
	return &cpu_topology[cpu].core_sibling;
}

void update_siblings_masks(unsigned int cpuid)
{
	struct cputopo_arm *cpu_topo, *cpuid_topo = &cpu_topology[cpuid];
	int cpu;

	/* update core and thread sibling masks */
	for_each_possible_cpu(cpu) {
		cpu_topo = &cpu_topology[cpu];

		if (cpuid_topo->socket_id != cpu_topo->socket_id)
			continue;

		cpumask_set_cpu(cpuid, &cpu_topo->core_sibling);
		if (cpu != cpuid)
			cpumask_set_cpu(cpu, &cpuid_topo->core_sibling);

		if (cpuid_topo->core_id != cpu_topo->core_id)
			continue;

		cpumask_set_cpu(cpuid, &cpu_topo->thread_sibling);
		if (cpu != cpuid)
			cpumask_set_cpu(cpu, &cpuid_topo->thread_sibling);
	}
	smp_wmb();
}

/*
 * clear cpu topology masks
 */
static void clear_cpu_topology_mask(void)
{
	unsigned int cpuid;
	for_each_possible_cpu(cpuid) {
		struct cputopo_arm *cpuid_topo = &(cpu_topology[cpuid]);
		cpumask_clear(&cpuid_topo->core_sibling);
		cpumask_clear(&cpuid_topo->thread_sibling);
	}
	smp_wmb();
}

/*
 * default_cpu_topology_mask set the core and thread mask as described in the
 * ARM ARM
 */
static void default_cpu_topology_mask(unsigned int cpuid)
{
	struct cputopo_arm *cpuid_topo = &cpu_topology[cpuid];
	unsigned int cpu;

	for_each_possible_cpu(cpu) {
		struct cputopo_arm *cpu_topo = &cpu_topology[cpu];

		if (cpuid_topo->socket_id == cpu_topo->socket_id) {
			cpumask_set_cpu(cpuid, &cpu_topo->core_sibling);
			if (cpu != cpuid)
				cpumask_set_cpu(cpu,
					&cpuid_topo->core_sibling);

			if (cpuid_topo->core_id == cpu_topo->core_id) {
				cpumask_set_cpu(cpuid,
					&cpu_topo->thread_sibling);
				if (cpu != cpuid)
					cpumask_set_cpu(cpu,
						&cpuid_topo->thread_sibling);
			}
		}
	}
	smp_wmb();
}

static void normal_cpu_topology_mask(void)
{
	unsigned int cpuid;

	for_each_possible_cpu(cpuid) {
		default_cpu_topology_mask(cpuid);
	}
	smp_wmb();
}

/*
 * For Cortex-A9 MPcore, we emulate a multi-package topology in power mode.
 * The goal is to gathers tasks on 1 virtual package
 */
static void power_cpu_topology_mask_CA9(unsigned int cpuid)
{
	struct cputopo_arm *cpuid_topo = &cpu_topology[cpuid];
	unsigned int cpu;

	for_each_possible_cpu(cpu) {
		struct cputopo_arm *cpu_topo = &cpu_topology[cpu];

		if ((cpuid_topo->socket_id == cpu_topo->socket_id)
		&& ((cpuid & 0x1) == (cpu & 0x1))) {
			cpumask_set_cpu(cpuid, &cpu_topo->core_sibling);
			if (cpu != cpuid)
				cpumask_set_cpu(cpu,
					&cpuid_topo->core_sibling);

			if (cpuid_topo->core_id == cpu_topo->core_id) {
				cpumask_set_cpu(cpuid,
					&cpu_topo->thread_sibling);
				if (cpu != cpuid)
					cpumask_set_cpu(cpu,
						&cpuid_topo->thread_sibling);
			}
		}
	}
	smp_wmb();
}

static int need_topology_update(void)
{
	int update;

	update = ((prev_sched_mc_power_savings ^ sched_mc_power_savings)
	       || (prev_sched_smt_power_savings ^ sched_smt_power_savings));

	prev_sched_mc_power_savings = sched_mc_power_savings;
	prev_sched_smt_power_savings = sched_smt_power_savings;

	return update;
}

#define ARM_CORTEX_A9_FAMILY 0x410FC090

/* update_cpu_topology_policy select a cpu topology policy according to the
 * available cores.
 * TODO: The current version assumes that all cores are exactly the same which
 * might not be true. We need to update it to take into account various
 * configuration among which system with different kind of core.
 */
static int update_cpu_topology_mask(void)
{
	unsigned long cpuid;

	if (sched_mc_power_savings == POWERSAVINGS_BALANCE_NONE) {
		normal_cpu_topology_mask();
		return 0;
	}

	for_each_possible_cpu(cpuid) {
		struct cputopo_arm *cpuid_topo = &(cpu_topology[cpuid]);

		switch (cpuid_topo->id) {
		case ARM_CORTEX_A9_FAMILY:
			power_cpu_topology_mask_CA9(cpuid);
		break;
		default:
			default_cpu_topology_mask(cpuid);
		break;
		}
	}

	return 0;
}

/*
 * store_cpu_topology is called at boot when only one cpu is running
 * and with the mutex cpu_hotplug.lock locked, when several cpus have booted,
 * which prevents simultaneous write access to cpu_topology array
 */
void store_cpu_topology(unsigned int cpuid)
{
	struct cputopo_arm *cpuid_topo = &cpu_topology[cpuid];
	unsigned int mpidr;

	/* If the cpu topology has been already set, just return */
	if (cpuid_topo->core_id != -1)
		return;

	mpidr = read_cpuid_mpidr();

	/* create cpu topology mapping */
	if ((mpidr & MPIDR_SMP_BITMASK) == MPIDR_SMP_VALUE) {
		/*
		 * This is a multiprocessor system
		 * multiprocessor format & multiprocessor mode field are set
		 */

		if (mpidr & MPIDR_MT_BITMASK) {
			/* core performance interdependency */
			cpuid_topo->thread_id = MPIDR_AFFINITY_LEVEL(mpidr, 0);
			cpuid_topo->core_id = MPIDR_AFFINITY_LEVEL(mpidr, 1);
			cpuid_topo->socket_id = MPIDR_AFFINITY_LEVEL(mpidr, 2);
		} else {
			/* largely independent cores */
			cpuid_topo->thread_id = -1;
			cpuid_topo->core_id = MPIDR_AFFINITY_LEVEL(mpidr, 0);
			cpuid_topo->socket_id = MPIDR_AFFINITY_LEVEL(mpidr, 1);
		}

		cpuid_topo->id = read_cpuid_id() & ARM_FAMILY_MASK;

	} else {
		/*
		 * This is an uniprocessor system
		 * we are in multiprocessor format but uniprocessor system
		 * or in the old uniprocessor format
		 */
		cpuid_topo->thread_id = -1;
		cpuid_topo->core_id = 0;
		cpuid_topo->socket_id = -1;
	}
	/*
	 * The core and thread sibling masks can also be updated during the
	 * call of arch_update_cpu_topology
	 */
	default_cpu_topology_mask(cpuid);

	printk(KERN_INFO "CPU%u: thread %d, cpu %d, socket %d, mpidr %x\n",
		cpuid, cpu_topology[cpuid].thread_id,
		cpu_topology[cpuid].core_id,
		cpu_topology[cpuid].socket_id, mpidr);
}

/*
 * arch_update_cpu_topology is called by the scheduler before building
 * a new sched_domain hierarchy.
 */
int arch_update_cpu_topology(void)
{
	if (!need_topology_update())
		return 0;

	/* clear core threads mask */
	clear_cpu_topology_mask();

	/* set topology mask */
	update_cpu_topology_mask();

	/* notify the topology update */
	atomic_notifier_call_chain(&topology_update_notifier_list,
				TOPOLOGY_POSTCHANGE, (void *)sched_mc_power_savings);

	return 1;
}

/*
 * init_cpu_topology is called at boot when only one cpu is running
 * which prevent simultaneous write access to cpu_topology array
 */
void __init init_cpu_topology(void)
{
	unsigned int cpu;

	/* init core mask and power*/
	for_each_possible_cpu(cpu) {
		struct cputopo_arm *cpu_topo = &(cpu_topology[cpu]);

		cpu_topo->id = -1;
		cpu_topo->thread_id = -1;
		cpu_topo->core_id =  -1;
		cpu_topo->socket_id = -1;
		cpumask_clear(&cpu_topo->core_sibling);
		cpumask_clear(&cpu_topo->thread_sibling);
		per_cpu(cpu_scale, cpu) = SCHED_POWER_SCALE;
	}
	smp_wmb();

	parse_dt_topology();
}


#ifdef CONFIG_ARCH_SCALE_INVARIANT_CPU_CAPACITY
#include <linux/cpufreq.h>

#define CPUPOWER_FREQSCALE_SHIFT 10
#define CPUPOWER_FREQSCALE_DEFAULT (1L << CPUPOWER_FREQSCALE_SHIFT)
struct cpufreq_extents {
       u32 max;
       u32 flags;
};
/* Flag set when the governor in use only allows one frequency.
 * Disables scaling.
 */
#define CPUPOWER_FREQINVAR_SINGLEFREQ 0x01
static struct cpufreq_extents freq_scale[CONFIG_NR_CPUS];

static unsigned long get_max_cpu_power(void)
{
       unsigned long max_cpu_power = 0;
       int cpu;
       for_each_online_cpu(cpu){
               if( per_cpu(cpu_scale, cpu) > max_cpu_power)
                       max_cpu_power = per_cpu(cpu_scale, cpu);
       }
       return max_cpu_power;
}


/* Called when the CPU Frequency is changed.
 * Once for each CPU.
 */
static int cpufreq_callback(struct notifier_block *nb,
                                       unsigned long val, void *data)
{
       struct cpufreq_freqs *freq = data;
       int cpu = freq->cpu;
       struct cpufreq_extents *extents;
       unsigned int curr_freq;

       if (freq->flags & CPUFREQ_CONST_LOOPS)
               return NOTIFY_OK;

       if (val != CPUFREQ_POSTCHANGE)
               return NOTIFY_OK;

       /* if dynamic load scale is disabled, set the load scale to 1.0 */
       if (!frequency_invariant_power_enabled) {
               per_cpu(invariant_cpu_capacity, cpu) = per_cpu(base_cpu_capacity, cpu);
               return NOTIFY_OK;
       }

       extents = &freq_scale[cpu];
       /* If our governor was recognised as a single-freq governor,
        * use curr = max to be sure multiplier is 1.0
        */
       if (extents->flags & CPUPOWER_FREQINVAR_SINGLEFREQ)
               curr_freq = extents->max;
       else
               curr_freq = freq->new >> CPUPOWER_FREQSCALE_SHIFT;

       per_cpu(invariant_cpu_capacity, cpu) = (curr_freq *
               per_cpu(prescaled_cpu_capacity, cpu)) >> CPUPOWER_FREQSCALE_SHIFT;
       return NOTIFY_OK;
}

/* Called when the CPUFreq governor is changed.
 * Only called for the CPUs which are actually changed by the
 * userspace.
 */
static int cpufreq_policy_callback(struct notifier_block *nb,
                                      unsigned long event, void *data)
{
       struct cpufreq_policy *policy = data;
       struct cpufreq_extents *extents;
       int cpu, singleFreq = 0, cpu_capacity;
       static const char performance_governor[] = "performance";
       static const char powersave_governor[] = "powersave";
       unsigned long max_cpu_power;

       if (event == CPUFREQ_START)
               return 0;

       if (event != CPUFREQ_INCOMPATIBLE)
               return 0;

       /* CPUFreq governors do not accurately report the range of
        * CPU Frequencies they will choose from.
        * We recognise performance and powersave governors as
        * single-frequency only.
        */
       if (!strncmp(policy->governor->name, performance_governor,
                       strlen(performance_governor)) ||
               !strncmp(policy->governor->name, powersave_governor,
                               strlen(powersave_governor)))
               singleFreq = 1;

       max_cpu_power = get_max_cpu_power();
       /* Make sure that all CPUs impacted by this policy are
        * updated since we will only get a notification when the
        * user explicitly changes the policy on a CPU.
        */
       for_each_cpu(cpu, policy->cpus) {
               /* scale cpu_power to max(1024) */
               cpu_capacity = (per_cpu(cpu_scale, cpu) << CPUPOWER_FREQSCALE_SHIFT)
                               / max_cpu_power;
               extents = &freq_scale[cpu];
               extents->max = policy->max >> CPUPOWER_FREQSCALE_SHIFT;
               if (!frequency_invariant_power_enabled) {
                       /* when disabled, invariant_cpu_scale = cpu_scale */
                       per_cpu(base_cpu_capacity, cpu) = CPUPOWER_FREQSCALE_DEFAULT;
                       per_cpu(invariant_cpu_capacity, cpu) = CPUPOWER_FREQSCALE_DEFAULT;
                       /* unused when disabled */
                       per_cpu(prescaled_cpu_capacity, cpu) = CPUPOWER_FREQSCALE_DEFAULT;
               } else {
                       if (singleFreq)
                               extents->flags |= CPUPOWER_FREQINVAR_SINGLEFREQ;
                       else
                               extents->flags &= ~CPUPOWER_FREQINVAR_SINGLEFREQ;
                       per_cpu(base_cpu_capacity, cpu) = cpu_capacity;
                       per_cpu(prescaled_cpu_capacity, cpu) = (cpu_capacity << CPUPOWER_FREQSCALE_SHIFT) / extents->max;
                       per_cpu(invariant_cpu_capacity, cpu) =
                                       ((policy->cur >> CPUPOWER_FREQSCALE_SHIFT) *
                                       per_cpu(prescaled_cpu_capacity, cpu)) >> CPUPOWER_FREQSCALE_SHIFT;
               }
       }
       return 0;
}
/*
 * debugfs interface for scaling cpu power
 */

#ifdef CONFIG_DEBUG_FS
static struct dentry *topo_debugfs_root;

static ssize_t dbg_write(struct file *file, const char __user *buf,
						size_t size, loff_t *off)
{
	unsigned int *value = file->f_dentry->d_inode->i_private;
	char cdata[128];
	unsigned long tmp;

	if (size < (sizeof(cdata)-1)) {
		if (copy_from_user(cdata, buf, size))
			return -EFAULT;
		cdata[size] = 0;
		if (!strict_strtoul(cdata, 10, &tmp)) {
			*value = tmp;
		}
		return size;
	}
	return -EINVAL;
}

static ssize_t dbg_read(struct file *file, char __user *buf,
						size_t size, loff_t *off)
{
	unsigned int *value = file->f_dentry->d_inode->i_private;
	char cdata[128];
	unsigned int len;

	len = sprintf(cdata, "%u\n", *value);
	return simple_read_from_buffer(buf, size, off, cdata, len);
}

static const struct file_operations debugfs_fops = {
	.read = dbg_read,
	.write = dbg_write,
};

static struct dentry *topo_debugfs_register(unsigned int cpu,
						struct dentry *parent)
{
	struct dentry *cpu_d, *d;
	char cpu_name[16];

	sprintf(cpu_name, "cpu%u", cpu);

	cpu_d = debugfs_create_dir(cpu_name, parent);
	if (!cpu_d)
		return NULL;

	d = debugfs_create_file("cpu_power", S_IRUGO  | S_IWUGO,
				cpu_d, &per_cpu(cpu_scale, cpu), &debugfs_fops);
	if (!d)
		goto err_out;

	return cpu_d;

err_out:
	debugfs_remove_recursive(cpu_d);
	return NULL;
}

static int __init topo_debugfs_init(void)
{
	struct dentry *d;
	unsigned int cpu;

	d = debugfs_create_dir("cpu_topo", NULL);
	if (!d)
		return -ENOMEM;
	topo_debugfs_root = d;

	for_each_possible_cpu(cpu) {
		d = topo_debugfs_register(cpu, topo_debugfs_root);
		if (d == NULL)
			goto err_out;
	}
	return 0;

err_out:
	debugfs_remove_recursive(topo_debugfs_root);
	return -ENOMEM;
}

late_initcall(topo_debugfs_init);
#endif
