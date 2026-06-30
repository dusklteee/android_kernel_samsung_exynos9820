/*
 * Copyright (C) 2014-2017, Sultanxda <sultanxda@gmail.com>
 *           (C) 2017, Joe Maples <joe@frap129.org>
 *           (C) 2026, NeoKernel-Beyond (touch input boost variant)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

/* drivers/cpufreq/cpu_input_boost.c: CPU touch input boost driver
 *
 * Boosts CPU clusters to an intermediate frequency (a percentage of each
 * cluster's max) for a short duration whenever a touchscreen input event is
 * received. This cuts UI latency on touch/scroll without pinning the clock to
 * max (which would hurt battery). It is purely additive: the governor still
 * controls the clock under load -- this only raises policy->min temporarily,
 * never lowers it. Derived from cpu_input_boost / fp-boost by Sultanxda.
 */

#define pr_fmt(fmt) "cpu_input_boost: " fmt

#include <linux/cpu.h>
#include <linux/cpufreq.h>
#include <linux/input.h>
#include <linux/slab.h>

/* Available bits for boost_policy state */
#define DRIVER_ENABLED		(1U << 0)
#define INPUT_BOOST		(1U << 1)

/* Boost each cluster up to this percentage of its max frequency on touch */
#ifdef CONFIG_INPUT_BOOST_PERCENT
#define IB_PERCENT CONFIG_INPUT_BOOST_PERCENT
#else
#define IB_PERCENT (65)
#endif

/* Duration in milliseconds of the touch boost */
#ifdef CONFIG_INPUT_BOOST_DURATION_MS
#define IB_DURATION_MS CONFIG_INPUT_BOOST_DURATION_MS
#else
#define IB_DURATION_MS (200)
#endif

/* Minimum gap between processed input events (ms) to avoid spamming work */
#define IB_THROTTLE_MS (50)

struct ib_config {
	struct delayed_work boost_work;
	struct delayed_work unboost_work;
};

struct boost_policy {
	spinlock_t lock;
	struct ib_config ib;
	struct workqueue_struct *wq;
	uint32_t state;
};

/* Global pointer to all of the data for the driver */
static struct boost_policy *boost_policy_g;

/* Last time an input event was processed (for throttling) */
static unsigned long last_input_jiffies;

static uint32_t get_boost_state(struct boost_policy *b);
static void set_boost_bit(struct boost_policy *b, uint32_t state);
static void clear_boost_bit(struct boost_policy *b, uint32_t state);
static void update_online_cpu_policy(void);

static void ib_boost_main(struct work_struct *work)
{
	struct boost_policy *b = boost_policy_g;
	struct ib_config *ib = &b->ib;

	set_boost_bit(b, INPUT_BOOST);

	/* Immediately boost the online CPUs */
	update_online_cpu_policy();

	queue_delayed_work(b->wq, &ib->unboost_work,
			msecs_to_jiffies(IB_DURATION_MS));
}

static void ib_unboost_main(struct work_struct *work)
{
	struct boost_policy *b = boost_policy_g;

	clear_boost_bit(b, INPUT_BOOST);

	/* Re-run the cpufreq notifier so policy->min returns to its base */
	update_online_cpu_policy();
}

static int do_cpu_boost(struct notifier_block *nb,
		unsigned long action, void *data)
{
	struct cpufreq_policy *policy = data;
	struct boost_policy *b = boost_policy_g;
	uint32_t state;
	uint32_t target;

	if (action != CPUFREQ_ADJUST)
		return NOTIFY_OK;

	state = get_boost_state(b);

	/*
	 * Don't do anything when the driver is disabled, unless there are
	 * still CPUs that need to be unboosted.
	 */
	if (!(state & DRIVER_ENABLED) &&
		policy->min == policy->cpuinfo.min_freq)
		return NOTIFY_OK;

	if (state & INPUT_BOOST) {
		/* Boost this cluster to a percentage of its own max freq */
		target = (policy->max / 100) * IB_PERCENT;
		if (target < policy->cpuinfo.min_freq)
			target = policy->cpuinfo.min_freq;
		policy->min = min(policy->max, target);
	}

	return NOTIFY_OK;
}

static struct notifier_block do_cpu_boost_nb = {
	.notifier_call = do_cpu_boost,
	.priority = INT_MAX,
};

static void cpu_ib_input_event(struct input_handle *handle, unsigned int type,
		unsigned int code, int value)
{
	struct boost_policy *b = boost_policy_g;
	struct ib_config *ib = &b->ib;
	uint32_t state;

	state = get_boost_state(b);

	if (!(state & DRIVER_ENABLED))
		return;

	/* Throttle: only act on one event per IB_THROTTLE_MS window */
	if (time_before(jiffies,
			last_input_jiffies + msecs_to_jiffies(IB_THROTTLE_MS)))
		return;
	last_input_jiffies = jiffies;

	if (state & INPUT_BOOST) {
		/* Already boosting (e.g. scrolling): extend the duration */
		mod_delayed_work(b->wq, &ib->unboost_work,
				msecs_to_jiffies(IB_DURATION_MS));
		return;
	}

	queue_delayed_work(b->wq, &ib->boost_work, 0);
}

static int cpu_ib_input_connect(struct input_handler *handler,
		struct input_dev *dev, const struct input_device_id *id)
{
	struct input_handle *handle;
	int ret;

	handle = kzalloc(sizeof(*handle), GFP_KERNEL);
	if (!handle)
		return -ENOMEM;

	handle->dev = dev;
	handle->handler = handler;
	handle->name = "cpu_ib_handle";

	ret = input_register_handle(handle);
	if (ret)
		goto err2;

	ret = input_open_device(handle);
	if (ret)
		goto err1;

	return 0;

err1:
	input_unregister_handle(handle);
err2:
	kfree(handle);
	return ret;
}

static void cpu_ib_input_disconnect(struct input_handle *handle)
{
	input_close_device(handle);
	input_unregister_handle(handle);
	kfree(handle);
}

static const struct input_device_id cpu_ib_ids[] = {
	/* multi-touch touchscreen */
	{
		.flags = INPUT_DEVICE_ID_MATCH_EVBIT |
			INPUT_DEVICE_ID_MATCH_ABSBIT,
		.evbit = { BIT_MASK(EV_ABS) },
		.absbit = { [BIT_WORD(ABS_MT_POSITION_X)] =
			BIT_MASK(ABS_MT_POSITION_X) },
	},
	/* touchscreen */
	{
		.flags = INPUT_DEVICE_ID_MATCH_KEYBIT |
			INPUT_DEVICE_ID_MATCH_ABSBIT,
		.keybit = { [BIT_WORD(BTN_TOUCH)] = BIT_MASK(BTN_TOUCH) },
		.absbit = { [BIT_WORD(ABS_X)] = BIT_MASK(ABS_X) },
	},
	{ },
};

static struct input_handler cpu_ib_input_handler = {
	.event      = cpu_ib_input_event,
	.connect    = cpu_ib_input_connect,
	.disconnect = cpu_ib_input_disconnect,
	.name       = "cpu_ib_handler",
	.id_table   = cpu_ib_ids,
};

static uint32_t get_boost_state(struct boost_policy *b)
{
	uint32_t state;

	spin_lock(&b->lock);
	state = b->state;
	spin_unlock(&b->lock);

	return state;
}

static void set_boost_bit(struct boost_policy *b, uint32_t state)
{
	spin_lock(&b->lock);
	b->state |= state;
	spin_unlock(&b->lock);
}

static void clear_boost_bit(struct boost_policy *b, uint32_t state)
{
	spin_lock(&b->lock);
	b->state &= ~state;
	spin_unlock(&b->lock);
}

static void update_online_cpu_policy(void)
{
	uint32_t cpu;

	/* Trigger cpufreq notifier for online CPUs */
	get_online_cpus();
	for_each_online_cpu(cpu)
		cpufreq_update_policy(cpu);
	put_online_cpus();
}

static ssize_t enabled_write(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t size)
{
	struct boost_policy *b = boost_policy_g;
	uint32_t data;
	int ret;

	ret = kstrtou32(buf, 10, &data);
	if (ret)
		return -EINVAL;

	if (data) {
		set_boost_bit(b, DRIVER_ENABLED);
	} else {
		clear_boost_bit(b, DRIVER_ENABLED);
		/* Stop everything */
		clear_boost_bit(b, INPUT_BOOST);
		update_online_cpu_policy();
	}

	return size;
}

static ssize_t enabled_read(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct boost_policy *b = boost_policy_g;

	return snprintf(buf, PAGE_SIZE, "%u\n",
				get_boost_state(b) & DRIVER_ENABLED);
}

static DEVICE_ATTR(enabled, 0644,
			enabled_read, enabled_write);

static struct attribute *cpu_ib_attr[] = {
	&dev_attr_enabled.attr,
	NULL
};

static struct attribute_group cpu_ib_attr_group = {
	.attrs = cpu_ib_attr,
};

static int sysfs_ib_init(void)
{
	struct kobject *kobj;
	int ret;

	kobj = kobject_create_and_add("cpu_input_boost", kernel_kobj);
	if (!kobj) {
		pr_err("Failed to create kobject\n");
		return -ENOMEM;
	}

	ret = sysfs_create_group(kobj, &cpu_ib_attr_group);
	if (ret) {
		pr_err("Failed to create sysfs interface\n");
		kobject_put(kobj);
	}

	return ret;
}

static struct boost_policy *alloc_boost_policy(void)
{
	struct boost_policy *b;

	b = kzalloc(sizeof(*b), GFP_KERNEL);
	if (!b)
		return NULL;

	b->wq = alloc_workqueue("cpu_ib_wq", WQ_HIGHPRI, 0);
	if (!b->wq) {
		pr_err("Failed to allocate workqueue\n");
		goto free_b;
	}

	return b;

free_b:
	kfree(b);
	return NULL;
}

static int __init cpu_ib_init(void)
{
	struct boost_policy *b;
	int ret;

	b = alloc_boost_policy();
	if (!b) {
		pr_err("Failed to allocate boost policy\n");
		return -ENOMEM;
	}

	spin_lock_init(&b->lock);

	INIT_DELAYED_WORK(&b->ib.boost_work, ib_boost_main);
	INIT_DELAYED_WORK(&b->ib.unboost_work, ib_unboost_main);

	/* Allow global boost config access */
	boost_policy_g = b;

	/* Enabled by default */
	set_boost_bit(b, DRIVER_ENABLED);

	ret = input_register_handler(&cpu_ib_input_handler);
	if (ret) {
		pr_err("Failed to register input handler, err: %d\n", ret);
		goto free_mem;
	}

	ret = sysfs_ib_init();
	if (ret)
		goto input_unregister;

	cpufreq_register_notifier(&do_cpu_boost_nb, CPUFREQ_POLICY_NOTIFIER);

	pr_info("initialized (%d%% boost for %dms on touch)\n",
			IB_PERCENT, IB_DURATION_MS);

	return 0;

input_unregister:
	input_unregister_handler(&cpu_ib_input_handler);
free_mem:
	boost_policy_g = NULL;
	destroy_workqueue(b->wq);
	kfree(b);
	return ret;
}
late_initcall(cpu_ib_init);
