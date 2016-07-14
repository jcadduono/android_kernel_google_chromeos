/* Copyright (c) 2014,2016 The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/reboot.h>
#include <linux/watchdog.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/qcom_scm.h>
#include <linux/smp.h>
#include <asm/system_misc.h>

#define WDOG_IPQ4019_COMPAT_STR "qcom,kpss-wdt-ipq4019"
#define WDOG_IPQ8064_COMPAT_STR "qcom,kpss-wdt-ipq8064"
#define WDOG_KPSS_COMPAT_STR "qcom,kpss-timer"
#define WDOG_SCSS_COMPAT_STR "qcom,scss-timer"

static int in_panic;

enum wdt_reg {
	WDT_RST,
	WDT_EN,
	WDT_BARK_TIME,
	WDT_BITE_TIME,
};

static const u32 reg_offset_data_apcs_tmr[] = {
	[WDT_RST] = 0x38,
	[WDT_EN] = 0x40,
	[WDT_BARK_TIME] = 0x4C,
	[WDT_BITE_TIME] = 0x5C,
};

static const u32 reg_offset_data_kpss[] = {
	[WDT_RST] = 0x4,
	[WDT_EN] = 0x8,
	[WDT_BARK_TIME] = 0x10,
	[WDT_BITE_TIME] = 0x14,
};

struct qcom_wdt {
	struct watchdog_device	wdd;
	struct clk		*clk;
	unsigned long		rate;
	unsigned int		bite;
	void __iomem		*base;
	const u32		*layout;
};

static void __iomem *wdt_addr(struct qcom_wdt *wdt, enum wdt_reg reg)
{
	return wdt->base + wdt->layout[reg];
}

static inline
struct qcom_wdt *to_qcom_wdt(struct watchdog_device *wdd)
{
	return container_of(wdd, struct qcom_wdt, wdd);
}

static int panic_prep_restart(struct notifier_block *this,
				unsigned long event, void *ptr)
{
	in_panic = 1;
	arm_pm_restart = NULL;
	return NOTIFY_DONE;
}

static struct notifier_block panic_blk = {
	.notifier_call  = panic_prep_restart,
};

static long qcom_wdt_configure_bark_dump(void *arg)
{
	long ret = -ENOMEM;
	const struct of_device_id *id = (const struct of_device_id *)arg;

	/*
	 * For IPQ4019 devices, TZ stores the register
	 * details in a preset address after the crash.
	 * Hence there is no need to allocate memory or
	 * call scm for crash register save functionality.
	 */

	if (!strncmp(id->compatible, WDOG_IPQ4019_COMPAT_STR,
		strlen(WDOG_IPQ4019_COMPAT_STR)))
		return ret;

	ret = qcom_scm_regsave(SCM_SVC_UTIL, SCM_CMD_SET_REGSAVE);
	if (ret)
		pr_err("Setting register save address failed.\n"
			"Registers won't be dumped on a dog bite\n");
	return ret;
}

static int qcom_wdt_start_secure(struct watchdog_device *wdd)
{
	struct qcom_wdt *wdt = to_qcom_wdt(wdd);

	writel(0, wdt_addr(wdt, WDT_EN));
	writel(1, wdt_addr(wdt, WDT_RST));

	if (wdt->bite) {
		writel((wdd->timeout - 1) * wdt->rate,
			wdt_addr(wdt, WDT_BARK_TIME));
		writel(wdd->timeout * wdt->rate, wdt_addr(wdt, WDT_BITE_TIME));
	} else {
		writel(wdd->timeout * wdt->rate, wdt_addr(wdt, WDT_BARK_TIME));
		writel(0x0FFFFFFF, wdt_addr(wdt, WDT_BITE_TIME));
	}

	writel(1, wdt_addr(wdt, WDT_EN));
	return 0;
}

static int qcom_wdt_start_nonsecure(struct watchdog_device *wdd)
{
	struct qcom_wdt *wdt = to_qcom_wdt(wdd);

	writel(0, wdt_addr(wdt, WDT_EN));
	writel(1, wdt_addr(wdt, WDT_RST));
	writel(wdd->timeout * wdt->rate, wdt_addr(wdt, WDT_BARK_TIME));
	writel(0x0FFFFFFF, wdt_addr(wdt, WDT_BITE_TIME));
	writel(1, wdt_addr(wdt, WDT_EN));
	return 0;
}

static int qcom_wdt_stop(struct watchdog_device *wdd)
{
	struct qcom_wdt *wdt = to_qcom_wdt(wdd);

	writel(0, wdt_addr(wdt, WDT_EN));
	return 0;
}

static int qcom_wdt_ping(struct watchdog_device *wdd)
{
	struct qcom_wdt *wdt = to_qcom_wdt(wdd);

	writel(1, wdt_addr(wdt, WDT_RST));
	return 0;
}

static int qcom_wdt_set_timeout(struct watchdog_device *wdd,
				unsigned int timeout)
{
	wdd->timeout = timeout;
	return wdd->ops->start(wdd);
}

static int qcom_wdt_restart(struct watchdog_device *wdd)
{
	struct qcom_wdt *wdt = to_qcom_wdt(wdd);
	u32 timeout;

	/*
	 * Trigger watchdog bite:
	 *    Setup BITE_TIME to be 128ms, and enable WDT.
	 */
	timeout = 128 * wdt->rate / 1000;

	writel(0, wdt_addr(wdt, WDT_EN));
	writel(1, wdt_addr(wdt, WDT_RST));
	if (in_panic) {
		writel(timeout, wdt_addr(wdt, WDT_BARK_TIME));
		writel(2 * timeout, wdt_addr(wdt, WDT_BITE_TIME));
	} else {
		writel(5 * timeout, wdt_addr(wdt, WDT_BARK_TIME));
		writel(timeout, wdt_addr(wdt, WDT_BITE_TIME));
	}

	writel(1, wdt_addr(wdt, WDT_EN));
	/*
	 * Actually make sure the above sequence hits hardware before sleeping.
	 */
	wmb();

	mdelay(150);
	return 0;
}


static const struct watchdog_ops qcom_wdt_ops_secure = {
	.start		= qcom_wdt_start_secure,
	.stop		= qcom_wdt_stop,
	.ping		= qcom_wdt_ping,
	.set_timeout	= qcom_wdt_set_timeout,
	.restart        = qcom_wdt_restart,
	.owner		= THIS_MODULE,
};

static const struct watchdog_ops qcom_wdt_ops_nonsecure = {
	.start		= qcom_wdt_start_nonsecure,
	.stop		= qcom_wdt_stop,
	.ping		= qcom_wdt_ping,
	.set_timeout	= qcom_wdt_set_timeout,
	.restart        = qcom_wdt_restart,
	.owner		= THIS_MODULE,
};

static const struct watchdog_info qcom_wdt_info = {
	.options	= WDIOF_KEEPALIVEPING
			| WDIOF_MAGICCLOSE
			| WDIOF_SETTIMEOUT,
	.identity	= KBUILD_MODNAME,
};

static const struct of_device_id qcom_wdt_of_table[] = {
	{
		.compatible = WDOG_IPQ8064_COMPAT_STR,
		.data = &reg_offset_data_apcs_tmr
	},
	{
		.compatible = WDOG_IPQ4019_COMPAT_STR,
		.data = &reg_offset_data_kpss
	},
	{
		.compatible = WDOG_KPSS_COMPAT_STR,
		.data = &reg_offset_data_kpss
	},
	{
		.compatible = WDOG_SCSS_COMPAT_STR,
		.data = &reg_offset_data_kpss
	},
	{ },
};

MODULE_DEVICE_TABLE(of, qcom_wdt_of_table);

static irqreturn_t wdt_bark_isr(int irq, void *wdd)
{
	struct qcom_wdt *wdt = to_qcom_wdt(wdd);
	unsigned long nanosec_rem;
	unsigned long long t = sched_clock();

	nanosec_rem = do_div(t, 1000000000);
	pr_info("Watchdog bark! Now = %lu.%06lu\n", (unsigned long) t,
							nanosec_rem / 1000);
	pr_info("Causing a watchdog bite!");
	writel(0, wdt_addr(wdt, WDT_EN));
	writel(1, wdt_addr(wdt, WDT_BITE_TIME));
	writel(1, wdt_addr(wdt, WDT_RST));
	writel(1, wdt_addr(wdt, WDT_EN));

	mdelay(1);
	pr_err("Wdog - CTL: 0x%x, BARK TIME: 0x%x, BITE TIME: 0x%x",
		readl(wdt_addr(wdt, WDT_EN)),
		readl(wdt_addr(wdt, WDT_BARK_TIME)),
		readl(wdt_addr(wdt, WDT_BITE_TIME)));
	return IRQ_HANDLED;
}

void register_wdt_bark_irq(int irq, struct qcom_wdt *wdt)
{
	int ret;

	ret = request_irq(irq, wdt_bark_isr, IRQF_TRIGGER_HIGH,
						"watchdog bark", wdt);
	if (ret)
		pr_err("error request_irq(irq_num:%d ) ret:%d\n", irq, ret);
}

static int qcom_wdt_probe(struct platform_device *pdev)
{
	const struct of_device_id *id;
	struct qcom_wdt *wdt;
	struct resource *res;
	struct device_node *np = pdev->dev.of_node;
	u32 percpu_offset;
	int ret, irq;

	wdt = devm_kzalloc(&pdev->dev, sizeof(*wdt), GFP_KERNEL);
	if (!wdt)
		return -ENOMEM;

	irq = platform_get_irq_byname(pdev, "bark_irq");
	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);

	/* We use CPU0's DGT for the watchdog */
	if (of_property_read_u32(np, "cpu-offset", &percpu_offset))
		percpu_offset = 0;

	res->start += percpu_offset;
	res->end += percpu_offset;

	wdt->base = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(wdt->base))
		return PTR_ERR(wdt->base);

	id = of_match_device(qcom_wdt_of_table, &pdev->dev);
	if (!id)
		return -ENODEV;

	if (id->data)
		wdt->bite = 1;

	if (irq > 0)
		register_wdt_bark_irq(irq, wdt);

	wdt->clk = devm_clk_get(&pdev->dev, NULL);
	if (IS_ERR(wdt->clk)) {
		dev_err(&pdev->dev, "failed to get input clock\n");
		return PTR_ERR(wdt->clk);
	}

	ret = clk_prepare_enable(wdt->clk);
	if (ret) {
		dev_err(&pdev->dev, "failed to setup clock\n");
		return ret;
	}

	/*
	 * We use the clock rate to calculate the max timeout, so ensure it's
	 * not zero to avoid a divide-by-zero exception.
	 *
	 * WATCHDOG_CORE assumes units of seconds, if the WDT is clocked such
	 * that it would bite before a second elapses it's usefulness is
	 * limited.  Bail if this is the case.
	 */
	wdt->rate = clk_get_rate(wdt->clk);
	if (wdt->rate == 0 ||
	    wdt->rate > 0x10000000U) {
		dev_err(&pdev->dev, "invalid clock rate\n");
		ret = -EINVAL;
		goto err_clk_unprepare;
	}

	ret = work_on_cpu(0, qcom_wdt_configure_bark_dump, (void *)id);
	if (ret)
		wdt->wdd.ops = &qcom_wdt_ops_nonsecure;
	else
		wdt->wdd.ops = &qcom_wdt_ops_secure;

	wdt->wdd.dev = &pdev->dev;
	wdt->wdd.info = &qcom_wdt_info;
	wdt->wdd.min_timeout = 1;
	wdt->wdd.max_timeout = 0x10000000U / wdt->rate;
	wdt->wdd.parent = &pdev->dev;
	wdt->layout = id->data;

	/*
	 * If 'timeout-sec' unspecified in devicetree, assume a 30 second
	 * default, unless the max timeout is less than 30 seconds, then use
	 * the max instead.
	 */
	wdt->wdd.timeout = min(wdt->wdd.max_timeout, 30U);
	watchdog_init_timeout(&wdt->wdd, 0, &pdev->dev);

	ret = watchdog_register_device(&wdt->wdd);
	if (ret) {
		dev_err(&pdev->dev, "failed to register watchdog\n");
		goto err_clk_unprepare;
	}

	/*
	 * WDT restart notifier has priority 0 (use as a last resort)
	 */
	atomic_notifier_chain_register(&panic_notifier_list, &panic_blk);

	platform_set_drvdata(pdev, wdt);
	return 0;

err_clk_unprepare:
	clk_disable_unprepare(wdt->clk);
	return ret;
}

static int qcom_wdt_remove(struct platform_device *pdev)
{
	struct qcom_wdt *wdt = platform_get_drvdata(pdev);

	watchdog_unregister_device(&wdt->wdd);
	clk_disable_unprepare(wdt->clk);
	return 0;
}

static struct platform_driver qcom_watchdog_driver = {
	.probe	= qcom_wdt_probe,
	.remove	= qcom_wdt_remove,
	.driver	= {
		.name		= KBUILD_MODNAME,
		.of_match_table	= qcom_wdt_of_table,
	},
};
module_platform_driver(qcom_watchdog_driver);

MODULE_DESCRIPTION("QCOM KPSS Watchdog Driver");
MODULE_LICENSE("GPL v2");
