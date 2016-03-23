/*
 * Copyright (c) 2016, The Linux Foundation. All rights reserved.
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

#include <linux/err.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>

static int __init ipq4019_cpufreq_driver_init(void)
{
	struct platform_device *pdev;

	if (!of_machine_is_compatible("qcom,ipq4019"))
		return -ENODEV;

	pdev = platform_device_register_simple("cpufreq-dt", -1, NULL, 0);
	return PTR_ERR_OR_ZERO(pdev);
}
module_init(ipq4019_cpufreq_driver_init);

MODULE_AUTHOR("Matthew McClintock <mmcclint@codeaurora.org>");
MODULE_DESCRIPTION("ipq4019 cpufreq driver");
MODULE_LICENSE("GPL");
