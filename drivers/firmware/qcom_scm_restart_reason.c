/* Copyright (c) 2015-2016, The Linux Foundation. All rights reserved.
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

#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>
#include <linux/notifier.h>
#include <linux/reboot.h>
#include <linux/qcom_scm.h>

#include "qcom_scm.h"

#define SET_MAGIC	0x1
#define CLEAR_MAGIC	0x0
#define SCM_CMD_TZ_CONFIG_HW_FOR_RAM_DUMP_ID	0x9
#define SCM_CMD_TZ_FORCE_DLOAD_ID		0x10
#define SCM_CMD_TZ_SET_DLOAD_FOR_SECURE_BOOT	0x14

static int dload_dis;

static void scm_restart_dload_mode_enable(void)
{
	if (!dload_dis) {
		unsigned int magic_cookie = SET_MAGIC;

		qcom_scm_call(QCOM_SCM_SVC_BOOT, SCM_CMD_TZ_FORCE_DLOAD_ID, &magic_cookie,
			sizeof(magic_cookie), NULL, 0);
	}
}

static void scm_restart_dload_mode_disable(void)
{
	unsigned int magic_cookie = CLEAR_MAGIC;
	qcom_scm_call(QCOM_SCM_SVC_BOOT, SCM_CMD_TZ_FORCE_DLOAD_ID, &magic_cookie,
		sizeof(magic_cookie), NULL, 0);
}

static void scm_restart_sdi_disable(void)
{
	unsigned int clear_info[] = {
		1 /* Disable wdog debug */, 0 /* SDI enable*/, };
	qcom_scm_call(QCOM_SCM_SVC_BOOT, SCM_CMD_TZ_CONFIG_HW_FOR_RAM_DUMP_ID,
		&clear_info, sizeof(clear_info), NULL, 0);
}

static int scm_restart_panic(struct notifier_block *this,
	unsigned long event, void *data)
{
	scm_restart_dload_mode_enable();
	scm_restart_sdi_disable();

	return NOTIFY_DONE;
}

static struct notifier_block panic_nb = {
	.notifier_call = scm_restart_panic,
};

static int scm_restart_reason_reboot(struct notifier_block *nb,
				unsigned long action, void *data)
{
	scm_restart_sdi_disable();
	scm_restart_dload_mode_disable();

	return NOTIFY_DONE;
}

static struct notifier_block reboot_nb = {
	.notifier_call = scm_restart_reason_reboot,
};

static int scm_restart_reason_probe(struct platform_device *pdev)
{
	int ret, dload_dis_sec;

	ret = of_property_read_u32(pdev->dev.of_node, "dload_status", &dload_dis);
	if (ret)
		dload_dis = 0;

	ret = of_property_read_u32(pdev->dev.of_node, "dload_sec_status", &dload_dis_sec);
	if (ret)
		dload_dis_sec = 0;

	if (dload_dis_sec) {
		qcom_scm_call(QCOM_SCM_SVC_BOOT, SCM_CMD_TZ_SET_DLOAD_FOR_SECURE_BOOT,
							NULL, 0, NULL, 0);
	}

	/* Ensure Disable before enabling the dload and sdi bits
	 * to make sure they are disabled during boot */
	if (dload_dis) {
		scm_restart_dload_mode_disable();
		scm_restart_sdi_disable();
	} else {
		scm_restart_dload_mode_enable();
	}

	ret = atomic_notifier_chain_register(&panic_notifier_list, &panic_nb);
	if (ret) {
		dev_err(&pdev->dev, "failed to setup download mode\n");
		return ret;
	}

	ret = register_reboot_notifier(&reboot_nb);
	if (ret) {
		dev_err(&pdev->dev, "failed to setup reboot handler\n");
		atomic_notifier_chain_unregister(&panic_notifier_list,
								&panic_nb);
		return ret;
	}

	return 0;
}

static int scm_restart_reason_remove(struct platform_device *pdev)
{
	atomic_notifier_chain_unregister(&panic_notifier_list, &panic_nb);
	unregister_reboot_notifier(&reboot_nb);
	return 0;
}

static const struct of_device_id scm_restart_reason_match_table[] = {
	{ .compatible = "qca,scm_restart_reason", },
	{}
};
MODULE_DEVICE_TABLE(of, scm_restart_reason_match_table);

static struct platform_driver scm_restart_reason_driver = {
	.probe      = scm_restart_reason_probe,
	.remove     = scm_restart_reason_remove,
	.driver     = {
		.name = "qca_scm_restart_reason",
		.of_match_table = scm_restart_reason_match_table,
	},
};

module_platform_driver(scm_restart_reason_driver);

MODULE_DESCRIPTION("QCA SCM Restart Reason Driver");
MODULE_LICENSE("GPL v2");
