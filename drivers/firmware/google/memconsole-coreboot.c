/*
 * memconsole-coreboot.c
 *
 * Memory based BIOS console accessed through coreboot table.
 *
 * Copyright 2016 Google Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License v2.0 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>

#include "memconsole.h"
#include "coreboot_table.h"

#define CB_TAG_CBMEM_CONSOLE	0x17

static int memconsole_probe(struct platform_device *pdev)
{
	int ret;
	struct lb_cbmem_ref entry;

	ret = coreboot_table_find(CB_TAG_CBMEM_CONSOLE, &entry, sizeof(entry));
	if (ret)
		return ret;

	ret = memconsole_coreboot_init(entry.cbmem_addr);
	if (ret)
		return ret;

	return memconsole_sysfs_init();
}

static int memconsole_remove(struct platform_device *pdev)
{
	memconsole_exit();
	return 0;
}

static struct platform_driver memconsole_driver = {
	.probe = memconsole_probe,
	.remove = memconsole_remove,
	.driver = {
		.name = "memconsole",
	},
};

static int __init platform_memconsole_init(void)
{
	struct platform_device *pdev;

	pdev = platform_device_register_simple("memconsole", -1, NULL, 0);
	if (pdev == NULL)
		return -ENODEV;

	platform_driver_register(&memconsole_driver);

	return 0;
}

module_init(platform_memconsole_init);

MODULE_AUTHOR("Google, Inc.");
MODULE_LICENSE("GPL");
