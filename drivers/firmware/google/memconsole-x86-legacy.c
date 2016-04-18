/*
 * memconsole-x86-legacy.c
 *
 * EBDA specific parts of the memory based BIOS console.
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

#include <asm/bios_ebda.h>
#include <asm/e820.h>
#include <linux/acpi.h>
#include <linux/dmi.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>

#include "memconsole.h"

#define BIOS_MEMCONSOLE_V1_MAGIC	0xDEADBABE
#define BIOS_MEMCONSOLE_V2_MAGIC	(('M')|('C'<<8)|('O'<<16)|('N'<<24))

#define CBMEM_CONSOLE_ACPI_NAME  "\\CBMC"

struct biosmemcon_ebda {
	u32 signature;
	union {
		struct {
			u8  enabled;
			u32 buffer_addr;
			u16 start;
			u16 end;
			u16 num_chars;
			u8  wrapped;
		} __packed v1;
		struct {
			u32 buffer_addr;
			/* Misdocumented as number of pages! */
			u16 num_bytes;
			u16 start;
			u16 end;
		} __packed v2;
	};
} __packed;

static void found_v1_header(struct biosmemcon_ebda *hdr)
{
	pr_info("memconsole: BIOS console v1 EBDA structure found at %p\n",
		hdr);
	pr_info("memconsole: BIOS console buffer at 0x%.8x, "
		"start = %d, end = %d, num = %d\n",
		hdr->v1.buffer_addr, hdr->v1.start,
		hdr->v1.end, hdr->v1.num_chars);

	memconsole_setup(phys_to_virt(hdr->v1.buffer_addr), hdr->v1.num_chars);
}

static void found_v2_header(struct biosmemcon_ebda *hdr)
{
	pr_info("memconsole: BIOS console v2 EBDA structure found at %p\n",
		hdr);
	pr_info("memconsole: BIOS console buffer at 0x%.8x, "
		"start = %d, end = %d, num_bytes = %d\n",
		hdr->v2.buffer_addr, hdr->v2.start,
		hdr->v2.end, hdr->v2.num_bytes);

	memconsole_setup(phys_to_virt(hdr->v2.buffer_addr + hdr->v2.start),
			 hdr->v2.end - hdr->v2.start);
}

/*
 * Search through the EBDA for the BIOS Memory Console, and
 * set the global variables to point to it.  Return true if found.
 */
static bool memconsole_ebda_init(void)
{
	unsigned int address;
	size_t length, cur;

	address = get_bios_ebda();
	if (!address) {
		pr_info("memconsole: BIOS EBDA non-existent.\n");
		return false;
	}

	/* EBDA length is byte 0 of EBDA (in KB) */
	length = *(u8 *)phys_to_virt(address);
	length <<= 10; /* convert to bytes */

	/*
	 * Search through EBDA for BIOS memory console structure
	 * note: signature is not necessarily dword-aligned
	 */
	for (cur = 0; cur < length; cur++) {
		struct biosmemcon_ebda *hdr = phys_to_virt(address + cur);

		/* memconsole v1 */
		if (hdr->signature == BIOS_MEMCONSOLE_V1_MAGIC) {
			found_v1_header(hdr);
			return true;
		}

		/* memconsole v2 */
		if (hdr->signature == BIOS_MEMCONSOLE_V2_MAGIC) {
			found_v2_header(hdr);
			return true;
		}
	}

	pr_info("memconsole: BIOS console EBDA structure not found!\n");
	return false;
}

static struct dmi_system_id memconsole_dmi_table[] __initdata = {
	{
		.ident = "Google Board",
		.matches = {
			DMI_MATCH(DMI_BOARD_VENDOR, "Google, Inc."),
		},
	},
	{
		.ident = "Google Board",
		.matches = {
			DMI_MATCH(DMI_BIOS_VENDOR, "coreboot"),
		},
	},
	{}
};
MODULE_DEVICE_TABLE(dmi, memconsole_dmi_table);

static phys_addr_t get_address_from_acpi(acpi_string pathname)
{
	acpi_handle handle;
	unsigned long long addr;

	if (!ACPI_SUCCESS(acpi_get_handle(NULL, pathname, &handle)))
		return 0;

	if (!ACPI_SUCCESS(acpi_evaluate_integer(handle, pathname, NULL, &addr)))
		return 0;

	return addr;
}

static bool __init memconsole_find(void)
{
	phys_addr_t physaddr;

	if (!dmi_check_system(memconsole_dmi_table))
		return false;

	physaddr = get_address_from_acpi(CBMEM_CONSOLE_ACPI_NAME);
	if (physaddr && memconsole_coreboot_init(physaddr) == 0)
		return true;

	return memconsole_ebda_init();
}

static int __init memconsole_x86_init(void)
{
	if (!memconsole_find())
		return -ENODEV;

	return memconsole_sysfs_init();
}

static void __exit memconsole_x86_exit(void)
{
	memconsole_exit();
}

module_init(memconsole_x86_init);
module_exit(memconsole_x86_exit);

MODULE_AUTHOR("Google, Inc.");
MODULE_LICENSE("GPL");
