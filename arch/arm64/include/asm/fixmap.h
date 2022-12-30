/*
 * fixmap.h: compile-time virtual memory allocation
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 1998 Ingo Molnar
 * Copyright (C) 2013 Mark Salter <msalter@redhat.com>
 *
 * Adapted from arch/x86 version.
 *
 */

#ifndef _ASM_ARM64_FIXMAP_H
#define _ASM_ARM64_FIXMAP_H

#ifndef __ASSEMBLY__
#include <linux/kernel.h>
#include <linux/sizes.h>
#include <asm/boot.h>
#include <asm/page.h>
#include <asm/pgtable-prot.h>

/*
 * Here we define all the compile-time 'special' virtual
 * addresses. The point is to have a constant address at
 * compile time, but to set the physical address only
 * in the boot process.
 *
 * Each enum increment in these 'compile-time allocated'
 * memory buffers is page-sized. Use set_fixmap(idx,phys)
 * to associate physical memory with a fixmap index.
 */
/*
 *                                                                  L0         L1          L2        L3
 *                                                              |         ||         ||         |          |
 * FIXADDR_TOP:   0xFFFF 7DFF FE7F 9000 --> 1111 1111 1111 1111 0111 1101 1111 1111 1111 1110 0111 1111 1001 0000 0000 0000
 * FIXADDR_START: 0xFFFF 7DFF FEC0 0000 --> 1111 1111 1111 1111 0111 1101 1111 1111 1111 1110 1100 0000 0000 0000 0000 0000
 *                                                                                              | 2M对齐
 * 因为(MAX_FDT_SIZE + SZ_2M)是4M，再往底下 (6 + 1) * 4 = 28K，总共是 4124KB大小的空间(FIXADDR_START - FIXADDR_TOP)
 * FDT一般是用块映射的，所以FDT用了L2 index (11 1110 110) 和 (11 1110 110)。后面再小的地址才开始用 11 1110 011(页映射)
 * 可以观察到L3 index (11 1111 1001)到(11 1111 1111)就是用了 7 * 4 KB = 28KB的范围，那么剩下的范围就给到Temporary Fixmap。
 * early_fixmap_init 已经把框架映射好了，所以FDT只需要填 L2那层的 PTE就可以，Temorary Fixmap只需要填L3那层的PTE就可以。
 */
enum fixed_addresses {
	FIX_HOLE,

	/*
	 * Reserve a virtual window for the FDT that is 2 MB larger than the
	 * maximum supported size, and put it at the top of the fixmap region.
	 * The additional space ensures that any FDT that does not exceed
	 * MAX_FDT_SIZE can be mapped regardless of whether it crosses any
	 * 2 MB alignment boundaries.
	 *
	 * Keep this at the top so it remains 2 MB aligned.
	 */
#define FIX_FDT_SIZE		(MAX_FDT_SIZE + SZ_2M)
	FIX_FDT_END,
	FIX_FDT = FIX_FDT_END + FIX_FDT_SIZE / PAGE_SIZE - 1,

	FIX_EARLYCON_MEM_BASE,
	FIX_TEXT_POKE0,

#ifdef CONFIG_ACPI_APEI_GHES
	/* Used for GHES mapping from assorted contexts */
	FIX_APEI_GHES_IRQ,
	FIX_APEI_GHES_SEA,
#ifdef CONFIG_ARM_SDE_INTERFACE
	FIX_APEI_GHES_SDEI_NORMAL,
	FIX_APEI_GHES_SDEI_CRITICAL,
#endif
#endif /* CONFIG_ACPI_APEI_GHES */

#ifdef CONFIG_UNMAP_KERNEL_AT_EL0
	FIX_ENTRY_TRAMP_TEXT3,
	FIX_ENTRY_TRAMP_TEXT2,
	FIX_ENTRY_TRAMP_TEXT1,
	FIX_ENTRY_TRAMP_DATA,
#define TRAMP_VALIAS		(__fix_to_virt(FIX_ENTRY_TRAMP_TEXT1))
#endif /* CONFIG_UNMAP_KERNEL_AT_EL0 */
	__end_of_permanent_fixed_addresses,

	/*
	 * Temporary boot-time mappings, used by early_ioremap(),
	 * before ioremap() is functional.
	 */
#define NR_FIX_BTMAPS		(SZ_256K / PAGE_SIZE)
#define FIX_BTMAPS_SLOTS	7
#define TOTAL_FIX_BTMAPS	(NR_FIX_BTMAPS * FIX_BTMAPS_SLOTS)

	FIX_BTMAP_END = __end_of_permanent_fixed_addresses,
	FIX_BTMAP_BEGIN = FIX_BTMAP_END + TOTAL_FIX_BTMAPS - 1,

	/*
	 * Used for kernel page table creation, so unmapped memory may be used
	 * for tables.
	 */
	FIX_PTE,
	FIX_PMD,
	FIX_PUD,
	FIX_PGD,

	__end_of_fixed_addresses
};

#define FIXADDR_SIZE	(__end_of_permanent_fixed_addresses << PAGE_SHIFT)
#define FIXADDR_START	(FIXADDR_TOP - FIXADDR_SIZE)

#define FIXMAP_PAGE_IO     __pgprot(PROT_DEVICE_nGnRE)

void __init early_fixmap_init(void);

#define __early_set_fixmap __set_fixmap

#define __late_set_fixmap __set_fixmap
#define __late_clear_fixmap(idx) __set_fixmap((idx), 0, FIXMAP_PAGE_CLEAR)

extern void __set_fixmap(enum fixed_addresses idx, phys_addr_t phys, pgprot_t prot);

#include <asm-generic/fixmap.h>

#endif /* !__ASSEMBLY__ */
#endif /* _ASM_ARM64_FIXMAP_H */
