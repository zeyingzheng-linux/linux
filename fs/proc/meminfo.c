// SPDX-License-Identifier: GPL-2.0
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/mman.h>
#include <linux/mmzone.h>
#include <linux/proc_fs.h>
#include <linux/percpu.h>
#include <linux/seq_file.h>
#include <linux/swap.h>
#include <linux/vmstat.h>
#include <linux/atomic.h>
#include <linux/vmalloc.h>
#ifdef CONFIG_CMA
#include <linux/cma.h>
#endif
#include <asm/page.h>
#include "internal.h"

void __attribute__((weak)) arch_report_meminfo(struct seq_file *m)
{
}

static void show_val_kb(struct seq_file *m, const char *s, unsigned long num)
{
	seq_put_decimal_ull_width(m, s, num << (PAGE_SHIFT - 10), 8);
	seq_write(m, " kB\n", 4);
}

static int meminfo_proc_show(struct seq_file *m, void *v)
{
	struct sysinfo i;
	unsigned long committed;
	long cached;
	long available;
	unsigned long pages[NR_LRU_LISTS];
	unsigned long sreclaimable, sunreclaim;
	int lru;

	si_meminfo(&i);
	si_swapinfo(&i);
	committed = vm_memory_committed();

	cached = global_node_page_state(NR_FILE_PAGES) -
			total_swapcache_pages() - i.bufferram;
	if (cached < 0)
		cached = 0;

	for (lru = LRU_BASE; lru < NR_LRU_LISTS; lru++)
		pages[lru] = global_node_page_state(NR_LRU_BASE + lru);

	available = si_mem_available();
	sreclaimable = global_node_page_state_pages(NR_SLAB_RECLAIMABLE_B);
	sunreclaim = global_node_page_state_pages(NR_SLAB_UNRECLAIMABLE_B);

	/* 内核是如何得到totalram_pages这个值的呢？是在初始化的过程中得到的，
	 * 具体如下：我们知道，在内核初始化的时候，我们可以通过memblock模块
	 * 来管理内存布局，从而得到了memory type和reserved type的内存列表信
	 * 息。在初始化阶段如果有内存分配的需求，那么也可以通过memblock来完
	 * 成，直到伙伴系统初始化完成，而在这个过程中，memory type的那些page
	 * frame被一个个的注入到各个zone的free list中，同时用totalram_pages
	 * 来记录那个时间点中空闲的page frame数量。这个点也就是伙伴系统的一
	 * 个初始内存数量的起点
	 * */
	show_val_kb(m, "MemTotal:       ", i.totalram);
	/* 启动的时候，系统确定了MemTotal的数目，但是随着系统启动过程，内核
	 * 会动态申请内存，此外，用户空间也会不断创建进程，也会不断的消耗内
	 * 存，因此MemTotal可以简单分成两个部分：正在使用的和空闲的。MemFree
	 * 表示的就是当前空闲的内存数目，这些空闲的page应该是挂在各个node的
	 * 各个zone的buddy系统中
	 * */
	show_val_kb(m, "MemFree:        ", i.freeram);
	/* 所谓memory available，其实就是不引起swapping操作的情况下，我们能
	 * 使用多少的内存。即便是free的，也不是每一个page都可以用于内存分配
	 * 。例如buddy system会设定一个水位，一旦free memory低于这个水位，
	 * 系统就会启动page reclaim，从而可能引起swapping操作。因此，我们需
	 * 要从MemFree这个数值中去掉各个节点、各个zone的预留的内存（WMARK_LOW）
	 * 数目。当然，也是不是说那些不是空闲的页面我们就不能使用，例如page
	 * cache，虽然不是空闲的，但是它也不过是为了加快性能而使用，其实也可
	 * 以回收使用。当然，也不是所有的page cache都可以计算进入MemAvailable，
	 * 有些page cache在回收的时候会引起swapping，这些page cache就不能算数
	 * 了。此外，reclaimable slab中也有一些可以使用的内存，MemAvailable也
	 * 会考虑这部分内存的情况
	 * */
	show_val_kb(m, "MemAvailable:   ", available);
	/* 其实新的内核已经没有buffer cache了，一切都统一到了page cache的框架
	 * 下了。因此，所谓的buffer cache就是块设备的page cache
	 * 我们知道，内核是通过address_space来管理page cache的，那么块设备的
	 * address_space在哪里呢？这个稍微复杂一点，涉及多个inode，假设
	 * /dev/aaa和/dev/bbb都是指向同一个物理块设备，那么open/dev/aaa和/dev/bbb
	 * 会分别产生两个inode，我们称之inode_aaa和inode_bbb，但是最后一个块设备
	 * 的page cache还是需要统一管理起来，不可能分别在inode_aaa和inode_bbb中
	 * 管理。因此，Linux构造了一个bdev文件系统，保存了系统所有块设备的inode，
	 * 我们假设该物理块设备在bdev文件系统中的inode是inode_bdev。上面讲了这么
	 * 多的inode，其实块设备的page cache就是在inode_bdev中管理的
	 * 一般来说，buffers的数量不多，因为产生buffer的操作包括：
	 * 1. 打开该block device的设备节点，直接进行读写操作（例如dd一个块设备）
	 * 2. mount文件系统的时候，需要从相应的block device上直接把块设备上的特定
	 * 文件系统的super block相关信息读取出来，这些super block的raw data会保存
	 * 在该block device的page cache中
	 * 3. 文件操作的时候，和文件元数据相关的操作（例如读取磁盘上的inode相关
	 * 的信息）也是通过buffer cache进行访问
	 * Linux中最多处理的是2和3的操作，1的操作很少有
	 * */
	show_val_kb(m, "Buffers:        ", i.bufferram);
	/* 读写普通文件的时候，我们并不会直接操作磁盘，而是通过page cache来加速
	 * 文件IO的性能。Cached域描述的就是用于普通文件IO的page cache的数量
	 * 系统中所有的page cache都会被记录在一个全局的状态中，通过
	 * global_page_state(NR_FILE_PAGES)可以知道这个数据，这个数据包括:
	 * 1. 普通文件的page cache
	 * 2. block device 的page cache
	 * 3. swap cache
	 * 对于Cached这个域，我们只关心普通文件的page cache，因此要从page cache
	 * 的total number中减去buffer cache和swap cache
	 * */
	show_val_kb(m, "Cached:         ", cached);
	/* 和其他的page cache不一样，swap cache并不是为了加快磁盘IO的性能，它是为
	 * 了解决page frame和swap area之间的同步问题而引入的。例如：一个进程准备
	 * swap in一个page的时候，内核的内存回收模块可能同时也在试图将这个page
	 * swap out。为了解决这些这些同步问题，内核引入了swap cache这个概念，在任
	 * 何模块进行swap in或者swap out的时候，都必须首先去swap cache中去看看，而
	 * 借助page descriptor的PG_locked的标记，我们可以避免swap中的race condition。
	 *
	 * swap cache在具体实现的时候，仍然借用了page cache的概念，每一个swap area
	 * 都有一个address space，管理该swap device（或者swap file）的page cache。因
	 * 此，一个swap device的所有swap cache仍然是保存在对应address space的radix
	 * tree中（仍然是熟悉的配方，仍然是熟悉的味道啊）
	 * */
	show_val_kb(m, "SwapCached:     ", total_swapcache_pages());
	show_val_kb(m, "Active:         ", pages[LRU_ACTIVE_ANON] +
					   pages[LRU_ACTIVE_FILE]);
	show_val_kb(m, "Inactive:       ", pages[LRU_INACTIVE_ANON] +
					   pages[LRU_INACTIVE_FILE]);
	show_val_kb(m, "Active(anon):   ", pages[LRU_ACTIVE_ANON]);
	show_val_kb(m, "Inactive(anon): ", pages[LRU_INACTIVE_ANON]);
	show_val_kb(m, "Active(file):   ", pages[LRU_ACTIVE_FILE]);
	show_val_kb(m, "Inactive(file): ", pages[LRU_INACTIVE_FILE]);
	show_val_kb(m, "Unevictable:    ", pages[LRU_UNEVICTABLE]);
	show_val_kb(m, "Mlocked:        ", global_zone_page_state(NR_MLOCK));

#ifdef CONFIG_HIGHMEM
	show_val_kb(m, "HighTotal:      ", i.totalhigh);
	show_val_kb(m, "HighFree:       ", i.freehigh);
	show_val_kb(m, "LowTotal:       ", i.totalram - i.totalhigh);
	show_val_kb(m, "LowFree:        ", i.freeram - i.freehigh);
#endif

#ifndef CONFIG_MMU
	show_val_kb(m, "MmapCopy:       ",
		    (unsigned long)atomic_long_read(&mmap_pages_allocated));
#endif

	show_val_kb(m, "SwapTotal:      ", i.totalswap);
	show_val_kb(m, "SwapFree:       ", i.freeswap);
	show_val_kb(m, "Dirty:          ",
		    global_node_page_state(NR_FILE_DIRTY));
	show_val_kb(m, "Writeback:      ",
		    global_node_page_state(NR_WRITEBACK));
	show_val_kb(m, "AnonPages:      ",
		    global_node_page_state(NR_ANON_MAPPED));
	show_val_kb(m, "Mapped:         ",
		    global_node_page_state(NR_FILE_MAPPED));
	show_val_kb(m, "Shmem:          ", i.sharedram);
	show_val_kb(m, "KReclaimable:   ", sreclaimable +
		    global_node_page_state(NR_KERNEL_MISC_RECLAIMABLE));
	show_val_kb(m, "Slab:           ", sreclaimable + sunreclaim);
	show_val_kb(m, "SReclaimable:   ", sreclaimable);
	show_val_kb(m, "SUnreclaim:     ", sunreclaim);
	seq_printf(m, "KernelStack:    %8lu kB\n",
		   global_node_page_state(NR_KERNEL_STACK_KB));
#ifdef CONFIG_SHADOW_CALL_STACK
	seq_printf(m, "ShadowCallStack:%8lu kB\n",
		   global_node_page_state(NR_KERNEL_SCS_KB));
#endif
	show_val_kb(m, "PageTables:     ",
		    global_node_page_state(NR_PAGETABLE));

	show_val_kb(m, "NFS_Unstable:   ", 0);
	show_val_kb(m, "Bounce:         ",
		    global_zone_page_state(NR_BOUNCE));
	show_val_kb(m, "WritebackTmp:   ",
		    global_node_page_state(NR_WRITEBACK_TEMP));
	show_val_kb(m, "CommitLimit:    ", vm_commit_limit());
	show_val_kb(m, "Committed_AS:   ", committed);
	seq_printf(m, "VmallocTotal:   %8lu kB\n",
		   (unsigned long)VMALLOC_TOTAL >> 10);
	show_val_kb(m, "VmallocUsed:    ", vmalloc_nr_pages());
	show_val_kb(m, "VmallocChunk:   ", 0ul);
	show_val_kb(m, "Percpu:         ", pcpu_nr_pages());

#ifdef CONFIG_MEMORY_FAILURE
	seq_printf(m, "HardwareCorrupted: %5lu kB\n",
		   atomic_long_read(&num_poisoned_pages) << (PAGE_SHIFT - 10));
#endif

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	show_val_kb(m, "AnonHugePages:  ",
		    global_node_page_state(NR_ANON_THPS));
	show_val_kb(m, "ShmemHugePages: ",
		    global_node_page_state(NR_SHMEM_THPS));
	show_val_kb(m, "ShmemPmdMapped: ",
		    global_node_page_state(NR_SHMEM_PMDMAPPED));
	show_val_kb(m, "FileHugePages:  ",
		    global_node_page_state(NR_FILE_THPS));
	show_val_kb(m, "FilePmdMapped:  ",
		    global_node_page_state(NR_FILE_PMDMAPPED));
#endif

#ifdef CONFIG_CMA
	show_val_kb(m, "CmaTotal:       ", totalcma_pages);
	show_val_kb(m, "CmaFree:        ",
		    global_zone_page_state(NR_FREE_CMA_PAGES));
#endif

	hugetlb_report_meminfo(m);

	arch_report_meminfo(m);

	return 0;
}

static int __init proc_meminfo_init(void)
{
	proc_create_single("meminfo", 0, NULL, meminfo_proc_show);
	return 0;
}
fs_initcall(proc_meminfo_init);
