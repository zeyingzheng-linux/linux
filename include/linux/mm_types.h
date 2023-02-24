/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MM_TYPES_H
#define _LINUX_MM_TYPES_H

#include <linux/mm_types_task.h>

#include <linux/auxvec.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/rbtree.h>
#include <linux/rwsem.h>
#include <linux/completion.h>
#include <linux/cpumask.h>
#include <linux/uprobes.h>
#include <linux/page-flags-layout.h>
#include <linux/workqueue.h>
#include <linux/seqlock.h>

#include <asm/mmu.h>

#ifndef AT_VECTOR_SIZE_ARCH
#define AT_VECTOR_SIZE_ARCH 0
#endif
#define AT_VECTOR_SIZE (2*(AT_VECTOR_SIZE_ARCH + AT_VECTOR_SIZE_BASE + 1))

#define INIT_PASID	0

struct address_space;
struct mem_cgroup;

/*
 * Each physical page in the system has a struct page associated with
 * it to keep track of whatever it is we are using the page for at the
 * moment. Note that we have no way to track which tasks are using
 * a page, though if it is a pagecache page, rmap structures can tell us
 * who is mapping it.
 *
 * If you allocate the page using alloc_pages(), you can use some of the
 * space in struct page for your own purposes.  The five words in the main
 * union are available, except for bit 0 of the first word which must be
 * kept clear.  Many users use this word to store a pointer to an object
 * which is guaranteed to be aligned.  If you use the same storage as
 * page->mapping, you must restore it to NULL before freeing the page.
 *
 * If your page will not be mapped to userspace, you can also use the four
 * bytes in the mapcount union, but you must call page_mapcount_reset()
 * before freeing it.
 *
 * If you want to use the refcount field, it must be used in such a way
 * that other CPUs temporarily incrementing and then decrementing the
 * refcount does not cause problems.  On receiving the page from
 * alloc_pages(), the refcount will be positive.
 *
 * If you allocate pages of order > 0, you can use some of the fields
 * in each subpage, but you may need to restore some of their values
 * afterwards.
 *
 * SLUB uses cmpxchg_double() to atomically update its freelist and
 * counters.  That requires that freelist & counters be adjacent and
 * double-word aligned.  We align all struct pages to double-word
 * boundaries, and ensure that 'freelist' is aligned within the
 * struct.
 */
#ifdef CONFIG_HAVE_ALIGNED_STRUCT_PAGE
#define _struct_page_alignment	__aligned(2 * sizeof(unsigned long))
#else
#define _struct_page_alignment
#endif

struct page {
	/* 页面标志位集合 */
	unsigned long flags;		/* Atomic flags, some possibly
					 * updated asynchronously */
	/*
	 * Five words (20/40 bytes) are available in this union.
	 * WARNING: bit 0 of the first word is used for PageTail(). That
	 * means the other users of this union MUST NOT use the bit to
	 * avoid collision and false-positive PageTail().
	 */
	union {
		struct {	/* Page cache and anonymous pages */
			/**
			 * @lru: Pageout list, eg. active_list protected by
			 * lruvec->lru_lock.  Sometimes used as a generic list
			 * by the page owner.
			 */
			/* 匿名页面或者文件映射页面会通过该成员添加到LRU链表中 */
			struct list_head lru;
			/* See page-flags.h for PAGE_MAPPING_FLAGS */
			/* mapping 成员表示页面锁指向的地址空间。内核中的地址空间通常有两个:
			 * 一个用于文件映射页面，如读取文件，地址空间将文件内容与存储介质做关联
			 * 一个用于匿名映射页面。
			 * 主要分成三种情况：
			 * 1. 对于匿名页面，mapping指向VMA的 anon_vma数据结构，也可能为NULL
			 * 2. 对于交换缓存页面，指向交换分区的 swapper_spaces
			 * 3. 对于文件映射页面，指向该文件所属的 address_space，它包含文件所属
			 * 的存储介质的相关信息，例如 inode。
			 * 内核将 mapping 的最低两位拿出来做判断:
			 * Bit[0]: 用于判断页面是否是匿名页面	PageAnon
			 * Bit[1]: 用于判断页面是否为非LRU页面 	__PageMovable
			 * Bit[1:0]: 都为1，则表示这是一个 KSM页面 PageKsm
			 * page_rmapping 用于返回 mapping 成员，但会清除最低2位
			 * page_mapping 用于返回page数据结构中 mapping 成员指向的地址空间
			 * page_mapped 用于判断该页面是否映射到用户PTE，利用 _mapcount成员
			 * */
			struct address_space *mapping;
			/* 放MIGRATE类型 */
			/* 表示这个页面在一个vma映射中的序号或偏移量 */
			pgoff_t index;		/* Our offset within mapping. */
			/**
			 * @private: Mapping-private opaque data.
			 * Usually used for buffer_heads if PagePrivate.
			 * Used for swp_entry_t if PageSwapCache.
			 * Indicates order in the buddy system if PageBuddy.
			 */
			/* 第一个页描述符会放order */
			/* 指向私有数据的指针 */
			unsigned long private;
		};
		struct {	/* page_pool used by netstack */
			/**
			 * @pp_magic: magic value to avoid recycling non
			 * page_pool allocated pages.
			 */
			unsigned long pp_magic;
			struct page_pool *pp;
			unsigned long _pp_mapping_pad;
			unsigned long dma_addr;
			union {
				/**
				 * dma_addr_upper: might require a 64-bit
				 * value on 32-bit architectures.
				 */
				unsigned long dma_addr_upper;
				/**
				 * For frag page support, not supported in
				 * 32-bit architectures with 64-bit DMA.
				 */
				atomic_long_t pp_frag_count;
			};
		};
		struct {	/* slab, slob and slub */
			union {
				struct list_head slab_list;
				struct {	/* Partial pages */
					struct page *next;
#ifdef CONFIG_64BIT
					int pages;	/* Nr of pages left */
					int pobjects;	/* Approximate count */
#else
					short int pages;
					short int pobjects;
#endif
				};
			};
			/* slab缓存描述符，slab分配器中的第一个物理页面的page数据结构中的
			 * slab_cache指向slab缓存描述符
			 * */
			struct kmem_cache *slab_cache; /* not slob */
			/* Double-word boundary */
			/* 管理区，可以看做一个数组，数组的每个成员占用1字节，每个成员代表
			 * 一个slab对象 */
			void *freelist;		/* first free object */
			union {
				/* 在slab分配器中用来指向第一个slab对象的起始地址 */
				void *s_mem;	/* slab: first object */
				unsigned long counters;		/* SLUB */
				struct {			/* SLUB */
					unsigned inuse:16;
					unsigned objects:15;
					unsigned frozen:1;
				};
			};
		};
		struct {	/* Tail pages of compound page */
			unsigned long compound_head;	/* Bit zero is set */

			/* First tail page only */
			unsigned char compound_dtor;
			unsigned char compound_order;
			atomic_t compound_mapcount;
			unsigned int compound_nr; /* 1 << compound_order */
		};
		struct {	/* Second tail page of compound page */
			unsigned long _compound_pad_1;	/* compound_head */
			atomic_t hpage_pinned_refcount;
			/* For both global and memcg */
			struct list_head deferred_list;
		};
		struct {	/* Page table pages */
			unsigned long _pt_pad_1;	/* compound_head */
			pgtable_t pmd_huge_pte; /* protected by page->ptl */
			unsigned long _pt_pad_2;	/* mapping */
			union {
				struct mm_struct *pt_mm; /* x86 pgds only */
				atomic_t pt_frag_refcount; /* powerpc */
			};
			/* 用于保护操作的自旋锁，通常在更新页表时候需要这个锁以进行保护 */
#if ALLOC_SPLIT_PTLOCKS
			spinlock_t *ptl;
#else
			spinlock_t ptl;
#endif
		};
		struct {	/* ZONE_DEVICE pages */
			/** @pgmap: Points to the hosting device page map. */
			struct dev_pagemap *pgmap;
			void *zone_device_data;
			/*
			 * ZONE_DEVICE private pages are counted as being
			 * mapped so the next 3 words hold the mapping, index,
			 * and private fields from the source anonymous or
			 * page cache page while the page is migrated to device
			 * private memory.
			 * ZONE_DEVICE MEMORY_DEVICE_FS_DAX pages also
			 * use the mapping, index, and private fields when
			 * pmem backed DAX files are mapped.
			 */
		};

		/** @rcu_head: You can use this to free a page by RCU. */
		/* RCU锁，在slab分配器中释放slab的物理页面 */
		struct rcu_head rcu_head;
	};

	union {		/* This union is 4 bytes in size. */
		/*
		 * If the page can be mapped to userspace, encodes the number
		 * of times this page is referenced by a page table.
		 */
		/* 用于标记page是否在buddy中，设置成-1或者PAGE_BUDDY_MAPCOUNT_VALUE(-128)
		 * 在buddy??? */

		/* 表示这个页面被进程映射的个数，即已经映射了多少个用户PTE。每个用户进程都拥有
		 * 各自独立的虚拟地址空间和一份独立的页表，所以会出现多个用户进程空间同时映射到
		 * 同一个物理页面的情况，RMAP系统就是利用这个特性来实现的，该成员主要用于RMAP中
		 * (记住，不包括内核地址空间映射物理页面时产生的PTE)
		 * -1 : 表示没有PTE映射到页面
		 *
		 *  0 : 表示只有父进程映射到页面。匿名页面刚分配时，初始化为0。do_anonymous_page
		 *  产生的匿名页面通过 page_add_new_anon_rmap添加到RAMP系统中，会设置成员为 0。
		 *
		 * >0 : 表示除了父进程还有其他进程映射到这个页面。例如父进程创建子进程为例子，
		 * 设置父进程的PTE内容到子进程中并增加页面的 _mapcount。copy_mm -> dup_mmap
		 * -> copy_pte_range -> copy_present_pte
		 * */
		atomic_t _mapcount;

		/*
		 * If the page is neither PageSlab nor mappable to userspace,
		 * the value stored here may help determine what this page
		 * is used for.  See page-flags.h for a list of page types
		 * which are currently stored here.
		 */
		unsigned int page_type;

		/* 表示slab分配器中活跃对象的数量，当为0时，表示这个slab分配器中没有活跃对象
		 * 可以销毁这个slab分配器。活跃对象就是已经被迁移到对象缓冲池中的对象 */
		unsigned int active;		/* SLAB */
		int units;			/* SLOB */
	};

	/* Usage count. *DO NOT USE DIRECTLY*. See page_ref.h */
	/* 内核中引用该页面的次数: =0: 表示该页面为空闲页面或即将要被释放的页面
	 *
	 * >0: 表示该页面一斤干杯分配且内核正在使用，暂时不会被释放。
	 * get_page : +1
	 * put_page : -1，若-1后等于0，那么会释放该页面
	 *
	 * 应用场景:
	 * 1. 初始状态下，空闲页面为0
	 * 2. 分配页面时，变成1. alloc_pages -> ... -> set_page_refcounted
	 * 3. 加入LRU链表，页面会被kswapd内核线程使用，因此+1。以 malloc分配内存为例子，发生缺页
	 *    中断后， do_anonymous_page 成功分配一个页面，在设置硬件PTE之前，调用 lru_cache_add
	 *    把这个匿名页面添加到LRU链表中，在这个过程中使用 get_page +1，当页面已经添加到LRU链
	 *    表调用__pagevec_lru_add 会 -1，这样做的目的是防止页面在添加到LRU链表过程中被释放。
	 * 4. 被映射到其他用户进程的PTE时，也会 +1.如父进程创建子进程共享地址空间时。copy_mm ->
	 *    dup_mmap -> copy_pte_range -> copy_present_pte -> get_page
	 * 5. 页面的private成员指向私有数据
	 *    1). 对于PG_swapable的页面， add_to_swap_cache 函数会增加 _refcount
	 *    2). 对于PG_private的页面，主要在块设备的 buffer_head中使用，如 buffer_migrate_page
	 *        函数中会增加 _refcount
	 * 6. 内核对页面进行操作的关键路径上也会使 _refcount +1，如内核的 follow_page 函数和
	 *    get_user_pages。以 follow_page 为例，调用者通常需要设置 FOLL_GET 标志位来使其增加
	 *    _refcount。如KSM 中获取可合并的页面函数 get_mergeable_page->follow_page。另一个例
	 *    子是 DIRECT_IO，见 write_protect_page -> follow_page. 
	 *    5.15 get_user_pages -> follow_page_mask
	 * */
	atomic_t _refcount;

#ifdef CONFIG_MEMCG
	unsigned long memcg_data;
#endif

	/*
	 * On machines where all RAM is mapped into kernel address space,
	 * we can simply calculate the virtual address. On machines with
	 * highmem some memory is mapped into kernel virtual memory
	 * dynamically, so we need a place to store that address.
	 * Note that this field could be 16 bits on x86 ... ;)
	 *
	 * Architectures with slow multiplication can define
	 * WANT_PAGE_VIRTUAL in asm/page.h
	 */
#if defined(WANT_PAGE_VIRTUAL)
	void *virtual;			/* Kernel virtual address (NULL if
					   not kmapped, ie. highmem) */
#endif /* WANT_PAGE_VIRTUAL */

#ifdef LAST_CPUPID_NOT_IN_PAGE_FLAGS
	int _last_cpupid;
#endif
} _struct_page_alignment;

static inline atomic_t *compound_mapcount_ptr(struct page *page)
{
	return &page[1].compound_mapcount;
}

static inline atomic_t *compound_pincount_ptr(struct page *page)
{
	return &page[2].hpage_pinned_refcount;
}

/*
 * Used for sizing the vmemmap region on some architectures
 */
#define STRUCT_PAGE_MAX_SHIFT	(order_base_2(sizeof(struct page)))

#define PAGE_FRAG_CACHE_MAX_SIZE	__ALIGN_MASK(32768, ~PAGE_MASK)
#define PAGE_FRAG_CACHE_MAX_ORDER	get_order(PAGE_FRAG_CACHE_MAX_SIZE)

#define page_private(page)		((page)->private)

static inline void set_page_private(struct page *page, unsigned long private)
{
	page->private = private;
}

struct page_frag_cache {
	void * va;
#if (PAGE_SIZE < PAGE_FRAG_CACHE_MAX_SIZE)
	__u16 offset;
	__u16 size;
#else
	__u32 offset;
#endif
	/* we maintain a pagecount bias, so that we dont dirty cache line
	 * containing page->_refcount every time we allocate a fragment.
	 */
	unsigned int		pagecnt_bias;
	bool pfmemalloc;
};

typedef unsigned long vm_flags_t;

/*
 * A region containing a mapping of a non-memory backed file under NOMMU
 * conditions.  These are held in a global tree and are pinned by the VMAs that
 * map parts of them.
 */
struct vm_region {
	struct rb_node	vm_rb;		/* link in global region tree */
	vm_flags_t	vm_flags;	/* VMA vm_flags */
	unsigned long	vm_start;	/* start address of region */
	unsigned long	vm_end;		/* region initialised to here */
	unsigned long	vm_top;		/* region allocated to here */
	unsigned long	vm_pgoff;	/* the offset in vm_file corresponding to vm_start */
	struct file	*vm_file;	/* the backing file or NULL */

	int		vm_usage;	/* region usage count (access under nommu_region_sem) */
	bool		vm_icache_flushed : 1; /* true if the icache has been flushed for
						* this region */
};

#ifdef CONFIG_USERFAULTFD
#define NULL_VM_UFFD_CTX ((struct vm_userfaultfd_ctx) { NULL, })
struct vm_userfaultfd_ctx {
	struct userfaultfd_ctx *ctx;
};
#else /* CONFIG_USERFAULTFD */
#define NULL_VM_UFFD_CTX ((struct vm_userfaultfd_ctx) {})
struct vm_userfaultfd_ctx {};
#endif /* CONFIG_USERFAULTFD */

/*
 * This struct describes a virtual memory area. There is one of these
 * per VM-area/task. A VM area is any part of the process virtual memory
 * space that has a special rule for the page-fault handlers (ie a shared
 * library, the executable area etc).
 */
struct vm_area_struct {
	/* The first cache line has the info for VMA tree walking. */

	/* 在进程地址空间的起始地址和结束地址 */
	unsigned long vm_start;		/* Our start address within vm_mm. */
	unsigned long vm_end;		/* The first byte after our end address
					   within vm_mm. */

	/* linked list of VM areas per task, sorted by address */
	/* 进程的VMA都连接成一个链表 */
	struct vm_area_struct *vm_next, *vm_prev;

	/* VMA作为一个节点加入红黑树，每个进程的 mm_struct 都有一根红黑树 mm->mm_rb */
	struct rb_node vm_rb;

	/*
	 * Largest free memory gap in bytes to the left of this VMA.
	 * Either between this VMA and vma->vm_prev, or between one of the
	 * VMAs below us in the VMA rbtree and its ->vm_prev. This helps
	 * get_unmapped_area find a free area of the right size.
	 */
	unsigned long rb_subtree_gap;

	/* Second cache line starts here. */

	/* 指向 VMA 所属进程的 mm_struct */
	struct mm_struct *vm_mm;	/* The address space we belong to. */

	/*
	 * Access permissions of this VMA.
	 * See vmf_insert_mixed_prot() for discussion.
	 */
	/* VMA的访问权限，用于将VMA属性标志位转换成处理相关的页表项的属性
	 * vm_get_page_prot ，例如 PAGE_READONLY*/
	pgprot_t vm_page_prot;
	/* 描述该VMA的一组标志位，VMA属性标志位 */
	unsigned long vm_flags;		/* Flags, see mm.h. */

	/*
	 * For areas with an address space and backing store,
	 * linkage into the address_space->i_mmap interval tree.
	 */
	struct {
		struct rb_node rb;
		unsigned long rb_subtree_last;
	} shared;

	/*
	 * A file's MAP_PRIVATE vma can be in both i_mmap tree and anon_vma
	 * list, after a COW of one of the file pages.	A MAP_SHARED vma
	 * can only be in the i_mmap tree.  An anonymous MAP_PRIVATE, stack
	 * or brk vma (with NULL file) can only be in an anon_vma list.
	 */
	/* 以下两个用于管理反向映射，RMAP 典型应用场景如下:
	 * 1. kswapd内核线程为了回收页面，需要断开素有映射到该匿名页面的用户PTE
	 * 2. 页面迁移时，需要断开多有映射到匿名页面的用户PTE
	 * RMAP的核心函数是 try_to_unmap，它会断开一个页面的所有映射
	 * */
	struct list_head anon_vma_chain; /* Serialized by mmap_lock &
					  * page_table_lock */
	struct anon_vma *anon_vma;	/* Serialized by page_table_lock */

	/* Function pointers to deal with this struct. */
	/* 方法集合，通常用于文件映射 */
	const struct vm_operations_struct *vm_ops;

	/* Information about our backing store: */
	/* 指向文件映射的偏移量，这个变量的单位不是字节，而是页面的大小(page size)
	 * 对于匿名页面来说，它的值可以是0或者 vm_addr / PAGE_SIZE，例如mmap中采用 MAP_SHARED
	 * 映射时为0，采用 MAP_PRIVATE 映射时为 vm_addr / PAGE_SIZE。vm_pgoff值在匿名页面的
	 * 生命周期中只有RMAP才用到*/
	unsigned long vm_pgoff;		/* Offset (within vm_file) in PAGE_SIZE
					   units */
	/* 指向file的实例，描述一个被映射的文件 */
	struct file * vm_file;		/* File we map to (can be NULL). */
	void * vm_private_data;		/* was vm_pte (shared mem) */

#ifdef CONFIG_SWAP
	atomic_long_t swap_readahead_info;
#endif
#ifndef CONFIG_MMU
	struct vm_region *vm_region;	/* NOMMU mapping region */
#endif
#ifdef CONFIG_NUMA
	struct mempolicy *vm_policy;	/* NUMA policy for the VMA */
#endif
	struct vm_userfaultfd_ctx vm_userfaultfd_ctx;
} __randomize_layout;

struct core_thread {
	struct task_struct *task;
	struct core_thread *next;
};

struct core_state {
	atomic_t nr_threads;
	struct core_thread dumper;
	struct completion startup;
};

struct kioctx_table;
struct mm_struct {
	struct {
		/* 进程的所有VMA形成一个单链表，这是该链表的头，VMA按照起始地址递增的
		 * 方式插入 mmap中，zzy 从 __vma_link_list 看不出是按照地址递增插入的 */
		struct vm_area_struct *mmap;		/* list of VMAs */
		/* VMA红黑树的根节点 */
		struct rb_root mm_rb;
		u64 vmacache_seqnum;                   /* per-thread vmacache */
#ifdef CONFIG_MMU
		/* 用于判断虚拟内存是否由足够的空间，返回一段没有映射过的空间的起始地址
		 * 这个函数会使用具体的处理器架构的实现 */
		unsigned long (*get_unmapped_area) (struct file *filp,
				unsigned long addr, unsigned long len,
				unsigned long pgoff, unsigned long flags);
#endif
		/* 指向mmap空间的起始地址，在32bit处理器中，mmap的起始地址是 0x4000 0000 */
		unsigned long mmap_base;	/* base of mmap area */
		unsigned long mmap_legacy_base;	/* base of mmap area in bottom-up allocations */
#ifdef CONFIG_HAVE_ARCH_COMPAT_MMAP_BASES
		/* Base addresses for compatible mmap() */
		unsigned long mmap_compat_base;
		unsigned long mmap_compat_legacy_base;
#endif
		unsigned long task_size;	/* size of task vm space */
		unsigned long highest_vm_end;	/* highest vma end address */
		/* 指向进程的PGD */
		pgd_t * pgd;

#ifdef CONFIG_MEMBARRIER
		/**
		 * @membarrier_state: Flags controlling membarrier behavior.
		 *
		 * This field is close to @pgd to hopefully fit in the same
		 * cache-line, which needs to be touched by switch_mm().
		 */
		atomic_t membarrier_state;
#endif

		/**
		 * @mm_users: The number of users including userspace.
		 *
		 * Use mmget()/mmget_not_zero()/mmput() to modify. When this
		 * drops to 0 (i.e. when the task exits and there are no other
		 * temporary reference holders), we also release a reference on
		 * @mm_count (which may then free the &struct mm_struct if
		 * @mm_count also drops to 0).
		 */
		/* 记录正在使用该进程地址空间的进程数目，如果两个线程共享该地址空间
		 * 那么 mm_users 等于2 */
		atomic_t mm_users;

		/**
		 * @mm_count: The number of references to &struct mm_struct
		 * (@mm_users count as 1).
		 *
		 * Use mmgrab()/mmdrop() to modify. When this drops to 0, the
		 * &struct mm_struct is freed.
		 */
		/* mm_struct 结构体的主体引用计数 */
		atomic_t mm_count;

#ifdef CONFIG_MMU
		atomic_long_t pgtables_bytes;	/* PTE page table pages */
#endif
		int map_count;			/* number of VMAs */

		spinlock_t page_table_lock; /* Protects page tables and some
					     * counters
					     */
		/*
		 * With some kernel config, the current mmap_lock's offset
		 * inside 'mm_struct' is at 0x120, which is very optimal, as
		 * its two hot fields 'count' and 'owner' sit in 2 different
		 * cachelines,  and when mmap_lock is highly contended, both
		 * of the 2 fields will be accessed frequently, current layout
		 * will help to reduce cache bouncing.
		 *
		 * So please be careful with adding new fields before
		 * mmap_lock, which can easily push the 2 fields into one
		 * cacheline.
		 */
		struct rw_semaphore mmap_lock;

		/* 所有的 mm_struct 数据结构都连接到一个双向链表中，该链表的头是
		 * init_mm 内存描述符，它是 init进程的地址空间 */
		struct list_head mmlist; /* List of maybe swapped mm's.	These
					  * are globally strung together off
					  * init_mm.mmlist, and are protected
					  * by mmlist_lock
					  */


		unsigned long hiwater_rss; /* High-watermark of RSS usage */
		unsigned long hiwater_vm;  /* High-water virtual memory usage */

		/* 已经使用的进程地址空间总和 */
		unsigned long total_vm;	   /* Total pages mapped */
		unsigned long locked_vm;   /* Pages that have PG_mlocked set */
		atomic64_t    pinned_vm;   /* Refcount permanently increased */
		unsigned long data_vm;	   /* VM_WRITE & ~VM_SHARED & ~VM_STACK */
		unsigned long exec_vm;	   /* VM_EXEC & ~VM_WRITE & ~VM_STACK */
		unsigned long stack_vm;	   /* VM_STACK */
		unsigned long def_flags;

		/**
		 * @write_protect_seq: Locked when any thread is write
		 * protecting pages mapped by this mm to enforce a later COW,
		 * for instance during page table copying for fork().
		 */
		seqcount_t write_protect_seq;

		spinlock_t arg_lock; /* protect the below fields */

		/* 代码段，数据段的 起始地址和结束地址 */
		unsigned long start_code, end_code, start_data, end_data;
		/* 堆空间的起始地址(start_brk)和当前底部(brk)  */
		unsigned long start_brk, brk, start_stack;
		unsigned long arg_start, arg_end, env_start, env_end;

		unsigned long saved_auxv[AT_VECTOR_SIZE]; /* for /proc/PID/auxv */

		/*
		 * Special counters, in some configurations protected by the
		 * page_table_lock, in other configurations by being atomic.
		 */
		struct mm_rss_stat rss_stat;

		struct linux_binfmt *binfmt;

		/* Architecture-specific MM context */
		mm_context_t context;

		unsigned long flags; /* Must use atomic bitops to access */

		struct core_state *core_state; /* coredumping support */

#ifdef CONFIG_AIO
		spinlock_t			ioctx_lock;
		struct kioctx_table __rcu	*ioctx_table;
#endif
#ifdef CONFIG_MEMCG
		/*
		 * "owner" points to a task that is regarded as the canonical
		 * user/owner of this mm. All of the following must be true in
		 * order for it to be changed:
		 *
		 * current == mm->owner
		 * current->mm != mm
		 * new_owner->mm == mm
		 * new_owner->alloc_lock is held
		 */
		struct task_struct __rcu *owner;
#endif
		struct user_namespace *user_ns;

		/* store ref to file /proc/<pid>/exe symlink points to */
		struct file __rcu *exe_file;
#ifdef CONFIG_MMU_NOTIFIER
		struct mmu_notifier_subscriptions *notifier_subscriptions;
#endif
#if defined(CONFIG_TRANSPARENT_HUGEPAGE) && !USE_SPLIT_PMD_PTLOCKS
		pgtable_t pmd_huge_pte; /* protected by page_table_lock */
#endif
#ifdef CONFIG_NUMA_BALANCING
		/*
		 * numa_next_scan is the next time that the PTEs will be marked
		 * pte_numa. NUMA hinting faults will gather statistics and
		 * migrate pages to new nodes if necessary.
		 */
		unsigned long numa_next_scan;

		/* Restart point for scanning and setting pte_numa */
		unsigned long numa_scan_offset;

		/* numa_scan_seq prevents two threads setting pte_numa */
		int numa_scan_seq;
#endif
		/*
		 * An operation with batched TLB flushing is going on. Anything
		 * that can move process memory needs to flush the TLB when
		 * moving a PROT_NONE or PROT_NUMA mapped page.
		 */
		atomic_t tlb_flush_pending;
#ifdef CONFIG_ARCH_WANT_BATCHED_UNMAP_TLB_FLUSH
		/* See flush_tlb_batched_pending() */
		bool tlb_flush_batched;
#endif
		struct uprobes_state uprobes_state;
#ifdef CONFIG_HUGETLB_PAGE
		atomic_long_t hugetlb_usage;
#endif
		struct work_struct async_put_work;

#ifdef CONFIG_IOMMU_SUPPORT
		u32 pasid;
#endif
	} __randomize_layout;

	/*
	 * The mm_cpumask needs to be at the end of mm_struct, because it
	 * is dynamically sized based on nr_cpu_ids.
	 */
	unsigned long cpu_bitmap[];
};

extern struct mm_struct init_mm;

/* Pointer magic because the dynamic array size confuses some compilers. */
static inline void mm_init_cpumask(struct mm_struct *mm)
{
	unsigned long cpu_bitmap = (unsigned long)mm;

	cpu_bitmap += offsetof(struct mm_struct, cpu_bitmap);
	cpumask_clear((struct cpumask *)cpu_bitmap);
}

/* Future-safe accessor for struct mm_struct's cpu_vm_mask. */
static inline cpumask_t *mm_cpumask(struct mm_struct *mm)
{
	return (struct cpumask *)&mm->cpu_bitmap;
}

struct mmu_gather;
extern void tlb_gather_mmu(struct mmu_gather *tlb, struct mm_struct *mm);
extern void tlb_gather_mmu_fullmm(struct mmu_gather *tlb, struct mm_struct *mm);
extern void tlb_finish_mmu(struct mmu_gather *tlb);

static inline void init_tlb_flush_pending(struct mm_struct *mm)
{
	atomic_set(&mm->tlb_flush_pending, 0);
}

static inline void inc_tlb_flush_pending(struct mm_struct *mm)
{
	atomic_inc(&mm->tlb_flush_pending);
	/*
	 * The only time this value is relevant is when there are indeed pages
	 * to flush. And we'll only flush pages after changing them, which
	 * requires the PTL.
	 *
	 * So the ordering here is:
	 *
	 *	atomic_inc(&mm->tlb_flush_pending);
	 *	spin_lock(&ptl);
	 *	...
	 *	set_pte_at();
	 *	spin_unlock(&ptl);
	 *
	 *				spin_lock(&ptl)
	 *				mm_tlb_flush_pending();
	 *				....
	 *				spin_unlock(&ptl);
	 *
	 *	flush_tlb_range();
	 *	atomic_dec(&mm->tlb_flush_pending);
	 *
	 * Where the increment if constrained by the PTL unlock, it thus
	 * ensures that the increment is visible if the PTE modification is
	 * visible. After all, if there is no PTE modification, nobody cares
	 * about TLB flushes either.
	 *
	 * This very much relies on users (mm_tlb_flush_pending() and
	 * mm_tlb_flush_nested()) only caring about _specific_ PTEs (and
	 * therefore specific PTLs), because with SPLIT_PTE_PTLOCKS and RCpc
	 * locks (PPC) the unlock of one doesn't order against the lock of
	 * another PTL.
	 *
	 * The decrement is ordered by the flush_tlb_range(), such that
	 * mm_tlb_flush_pending() will not return false unless all flushes have
	 * completed.
	 */
}

static inline void dec_tlb_flush_pending(struct mm_struct *mm)
{
	/*
	 * See inc_tlb_flush_pending().
	 *
	 * This cannot be smp_mb__before_atomic() because smp_mb() simply does
	 * not order against TLB invalidate completion, which is what we need.
	 *
	 * Therefore we must rely on tlb_flush_*() to guarantee order.
	 */
	atomic_dec(&mm->tlb_flush_pending);
}

static inline bool mm_tlb_flush_pending(struct mm_struct *mm)
{
	/*
	 * Must be called after having acquired the PTL; orders against that
	 * PTLs release and therefore ensures that if we observe the modified
	 * PTE we must also observe the increment from inc_tlb_flush_pending().
	 *
	 * That is, it only guarantees to return true if there is a flush
	 * pending for _this_ PTL.
	 */
	return atomic_read(&mm->tlb_flush_pending);
}

static inline bool mm_tlb_flush_nested(struct mm_struct *mm)
{
	/*
	 * Similar to mm_tlb_flush_pending(), we must have acquired the PTL
	 * for which there is a TLB flush pending in order to guarantee
	 * we've seen both that PTE modification and the increment.
	 *
	 * (no requirement on actually still holding the PTL, that is irrelevant)
	 */
	return atomic_read(&mm->tlb_flush_pending) > 1;
}

struct vm_fault;

/**
 * typedef vm_fault_t - Return type for page fault handlers.
 *
 * Page fault handlers return a bitmask of %VM_FAULT values.
 */
typedef __bitwise unsigned int vm_fault_t;

/**
 * enum vm_fault_reason - Page fault handlers return a bitmask of
 * these values to tell the core VM what happened when handling the
 * fault. Used to decide whether a process gets delivered SIGBUS or
 * just gets major/minor fault counters bumped up.
 *
 * @VM_FAULT_OOM:		Out Of Memory
 * @VM_FAULT_SIGBUS:		Bad access
 * @VM_FAULT_MAJOR:		Page read from storage
 * @VM_FAULT_WRITE:		Special case for get_user_pages
 * @VM_FAULT_HWPOISON:		Hit poisoned small page
 * @VM_FAULT_HWPOISON_LARGE:	Hit poisoned large page. Index encoded
 *				in upper bits
 * @VM_FAULT_SIGSEGV:		segmentation fault
 * @VM_FAULT_NOPAGE:		->fault installed the pte, not return page
 * @VM_FAULT_LOCKED:		->fault locked the returned page
 * @VM_FAULT_RETRY:		->fault blocked, must retry
 * @VM_FAULT_FALLBACK:		huge page fault failed, fall back to small
 * @VM_FAULT_DONE_COW:		->fault has fully handled COW
 * @VM_FAULT_NEEDDSYNC:		->fault did not modify page tables and needs
 *				fsync() to complete (for synchronous page faults
 *				in DAX)
 * @VM_FAULT_HINDEX_MASK:	mask HINDEX value
 *
 */
enum vm_fault_reason {
	/* 在缺页异常处理过程中无法分配内存 */
	VM_FAULT_OOM            = (__force vm_fault_t)0x000001,
	/* 系统中有内存但是遇到了无法处理的错误，只能发送信号给内核来终止发生异常的进程 */
	VM_FAULT_SIGBUS         = (__force vm_fault_t)0x000002,
	/* 主缺页: 是由交换机制引入的，对于交换的页面，地址映射建立好之后，还需要从交换分区
	 * 中读取数据，这个过程涉及IO操作，耗时比较久，因此当前进程会被阻塞很长时间
	 *
	 * 次缺页: 从内存中直接分配了页面的情况，不需要冲交换分区中读数据 */
	VM_FAULT_MAJOR          = (__force vm_fault_t)0x000004,
	/* 写错误导致的缺页 */
	VM_FAULT_WRITE          = (__force vm_fault_t)0x000008,
	VM_FAULT_HWPOISON       = (__force vm_fault_t)0x000010,
	VM_FAULT_HWPOISON_LARGE = (__force vm_fault_t)0x000020,
	/* 对于无法处理的错误，内核发送SIGSEGV信号来终止进程 */
	VM_FAULT_SIGSEGV        = (__force vm_fault_t)0x000040,
	/* 表示缺页异常处理函数安装了新的PTE，这次缺页异常不需要返回一个新的页面 */
	VM_FAULT_NOPAGE         = (__force vm_fault_t)0x000100,
	/* 缺页异常处理函数持有了页锁 */
	VM_FAULT_LOCKED         = (__force vm_fault_t)0x000200,
	/* 缺页异常处理函数被阻塞了，需要重试 */
	VM_FAULT_RETRY          = (__force vm_fault_t)0x000400,
	/* 巨页的缺页异常处理失败，切换到小页 */
	VM_FAULT_FALLBACK       = (__force vm_fault_t)0x000800,
	/* 处理完成写时复制的情况 */
	VM_FAULT_DONE_COW       = (__force vm_fault_t)0x001000,
	/* 表示缺页异常处理函数没有修改页表，但是需要fsync来同步 */
	VM_FAULT_NEEDDSYNC      = (__force vm_fault_t)0x002000,
	VM_FAULT_HINDEX_MASK    = (__force vm_fault_t)0x0f0000,
};

/* Encode hstate index for a hwpoisoned large page */
#define VM_FAULT_SET_HINDEX(x) ((__force vm_fault_t)((x) << 16))
#define VM_FAULT_GET_HINDEX(x) (((__force unsigned int)(x) >> 16) & 0xf)

#define VM_FAULT_ERROR (VM_FAULT_OOM | VM_FAULT_SIGBUS |	\
			VM_FAULT_SIGSEGV | VM_FAULT_HWPOISON |	\
			VM_FAULT_HWPOISON_LARGE | VM_FAULT_FALLBACK)

#define VM_FAULT_RESULT_TRACE \
	{ VM_FAULT_OOM,                 "OOM" },	\
	{ VM_FAULT_SIGBUS,              "SIGBUS" },	\
	{ VM_FAULT_MAJOR,               "MAJOR" },	\
	{ VM_FAULT_WRITE,               "WRITE" },	\
	{ VM_FAULT_HWPOISON,            "HWPOISON" },	\
	{ VM_FAULT_HWPOISON_LARGE,      "HWPOISON_LARGE" },	\
	{ VM_FAULT_SIGSEGV,             "SIGSEGV" },	\
	{ VM_FAULT_NOPAGE,              "NOPAGE" },	\
	{ VM_FAULT_LOCKED,              "LOCKED" },	\
	{ VM_FAULT_RETRY,               "RETRY" },	\
	{ VM_FAULT_FALLBACK,            "FALLBACK" },	\
	{ VM_FAULT_DONE_COW,            "DONE_COW" },	\
	{ VM_FAULT_NEEDDSYNC,           "NEEDDSYNC" }

struct vm_special_mapping {
	const char *name;	/* The name, e.g. "[vdso]". */

	/*
	 * If .fault is not provided, this points to a
	 * NULL-terminated array of pages that back the special mapping.
	 *
	 * This must not be NULL unless .fault is provided.
	 */
	struct page **pages;

	/*
	 * If non-NULL, then this is called to resolve page faults
	 * on the special mapping.  If used, .pages is not checked.
	 */
	vm_fault_t (*fault)(const struct vm_special_mapping *sm,
				struct vm_area_struct *vma,
				struct vm_fault *vmf);

	int (*mremap)(const struct vm_special_mapping *sm,
		     struct vm_area_struct *new_vma);
};

enum tlb_flush_reason {
	TLB_FLUSH_ON_TASK_SWITCH,
	TLB_REMOTE_SHOOTDOWN,
	TLB_LOCAL_SHOOTDOWN,
	TLB_LOCAL_MM_SHOOTDOWN,
	TLB_REMOTE_SEND_IPI,
	NR_TLB_FLUSH_REASONS,
};

 /*
  * A swap entry has to fit into a "unsigned long", as the entry is hidden
  * in the "index" field of the swapper address space.
  */
typedef struct {
	unsigned long val;
} swp_entry_t;

#endif /* _LINUX_MM_TYPES_H */
