// SPDX-License-Identifier: GPL-2.0-only
/*
 * AArch64-specific system calls implementation
 *
 * Copyright (C) 2012 ARM Ltd.
 * Author: Catalin Marinas <catalin.marinas@arm.com>
 */

#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/export.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/syscalls.h>

#include <asm/cpufeature.h>
#include <asm/syscall.h>

/* addr: 用于指定映射到进程地址空间的起始地址，一般设置为NULL，让内核来分配
 * len: 表示映射到进程地址空间的大小
 *
 * prot: 用于设置内存映射区域的读写属性等
 * 	PROT_EXEC:  表示映射的页面是可以执行的
 * 	PROT_READ:  表示映射的页面是可以读取的
 * 	PROT_WRITE: 表示映射的页面是可以写入的
 * 	PROT_NONE:  表示映射的页面是不可访问的
 *
 * flags: 用于设置内存映射的属性，如 共享映射、私有映射等
 * 	MAP_SHARED: 创建一个共享映射的区域。多个进程可以通过共享映射方式来映射
 * 		    一个文件，这样其他进程也可以看到映射内容的改变，修改后的内
 * 		    容会同步到磁盘文件中。
 *
 *	MAP_PRIVATE: 创建一个私有的写时复制的映射。多个进程可以通过私有映射的方
 *		     式来映射一个文件，这样其他进程不会看到映射内容的改变，修改
 *		     后的内容也不会同步到磁盘文件中。
 *
 *	MAP_ANONYMOUS: 创建一个匿名，即没有关联到文件的映射。
 *
 *	MAP_FIXED: 使用参数addr创建映射，如果在内核中无法映射指定的地址，那么返回
 *		   失败，参数addr要求页面对齐。如果addr和len指定的进程地址空间和已
 *		   有的VMA重叠，那么内核会调用do_munmap函数把这段重叠区域销毁，然后
 *		   重新映射新的内容。
 *
 *	MAP_POPULATE: 对于文件映射来说，会提前预读文件内容到映射区域，该特性只支持
 *		      私有映射。
 *
 * fd: 表示这是一个文件映射，fd是打开的文件句柄
 * off: 在文件映射时，表示文件的偏移量
 *
 * 映射分类:
 *
 * 匿名映射没有对应的相关文件，映射的内存区域的内容会初始化为0，这点存疑。
 * 文件映射和实际文件相关联，这样程序可以像操作进程地址空间一样读写文件
 *
 * 私有匿名映射: 当使用参数 fd=-1 & flags = MAP_ANONYMOUS | MAP_PRIVATE 时，创建的mmap
 * 	         映射是私有匿名映射。常见的用途是在glibc分配大内存时，如果需要分配的内
 * 	         存大于MMAP_THREASHOLD(128KB)，glibc会默认使用mmap代替brk来分配内存。
 *
 * 共享匿名映射: 当使用参数 fd=-1 & flags = MAP_ANONYMOUS | MAP_SHARED 时，创建的mmap
 * 		 映射是共享匿名映射。它让相关进程共享一个内存区域，通常用于父、子进程
 * 		 之间的通信。一般有如下两种实现方式，最终都调用shmem模块：
 * 		 1. 使 fd=-1 & flags = MAP_ANONYMOUS | MAP_SHARED。在这种情况下，
 * 		    do_mmap_pgoff()->mmap_region()函数最终调用 shmem_zero_setup()来打开
 * 		    特殊的"/dev/zero"设备文件。
 * 		 2. 直接打开"/dev/zero"设备文件，然后使用这个文件句柄来创建mmap。
 *
 * 私有文件映射: 创建文件映射时，如果flags设置为 MAP_PRIVATE ，就会创建私有文件映射。私
 * 		 有文件映射常用的场景就是加载动态共享库。
 *
 * 共享文件映射: 创建文件映射时，如果flags设置为 MAP_SHARED，就会创建共享文件映射。如果
 * 		 参数指定了PROT_WRITE，那么打开文件时需要指定O_RDWR标志位。共享文件映射
 * 		 通常有如下两个常用的场景：
 * 		 1. 读写文件: 把文件内容映射到进程地址空间，同时对映射的内容做了修改，内核
 * 		    的回写(write back)机制最终会把修改的内容同步到磁盘中。
 * 		 2. 进程间通讯。进程之间的进程地址空间相互隔离，一个进程不能访问另一个进程
 * 		    的地址空间。如果多个进程同时映射到同一个文件，就实现了多进程间的共享内
 * 		    存通讯。如果一个进程对映射内容做了修改，那么另外的进程是可以看到的。
 * */
SYSCALL_DEFINE6(mmap, unsigned long, addr, unsigned long, len,
		unsigned long, prot, unsigned long, flags,
		unsigned long, fd, unsigned long, off)
{
	if (offset_in_page(off) != 0)
		return -EINVAL;

	return ksys_mmap_pgoff(addr, len, prot, flags, fd, off >> PAGE_SHIFT);
}

SYSCALL_DEFINE1(arm64_personality, unsigned int, personality)
{
	if (personality(personality) == PER_LINUX32 &&
		!system_supports_32bit_el0())
		return -EINVAL;
	return ksys_personality(personality);
}

asmlinkage long sys_ni_syscall(void);

asmlinkage long __arm64_sys_ni_syscall(const struct pt_regs *__unused)
{
	return sys_ni_syscall();
}

/*
 * Wrappers to pass the pt_regs argument.
 */
#define __arm64_sys_personality		__arm64_sys_arm64_personality

#undef __SYSCALL
#define __SYSCALL(nr, sym)	asmlinkage long __arm64_##sym(const struct pt_regs *);
#include <asm/unistd.h>

#undef __SYSCALL
#define __SYSCALL(nr, sym)	[nr] = __arm64_##sym,

const syscall_fn_t sys_call_table[__NR_syscalls] = {
	[0 ... __NR_syscalls - 1] = __arm64_sys_ni_syscall,
#include <asm/unistd.h>
};
