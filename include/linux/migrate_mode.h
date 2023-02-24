/* SPDX-License-Identifier: GPL-2.0 */
#ifndef MIGRATE_MODE_H_INCLUDED
#define MIGRATE_MODE_H_INCLUDED
/*
 * MIGRATE_ASYNC means never block
 * MIGRATE_SYNC_LIGHT in the current implementation means to allow blocking
 *	on most operations but not ->writepage as the potential stall time
 *	is too significant
 * MIGRATE_SYNC will block when migrating pages
 * MIGRATE_SYNC_NO_COPY will block when migrating pages but will not copy pages
 *	with the CPU. Instead, page copy happens outside the migratepage()
 *	callback and is likely using a DMA engine. See migrate_vma() and HMM
 *	(mm/hmm.c) for users of this mode.
 */
enum migrate_mode {
	/* 异步模式。在判断内存规整时候完成时，若可以从其他迁移类型中挪用空闲
	 * 页块，那么也算完成任务。
	 * 若发现大量的临时分离页面(即分离的页面数量大于LRU页面数量的一 般)，会
	 * 睡眠等待100ms，见 too_many_isolated
	 * 当进程需要调用时，退出内存规整，详见 compact_unlock_should_abort
	 * */
	MIGRATE_ASYNC,
	/* 同步模式，允许调用者被阻塞。kcompactd内核线程设置这个模式。在分离页
	 * 面时，若发现大量的临时分离页面(即分离的页面数量大于LRU页面数量的一
	 * 般)，会睡眠等待100ms，见 too_many_isolated
	 * */
	MIGRATE_SYNC_LIGHT,
	/* 同步模式。在页面迁移时会被阻塞，手工设置/proc/sys/vm/compact_memory
	 * 会采用这个模式。在分离页面时，若发现大量的临时分离页面(即分离的页面
	 * 数量大于LRU页面数量的一般)，会睡眠等待100ms，见 too_many_isolated
	 * */
	MIGRATE_SYNC,
	/* 类似于同步模式，但是在迁移页面时CPU不会复制页面的内容，而是由DMA引擎
	 * 来复制，如HMM(见 mm/hmm.c)机制使用这种模式
	 * */
	MIGRATE_SYNC_NO_COPY,
};

#endif		/* MIGRATE_MODE_H_INCLUDED */
