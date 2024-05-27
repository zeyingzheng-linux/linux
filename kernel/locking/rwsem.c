// SPDX-License-Identifier: GPL-2.0
/* kernel/rwsem.c: R/W semaphores, public implementation
 *
 * Written by David Howells (dhowells@redhat.com).
 * Derived from asm-i386/semaphore.h
 *
 * Writer lock-stealing by Alex Shi <alex.shi@intel.com>
 * and Michel Lespinasse <walken@google.com>
 *
 * Optimistic spinning by Tim Chen <tim.c.chen@intel.com>
 * and Davidlohr Bueso <davidlohr@hp.com>. Based on mutexes.
 *
 * Rwsem count bit fields re-definition and rwsem rearchitecture by
 * Waiman Long <longman@redhat.com> and
 * Peter Zijlstra <peterz@infradead.org>.
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/rt.h>
#include <linux/sched/task.h>
#include <linux/sched/debug.h>
#include <linux/sched/wake_q.h>
#include <linux/sched/signal.h>
#include <linux/sched/clock.h>
#include <linux/export.h>
#include <linux/rwsem.h>
#include <linux/atomic.h>

#ifndef CONFIG_PREEMPT_RT
#include "lock_events.h"
/* 1. 设置handoff标记
 *
 * 设置handoff往往是发生在唤醒持锁阶段。对于等待队列的writer，唤醒之后要调度执行后才去持锁，
 * 这是一个长路径，很可能被其他的write或者reader把锁抢走。唤醒等待队列中的reader们有点不一样
 * ，在唤醒路径上就会从这一组待唤醒的reader们选出一个代表（一般是top waiter）去持锁，然后再
 * 一个个的唤醒。在这个reader代表线程持锁的时候也有可能由于writer偷锁而失败（reader虽然也会
 * 偷锁，但是偷锁的reader也会唤醒等待队列的reader们，完成top waiter未完成的工作）。无论是
 * reader还是writer，如果唤醒后持锁失败，并且等待时间已经超过了RWSEM_WAIT_TIMEOUT，这时候就会
 * 设置handoff bit，防止等待队列的waiter饿死
 *
 * 1>
 * 唤醒阻塞在该rwsem线程（writer或者reader们）的场景rwsem_mark_wake:
 * 在唤醒top waiter（是reader线程且需要持锁）的时候，发现锁被writer偷走。在这种场景下，如果
 * 尚未设置handoff，并且超过4ms的等待时长，那么将设置handoff标记，阻止writer线程继续抢锁
 * 2>
 * 阻塞在该rwsem的writer线程被唤醒后去试图持锁场景rwsem_try_write_lock:
 * 在writer试图持锁的过程中，如果发现锁被reader或者writer偷走，并且超过4ms的等待时长，那么
 * 将设置handoff标记，阻止其他线程继续抢锁
 *
 * 2. 清除handoff标记
 * 标记了hand off之后，快速路径、乐观偷锁（reader）、乐观自旋（writer）都无法完成持锁，锁最终
 * 会递交给top waiter的线程，完成持锁。一旦完成持锁，handoff标记就会被清除。具体清除handoff
 * bit的场景包括:
 *
 * 1>
 * 在down read或者down write慢速路径中持锁失败进入阻塞，线程在等锁的时候被信号打断。
 * 参考rwsem_del_waiter函数:
 * 将该rwsem waiter对象从等待队列中摘下的时候，如果是最后一个等待对象（即摘下后等待队列变成空
 * 队列），那么清除handoff标记（当然也清除waiter标记）
 * 2>
 * 阻塞的reader线程被唤醒的时候，参考函数rwsem_mark_wake:
 * 在唤醒reader线程们的时候，等待对象节点会从等待队列中摘下。如果已经唤醒top waiter线程的时候，
 * 清除handoff标记。
 * 3>
 * 阻塞的 writer被唤醒且被调度执行后会去试图持锁，如果持锁成功会清除handoff标记。具体请参考
 * 函数rwsem_try_write_lock:
 * 唤醒writer，通过rwsem_try_write_lock去试图持锁，持锁成功后就会清除handoff标记
 *
 * 3. 确保锁的所有权递交给top waiter
 * 1>
 * Down read系列接口中的快速路径（rwsem_read_trylock）:
 * 如果rwsem设置了handoff标记，那么将无法走快速路径持锁
 * 2>
 * Read try lock中过滤handoff条件（down_read_trylock）:
 * 如果rwsem设置了handoff标记，那么将无法try lock成功
 * 3>
 * Writer线程的乐观自旋场景 rwsem_try_write_lock_unqueued:
 * 如果rwsem设置了handoff标记，writer将无法通过乐观自旋完成持锁
 * 4>
 * Down read系列接口中的慢速路径中的偷锁场景rwsem_down_read_slowpath:
 * 由于reader不允许乐观自旋，因此reader在慢速路径上进行一次（没有spin）偷锁行为。如果rwsem设置
 * 了handoff标记，reader将无法完成偷锁行为
 * */
/*
 * The least significant 2 bits of the owner value has the following
 * meanings when set.
 *  - Bit 0: RWSEM_READER_OWNED - The rwsem is owned by readers
 *  - Bit 1: RWSEM_NONSPINNABLE - Cannot spin on a reader-owned lock
 *
 * When the rwsem is reader-owned and a spinning writer has timed out,
 * the nonspinnable bit will be set to disable optimistic spinning.

 * When a writer acquires a rwsem, it puts its task_struct pointer
 * into the owner field. It is cleared after an unlock.
 *
 * When a reader acquires a rwsem, it will also puts its task_struct
 * pointer into the owner field with the RWSEM_READER_OWNED bit set.
 * On unlock, the owner field will largely be left untouched. So
 * for a free or reader-owned rwsem, the owner value may contain
 * information about the last reader that acquires the rwsem.
 *
 * That information may be helpful in debugging cases where the system
 * seems to hang on a reader owned rwsem especially if only one reader
 * is involved. Ideally we would like to track all the readers that own
 * a rwsem, but the overhead is simply too big.
 *
 * A fast path reader optimistic lock stealing is supported when the rwsem
 * is previously owned by a writer and the following conditions are met:
 *  - OSQ is empty
 *  - rwsem is not currently writer owned
 *  - the handoff isn't set.
 */
#define RWSEM_READER_OWNED	(1UL << 0)
#define RWSEM_NONSPINNABLE	(1UL << 1)
#define RWSEM_OWNER_FLAGS_MASK	(RWSEM_READER_OWNED | RWSEM_NONSPINNABLE)

#ifdef CONFIG_DEBUG_RWSEMS
# define DEBUG_RWSEMS_WARN_ON(c, sem)	do {			\
	if (!debug_locks_silent &&				\
	    WARN_ONCE(c, "DEBUG_RWSEMS_WARN_ON(%s): count = 0x%lx, magic = 0x%lx, owner = 0x%lx, curr 0x%lx, list %sempty\n",\
		#c, atomic_long_read(&(sem)->count),		\
		(unsigned long) sem->magic,			\
		atomic_long_read(&(sem)->owner), (long)current,	\
		list_empty(&(sem)->wait_list) ? "" : "not "))	\
			debug_locks_off();			\
	} while (0)
#else
# define DEBUG_RWSEMS_WARN_ON(c, sem)
#endif

/*
 * On 64-bit architectures, the bit definitions of the count are:
 *
 * Bit  0    - writer locked bit
 * Bit  1    - waiters present bit
 * Bit  2    - lock handoff bit
 * Bits 3-7  - reserved
 * Bits 8-62 - 55-bit reader count
 * Bit  63   - read fail bit
 *
 * On 32-bit architectures, the bit definitions of the count are:
 *
 * Bit  0    - writer locked bit
 * Bit  1    - waiters present bit
 * Bit  2    - lock handoff bit
 * Bits 3-7  - reserved
 * Bits 8-30 - 23-bit reader count
 * Bit  31   - read fail bit
 *
 * It is not likely that the most significant bit (read fail bit) will ever
 * be set. This guard bit is still checked anyway in the down_read() fastpath
 * just in case we need to use up more of the reader bits for other purpose
 * in the future.
 *
 * atomic_long_fetch_add() is used to obtain reader lock, whereas
 * atomic_long_cmpxchg() will be used to obtain writer lock.
 *
 * There are three places where the lock handoff bit may be set or cleared.
 * 1) rwsem_mark_wake() for readers		-- set, clear
 * 2) rwsem_try_write_lock() for writers	-- set, clear
 * 3) rwsem_del_waiter()			-- clear
 *
 * For all the above cases, wait_lock will be held. A writer must also
 * be the first one in the wait_list to be eligible for setting the handoff
 * bit. So concurrent setting/clearing of handoff bit is not possible.
 */
#define RWSEM_WRITER_LOCKED	(1UL << 0)
#define RWSEM_FLAG_WAITERS	(1UL << 1)
#define RWSEM_FLAG_HANDOFF	(1UL << 2)
#define RWSEM_FLAG_READFAIL	(1UL << (BITS_PER_LONG - 1))

#define RWSEM_READER_SHIFT	8
#define RWSEM_READER_BIAS	(1UL << RWSEM_READER_SHIFT)
#define RWSEM_READER_MASK	(~(RWSEM_READER_BIAS - 1))
#define RWSEM_WRITER_MASK	RWSEM_WRITER_LOCKED
#define RWSEM_LOCK_MASK		(RWSEM_WRITER_MASK|RWSEM_READER_MASK)
#define RWSEM_READ_FAILED_MASK	(RWSEM_WRITER_MASK|RWSEM_FLAG_WAITERS|\
				 RWSEM_FLAG_HANDOFF|RWSEM_FLAG_READFAIL)

/*
 * All writes to owner are protected by WRITE_ONCE() to make sure that
 * store tearing can't happen as optimistic spinners may read and use
 * the owner value concurrently without lock. Read from owner, however,
 * may not need READ_ONCE() as long as the pointer value is only used
 * for comparison and isn't being dereferenced.
 */
static inline void rwsem_set_owner(struct rw_semaphore *sem)
{
	atomic_long_set(&sem->owner, (long)current);
}

static inline void rwsem_clear_owner(struct rw_semaphore *sem)
{
	atomic_long_set(&sem->owner, 0);
}

/*
 * Test the flags in the owner field.
 */
static inline bool rwsem_test_oflags(struct rw_semaphore *sem, long flags)
{
	return atomic_long_read(&sem->owner) & flags;
}

/*
 * The task_struct pointer of the last owning reader will be left in
 * the owner field.
 *
 * Note that the owner value just indicates the task has owned the rwsem
 * previously, it may not be the real owner or one of the real owners
 * anymore when that field is examined, so take it with a grain of salt.
 *
 * The reader non-spinnable bit is preserved.
 */
static inline void __rwsem_set_reader_owned(struct rw_semaphore *sem,
					    struct task_struct *owner)
{
	unsigned long val = (unsigned long)owner | RWSEM_READER_OWNED |
		(atomic_long_read(&sem->owner) & RWSEM_NONSPINNABLE);

	atomic_long_set(&sem->owner, val);
}

static inline void rwsem_set_reader_owned(struct rw_semaphore *sem)
{
	__rwsem_set_reader_owned(sem, current);
}

/*
 * Return true if the rwsem is owned by a reader.
 */
static inline bool is_rwsem_reader_owned(struct rw_semaphore *sem)
{
#ifdef CONFIG_DEBUG_RWSEMS
	/*
	 * Check the count to see if it is write-locked.
	 */
	long count = atomic_long_read(&sem->count);

	if (count & RWSEM_WRITER_MASK)
		return false;
#endif
	return rwsem_test_oflags(sem, RWSEM_READER_OWNED);
}

#ifdef CONFIG_DEBUG_RWSEMS
/*
 * With CONFIG_DEBUG_RWSEMS configured, it will make sure that if there
 * is a task pointer in owner of a reader-owned rwsem, it will be the
 * real owner or one of the real owners. The only exception is when the
 * unlock is done by up_read_non_owner().
 */
static inline void rwsem_clear_reader_owned(struct rw_semaphore *sem)
{
	unsigned long val = atomic_long_read(&sem->owner);

	while ((val & ~RWSEM_OWNER_FLAGS_MASK) == (unsigned long)current) {
		if (atomic_long_try_cmpxchg(&sem->owner, &val,
					    val & RWSEM_OWNER_FLAGS_MASK))
			return;
	}
}
#else
static inline void rwsem_clear_reader_owned(struct rw_semaphore *sem)
{
}
#endif

/*
 * Set the RWSEM_NONSPINNABLE bits if the RWSEM_READER_OWNED flag
 * remains set. Otherwise, the operation will be aborted.
 */
static inline void rwsem_set_nonspinnable(struct rw_semaphore *sem)
{
	unsigned long owner = atomic_long_read(&sem->owner);

	do {
		if (!(owner & RWSEM_READER_OWNED))
			break;
		if (owner & RWSEM_NONSPINNABLE)
			break;
	} while (!atomic_long_try_cmpxchg(&sem->owner, &owner,
					  owner | RWSEM_NONSPINNABLE));
}

static inline bool rwsem_read_trylock(struct rw_semaphore *sem, long *cntp)
{
	/* 成功的情况：
	 * 1. 锁为空
	 * 2. 锁纯reader的场景，即没有任何writer/reader的waiter
	 * */

	*cntp = atomic_long_add_return_acquire(RWSEM_READER_BIAS, &sem->count);

	/* 溢出了，需要禁止乐观自旋 */
	if (WARN_ON_ONCE(*cntp < 0))
		rwsem_set_nonspinnable(sem);

	/* 1. 有写者
	 * 2. 有读/写 者等待
	 * 3. 有锁正在递交
	 * 4. 读者太多导致溢出
	 * 都会导致try lock失败，反之，拿锁
	 * */
	if (!(*cntp & RWSEM_READ_FAILED_MASK)) {
		rwsem_set_reader_owned(sem);
		return true;
	}

	return false;
}

static inline bool rwsem_write_trylock(struct rw_semaphore *sem)
{
	long tmp = RWSEM_UNLOCKED_VALUE;

	/* tmp的初始值设定为RWSEM_UNLOCKED_VALUE（0值），对于writer而言，只有rwsem是空锁的时候
	 * 才能进入临界区。如果当前的sem->count等于0，那么给sem->count赋值RWSEM_WRITER_LOCKED
	 * ，标记持锁成功，并且把owner设定为当前task
	 * */
	if (atomic_long_try_cmpxchg_acquire(&sem->count, &tmp, RWSEM_WRITER_LOCKED)) {
		rwsem_set_owner(sem);
		return true;
	}

	return false;
}

/*
 * Return just the real task structure pointer of the owner
 */
static inline struct task_struct *rwsem_owner(struct rw_semaphore *sem)
{
	return (struct task_struct *)
		(atomic_long_read(&sem->owner) & ~RWSEM_OWNER_FLAGS_MASK);
}

/*
 * Return the real task structure pointer of the owner and the embedded
 * flags in the owner. pflags must be non-NULL.
 */
static inline struct task_struct *
rwsem_owner_flags(struct rw_semaphore *sem, unsigned long *pflags)
{
	unsigned long owner = atomic_long_read(&sem->owner);

	*pflags = owner & RWSEM_OWNER_FLAGS_MASK;
	return (struct task_struct *)(owner & ~RWSEM_OWNER_FLAGS_MASK);
}

/*
 * Guide to the rw_semaphore's count field.
 *
 * When the RWSEM_WRITER_LOCKED bit in count is set, the lock is owned
 * by a writer.
 *
 * The lock is owned by readers when
 * (1) the RWSEM_WRITER_LOCKED isn't set in count,
 * (2) some of the reader bits are set in count, and
 * (3) the owner field has RWSEM_READ_OWNED bit set.
 *
 * Having some reader bits set is not enough to guarantee a readers owned
 * lock as the readers may be in the process of backing out from the count
 * and a writer has just released the lock. So another writer may steal
 * the lock immediately after that.
 */

/*
 * Initialize an rwsem:
 */
void __init_rwsem(struct rw_semaphore *sem, const char *name,
		  struct lock_class_key *key)
{
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	/*
	 * Make sure we are not reinitializing a held semaphore:
	 */
	debug_check_no_locks_freed((void *)sem, sizeof(*sem));
	lockdep_init_map_wait(&sem->dep_map, name, key, 0, LD_WAIT_SLEEP);
#endif
#ifdef CONFIG_DEBUG_RWSEMS
	sem->magic = sem;
#endif
	atomic_long_set(&sem->count, RWSEM_UNLOCKED_VALUE);
	raw_spin_lock_init(&sem->wait_lock);
	INIT_LIST_HEAD(&sem->wait_list);
	atomic_long_set(&sem->owner, 0L);
#ifdef CONFIG_RWSEM_SPIN_ON_OWNER
	osq_lock_init(&sem->osq);
#endif
}
EXPORT_SYMBOL(__init_rwsem);

enum rwsem_waiter_type {
	RWSEM_WAITING_FOR_WRITE,
	RWSEM_WAITING_FOR_READ
};

struct rwsem_waiter {
	struct list_head list;
	struct task_struct *task;
	enum rwsem_waiter_type type;
	unsigned long timeout;
	bool handoff_set;
};
#define rwsem_first_waiter(sem) \
	list_first_entry(&sem->wait_list, struct rwsem_waiter, list)

/* 在RWSEM_WAKE_READERS场景中，多个reader被唤醒，并且当前很可能是空锁状态，为了防止writer
 * 抢锁，因此会先让top waiter持有读锁，然后慢慢处理后续。RWSEM_WAKE_READ_OWNED则没有这个
 * 顾虑，因为唤醒者已经持有读锁
 * */
enum rwsem_wake_type {
	/* 唤醒等待队列头部的waiter（一个writer或者若干reader） */
	RWSEM_WAKE_ANY,		/* Wake whatever's at head of wait list */
	/* 唤醒等待队列头部的若干readers */
	RWSEM_WAKE_READERS,	/* Wake readers only */
	/* 同RWSEM_WAKE_READERS，只不过唤醒者已经持有读锁 */
	RWSEM_WAKE_READ_OWNED	/* Waker thread holds the read lock */
};

/*
 * The typical HZ value is either 250 or 1000. So set the minimum waiting
 * time to at least 4ms or 1 jiffy (if it is higher than 4ms) in the wait
 * queue before initiating the handoff protocol.
 */
#define RWSEM_WAIT_TIMEOUT	DIV_ROUND_UP(HZ, 250)

/*
 * Magic number to batch-wakeup waiting readers, even when writers are
 * also present in the queue. This both limits the amount of work the
 * waking thread must do and also prevents any potential counter overflow,
 * however unlikely.
 */
#define MAX_READERS_WAKEUP	0x100

static inline void
rwsem_add_waiter(struct rw_semaphore *sem, struct rwsem_waiter *waiter)
{
	lockdep_assert_held(&sem->wait_lock);
	list_add_tail(&waiter->list, &sem->wait_list);
	/* caller will set RWSEM_FLAG_WAITERS */
}

/*
 * Remove a waiter from the wait_list and clear flags.
 *
 * Both rwsem_mark_wake() and rwsem_try_write_lock() contain a full 'copy' of
 * this function. Modify with care.
 */
static inline void
rwsem_del_waiter(struct rw_semaphore *sem, struct rwsem_waiter *waiter)
{
	lockdep_assert_held(&sem->wait_lock);
	list_del(&waiter->list);
	if (likely(!list_empty(&sem->wait_list)))
		return;

	atomic_long_andnot(RWSEM_FLAG_HANDOFF | RWSEM_FLAG_WAITERS, &sem->count);
}

/*
 * handle the lock release when processes blocked on it that can now run
 * - if we come here from up_xxxx(), then the RWSEM_FLAG_WAITERS bit must
 *   have been set.
 * - there must be someone on the queue
 * - the wait_lock must be held by the caller
 * - tasks are marked for wakeup, the caller must later invoke wake_up_q()
 *   to actually wakeup the blocked task(s) and drop the reference count,
 *   preferably when the wait_lock is released
 * - woken process blocks are discarded from the list after having task zeroed
 * - writers are only marked woken if downgrading is false
 *
 * Implies rwsem_del_waiter() for all woken readers.
 */
static void rwsem_mark_wake(struct rw_semaphore *sem,
			    enum rwsem_wake_type wake_type,
			    struct wake_q_head *wake_q)
{
	struct rwsem_waiter *waiter, *tmp;
	long oldcount, woken = 0, adjustment = 0;
	struct list_head wlist;

	lockdep_assert_held(&sem->wait_lock);

	/*
	 * Take a peek at the queue head waiter such that we can determine
	 * the wakeup(s) to perform.
	 */
	waiter = rwsem_first_waiter(sem);

	/* 这段代码是处理top waiter是writer的逻辑。这时候，如果wake type是RWSEM_WAKE_ANY，
	 * 即不关心唤醒的是reader还是writer，只要唤醒等待队列头部的waiter就好。如果top waiter
	 * 是writer，我们只需要将这个writer唤醒即可，不需要修改锁的状态，出队等操作，这些都是
	 * 在唤醒之后完成。如果wake type是其他两种类型（都是唤醒reader的），那么就直接返回。
	 * 也就是说在rwsem_mark_wake想要唤醒reader的场景中，如果top waiter是writer，那么将不
	 * 会唤醒任何reader线程。如果top waiter是reader的话，那么基本上是需要唤醒一组reader了
	 * */
	if (waiter->type == RWSEM_WAITING_FOR_WRITE) {
		if (wake_type == RWSEM_WAKE_ANY) {
			/*
			 * Mark writer at the front of the queue for wakeup.
			 * Until the task is actually later awoken later by
			 * the caller, other writers are able to steal it.
			 * Readers, on the other hand, will block as they
			 * will notice the queued writer.
			 */
			wake_q_add(wake_q, waiter->task);
			lockevent_inc(rwsem_wake_writer);
		}

		return;
	}

	/*
	 * No reader wakeup if there are too many of them already.
	 */
	if (unlikely(atomic_long_read(&sem->count) < 0))
		return;

	/*
	 * Writers might steal the lock before we grant it to the next reader.
	 * We prefer to do the first reader grant before counting readers
	 * so we can bail out early if a writer stole the lock.
	 */
	/* 执行到这里，我们需要唤醒等待队列头部的若干reader线程去持锁。由于writer有可能会在
	 * 这个阶段偷锁，因此，这里我们会先让top waiter（reader）持锁，然后再慢慢去计算到底
	 * 需要唤醒多少个reader并将其唤醒。如果当前线程已经持有了读锁（wake type的类型是
	 * RWSEM_WAKE_READ_OWNED），则不需要提前持锁，直接越过这部分的逻辑即可
	 * */
	if (wake_type != RWSEM_WAKE_READ_OWNED) {
		struct task_struct *owner;

		adjustment = RWSEM_READER_BIAS;
		oldcount = atomic_long_fetch_add(adjustment, &sem->count);
		/* 如果的确发生了writer通过乐观自旋偷锁，那么我们需要检查设置handoff的条件。
		 * 如果reader被writer阻塞太久，那么我们设定handoff标记，要求rwsem的writer停止
		 * 通过乐观自旋偷锁，将锁的所有权转交给top waiter（reader）
		 * zzy: 对着writer看
		 * */
		if (unlikely(oldcount & RWSEM_WRITER_MASK)) {
			/*
			 * When we've been waiting "too" long (for writers
			 * to give up the lock), request a HANDOFF to
			 * force the issue.
			 */
			if (time_after(jiffies, waiter->timeout)) {
				if (!(oldcount & RWSEM_FLAG_HANDOFF)) {
					adjustment -= RWSEM_FLAG_HANDOFF;
					lockevent_inc(rwsem_rlock_handoff);
				}
				waiter->handoff_set = true;
			}

			atomic_long_add(-adjustment, &sem->count);
			return;
		}
		/*
		 * Set it to reader-owned to give spinners an early
		 * indication that readers now have the lock.
		 * The reader nonspinnable bit seen at slowpath entry of
		 * the reader is copied over.
		 */
		/* 上面已经向rwsem的count增加reader计数，这里把owner也设定上（flag也同步
		 * 安排，这里non-spinnable bit保持不变）。随后top waiter的reader会唤醒若干
		 * 队列中的non top reader，但是它们都不配拥有名字
		 * */
		owner = waiter->task;
		__rwsem_set_reader_owned(sem, owner);
	}

	/*
	 * Grant up to MAX_READERS_WAKEUP read locks to all the readers in the
	 * queue. We know that the woken will be at least 1 as we accounted
	 * for above. Note we increment the 'active part' of the count by the
	 * number of readers before waking any processes up.
	 *
	 * This is an adaptation of the phase-fair R/W locks where at the
	 * reader phase (first waiter is a reader), all readers are eligible
	 * to acquire the lock at the same time irrespective of their order
	 * in the queue. The writers acquire the lock according to their
	 * order in the queue.
	 *
	 * We have to do wakeup in 2 passes to prevent the possibility that
	 * the reader count may be decremented before it is incremented. It
	 * is because the to-be-woken waiter may not have slept yet. So it
	 * may see waiter->task got cleared, finish its critical section and
	 * do an unlock before the reader count increment.
	 *
	 * 1) Collect the read-waiters in a separate list, count them and
	 *    fully increment the reader count in rwsem.
	 * 2) For each waiters in the new list, clear waiter->task and
	 *    put them into wake_q to be woken up later.
	 */
	/* 1. 将等待队列中的reader摘下放入到一个单独的列表中（wlist），同时对reader进行计
	 * 数。后续这个计数会写入rwsem 的reader counte域
	 * 2. 对于wlist中的每一个waiter对象（reader任务），清除waiter->task并将它们放入
	 * wake_q以便稍后被唤醒
	 * */
	INIT_LIST_HEAD(&wlist);
	list_for_each_entry_safe(waiter, tmp, &sem->wait_list, list) {
		/* 对于rwsem，其公平性是区分读写的。对于读，如果top waiter是reader，那么所有
		 * 的reader都可以进入临界区，不管reader在队列中的顺序。对于writer，我们要确
		 * 保其公平性，我们要按照writer在队列中的顺序依次持锁。根据上面的原则，我们
		 * 会略过队列中的writer，将尽量多的reader唤醒并进入临界区
		 * */
		if (waiter->type == RWSEM_WAITING_FOR_WRITE)
			continue;

		woken++;
		list_move_tail(&waiter->list, &wlist);

		/*
		 * Limit # of readers that can be woken up per wakeup call.
		 */
		/* 唤醒数量不能大于256，否则会饿死writer  */
		if (woken >= MAX_READERS_WAKEUP)
			break;
	}

	/* 根据唤醒的reader数量计算count调整值 */
	adjustment = woken * RWSEM_READER_BIAS - adjustment;
	lockevent_cond_inc(rwsem_wake_reader, woken);

	oldcount = atomic_long_read(&sem->count);
	if (list_empty(&sem->wait_list)) {
		/*
		 * Combined with list_move_tail() above, this implies
		 * rwsem_del_waiter().
		 */
		/* 如果等待队列为空了，肯定是要清除waiter flag，同时要清除handoff flag，毕竟
		 * 没有什么等待任务可以递交锁了
		 * */
		adjustment -= RWSEM_FLAG_WAITERS;
		if (oldcount & RWSEM_FLAG_HANDOFF)
			adjustment -= RWSEM_FLAG_HANDOFF;
	} else if (woken) {
		/*
		 * When we've woken a reader, we no longer need to force
		 * writers to give up the lock and we can clear HANDOFF.
		 */
		/* 虽然队列非空，但已经唤醒了reader，那么需要清除handoff标记，毕竟
		 * top waiter已经被唤醒去持锁了，完成了锁的递交
		 * */
		if (oldcount & RWSEM_FLAG_HANDOFF)
			adjustment -= RWSEM_FLAG_HANDOFF;
	}

	/* 完成sem->count的调整 */
	if (adjustment)
		atomic_long_add(adjustment, &sem->count);

	/* 2nd pass */
	list_for_each_entry_safe(waiter, tmp, &wlist, list) {
		struct task_struct *tsk;

		tsk = waiter->task;
		get_task_struct(tsk);

		/*
		 * Ensure calling get_task_struct() before setting the reader
		 * waiter to nil such that rwsem_down_read_slowpath() cannot
		 * race with do_exit() by always holding a reference count
		 * to the task to wakeup.
		 */
		/* 主要是把等待任务对象的task成员设置为NULL，唤醒之后根据这个成员来判断
		 * 是正常唤醒还是异常唤醒路径
		 * */
		smp_store_release(&waiter->task, NULL);
		/*
		 * Ensure issuing the wakeup (either by us or someone else)
		 * after setting the reader waiter to nil.
		 */
		wake_q_add_safe(wake_q, tsk);
	}
	/* 这里对唤醒等待队列上的reader和writer处理是不一样的。对于writer，唤醒之然后被调度
	 * 到之后再去试图持锁。对于reader，在唤醒路径上就已经持锁（增加rwsem的reader count，
	 * 并且修改了相关的状态标记）。之所以这么做主要是降低调度的开销，毕竟若干个reader线
	 * 程被唤醒之后，获得CPU资源再去持锁，持锁失败然后继续阻塞，这些都会增加调度的负载
	 * */
}

/*
 * This function must be called with the sem->wait_lock held to prevent
 * race conditions between checking the rwsem wait list and setting the
 * sem->count accordingly.
 *
 * Implies rwsem_del_waiter() on success.
 */
static inline bool rwsem_try_write_lock(struct rw_semaphore *sem,
					struct rwsem_waiter *waiter)
{
	struct rwsem_waiter *first = rwsem_first_waiter(sem);
	long count, new;

	lockdep_assert_held(&sem->wait_lock);

	count = atomic_long_read(&sem->count);
	do {
		bool has_handoff = !!(count & RWSEM_FLAG_HANDOFF);

		/* 如果已经设置了handoff，并且自己不是top waiter（top waiter才是锁要递交的
		 * 对象），返回false，持锁失败。如果是top waiter，那么就设置handoff_set，
		 * 标记自己就是锁递交的目标任务
		 * */
		if (has_handoff) {
			/*
			 * Honor handoff bit and yield only when the first
			 * waiter is the one that set it. Otherwisee, we
			 * still try to acquire the rwsem.
			 */
			if (first->handoff_set && (waiter != first))
				return false;

			/*
			 * First waiter can inherit a previously set handoff
			 * bit and spin on rwsem if lock acquisition fails.
			 */
			if (waiter == first)
				waiter->handoff_set = true;
		}

		new = count;

		if (count & RWSEM_LOCK_MASK) {
			/* 如果当前rwsem已经有了owner，那么说明该锁被偷走了。在适当的条件下
			 * （等待超时）设置handoff标记，防止后续继续被抢。如果已经设置了
			 * handoff就不必重复设置了
			 * */
			if (has_handoff || (!rt_task(waiter->task) &&
					    !time_after(jiffies, waiter->timeout)))
				return false;

			new |= RWSEM_FLAG_HANDOFF;
		} else {
			/* 如果当前rwsem没有owner，则持锁成功，清除handoff标记并根据情况
			 * 设置waiter标记
			 * */
			new |= RWSEM_WRITER_LOCKED;
			new &= ~RWSEM_FLAG_HANDOFF;

			if (list_is_singular(&sem->wait_list))
				new &= ~RWSEM_FLAG_WAITERS;
		}
	/* 通过原子操作来持锁，成功操作后退出循环，否则是有其他线程插入，需要重复上面的逻辑 */
	} while (!atomic_long_try_cmpxchg_acquire(&sem->count, &count, new));

	/*
	 * We have either acquired the lock with handoff bit cleared or
	 * set the handoff bit.
	 */
	/* 没有获取锁，仅仅是设置了handoff bit */
	if (new & RWSEM_FLAG_HANDOFF) {
		waiter->handoff_set = true;
		lockevent_inc(rwsem_wlock_handoff);
		return false;
	}

	/*
	 * Have rwsem_try_write_lock() fully imply rwsem_del_waiter() on
	 * success.
	 */
	/* 获取了锁并清除了handoff bit */
	list_del(&waiter->list);
	rwsem_set_owner(sem);
	return true;
}

/*
 * The rwsem_spin_on_owner() function returns the following 4 values
 * depending on the lock owner state.
 *   OWNER_NULL  : owner is currently NULL
 *   OWNER_WRITER: when owner changes and is a writer
 *   OWNER_READER: when owner changes and the new owner may be a reader.
 *   OWNER_NONSPINNABLE:
 *		   when optimistic spinning has to stop because either the
 *		   owner stops running, is unknown, or its timeslice has
 *		   been used up.
 */
enum owner_state {
	OWNER_NULL		= 1 << 0,
	OWNER_WRITER		= 1 << 1,
	OWNER_READER		= 1 << 2,
	/* 禁止了乐观自旋，主要有两种情况:
	 * 1. 对于writer-owned，当持锁的writer处于off cpu或者执行writer的cpu需要resched
	 * 2. 对于reader-owned，超时会禁止乐观自旋
	 * */
	OWNER_NONSPINNABLE	= 1 << 3,
};

#ifdef CONFIG_RWSEM_SPIN_ON_OWNER
/*
 * Try to acquire write lock before the writer has been put on wait queue.
 */
static inline bool rwsem_try_write_lock_unqueued(struct rw_semaphore *sem)
{
	long count = atomic_long_read(&sem->count);

	while (!(count & (RWSEM_LOCK_MASK|RWSEM_FLAG_HANDOFF))) {
		if (atomic_long_try_cmpxchg_acquire(&sem->count, &count,
					count | RWSEM_WRITER_LOCKED)) {
			rwsem_set_owner(sem);
			lockevent_inc(rwsem_opt_lock);
			return true;
		}
	}
	return false;
}

static inline bool owner_on_cpu(struct task_struct *owner)
{
	/*
	 * As lock holder preemption issue, we both skip spinning if
	 * task is not on cpu or its cpu is preempted
	 */
	return owner->on_cpu && !vcpu_is_preempted(task_cpu(owner));
}

static inline bool rwsem_can_spin_on_owner(struct rw_semaphore *sem)
{
	struct task_struct *owner;
	unsigned long flags;
	bool ret = true;

	/* cpu上需要reschedule，还自旋个毛线，赶紧去睡眠也顺便触发一次调度 */
	if (need_resched()) {
		lockevent_inc(rwsem_opt_fail);
		return false;
	}

	preempt_disable();
	rcu_read_lock();
	/* 读取sem->owner，标记部分保存在flags临时变量中，任务指针保存在owner中 */
	owner = rwsem_owner_flags(sem, &flags);
	/*
	 * Don't check the read-owner as the entry may be stale.
	 */
	/* 如果该rwsem已经禁止了对应的nonspinnable标志，那么肯定是不能乐观自旋了。如果当前
	 * rwsem没有禁止，那么需要看看owner的状态。这里需要特别说明的是：为了方便debug，我们在
	 * 释放读锁的时候并不会清除owner task。也就是说，对于reader而言，owner中的task信息是最
	 * 后进入临界区的那个reader，仅此而已，实际这个task可能已经离开临界区，甚至已经销毁都
	 * 有可能。所以，如果rwsem是reader拥有，那么其实判断owner是否在cpu上运行是没有意义的，
	 * 因此owner是reader的话是允许进行乐观自旋的（ret的缺省值是true），通过超时来控制自旋
	 * 的退出。如果rwsem是writer拥有，那么owner的的确确是正在持锁的线程，如果该线程没有在
	 * CPU上运行（不能很快离开临界区），那么也不能乐观自旋
	 * */
	if ((flags & RWSEM_NONSPINNABLE) ||
	    (owner && !(flags & RWSEM_READER_OWNED) && !owner_on_cpu(owner)))
		ret = false;
	rcu_read_unlock();
	preempt_enable();

	lockevent_cond_inc(rwsem_opt_fail, !ret);
	return ret;
}

#define OWNER_SPINNABLE		(OWNER_NULL | OWNER_WRITER | OWNER_READER)

static inline enum owner_state
rwsem_owner_state(struct task_struct *owner, unsigned long flags)
{
	if (flags & RWSEM_NONSPINNABLE)
		return OWNER_NONSPINNABLE;

	if (flags & RWSEM_READER_OWNED)
		return OWNER_READER;

	return owner ? OWNER_WRITER : OWNER_NULL;
}

static noinline enum owner_state
rwsem_spin_on_owner(struct rw_semaphore *sem)
{
	struct task_struct *new, *owner;
	unsigned long flags, new_flags;
	enum owner_state state;

	/* 在自旋之前，首先要获得初始的状态（owner task指针以及2-bit LSB flag），当这些状态
	 * 发生变化才好退出自旋 */
	owner = rwsem_owner_flags(sem, &flags);
	state = rwsem_owner_state(owner, flags);
	if (state != OWNER_WRITER)
		return state;

	rcu_read_lock();
	for (;;) {
		/*
		 * When a waiting writer set the handoff flag, it may spin
		 * on the owner as well. Once that writer acquires the lock,
		 * we can spin on it. So we don't need to quit even when the
		 * handoff bit is set.
		 */
		new = rwsem_owner_flags(sem, &new_flags);
		if ((new != owner) || (new_flags != flags)) {
			/* 只要owner task或者flag其一发生变化，这里就会停止轮询，同时也会返回
			 * 当前的状态，说明停止自旋的原因。例如当owner task（一定是writer）离
			 * 开临界区的时候会清空rwsem的owner域（owner task和flag会清零），这时
			 * 候自旋的writer会停止自旋，到外层函数会去试图持锁。当然也有可能是其
			 * 他自旋writer抢到了锁，owner task从A切到B。无论那种情况，统一终止对
			 * owner的自旋
			 * */
			state = rwsem_owner_state(new, new_flags);
			break;
		}

		/*
		 * Ensure we emit the owner->on_cpu, dereference _after_
		 * checking sem->owner still matches owner, if that fails,
		 * owner might point to free()d memory, if it still matches,
		 * the rcu_read_lock() ensures the memory stays valid.
		 */
		barrier();

		/* 如果当前cpu需要reschedule或者owner task没有正在运行，那么也需要停止自旋 */
		if (need_resched() || !owner_on_cpu(owner)) {
			state = OWNER_NONSPINNABLE;
			break;
		}

		cpu_relax();
	}
	rcu_read_unlock();

	return state;
}

/*
 * Calculate reader-owned rwsem spinning threshold for writer
 *
 * The more readers own the rwsem, the longer it will take for them to
 * wind down and free the rwsem. So the empirical formula used to
 * determine the actual spinning time limit here is:
 *
 *   Spinning threshold = (10 + nr_readers/2)us
 *
 * The limit is capped to a maximum of 25us (30 readers). This is just
 * a heuristic and is subjected to change in the future.
 */
static inline u64 rwsem_rspin_threshold(struct rw_semaphore *sem)
{
	long count = atomic_long_read(&sem->count);
	int readers = count >> RWSEM_READER_SHIFT;
	u64 delta;

	if (readers > 30)
		readers = 30;
	delta = (20 + readers) * NSEC_PER_USEC / 2;

	return sched_clock() + delta;
}

static bool rwsem_optimistic_spin(struct rw_semaphore *sem)
{
	bool taken = false;
	int prev_owner_state = OWNER_NULL;
	int loop = 0;
	u64 rspin_threshold = 0;

	preempt_disable();

	/* sem->wait_lock should not be held when doing optimistic spinning */
	if (!osq_lock(&sem->osq))
		goto done;

	/*
	 * Optimistically spin on the owner field and attempt to acquire the
	 * lock whenever the owner changes. Spinning will be stopped when:
	 *  1) the owning writer isn't running; or
	 *  2) readers own the lock and spinning time has exceeded limit.
	 */
	for (;;) {
		enum owner_state owner_state;

		owner_state = rwsem_spin_on_owner(sem);
		/* 对于rwsem，只有writer-owned场景能清楚的知道owner task是哪一个。因此，如果
		 * 是writer-owned场景，会在rwsem_spin_on_owner函数进行自旋。对于非
		 * writer-owned场景（reader-owned场景或者禁止了乐观自旋），在
		 * rwsem_spin_on_owner函数中会直接返回。从rwsem_spin_on_owner函数返回会给出
		 * owner state，如果需要退出乐观自旋，那么这里break掉，自旋失败，下面就准备
		 * 挂入等待队列了
		 * */
		if (!(owner_state & OWNER_SPINNABLE))
			break;

		/*
		 * Try to acquire the lock
		 */
		/* 每次退出rwsem_spin_on_owner并且没有要退出自旋的时候，都试着去获取rwsem
		 * ，如果持锁成功那么退出乐观自旋
		 * */
		taken = rwsem_try_write_lock_unqueued(sem);

		if (taken)
			break;

		/*
		 * Time-based reader-owned rwsem optimistic spinning
		 */
		/* 对reader-owned场景的处理。每次rwsem的owner state发生变化（从non-reader
		 * 变成reader-owned状态）时都会重新初始化 rspin_threshold */
		if (owner_state == OWNER_READER) {
			/*
			 * Re-initialize rspin_threshold every time when
			 * the owner state changes from non-reader to reader.
			 * This allows a writer to steal the lock in between
			 * 2 reader phases and have the threshold reset at
			 * the beginning of the 2nd reader phase.
			 */
			if (prev_owner_state != OWNER_READER) {
				if (rwsem_test_oflags(sem, RWSEM_NONSPINNABLE))
					break;
				rspin_threshold = rwsem_rspin_threshold(sem);
				loop = 0;
			}

			/*
			 * Check time threshold once every 16 iterations to
			 * avoid calling sched_clock() too frequently so
			 * as to reduce the average latency between the times
			 * when the lock becomes free and when the spinner
			 * is ready to do a trylock.
			 */
			/* Owner state没有发生变化，那么当前试图持锁的writer可以进行乐观
			 * 自旋，但是需要有一个度，毕竟rwsem的临界区内可能有多个reader线
			 * 程，这有可能使得writer乐观自旋很长时间。设置自旋门限阈值的公式
			 * 是Spinning threshold = (10 + nr_readers/2)us，最大25us
			 * （30 reader）。一旦自旋超期，那么将调用rwsem_set_nonspinnable
			 * 禁止乐观自旋
			 * */
			else if (!(++loop & 0xf) && (sched_clock() > rspin_threshold)) {
				rwsem_set_nonspinnable(sem);
				lockevent_inc(rwsem_opt_nospin);
				break;
			}
		}

		/*
		 * An RT task cannot do optimistic spinning if it cannot
		 * be sure the lock holder is running or live-lock may
		 * happen if the current task and the lock holder happen
		 * to run in the same CPU. However, aborting optimistic
		 * spinning while a NULL owner is detected may miss some
		 * opportunity where spinning can continue without causing
		 * problem.
		 *
		 * There are 2 possible cases where an RT task may be able
		 * to continue spinning.
		 *
		 * 1) The lock owner is in the process of releasing the
		 *    lock, sem->owner is cleared but the lock has not
		 *    been released yet.
		 * 2) The lock was free and owner cleared, but another
		 *    task just comes in and acquire the lock before
		 *    we try to get it. The new owner may be a spinnable
		 *    writer.
		 *
		 * To take advantage of two scenarios listed above, the RT
		 * task is made to retry one more time to see if it can
		 * acquire the lock or continue spinning on the new owning
		 * writer. Of course, if the time lag is long enough or the
		 * new owner is not a writer or spinnable, the RT task will
		 * quit spinning.
		 *
		 * If the owner is a writer, the need_resched() check is
		 * done inside rwsem_spin_on_owner(). If the owner is not
		 * a writer, need_resched() check needs to be done here.
		 */
		/* 对于writer-owned场景，need_resched在函数rwsem_spin_on_owner中完成，对于
		 * reader-owned场景，也是需要检查owner task所在cpu的resched情况。毕竟当前
		 * 任务如果有调度需求，无论reader持锁还是writer持锁场景都要停止自旋
		 * */
		if (owner_state != OWNER_WRITER) {
			if (need_resched())
				break;
			/* 在reader-owned场景中，由于无法判定临界区reader们的执行状态，因此
			 * rt线程的乐观自旋需要更加的谨慎，毕竟有可能自旋的rt线程和临界区的
			 * reader在一个CPU上从而导致活锁现象。当然也不能禁止rt线程的自旋，
			 * 毕竟在临界区为空的情况下，rt自旋会有一定的收益的
			 * 允许rt线程自旋的场景有两个:
			 * 1. lock owner正在释放锁，sem->owner被清除但是锁还没有释放
			 * 2. 锁是空闲的并且sem->owner已清除，但是在我们尝试获取锁之前另一个
			 * 任务刚刚进入并获取了锁（例如一个自旋的writer先于我们进入临界区）
			 * */
			if (rt_task(current) &&
			   (prev_owner_state != OWNER_WRITER))
				break;
		}
		prev_owner_state = owner_state;

		/*
		 * The cpu_relax() call is a compiler barrier which forces
		 * everything in this loop to be re-loaded. We don't need
		 * memory barriers as we'll eventually observe the right
		 * values at the cost of a few extra spins.
		 */
		cpu_relax();
	}
	osq_unlock(&sem->osq);
done:
	preempt_enable();
	lockevent_cond_inc(rwsem_opt_fail, !taken);
	return taken;
}

/*
 * Clear the owner's RWSEM_NONSPINNABLE bit if it is set. This should
 * only be called when the reader count reaches 0.
 */
static inline void clear_nonspinnable(struct rw_semaphore *sem)
{
	if (rwsem_test_oflags(sem, RWSEM_NONSPINNABLE))
		atomic_long_andnot(RWSEM_NONSPINNABLE, &sem->owner);
}

#else
static inline bool rwsem_can_spin_on_owner(struct rw_semaphore *sem)
{
	return false;
}

static inline bool rwsem_optimistic_spin(struct rw_semaphore *sem)
{
	return false;
}

static inline void clear_nonspinnable(struct rw_semaphore *sem) { }

static inline enum owner_state
rwsem_spin_on_owner(struct rw_semaphore *sem)
{
	return OWNER_NONSPINNABLE;
}
#endif

/*
 * Wait for the read lock to be granted
 */
static struct rw_semaphore __sched *
rwsem_down_read_slowpath(struct rw_semaphore *sem, long count, unsigned int state)
{
	long adjustment = -RWSEM_READER_BIAS;
	long rcnt = (count >> RWSEM_READER_SHIFT);
	struct rwsem_waiter waiter;
	DEFINE_WAKE_Q(wake_q);
	bool wake = false;
	/* 能进来这里应该就几种情况：
	 * 1. 锁的owner就是writer
	 * 2. 锁的owner是reader，但reader太多，溢出的情况
	 * 3. 锁的owner是reader，但waiter里面有writer/readers
	 * 4. 锁正在递交，owner是?
	 * 并且此时sem->count已经是被+1过的，如果失败应该-1
	 * */

	/*
	 * To prevent a constant stream of readers from starving a sleeping
	 * waiter, don't attempt optimistic lock stealing if the lock is
	 * currently owned by readers.
	 */
	/* 如果当前的锁被reader持有（至少有一个reader在临界区），那么不再乐观偷锁而是直接
	 * 进行挂等待队列的操作。为何怎么做呢？因为需要在饿死waiter和reader吞吐量上进行平衡。
	 * 一方面，连续的reader持续偷锁的话会饿死等待队列上的任务。另外，在唤醒路径上，被唤
	 * 醒的top reader会顺便将队列中的若干（不大于256个）reader也同时唤醒，以便增加rwsem
	 * 的吞吐量。所以这里的reader直接挂入队列，累计多个reader以便可以批量唤醒
	 * */
	if ((atomic_long_read(&sem->owner) & RWSEM_READER_OWNED) &&
	    (rcnt > 1) && !(count & RWSEM_WRITER_LOCKED))
		goto queue;

	/*
	 * Reader optimistic lock stealing.
	 */
	/* Reader偷锁的场景主要发生在唤醒top waiter的过程中，这时候临界区没有线程，被唤醒的
	 * reader或者writer也没有持锁（writer需要被调度到CPU上执行之后才会试图持锁，高负载
	 * 的场景下，锁被偷的概率比较大，reader是唤醒后立刻持锁，被偷的几率小一点）
	 * */
	if (!(count & (RWSEM_WRITER_LOCKED | RWSEM_FLAG_HANDOFF))) {
		/* 允许偷锁的场景是这样的：临界区没有writer持锁，也没有设置handoff，其实这时
		 * 候临界区也不会有reader了吧，正在唤醒top waiter的过程中，并且有任务在等待
		 * 队列的情况。这时候进入慢速路径的reader可以先于top waiter唤醒之前把锁偷走。
		 * 需要特别说明的是：这时候reader counter已经加一，还是尽量让reader偷锁成功，
		 * 否则还需要回退
		 * */
		/* 当前线程获得了读锁，需要设置owner，毕竟它是临界区的新客 */
		rwsem_set_reader_owned(sem);
		lockevent_inc(rwsem_rlock_steal);

		/*
		 * Wake up other readers in the wait queue if it is
		 * the first reader.
		 */
		/* 如果偷锁成功并且它是临界区第一个reader，那么它还会把等待队列中的reader都
		 * 唤醒（前提是top waiter不是writer），带领大家一起往前冲（这里会打破FIFO的
		 * 顺序，惩罚了队列中的writer）。具体是通过rwsem_mark_wake来标记唤醒的reader
		 * ，然后通过wake_up_q将reader唤醒并进入读临界区。为了减低对等待中的writer
		 * 线程的影响，这时候对reader的并发是受限的，最多可以唤醒MAX_READERS_WAKEUP
		 * 个reader
		 * */
		if ((rcnt == 1) && (count & RWSEM_FLAG_WAITERS)) {
			raw_spin_lock_irq(&sem->wait_lock);
			if (!list_empty(&sem->wait_list))
				rwsem_mark_wake(sem, RWSEM_WAKE_READ_OWNED,
						&wake_q);
			raw_spin_unlock_irq(&sem->wait_lock);
			wake_up_q(&wake_q);
		}
		return sem;
	}

queue:
	waiter.task = current;
	waiter.type = RWSEM_WAITING_FOR_READ;
	/* 准备好挂入等待队列的rwsem waiter数据，需要特别说明的是这里的timeout时间：目前手机
	 * 平台的HZ设置的是250，也就是说在触发handoff机制之前waiter需要至少在队列中等待一个
	 * tick（4ms）的时间。这里的timeout是指handoff timeout，为了防止偷锁或者自旋导致等待
	 * 队列中的top waiter有一个长时间的持锁延迟。在timeout时间内，乐观偷锁或者自旋可以顺利
	 * 进行，但是一旦超时就会设定handoff标记，乐观偷锁或者自旋被禁止，锁的所有权需要递交
	 * 给等待队列中的top waiter
	 * */
	waiter.timeout = jiffies + RWSEM_WAIT_TIMEOUT;
	waiter.handoff_set = false;

	raw_spin_lock_irq(&sem->wait_lock);
	if (list_empty(&sem->wait_list)) {
		/*
		 * In case the wait queue is empty and the lock isn't owned
		 * by a writer or has the handoff bit set, this reader can
		 * exit the slowpath and return immediately as its
		 * RWSEM_READER_BIAS has already been set in the count.
		 */
		/* 当然，在入队之前还要垂死挣扎一下（等待队列为空的时候逻辑简单一些，不需要
		 * 唤醒队列上的wait），看看是不是当前有机可乘，如果是这样，那么就顺势而为，
		 * 直接持锁成功，而且counter都已经准备好了，前面已经加一了
		 * */
		if (!(atomic_long_read(&sem->count) &
		     (RWSEM_WRITER_MASK | RWSEM_FLAG_HANDOFF))) {
			/* Provide lock ACQUIRE */
			smp_acquire__after_ctrl_dep();
			raw_spin_unlock_irq(&sem->wait_lock);
			rwsem_set_reader_owned(sem);
			lockevent_inc(rwsem_rlock_fast);
			return sem;
		}
		adjustment += RWSEM_FLAG_WAITERS;
	}
	/* 等待队列非空的时候，逻辑稍微负载一点。调用rwsem_add_waiter函数即可以把当前任务挂入
	 * 等待队列尾部。这时候也需要把之前武断增加的counter给修正回来了（adjustment初始化为
	 * -RWSEM_READER_BIAS）。如果是第一个waiter，也顺便设置了RWSEM_FLAG_WAITERS标记
	 * */
	rwsem_add_waiter(sem, &waiter);

	/* we're now waiting on the lock, but no longer actively locking */
	count = atomic_long_add_return(adjustment, &sem->count);

	/*
	 * If there are no active locks, wake the front queued process(es).
	 *
	 * If there are no writers and we are first in the queue,
	 * wake our own waiter to join the existing active readers !
	 */
	/* 如果这时候发现锁的owner恰好都离开了临界区，那么我们是需要执行唤醒top waiter操作的
	 * ，唤醒之前需要清除禁止乐观自旋的标记，毕竟目前临界区没有任何线程
	 * */
	if (!(count & RWSEM_LOCK_MASK)) {
		clear_nonspinnable(sem);
		wake = true;
	}
	/* 除了上面说的场景需要唤醒，在reader持锁并且我们是队列中的第一个waiter的时候，也需要
	 * 唤醒的动作（唤醒自己），因为多个读者是可以并发读的呀
	 * */
	if (wake || (!(count & RWSEM_WRITER_MASK) &&
		    (adjustment & RWSEM_FLAG_WAITERS)))
		rwsem_mark_wake(sem, RWSEM_WAKE_ANY, &wake_q);

	raw_spin_unlock_irq(&sem->wait_lock);
	wake_up_q(&wake_q);

	/* wait to be given the lock */
	for (;;) {
		set_current_state(state);
		/* 在rwsem_mark_wake函数中我们会唤醒reader并将其等待对象的task成员
		 * （waiter.task）设置为NULL。因此，这里如果发现waiter.task等于NULL，那么说明
		 * 是该线程被正常唤醒，那么从阻塞状态返回，持锁成功
		 * */
		if (!smp_load_acquire(&waiter.task)) {
			/* Matches rwsem_mark_wake()'s smp_store_release(). */
			break;
		}
		/* 如果在该线程阻塞的时候，有其他任务发送信号给该线程，那么就持锁失败退出。
		 * 如果已经被唤醒，同时又收到信号，这时候需要首先完成唤醒，持锁成功，然后
		 * 在其他的合适点再处理该信号。当然，大部分的rwsem都是D状态，也就不需要处理
		 * 信号了
		 * */
		if (signal_pending_state(state, current)) {
			raw_spin_lock_irq(&sem->wait_lock);
			if (waiter.task)
				goto out_nolock;
			raw_spin_unlock_irq(&sem->wait_lock);
			/* Ordered by sem->wait_lock against rwsem_mark_wake(). */
			break;
		}
		schedule();
		lockevent_inc(rwsem_sleep_reader);
	}

	__set_current_state(TASK_RUNNING);
	lockevent_inc(rwsem_rlock);
	return sem;

out_nolock:
	rwsem_del_waiter(sem, &waiter);
	raw_spin_unlock_irq(&sem->wait_lock);
	__set_current_state(TASK_RUNNING);
	lockevent_inc(rwsem_rlock_fail);
	return ERR_PTR(-EINTR);
}

/*
 * Wait until we successfully acquire the write lock
 */
static struct rw_semaphore *
rwsem_down_write_slowpath(struct rw_semaphore *sem, int state)
{
	long count;
	struct rwsem_waiter waiter;
	DEFINE_WAKE_Q(wake_q);

	/* do optimistic spinning and steal lock if possible */
	if (rwsem_can_spin_on_owner(sem) && rwsem_optimistic_spin(sem)) {
		/* rwsem_optimistic_spin() implies ACQUIRE on success */
		return sem;
	}

	/*
	 * Optimistic spinning failed, proceed to the slowpath
	 * and block until we can acquire the sem.
	 */
	/* 首先准备好一个等待任务对象（栈上）并初始化，将其挂入等待队列。在真正睡眠之前，
	 * 我们需要做一些唤醒动作（和reader持锁过程类似，有可能在挂入等待队列的时候，
	 * 临界区线程恰好离开，变成空锁）
	 * */
	waiter.task = current;
	waiter.type = RWSEM_WAITING_FOR_WRITE;
	waiter.timeout = jiffies + RWSEM_WAIT_TIMEOUT;
	waiter.handoff_set = false;

	raw_spin_lock_irq(&sem->wait_lock);
	rwsem_add_waiter(sem, &waiter);

	/* we're now waiting on the lock */
	if (rwsem_first_waiter(sem) != &waiter) {
		count = atomic_long_read(&sem->count);

		/*
		 * If there were already threads queued before us and:
		 *  1) there are no active locks, wake the front
		 *     queued process(es) as the handoff bit might be set.
		 *  2) there are no active writers and some readers, the lock
		 *     must be read owned; so we try to wake any read lock
		 *     waiters that were queued ahead of us.
		 */
		/* 如果是writer持锁，那么不需要任何唤醒动作，毕竟writer是排他的 */
		if (count & RWSEM_WRITER_MASK)
			goto wait;

		/* 如果是空锁状态，我们需要唤醒top waiter（RWSEM_WAKE_ANY，top writer
		 * 或者reader们）。你可能会疑问：为何空锁还要唤醒等待队列的线程？当前线程快马
		 * 加鞭去持锁不就OK了吗？这主要是和handoff逻辑相关，这时候更应该持锁的是等待
		 * 队列中设置了handoff的那个waiter，而不是当前writer。如果是reader在临界区内，
		 * 那么，我们将唤醒本等待队列头部的所有reader（RWSEM_WAKE_READERS）
		 * */
		rwsem_mark_wake(sem, (count & RWSEM_READER_MASK)
					? RWSEM_WAKE_READERS
					: RWSEM_WAKE_ANY, &wake_q);

		/* 上面仅仅是标记唤醒者，这里的代码段完成具体的唤醒动作 */
		if (!wake_q_empty(&wake_q)) {
			/*
			 * We want to minimize wait_lock hold time especially
			 * when a large number of readers are to be woken up.
			 */
			raw_spin_unlock_irq(&sem->wait_lock);
			wake_up_q(&wake_q);
			wake_q_init(&wake_q);	/* Used again, reinit */
			raw_spin_lock_irq(&sem->wait_lock);
		}
	} else {
		/* 如果我们是等待队列的top waiter（等待队列从空变为非空），那么需要设定
		 * RWSEM_FLAG_WAITERS标记，直接进入后续阻塞逻辑。如果不是，那么逻辑要复杂点
		 * ，需要扫描一下之前挂入队列的任务，看看是否需要唤醒
		 * */
		atomic_long_or(RWSEM_FLAG_WAITERS, &sem->count);
	}

wait:
	/* wait until we successfully acquire the lock */
	set_current_state(state);
	for (;;) {
		/* 调用rwsem_try_write_lock试图持锁，如果成功持锁则退出循环，不再阻塞。
		 * 有两个逻辑路径会路过这里。一个是线程持锁失败进入这里，另外一个是阻塞后
		 * 被唤醒试图持锁
		 * */
		if (rwsem_try_write_lock(sem, &waiter)) {
			/* rwsem_try_write_lock() implies ACQUIRE on success */
			break;
		}

		raw_spin_unlock_irq(&sem->wait_lock);

		/* 有pending的信号，异常路径退出 */
		if (signal_pending_state(state, current))
			goto out_nolock;

		/*
		 * After setting the handoff bit and failing to acquire
		 * the lock, attempt to spin on owner to accelerate lock
		 * transfer. If the previous owner is a on-cpu writer and it
		 * has just released the lock, OWNER_NULL will be returned.
		 * In this case, we attempt to acquire the lock again
		 * without sleeping.
		 */
		/* 持锁失败但是设置了handoff，那么该线程对owner进行自旋等待
		 * 以便加快锁的传递 */
		if (waiter.handoff_set) {
			enum owner_state owner_state;

			preempt_disable();
			owner_state = rwsem_spin_on_owner(sem);
			preempt_enable();

			if (owner_state == OWNER_NULL)
				goto trylock_again;
		}

		schedule();
		/* 唤醒之后，重新试图持锁。Writer和reader不一样，writer是唤醒之后自己再通过
		 * rwsem_try_write_lock试图持锁，而reader是在唤醒路径上持锁
		 * */
		lockevent_inc(rwsem_sleep_writer);
		set_current_state(state);
trylock_again:
		raw_spin_lock_irq(&sem->wait_lock);
	}
	__set_current_state(TASK_RUNNING);
	raw_spin_unlock_irq(&sem->wait_lock);
	lockevent_inc(rwsem_wlock);
	return sem;

out_nolock:
	__set_current_state(TASK_RUNNING);
	raw_spin_lock_irq(&sem->wait_lock);
	rwsem_del_waiter(sem, &waiter);
	if (!list_empty(&sem->wait_list))
		rwsem_mark_wake(sem, RWSEM_WAKE_ANY, &wake_q);
	raw_spin_unlock_irq(&sem->wait_lock);
	wake_up_q(&wake_q);
	lockevent_inc(rwsem_wlock_fail);
	return ERR_PTR(-EINTR);
}

/*
 * handle waking up a waiter on the semaphore
 * - up_read/up_write has decremented the active part of count if we come here
 */
static struct rw_semaphore *rwsem_wake(struct rw_semaphore *sem)
{
	unsigned long flags;
	DEFINE_WAKE_Q(wake_q);

	raw_spin_lock_irqsave(&sem->wait_lock, flags);

	if (!list_empty(&sem->wait_list))
		rwsem_mark_wake(sem, RWSEM_WAKE_ANY, &wake_q);

	raw_spin_unlock_irqrestore(&sem->wait_lock, flags);
	wake_up_q(&wake_q);

	return sem;
}

/*
 * downgrade a write lock into a read lock
 * - caller incremented waiting part of count and discovered it still negative
 * - just wake up any readers at the front of the queue
 */
static struct rw_semaphore *rwsem_downgrade_wake(struct rw_semaphore *sem)
{
	unsigned long flags;
	DEFINE_WAKE_Q(wake_q);

	raw_spin_lock_irqsave(&sem->wait_lock, flags);

	if (!list_empty(&sem->wait_list))
		rwsem_mark_wake(sem, RWSEM_WAKE_READ_OWNED, &wake_q);

	raw_spin_unlock_irqrestore(&sem->wait_lock, flags);
	wake_up_q(&wake_q);

	return sem;
}

/*
 * lock for reading
 */
static inline int __down_read_common(struct rw_semaphore *sem, int state)
{
	long count;

	if (!rwsem_read_trylock(sem, &count)) {
		if (IS_ERR(rwsem_down_read_slowpath(sem, count, state)))
			return -EINTR;
		DEBUG_RWSEMS_WARN_ON(!is_rwsem_reader_owned(sem), sem);
	}
	return 0;
}

static inline void __down_read(struct rw_semaphore *sem)
{
	__down_read_common(sem, TASK_UNINTERRUPTIBLE);
}

static inline int __down_read_interruptible(struct rw_semaphore *sem)
{
	return __down_read_common(sem, TASK_INTERRUPTIBLE);
}

static inline int __down_read_killable(struct rw_semaphore *sem)
{
	return __down_read_common(sem, TASK_KILLABLE);
}

static inline int __down_read_trylock(struct rw_semaphore *sem)
{
	long tmp;

	DEBUG_RWSEMS_WARN_ON(sem->magic != sem, sem);

	/*
	 * Optimize for the case when the rwsem is not locked at all.
	 */
	tmp = RWSEM_UNLOCKED_VALUE;
	do {
		if (atomic_long_try_cmpxchg_acquire(&sem->count, &tmp,
					tmp + RWSEM_READER_BIAS)) {
			rwsem_set_reader_owned(sem);
			return 1;
		}
	} while (!(tmp & RWSEM_READ_FAILED_MASK));
	return 0;
}

/*
 * lock for writing
 */
static inline int __down_write_common(struct rw_semaphore *sem, int state)
{
	if (unlikely(!rwsem_write_trylock(sem))) {
		if (IS_ERR(rwsem_down_write_slowpath(sem, state)))
			return -EINTR;
	}

	return 0;
}

static inline void __down_write(struct rw_semaphore *sem)
{
	__down_write_common(sem, TASK_UNINTERRUPTIBLE);
}

static inline int __down_write_killable(struct rw_semaphore *sem)
{
	return __down_write_common(sem, TASK_KILLABLE);
}

static inline int __down_write_trylock(struct rw_semaphore *sem)
{
	DEBUG_RWSEMS_WARN_ON(sem->magic != sem, sem);
	return rwsem_write_trylock(sem);
}

/*
 * unlock after reading
 */
static inline void __up_read(struct rw_semaphore *sem)
{
	long tmp;

	DEBUG_RWSEMS_WARN_ON(sem->magic != sem, sem);
	DEBUG_RWSEMS_WARN_ON(!is_rwsem_reader_owned(sem), sem);

	rwsem_clear_reader_owned(sem);
	/* 这里仅仅是减去了读临界区的counter计数，并没有清除owner中的task pointer。此外，
	 * 当等待队列有waiter并且没有writer或者reader在临界区的时候，我们会调用rwsem_wake
	 * 来唤醒等待队列的线程。因为临界区已经没有线程，所以需要清除nonspinable标记
	 * */
	tmp = atomic_long_add_return_release(-RWSEM_READER_BIAS, &sem->count);
	DEBUG_RWSEMS_WARN_ON(tmp < 0, sem);
	/* zzy：不怕变量被抢掉吗？ */
	if (unlikely((tmp & (RWSEM_LOCK_MASK|RWSEM_FLAG_WAITERS)) ==
		      RWSEM_FLAG_WAITERS)) {
		clear_nonspinnable(sem);
		rwsem_wake(sem);
	}
}

/*
 * unlock after writing
 */
static inline void __up_write(struct rw_semaphore *sem)
{
	long tmp;

	DEBUG_RWSEMS_WARN_ON(sem->magic != sem, sem);
	/*
	 * sem->owner may differ from current if the ownership is transferred
	 * to an anonymous writer by setting the RWSEM_NONSPINNABLE bits.
	 */
	DEBUG_RWSEMS_WARN_ON((rwsem_owner(sem) != current) &&
			    !rwsem_test_oflags(sem, RWSEM_NONSPINNABLE), sem);

	rwsem_clear_owner(sem);
	tmp = atomic_long_fetch_add_release(-RWSEM_WRITER_LOCKED, &sem->count);
	if (unlikely(tmp & RWSEM_FLAG_WAITERS))
		rwsem_wake(sem);
}

/*
 * downgrade write lock to read lock
 */
static inline void __downgrade_write(struct rw_semaphore *sem)
{
	long tmp;

	/*
	 * When downgrading from exclusive to shared ownership,
	 * anything inside the write-locked region cannot leak
	 * into the read side. In contrast, anything in the
	 * read-locked region is ok to be re-ordered into the
	 * write side. As such, rely on RELEASE semantics.
	 */
	DEBUG_RWSEMS_WARN_ON(rwsem_owner(sem) != current, sem);
	tmp = atomic_long_fetch_add_release(
		-RWSEM_WRITER_LOCKED+RWSEM_READER_BIAS, &sem->count);
	rwsem_set_reader_owned(sem);
	if (tmp & RWSEM_FLAG_WAITERS)
		rwsem_downgrade_wake(sem);
}

#else /* !CONFIG_PREEMPT_RT */

#define RT_MUTEX_BUILD_MUTEX
#include "rtmutex.c"

#define rwbase_set_and_save_current_state(state)	\
	set_current_state(state)

#define rwbase_restore_current_state()			\
	__set_current_state(TASK_RUNNING)

#define rwbase_rtmutex_lock_state(rtm, state)		\
	__rt_mutex_lock(rtm, state)

#define rwbase_rtmutex_slowlock_locked(rtm, state)	\
	__rt_mutex_slowlock_locked(rtm, NULL, state)

#define rwbase_rtmutex_unlock(rtm)			\
	__rt_mutex_unlock(rtm)

#define rwbase_rtmutex_trylock(rtm)			\
	__rt_mutex_trylock(rtm)

#define rwbase_signal_pending_state(state, current)	\
	signal_pending_state(state, current)

#define rwbase_schedule()				\
	schedule()

#include "rwbase_rt.c"

void __init_rwsem(struct rw_semaphore *sem, const char *name,
		  struct lock_class_key *key)
{
	init_rwbase_rt(&(sem)->rwbase);

#ifdef CONFIG_DEBUG_LOCK_ALLOC
	debug_check_no_locks_freed((void *)sem, sizeof(*sem));
	lockdep_init_map_wait(&sem->dep_map, name, key, 0, LD_WAIT_SLEEP);
#endif
}
EXPORT_SYMBOL(__init_rwsem);

static inline void __down_read(struct rw_semaphore *sem)
{
	rwbase_read_lock(&sem->rwbase, TASK_UNINTERRUPTIBLE);
}

static inline int __down_read_interruptible(struct rw_semaphore *sem)
{
	return rwbase_read_lock(&sem->rwbase, TASK_INTERRUPTIBLE);
}

static inline int __down_read_killable(struct rw_semaphore *sem)
{
	return rwbase_read_lock(&sem->rwbase, TASK_KILLABLE);
}

static inline int __down_read_trylock(struct rw_semaphore *sem)
{
	return rwbase_read_trylock(&sem->rwbase);
}

static inline void __up_read(struct rw_semaphore *sem)
{
	rwbase_read_unlock(&sem->rwbase, TASK_NORMAL);
}

static inline void __sched __down_write(struct rw_semaphore *sem)
{
	rwbase_write_lock(&sem->rwbase, TASK_UNINTERRUPTIBLE);
}

static inline int __sched __down_write_killable(struct rw_semaphore *sem)
{
	return rwbase_write_lock(&sem->rwbase, TASK_KILLABLE);
}

static inline int __down_write_trylock(struct rw_semaphore *sem)
{
	return rwbase_write_trylock(&sem->rwbase);
}

static inline void __up_write(struct rw_semaphore *sem)
{
	rwbase_write_unlock(&sem->rwbase);
}

static inline void __downgrade_write(struct rw_semaphore *sem)
{
	rwbase_write_downgrade(&sem->rwbase);
}

/* Debug stubs for the common API */
#define DEBUG_RWSEMS_WARN_ON(c, sem)

static inline void __rwsem_set_reader_owned(struct rw_semaphore *sem,
					    struct task_struct *owner)
{
}

static inline bool is_rwsem_reader_owned(struct rw_semaphore *sem)
{
	int count = atomic_read(&sem->rwbase.readers);

	return count < 0 && count != READER_BIAS;
}

#endif /* CONFIG_PREEMPT_RT */

/*
 * lock for reading
 */
void __sched down_read(struct rw_semaphore *sem)
{
	might_sleep();
	rwsem_acquire_read(&sem->dep_map, 0, 0, _RET_IP_);

	LOCK_CONTENDED(sem, __down_read_trylock, __down_read);
}
EXPORT_SYMBOL(down_read);

int __sched down_read_interruptible(struct rw_semaphore *sem)
{
	might_sleep();
	rwsem_acquire_read(&sem->dep_map, 0, 0, _RET_IP_);

	if (LOCK_CONTENDED_RETURN(sem, __down_read_trylock, __down_read_interruptible)) {
		rwsem_release(&sem->dep_map, _RET_IP_);
		return -EINTR;
	}

	return 0;
}
EXPORT_SYMBOL(down_read_interruptible);

int __sched down_read_killable(struct rw_semaphore *sem)
{
	might_sleep();
	rwsem_acquire_read(&sem->dep_map, 0, 0, _RET_IP_);

	if (LOCK_CONTENDED_RETURN(sem, __down_read_trylock, __down_read_killable)) {
		rwsem_release(&sem->dep_map, _RET_IP_);
		return -EINTR;
	}

	return 0;
}
EXPORT_SYMBOL(down_read_killable);

/*
 * trylock for reading -- returns 1 if successful, 0 if contention
 */
int down_read_trylock(struct rw_semaphore *sem)
{
	int ret = __down_read_trylock(sem);

	if (ret == 1)
		rwsem_acquire_read(&sem->dep_map, 0, 1, _RET_IP_);
	return ret;
}
EXPORT_SYMBOL(down_read_trylock);

/*
 * lock for writing
 */
void __sched down_write(struct rw_semaphore *sem)
{
	might_sleep();
	rwsem_acquire(&sem->dep_map, 0, 0, _RET_IP_);
	LOCK_CONTENDED(sem, __down_write_trylock, __down_write);
}
EXPORT_SYMBOL(down_write);

/*
 * lock for writing
 */
int __sched down_write_killable(struct rw_semaphore *sem)
{
	might_sleep();
	rwsem_acquire(&sem->dep_map, 0, 0, _RET_IP_);

	if (LOCK_CONTENDED_RETURN(sem, __down_write_trylock,
				  __down_write_killable)) {
		rwsem_release(&sem->dep_map, _RET_IP_);
		return -EINTR;
	}

	return 0;
}
EXPORT_SYMBOL(down_write_killable);

/*
 * trylock for writing -- returns 1 if successful, 0 if contention
 */
int down_write_trylock(struct rw_semaphore *sem)
{
	int ret = __down_write_trylock(sem);

	if (ret == 1)
		rwsem_acquire(&sem->dep_map, 0, 1, _RET_IP_);

	return ret;
}
EXPORT_SYMBOL(down_write_trylock);

/*
 * release a read lock
 */
void up_read(struct rw_semaphore *sem)
{
	rwsem_release(&sem->dep_map, _RET_IP_);
	__up_read(sem);
}
EXPORT_SYMBOL(up_read);

/*
 * release a write lock
 */
void up_write(struct rw_semaphore *sem)
{
	rwsem_release(&sem->dep_map, _RET_IP_);
	__up_write(sem);
}
EXPORT_SYMBOL(up_write);

/*
 * downgrade write lock to read lock
 */
void downgrade_write(struct rw_semaphore *sem)
{
	lock_downgrade(&sem->dep_map, _RET_IP_);
	__downgrade_write(sem);
}
EXPORT_SYMBOL(downgrade_write);

#ifdef CONFIG_DEBUG_LOCK_ALLOC

void down_read_nested(struct rw_semaphore *sem, int subclass)
{
	might_sleep();
	rwsem_acquire_read(&sem->dep_map, subclass, 0, _RET_IP_);
	LOCK_CONTENDED(sem, __down_read_trylock, __down_read);
}
EXPORT_SYMBOL(down_read_nested);

int down_read_killable_nested(struct rw_semaphore *sem, int subclass)
{
	might_sleep();
	rwsem_acquire_read(&sem->dep_map, subclass, 0, _RET_IP_);

	if (LOCK_CONTENDED_RETURN(sem, __down_read_trylock, __down_read_killable)) {
		rwsem_release(&sem->dep_map, _RET_IP_);
		return -EINTR;
	}

	return 0;
}
EXPORT_SYMBOL(down_read_killable_nested);

void _down_write_nest_lock(struct rw_semaphore *sem, struct lockdep_map *nest)
{
	might_sleep();
	rwsem_acquire_nest(&sem->dep_map, 0, 0, nest, _RET_IP_);
	LOCK_CONTENDED(sem, __down_write_trylock, __down_write);
}
EXPORT_SYMBOL(_down_write_nest_lock);

void down_read_non_owner(struct rw_semaphore *sem)
{
	might_sleep();
	__down_read(sem);
	__rwsem_set_reader_owned(sem, NULL);
}
EXPORT_SYMBOL(down_read_non_owner);

void down_write_nested(struct rw_semaphore *sem, int subclass)
{
	might_sleep();
	rwsem_acquire(&sem->dep_map, subclass, 0, _RET_IP_);
	LOCK_CONTENDED(sem, __down_write_trylock, __down_write);
}
EXPORT_SYMBOL(down_write_nested);

int __sched down_write_killable_nested(struct rw_semaphore *sem, int subclass)
{
	might_sleep();
	rwsem_acquire(&sem->dep_map, subclass, 0, _RET_IP_);

	if (LOCK_CONTENDED_RETURN(sem, __down_write_trylock,
				  __down_write_killable)) {
		rwsem_release(&sem->dep_map, _RET_IP_);
		return -EINTR;
	}

	return 0;
}
EXPORT_SYMBOL(down_write_killable_nested);

void up_read_non_owner(struct rw_semaphore *sem)
{
	DEBUG_RWSEMS_WARN_ON(!is_rwsem_reader_owned(sem), sem);
	__up_read(sem);
}
EXPORT_SYMBOL(up_read_non_owner);

#endif
