// SPDX-License-Identifier: GPL-2.0-only
/*
 * Virtual DMA channel support for DMAengine
 *
 * Copyright (C) 2012 Russell King
 */
#include <linux/device.h>
#include <linux/dmaengine.h>
#include <linux/module.h>
#include <linux/spinlock.h>

#include "virt-dma.h"

static struct virt_dma_desc *to_virt_desc(struct dma_async_tx_descriptor *tx)
{
	return container_of(tx, struct virt_dma_desc, tx);
}

dma_cookie_t vchan_tx_submit(struct dma_async_tx_descriptor *tx)
{
	struct virt_dma_chan *vc = to_virt_chan(tx->chan);
	struct virt_dma_desc *vd = to_virt_desc(tx);
	unsigned long flags;
	dma_cookie_t cookie;

	spin_lock_irqsave(&vc->lock, flags);
	/* 为传输描述符分配cookie */
	cookie = dma_cookie_assign(tx);

	/* 刚才还在vc->desc_allocated，现在转移到vc->desc_submitted */
	list_move_tail(&vd->node, &vc->desc_submitted);
	spin_unlock_irqrestore(&vc->lock, flags);

	dev_dbg(vc->chan.device->dev, "vchan %p: txd %p[%x]: submitted\n",
		vc, vd, cookie);

	return cookie;
}
EXPORT_SYMBOL_GPL(vchan_tx_submit);

/**
 * vchan_tx_desc_free - free a reusable descriptor
 * @tx: the transfer
 *
 * This function frees a previously allocated reusable descriptor. The only
 * other way is to clear the DMA_CTRL_REUSE flag and submit one last time the
 * transfer.
 *
 * Returns 0 upon success
 */
int vchan_tx_desc_free(struct dma_async_tx_descriptor *tx)
{
	struct virt_dma_chan *vc = to_virt_chan(tx->chan);
	struct virt_dma_desc *vd = to_virt_desc(tx);
	unsigned long flags;

	spin_lock_irqsave(&vc->lock, flags);
	list_del(&vd->node);
	spin_unlock_irqrestore(&vc->lock, flags);

	dev_dbg(vc->chan.device->dev, "vchan %p: txd %p[%x]: freeing\n",
		vc, vd, vd->tx.cookie);
	vc->desc_free(vd);
	return 0;
}
EXPORT_SYMBOL_GPL(vchan_tx_desc_free);

struct virt_dma_desc *vchan_find_desc(struct virt_dma_chan *vc,
	dma_cookie_t cookie)
{
	struct virt_dma_desc *vd;

	list_for_each_entry(vd, &vc->desc_issued, node)
		if (vd->tx.cookie == cookie)
			return vd;

	return NULL;
}
EXPORT_SYMBOL_GPL(vchan_find_desc);

/*
 * This tasklet handles the completion of a DMA descriptor by
 * calling its callback and freeing it.
 */
static void vchan_complete(struct tasklet_struct *t)
{
	struct virt_dma_chan *vc = from_tasklet(vc, t, task);
	struct virt_dma_desc *vd, *_vd;
	struct dmaengine_desc_callback cb;
	LIST_HEAD(head);

	spin_lock_irq(&vc->lock);
	/* 将desc_completed链表上的所有传输描述符移动到head链表上 */
	list_splice_tail_init(&vc->desc_completed, &head);
	vd = vc->cyclic;
	if (vd) {
		vc->cyclic = NULL;
		dmaengine_desc_get_callback(&vd->tx, &cb);
	} else {
		memset(&cb, 0, sizeof(cb));
	}
	spin_unlock_irq(&vc->lock);

	dmaengine_desc_callback_invoke(&cb, &vd->tx_result);

	list_for_each_entry_safe(vd, _vd, &head, node) {
		dmaengine_desc_get_callback(&vd->tx, &cb);

		/* 将传输描述符去head链表上移除 */
		list_del(&vd->node);
		dmaengine_desc_callback_invoke(&cb, &vd->tx_result);
		vchan_vdesc_fini(vd);
	}
}

void vchan_dma_desc_free_list(struct virt_dma_chan *vc, struct list_head *head)
{
	struct virt_dma_desc *vd, *_vd;

	list_for_each_entry_safe(vd, _vd, head, node) {
		list_del(&vd->node);
		vchan_vdesc_fini(vd);
	}
}
EXPORT_SYMBOL_GPL(vchan_dma_desc_free_list);

void vchan_init(struct virt_dma_chan *vc, struct dma_device *dmadev)
{
	dma_cookie_init(&vc->chan);

	spin_lock_init(&vc->lock);
	/* 初始化虚拟通道的各个工作链表，每个链表代表节点的状态
	 * 虚拟通道的每个传输任务将会在这些链表上流转，以执行不
	 * 同状态时所需要的操作 */
	INIT_LIST_HEAD(&vc->desc_allocated);
	INIT_LIST_HEAD(&vc->desc_submitted);
	INIT_LIST_HEAD(&vc->desc_issued);
	INIT_LIST_HEAD(&vc->desc_completed);
	INIT_LIST_HEAD(&vc->desc_terminated);

	/* 初始化虚拟通道的tasklet，每当虚拟通道完成一次传输任务，
	 * 就会调用一次vchan_complete
	 * */
	tasklet_setup(&vc->task, vchan_complete);

	/* 初始化虚拟通道，将虚拟通道挂在到slave的channel成员上，
	 * 以后就可以直接通过dma_device找到所有的虚拟通道，例如
	 * drivers/dma/sun6i-dma.c 的 sun6i_dma_tasklet
	 * */
	vc->chan.device = dmadev;
	list_add_tail(&vc->chan.device_node, &dmadev->channels);
}
EXPORT_SYMBOL_GPL(vchan_init);

MODULE_AUTHOR("Russell King");
MODULE_LICENSE("GPL");
