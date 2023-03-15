#include <drm/drm_atomic_helper.h>
#include <drm/drm_crtc_helper.h>
#include <drm/drm_fb_cma_helper.h>
#include <drm/drm_gem_cma_helper.h>
#include <linux/hrtimer.h>

static struct drm_device drm;
static struct drm_plane primary;
static struct drm_crtc crtc;
static struct drm_encoder encoder;
static struct drm_connector connector;
static struct hrtimer vblank_hrtimer;

static enum hrtimer_restart vkms_vblank_simulate(struct hrtimer *timer)
{
	drm_crtc_handle_vblank(&crtc);

	hrtimer_forward_now(&vblank_hrtimer, 16666667);

	return HRTIMER_RESTART;
}

static void vkms_crtc_atomic_enable(struct drm_crtc *crtc,
		struct drm_crtc_state *old_state)
{
	hrtimer_init(&vblank_hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	vblank_hrtimer.function = &vkms_vblank_simulate;
	hrtimer_start(&vblank_hrtimer, 16666667, HRTIMER_MODE_REL);
}

static void vkms_crtc_atomic_disable(struct drm_crtc *crtc,
		struct drm_crtc_state *old_state)
{
	hrtimer_cancel(&vblank_hrtimer);
}

static void vkms_crtc_atomic_flush(struct drm_crtc *crtc,
		struct drm_crtc_state *old_crtc_state)
{
	unsigned long flags;

	if (crtc->state->event) {
		spin_lock_irqsave(&crtc->dev->event_lock, flags);
		drm_crtc_send_vblank_event(crtc, crtc->state->event);
		spin_unlock_irqrestore(&crtc->dev->event_lock, flags);

		crtc->state->event = NULL;
	}
}

static const struct drm_crtc_helper_funcs vkms_crtc_helper_funcs = {
	.atomic_enable = vkms_crtc_atomic_enable,
	.atomic_disable = vkms_crtc_atomic_disable,
	.atomic_flush = vkms_crtc_atomic_flush,
};

static const struct drm_crtc_funcs vkms_crtc_funcs = {
	.set_config             = drm_atomic_helper_set_config,
	.page_flip              = drm_atomic_helper_page_flip,
	.destroy                = drm_crtc_cleanup,
	.reset                  = drm_atomic_helper_crtc_reset,
	.atomic_duplicate_state = drm_atomic_helper_crtc_duplicate_state,
	.atomic_destroy_state   = drm_atomic_helper_crtc_destroy_state,
};

static void vkms_plane_atomic_update(struct drm_plane *plane,
		struct drm_plane_state *old_state)
{
}

static const struct drm_plane_helper_funcs vkms_plane_helper_funcs = {
	.atomic_update  = vkms_plane_atomic_update,
};

static const struct drm_plane_funcs vkms_plane_funcs = {
	.update_plane  = drm_atomic_helper_update_plane,
	.disable_plane  = drm_atomic_helper_disable_plane,
	.destroy   = drm_plane_cleanup,
	.reset    = drm_atomic_helper_plane_reset,
	.atomic_duplicate_state = drm_atomic_helper_plane_duplicate_state,
	.atomic_destroy_state = drm_atomic_helper_plane_destroy_state,
};

static int vkms_conn_get_modes(struct drm_connector *connector)
{
	int count;

	count = drm_add_modes_noedid(connector, 8192, 8192);
	drm_set_preferred_mode(connector, 1024, 768);

	return count;
}

static const struct drm_connector_helper_funcs vkms_conn_helper_funcs = {
	.get_modes = vkms_conn_get_modes,
};

static const struct drm_connector_funcs vkms_connector_funcs = {
	.fill_modes = drm_helper_probe_single_connector_modes,
	.destroy = drm_connector_cleanup,
	.reset = drm_atomic_helper_connector_reset,
	.atomic_duplicate_state = drm_atomic_helper_connector_duplicate_state,
	.atomic_destroy_state = drm_atomic_helper_connector_destroy_state,
};

static const struct drm_encoder_funcs vkms_encoder_funcs = {
	.destroy = drm_encoder_cleanup,
};

static const struct drm_mode_config_funcs vkms_mode_funcs = {
	.fb_create = drm_fb_cma_create,
	.atomic_check = drm_atomic_helper_check,
	.atomic_commit = drm_atomic_helper_commit,
};

static const u32 vkms_formats[] = {
	DRM_FORMAT_XRGB8888,
};

static void vkms_modeset_init(void)
{
	drm_mode_config_init(&drm);
	drm.mode_config.max_width = 8192;
	drm.mode_config.max_height = 8192;
	drm.mode_config.funcs = &vkms_mode_funcs;

	drm_universal_plane_init(&drm, &primary, 0, &vkms_plane_funcs,
			vkms_formats, ARRAY_SIZE(vkms_formats),
			NULL, DRM_PLANE_TYPE_PRIMARY, NULL);
	drm_plane_helper_add(&primary, &vkms_plane_helper_funcs);

	drm_crtc_init_with_planes(&drm, &crtc, &primary, NULL, &vkms_crtc_funcs, NULL);
	drm_crtc_helper_add(&crtc, &vkms_crtc_helper_funcs);

	drm_encoder_init(&drm, &encoder, &vkms_encoder_funcs, DRM_MODE_ENCODER_VIRTUAL, NULL);

	drm_connector_init(&drm, &connector, &vkms_connector_funcs, DRM_MODE_CONNECTOR_VIRTUAL);
	drm_connector_helper_add(&connector, &vkms_conn_helper_funcs);
	drm_mode_connector_attach_encoder(&connector, &encoder);

	drm_mode_config_reset(&drm);
}

static const struct file_operations vkms_fops = {
	.owner = THIS_MODULE,
	.open = drm_open,
	.release = drm_release,
	.unlocked_ioctl = drm_ioctl,
	.poll = drm_poll,
	.read = drm_read,
	.mmap = drm_gem_cma_mmap,
};

static struct drm_driver vkms_driver = {
	.driver_features = DRIVER_MODESET | DRIVER_GEM | DRIVER_ATOMIC,
	.fops   = &vkms_fops,

	.dumb_create = drm_gem_cma_dumb_create,
	.gem_vm_ops  = &drm_gem_cma_vm_ops,
	.gem_free_object_unlocked = drm_gem_cma_free_object,

	.name   = "vkms",
	.desc   = "Virtual Kernel Mode Setting",
	.date   = "20180514",
	.major   = 1,
	.minor   = 0,
};

static int __init vkms_init(void)
{
	drm_dev_init(&drm, &vkms_driver, NULL);

	vkms_modeset_init();

	drm_vblank_init(&drm, 1);

	drm.irq_enabled = true;

	drm_dev_register(&drm, 0);

	return 0;
}

module_init(vkms_init);

/*
将上面的 Legacy code 转换为 Atomic 版本：
重点：

1. 给 driver_features 添加上 DRIVER_ATOMIC 标志位，告诉 DRM Core 该驱动支持 Atomic 操作。
2. drm_mode_config_funcs.atomic_commit() 接口是 atomic 操作的主要入口函数，必须实现。这里直接使用 drm_atomic_helper_commit() 函数实现。
3. Atomic 操作依赖 VSYNC 中断（即 VBLANK 事件），因此需要使用 hrtimer 来提供软件中断信号。在驱动初始化时调用 drm_vblank_init()，在 VSYNC 中断处理函数中调用 drm_handle_vblank()。
4. 在 plane/crtc/encoder/connector objects 初始化完成之后，一定要调用 drm_mode_config_reset() 来动态创建各个 pipeline 的软件状态（即 drm_xxx_state）。
5. 与 Legacy 相比，Atomic 的 xxx_funcs 必须 实现如下接口：reset()，atomic_duplicate_state()，atomic_destroy_state()，它们主要用于维护 drm_xxx_state 数据结构，不能省略！
6. drm_plane_helper_funcs.atomic_update() 必须实现！
终于，我们可以使用 drmModeAtomicCommit() 了。


要实现一个 DRM KMS 驱动，通常需要实现如下代码：

1. fops、drm_driver
2. dumb_create、fb_create、atomic_commit
3. drm_xxx_funcs、drm_xxx_helper_funcs
4. drm_xxx_init()、drm_xxx_helper_add()
5. drm_dev_init()、drm_dev_register()
但这都只是表象，核心仍然是上面介绍的7个 objects，一切都围绕着这几个 objects 展开：

1. 为了创建 crtc/plane/encoder/connector objects，需要调用 drm_xxx_init()。
2. 为了创建 framebuffer object，需要实现 fb_create() callback。
3. 为了创建 gem object，需要实现 dumb_create() callback。
4. 为了创建 property objects，需要调用 drm_mode_config_init()。
5. 为了让这些 objects 动起来，需要实现各种 funcs 和 helper funcs。
6. 为了支持 atomic 操作，需要实现 atomic_commit() callback。
*/
