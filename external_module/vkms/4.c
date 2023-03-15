#include <drm/drmP.h>
#include <drm/drm_encoder.h>
#include <drm/drm_fb_cma_helper.h>
#include <drm/drm_gem_cma_helper.h>

static struct drm_device drm;
static struct drm_plane primary;
static struct drm_crtc crtc;
static struct drm_encoder encoder;
static struct drm_connector connector;

static const struct drm_plane_funcs vkms_plane_funcs;
static const struct drm_crtc_funcs vkms_crtc_funcs;
static const struct drm_encoder_funcs vkms_encoder_funcs;
static const struct drm_connector_funcs vkms_connector_funcs;

/* add here */
static const struct drm_mode_config_funcs vkms_mode_funcs = {
	.fb_create = drm_fb_cma_create,
};

static const u32 vkms_formats[] = {
	DRM_FORMAT_XRGB8888,
};

static void vkms_modeset_init(void)
{
	drm_mode_config_init(&drm);
	drm.mode_config.max_width = 8192;
	drm.mode_config.max_height = 8192;
	/* add here */
	drm.mode_config.funcs = &vkms_mode_funcs;

	drm_universal_plane_init(&drm, &primary, 0, &vkms_plane_funcs,
			vkms_formats, ARRAY_SIZE(vkms_formats),
			NULL, DRM_PLANE_TYPE_PRIMARY, NULL);

	drm_crtc_init_with_planes(&drm, &crtc, &primary, NULL, &vkms_crtc_funcs, NULL);

	drm_encoder_init(&drm, &encoder, &vkms_encoder_funcs, DRM_MODE_ENCODER_VIRTUAL, NULL);

	drm_connector_init(&drm, &connector, &vkms_connector_funcs, DRM_MODE_CONNECTOR_VIRTUAL);
}

static const struct file_operations vkms_fops = {
	.owner = THIS_MODULE,
	.open = drm_open,
	.release = drm_release,
	.unlocked_ioctl = drm_ioctl,
	.poll = drm_poll,
	.read = drm_read,
	/* add here */
	.mmap = drm_gem_cma_mmap,
};

static struct drm_driver vkms_driver = {
	.driver_features = DRIVER_MODESET | DRIVER_GEM,
	.fops   = &vkms_fops,

	/* add here */
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

	drm_dev_register(&drm, 0);

	return 0;
}

module_init(vkms_init);

/*
添加 FB 和 GEM 支持：
1. 给 driver_features 添加上 DRIVER_GEM 标志位，告诉 DRM Core 该驱动支持 GEM 操作；
2. dumb_create 回调接口用于创建 gem object，并分配物理 buffer。这里直接使用 CMA helper 函数来实现；
3. fb_create 回调接口用于创建 framebuffer object，并绑定 gem objects。这里直接使用 CMA helper 函数实现。
4. fops 中的 mmap 接口，用于将 dumb buffer 映射到 userspace，它依赖 drm driver 中的 gem_vm_ops 实现。这里也直接使用 CMA helper 函数来实现。
现在，我们可以使用如下 IOCTL 来进行一些标准的 GEM 和 FB 操作了！

*/
