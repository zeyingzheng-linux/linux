#include <drm/drmP.h>

static struct drm_device drm;

static const struct file_operations vkms_fops = {
	.owner = THIS_MODULE,
	.open = drm_open,
	.release = drm_release,
	.unlocked_ioctl = drm_ioctl,
	.poll = drm_poll,
	.read = drm_read,
};

static struct drm_driver vkms_driver = {
	.fops   = &vkms_fops,

	.name   = "vkms",
	.desc   = "Virtual Kernel Mode Setting",
	.date   = "20180514",
	.major   = 1,
	.minor   = 0,
};

static int __init vkms_init(void)
{
	drm_dev_init(&drm, &vkms_driver, NULL);
	drm_dev_register(&drm, 0);

	return 0;
}

module_init(vkms_init);
/*
有了 fops，我们就可以对 card0 进行 open，read，ioctl 操作了。
让我们看看现在可以执行哪些 IOCTL： 

但是到目前为止，凡是和 modesetting 相关的操作，还是操作不了。
 */
