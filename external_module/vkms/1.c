#include <drm/drmP.h>

static struct drm_device drm;

static struct drm_driver vkms_driver = {
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
 	这是一个最简单的 DRM 驱动代码

	DRM 框架还为我们做了下面这些事情：
	创建设备节点：/dev/dri/card0
	创建 sysfs 节点：/sys/class/drm/card0
	创建 debugfs 节点：/sys/kernel/debug/dri/0
	不过该驱动目前什么事情也做不了，你唯一能做的就是查看该驱动的名字：
	$ cat /sys/kernel/debug/dri/0/name
	vkms unique=vkms
	你甚至都无法对 /dev/dri/card0 进行 open 操作，因为该驱动还没有实现 fops 接口。
*/
