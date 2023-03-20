# SPDX-License-Identifier: GPL-2.0
# Please keep these build lists sorted!

# If we are running by kernel building system
ifneq ($(KERNELRELEASE),)
# If we running without kernel build system
# core driver code

obj-m += dma-fence-example.o

else

BUILDSYSTEM_DIR:=/home/rlk/code/raspberrypi/linux
PWD:=$(shell pwd)

all:
# run kernel build system to make module
	$(MAKE) -C $(BUILDSYSTEM_DIR) M=$(PWD) modules
	gcc -Wall -o dma-fence-test dma-fence-test.c -lpthread

clean:
# run kernel build system to cleanup in current directory
	$(MAKE) -C $(BUILDSYSTEM_DIR) M=$(PWD) clean
	rm -rf dma-fence-test
endif
