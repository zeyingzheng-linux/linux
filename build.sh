export KERNEL=kernel8
export ARCH=arm64
export CROSS_COMPILE=aarch64-linux-gnu-
make bcm2711_defconfig
bear make Image modules dtbs -j4
