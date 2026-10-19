# OrangeFox build variables for jackpotlte (SM-A530F).
#
# build/envsetup.sh sources the vendorsetup.sh of every device in the tree.
# The variables are exported only after `lunch twrp_jackpotlte-*`, so they
# do not leak into the builds of other devices sharing the same source tree.
if [ "$TARGET_PRODUCT" = "twrp_jackpotlte" ]; then
	export FOX_BUILD_DEVICE="jackpotlte"
	export ALLOW_MISSING_DEPENDENCIES=true
	export LC_ALL="C"

	# recovery.img is built by the tree's own mkboot/bootimg.mk
	export FOX_USE_TWRP_RECOVERY_IMAGE_BUILDER=1

	# 1080x2220 panel
	export OF_SCREEN_H=2220

	# RECOVERY is 39845888 bytes and the uncompressed prebuilt kernel alone
	# is 24288872 bytes, so the ramdisk has to stay small.
	export FOX_DRASTIC_SIZE_REDUCTION=1
	export FOX_DELETE_AROMAFM=1
	export FOX_DELETE_MAGISK_ADDON=1

	# Physical (non-dynamic) system and vendor partitions
	export FOX_RECOVERY_SYSTEM_PARTITION="/dev/block/platform/13500000.dwmmc0/by-name/SYSTEM"
	export FOX_RECOVERY_VENDOR_PARTITION="/dev/block/platform/13500000.dwmmc0/by-name/VENDOR"
fi
