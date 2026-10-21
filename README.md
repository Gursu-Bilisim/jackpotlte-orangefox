# jackpotlte-orangefox

OrangeFox R12.0 (fox_12.1) for the Samsung Galaxy A8 2018, SM-A530F (`jackpotlte`), on a device
converted to the **Treble partition layout**. Built on AlexFurina's TWRP 12.1 tree
(`android_device_samsung_jackpotlte`, branch `android-12.1`); the git history of that tree is kept.

Tested build, test results and known gaps: [test-notes.md](test-notes.md). Every release carries
its own `TEST-NOTES.md`.

## What works

ADB, MTP, battery indicator, brightness, microSD, EFS backup, flashlight, reboot to Download mode,
`/data` on an unencrypted ROM, the orange OrangeFox accent color.

- USB storage: a USB stick or card reader on an OTG adapter is listed as USB-OTG on the Mount page
  and as USB Storage in the Files menu, and can hold backups. FAT32, exFAT (`exfat-fuse`) and
  NTFS (`ntfs-3g`) are mounted. The phone has one USB port, so while a stick is attached there is
  no MTP or adb over USB: OrangeFox turns MTP off when the stick is attached, and after the stick
  is removed the computer sees the phone again.

## Read this before flashing

- **Treble layout only.** The recovery expects physical `SYSTEM`, `VENDOR`, `PRODUCT`, `ODM`,
  `PRISM` and `OPTICS` partitions (see `recovery/root/system/etc/twrp.flags`). It was tested on a
  device converted to that layout, with SYSTEM at 6081740800 bytes and VENDOR at 943718400 bytes.
  On the stock partition table these entries do not match. Check yours with
  `adb shell ls -l /dev/block/platform/13500000.dwmmc0/by-name/`: a `VENDOR` entry means Treble.
- **No /data decryption.** The image does not depend on the ROM's security patch or kernel, but
  on a ROM that encrypts `/data` the data partition stays unreadable.
- Keep a copy of your current recovery. From a running TWRP or OrangeFox:
  `adb shell dd if=/dev/block/platform/13500000.dwmmc0/by-name/RECOVERY of=/sdcard/recovery_backup.img`.

## Installing

One of:

- Odin: put the release `.tar` in the AP slot, flash, then hold Power + Volume Up to enter the
  recovery.
- From a running TWRP or OrangeFox: Install, Install Image, select the release `.img`, Recovery.
- From a running OrangeFox: install the release `.zip`.

The recovery partition is 39845888 bytes. `recovery-inspect.ps1` reports the image size against it.

## Building

1. Sync OrangeFox `fox_12.1` (see the OrangeFox wiki) into `<OrangeFox source tree>`.
2. Clone this repository to `<OrangeFox source tree>/device/samsung/jackpotlte`.
3. Apply [patches/bootable_recovery.diff](patches/README.md) to `bootable/recovery`.
4. Build:

```bash
cd <OrangeFox source tree>
export ALLOW_MISSING_DEPENDENCIES=true
source build/envsetup.sh
for v in $(compgen -e | grep -E '^(OF_|FOX_)'); do unset "$v"; done
export TARGET_PRODUCT=twrp_jackpotlte
source device/samsung/jackpotlte/vendorsetup.sh
lunch twrp_jackpotlte-eng
touch bootable/recovery/orangefox.mk
mka adbd recoveryimage
```

The output is `out/target/product/jackpotlte/OrangeFox-*-jackpotlte.img`, `.img.tar` and `.zip`.

The order matters when the source tree holds other OrangeFox devices:

- `envsetup.sh` sources every `device/*/*/vendorsetup.sh`. This tree's `vendorsetup.sh` exports
  its variables only when `TARGET_PRODUCT` is `twrp_jackpotlte`, so it does not leak into other
  devices; other trees may not do the same, hence the `unset` line.
- OrangeFox saves the environment to `/tmp/jackpotlte/fox_env.sh` during `lunch`, and its packaging
  step (`vendor/recovery/OrangeFox_vendor.sh`) reads the variables from there. The variables have
  to be set before `lunch`.
- The `OF_` values are compiled in through `bootable/recovery/orangefox.mk`, which Kati only
  re-reads when a makefile changes, hence the `touch`.

On an incremental build, TWRP's `relink_libraries` step does not copy a rebuilt
`libminuitwrp.so` into the ramdisk, so the image keeps the old library. After a change to
`bootable/recovery/minuitwrp`, build it on its own and copy it before packing:

```bash
mka adbd libminuitwrp
cp out/target/product/jackpotlte/system/lib64/libminuitwrp.so \
   out/target/product/jackpotlte/recovery/root/system/lib64/
mka recoveryimage
```

`recovery-inspect.ps1` reports an old library under "Display".

The tree builds `recovery.img` with its own `mkboot/bootimg.mk` (Samsung `--dt` image and the
`SEANDROIDENFORCE` trailer). The build stops if the image does not fit the recovery partition.

### Size

The prebuilt kernel is not compressed (24288872 bytes) and the DT adds 882688 bytes, so the
ramdisk has about 14.6 MB. `vendorsetup.sh` enables `FOX_DRASTIC_SIZE_REDUCTION`, and
`BoardConfig.mk` and `device.mk` drop the extra language fonts and fastbootd (Samsung
bootloaders have no fastboot mode).

### Colors

The framebuffer is BGRA (`red.offset` 16). `TARGET_RECOVERY_PIXEL_FORMAT := ABGR_8888` makes
TWRP's text and PNG drawing match it; OrangeFox's SVG, `tint` and shape code needs the patch in
[patches/](patches/README.md), otherwise the orange accent is drawn blue.

### Flashlight

OrangeFox reads `<path>/max_brightness` and writes that value to `<path>/brightness`. The rear
flash on this device is a single file, `/sys/class/camera/flash/rear_flash` (1 on, 0 off), so
`init.recovery.samsungexynos7885.rc` creates `/tmp/flashlight` with `max_brightness` set to 1 and
`brightness` linked to `rear_flash`, and `OF_FL_PATH1` points there.

## Tools

### recovery-inspect.ps1

Lists what an OrangeFox image contains, without flashing it. The same script is shared by the
`Gursu-Bilisim` OrangeFox repositories (bramble, tucana, jackpotlte): it reads the device from the
image's `prop.default` and runs that device's checks; images of other devices get the common
checks (image layout, recovery files, display colors and `libminuitwrp.so`, USB). For jackpotlte it
also checks the Samsung image layout (kernel, DT, `SEANDROIDENFORCE`, partition size), the device
files for the Treble layout, battery and flashlight. Accepts the `.img`, the Odin `.tar` or the
OrangeFox `.zip`. Works in Windows PowerShell 5.1 and PowerShell 7.

```
powershell -ExecutionPolicy Bypass -File recovery-inspect.ps1 -Img <img | tar | zip>
```

### patch-check.ps1

Shared with the other `Gursu-Bilisim` OrangeFox trees, where the recovery has to match the ROM's
security patch or kernel. For this image it reports that there is no such dependency:

```
powershell -ExecutionPolicy Bypass -File patch-check.ps1 -RecoveryImg <img>
```

### release.sh

Publishes the latest build as a GitHub release: image, Odin tar, zip, both scripts,
`TEST-NOTES.md` and `SHA256SUMS`. It stops if `test-notes.md` is older than the image, if the
image's SHA-256 is not recorded in `test-notes.md`, or if `bootable/recovery` no longer matches
`patches/bootable_recovery.diff`. `./release.sh r2` adds a suffix for a second release on the
same day; `FOX_TREE=<OrangeFox source tree> ./release.sh` if the build is not three folders
above the device tree.

## Credits and license

Built with the work of AlexFurina, TeamWin, OrangeFox and the sources listed in [NOTICE](NOTICE).

- Files written for this repository: Apache License 2.0 ([LICENSE](LICENSE)).
- Changes to OrangeFox/TWRP: GPL-3.0-or-later, in [patches/](patches/).
- The prebuilt kernel and DT: GPL-2.0, see NOTICE for the source.
