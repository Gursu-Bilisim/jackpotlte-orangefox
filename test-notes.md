## Pre-release test notes

Tested by the maintainer before publishing. Update this file for every release.

| Item | Value |
|---|---|
| Device | Samsung Galaxy A8 2018, SM-A530F (jackpotlte), bootloader A530FXXULCUK6 |
| Partition layout | Converted to the Treble layout: physical VENDOR, ODM, PRODUCT, PRISM and OPTICS partitions, SYSTEM enlarged to 6081740800 bytes. Not tested on the stock partition table. |
| ROM | One UI port from the Galaxy S23 FE (SM-S711B), Android 16, `S711BXXSFFZD2` (XROM-V16.1), vendor from SM-A530N Android 9 (`A530NKSU9CUL1`) |
| /data | ext4, not encrypted |
| Recovery kernel | 4.4.302 (prebuilt in this tree) |
| Tested image | SHA-256 `fa794b9a36d646d263c2e579008aabb0662fcfe5d0ea1dafa269492e44cbd07e` |

| Test | Result | Notes |
|---|---|---|
| Boot, display, touch | OK | 1080x2220 |
| Accent color | OK | orange logo, check boxes, radio buttons, Menu button and unlock slider; text and PNG icons unchanged |
| /data and internal storage | OK | "Storage is not encrypted" |
| ADB | OK | |
| MTP | OK | |
| Battery indicator | OK | health HAL 2.1 |
| Brightness | OK | |
| USB storage in the Files menu | OK | `/usb_otg`, listed as USB Storage |
| USB storage: FAT32, exFAT, NTFS | OK | all three mounted |
| Backup and restore of BOOT on an NTFS stick | OK, see note | first boot after the restore stopped at the Android logo, a reboot started normally |
| MTP with a stick attached | OK | OrangeFox turns MTP off; after removing the stick the computer sees the phone again |
| microSD | OK | |
| EFS backup | OK | 6 MB |
| Flashlight | OK | menu button and Power + Volume Up |
| Reboot to Download mode | OK | |
| `recovery-inspect.ps1` | OK | all checks |
| `patch-check.ps1` | OK | reports no dependency on the ROM build |

Installed for the test with `dd` from a running TWRP or OrangeFox.

This build moves USB storage from `/usb-otg` to `/usb_otg` (Files menu) with automatic file system
detection, and takes the shared `bootable/recovery` patch of bramble and tucana (no effect on
jackpotlte). On it USB storage, backup and restore, MTP, the accent color, the bottom menu, the
lock-screen slider and ADB were checked; the other rows come from the previous builds
(`48d14b18…dd76d`, `fa07ca41…46c3f`); the device files they depend on did not change.

Restore note: after BOOT was restored from the NTFS stick, the first boot stopped at the Android
logo and a second reboot started normally. The cause was not isolated. The ported ROM on this
device already shows other faults, so it may come from the ROM.

Not tested: flashing the `.img.tar` with Odin, installing the OrangeFox `.zip`, restoring other
partitions than BOOT, installing a ROM, an encrypted ROM, the stock partition table, SM-A530N and SM-A530W.
