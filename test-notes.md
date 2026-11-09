## Pre-release test notes

Tested by the maintainer before publishing. Update this file for every release.

| Item | Value |
|---|---|
| Device | Samsung Galaxy A8 2018, SM-A530F (jackpotlte), bootloader A530FXXULCUK6 |
| Partition layout | Converted to the Treble layout: physical VENDOR, ODM, PRODUCT, PRISM and OPTICS partitions, SYSTEM enlarged to 6081740800 bytes. Not tested on the stock partition table. |
| ROM | One UI port from the Galaxy S23 FE (SM-S711B), Android 16, `S711BXXSFFZD2` (XROM-V16.1), vendor from SM-A530N Android 9 (`A530NKSU9CUL1`) |
| /data | ext4, not encrypted |
| Recovery kernel | 4.4.302 (prebuilt in this tree) |
| Tested image | SHA-256 `0374cdffae4ba52e2e8fb688d8f29162cb6e00d1d36b63602b99830aee1bafb9` |

| Test | Result | Notes |
|---|---|---|
| Boot, display, touch | OK | 1080x2220 |
| Accent color | OK | orange logo, check boxes, radio buttons, Menu button and unlock slider; text and PNG icons unchanged |
| Screens | OK | home, Files, Menu, Settings, Terminal and the install/backup console drawn without missing or broken pixels |
| /data and internal storage | OK | "Storage is not encrypted" |
| ADB | OK | |
| MTP | OK | |
| Battery indicator | OK | health HAL 2.1 |
| Brightness | OK | |
| USB storage in the Files menu | OK | `/usb_otg`, listed as USB Storage |
| USB storage: FAT32, exFAT, NTFS | OK | all three mounted |
| Backup of BOOT to an exFAT USB stick | OK | |
| Restore of BOOT from an NTFS stick | OK, see note | previous build; first boot after the restore stopped at the Android logo, a reboot started normally |
| MTP with a stick attached | OK | OrangeFox turns MTP off; after removing the stick the computer sees the phone again |
| microSD | OK | |
| EFS backup | OK | 6 MB |
| Flashlight | OK | menu button and Power + Volume Up |
| Reboot to Download mode | OK | |
| `recovery-inspect.ps1` | OK | 2026.11.09, all checks |
| `patch-check.ps1` | OK | reports no dependency on the ROM build |

Installed for the test with `dd` from a running TWRP or OrangeFox.

This build takes the shared `bootable/recovery` patch `9e54a740` of tucana, bramble and gts7xlwifi.
The change that runs on jackpotlte is in `libminuitwrp.so`: `gr_blit()` clamps the drawn area to the
size of the source image. On it the boot, the accent color, the screens listed above, USB storage in
the Files menu, a BOOT backup to an exFAT stick, ADB, MTP and both scripts were checked; the other
rows come from the previous builds (`fa794b9a…cbd07e`, `48d14b18…dd76d`, `fa07ca41…46c3f`); the
device files they depend on did not change.

Restore note (previous build `fa794b9a…cbd07e`): after BOOT was restored from the NTFS stick, the
first boot stopped at the Android logo and a second reboot started normally. The cause was not
isolated. The ported ROM on this device already shows other faults, so it may come from the ROM.

Not tested: flashing the `.img.tar` with Odin, installing the OrangeFox `.zip`, restoring other
partitions than BOOT, installing a ROM, an encrypted ROM, the stock partition table, SM-A530N and SM-A530W.
