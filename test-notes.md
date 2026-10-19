## Pre-release test notes

Tested by the maintainer before publishing. Update this file for every release.

| Item | Value |
|---|---|
| Device | Samsung Galaxy A8 2018, SM-A530F (jackpotlte), bootloader A530FXXULCUK6 |
| Partition layout | Converted to the Treble layout: physical VENDOR, ODM, PRODUCT, PRISM and OPTICS partitions, SYSTEM enlarged to 6081740800 bytes. Not tested on the stock partition table. |
| ROM | One UI port from the Galaxy S23 FE (SM-S711B), Android 16, `S711BXXSFFZD2` (XROM-V16.1), vendor from SM-A530N Android 9 (`A530NKSU9CUL1`) |
| /data | ext4, not encrypted |
| Recovery kernel | 4.4.302 (prebuilt in this tree) |
| Tested image | SHA-256 `fa07ca41c92f4939b93f50edb23f2328ef07e29e02cdb991a75fc5734dc46c3f` |

| Test | Result | Notes |
|---|---|---|
| Boot, display, touch | OK | 1080x2220 |
| /data and internal storage | OK | "Storage is not encrypted" |
| ADB | OK | |
| MTP | OK | |
| Battery indicator | OK | health HAL 2.1 |
| Brightness | OK | |
| USB-OTG | OK | backup written to `/usb-otg/Fox/BACKUPS` |
| microSD | OK | |
| EFS backup | OK | 6 MB |
| Flashlight | OK | menu button and Power + Volume Up |
| Reboot to Download mode | OK | |
| `recovery-inspect.ps1` | OK | all checks |
| `patch-check.ps1` | OK | reports no dependency on the ROM build |

Installed for the test with `dd` from the previous TWRP (AlexFurina, 3.7.1_12).

Not tested: flashing the `.img.tar` with Odin, installing the OrangeFox `.zip`, restoring a backup,
installing a ROM, an encrypted ROM, the stock partition table, SM-A530N and SM-A530W.
