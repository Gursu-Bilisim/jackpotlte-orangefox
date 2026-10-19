## Pre-release test notes

Tested by the maintainer before publishing. Update this file for every release.

| Item | Value |
|---|---|
| Device | Samsung Galaxy A8 2018, SM-A530F (jackpotlte), bootloader A530FXXULCUK6 |
| Partition layout | Converted to the Treble layout: physical VENDOR, ODM, PRODUCT, PRISM and OPTICS partitions, SYSTEM enlarged to 6081740800 bytes. Not tested on the stock partition table. |
| ROM | One UI port from the Galaxy S23 FE (SM-S711B), Android 16, `S711BXXSFFZD2` (XROM-V16.1), vendor from SM-A530N Android 9 (`A530NKSU9CUL1`) |
| /data | ext4, not encrypted |
| Recovery kernel | 4.4.302 (prebuilt in this tree) |
| Tested image | SHA-256 `48d14b18ea95451a0663b7f658338d38b858fdc6684c1b3d87f9b785882dd76d` |

| Test | Result | Notes |
|---|---|---|
| Boot, display, touch | OK | 1080x2220 |
| Accent color | OK | orange logo, check boxes, radio buttons, Menu button and unlock slider; text and PNG icons unchanged |
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

Installed for the test with `dd` from a running TWRP or OrangeFox.

The full table was first run on the previous build (SHA-256 `fa07ca41…46c3f`), where the accent
was drawn blue. This build adds the color patch described in `patches/README.md`; on it the
accent color, touch, flashlight, ADB and MTP were checked again.

Not tested: flashing the `.img.tar` with Odin, installing the OrangeFox `.zip`, restoring a backup,
installing a ROM, an encrypted ROM, the stock partition table, SM-A530N and SM-A530W.
