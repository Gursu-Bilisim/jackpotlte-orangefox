# Changes outside the device tree

The releases of this repository are built from OrangeFox Recovery `fox_12.1` with one patch
applied outside `device/samsung/jackpotlte`. The base revision is listed in `BASE_REVISION`.

## bootable_recovery.diff

Applies to OrangeFox `bootable/recovery`, commit `cbcc4f713dbef98d76d6d2cfd019b1ebfd9418e9`.
TWRP and OrangeFox are licensed under the GNU General Public License, version 3 or later, and so
are these changes (see `COPYING`).

The same source tree builds [Gursu-Bilisim/tucana-orangefox](https://github.com/Gursu-Bilisim/tucana-orangefox)
and [Gursu-Bilisim/bramble-orangefox](https://github.com/Gursu-Bilisim/bramble-orangefox), so the
patch also holds the changes made for those devices. The image in each release is built with this
patch applied.

- `minuitwrp/resources.cpp`, `minuitwrp/include/minuitwrp/minui.h`, `gui/nanosvg.cpp`,
  `gui/resources.cpp` (made for jackpotlte): new function `res_swap_red_blue()`, which returns 1
  when the build uses `TARGET_RECOVERY_PIXEL_FORMAT := ABGR_8888`. With that setting `gr_color()`
  and the PNG loader (`png_set_bgr`) put blue in the first byte of each pixel, but the SVG
  rasterizer, the `tint` attribute and `createShape()` put red there. On jackpotlte (fbdev,
  `red.offset` 16) the orange accent, the logo and the shapes were drawn blue while text and PNG
  icons had the right colors. These three places now swap red and blue when the function
  returns 1. Builds with another pixel format are unchanged.

Changes made for tucana and bramble:

- `partitionmanager.cpp`: when the ROM's fstab is copied to `/etc/additional.fstab`,
  `/dev/block/bootdevice/by-name/` paths are rewritten to `/dev/block/by-name/`. jackpotlte
  uses `/dev/block/platform/13500000.dwmmc0/by-name/` paths, which this does not touch.
- `partitionmanager.cpp`: when `/data` uses file-based encryption, the Qualcomm `persist` and
  `modem` partitions are mounted read-only before decryption. This build has no decryption and
  jackpotlte has no such partitions, so the code does not run.
- `gui/patternpassword.cpp`, `gui/objects.hpp`: `GUIPatternPassword::IsInRegion`. The pattern
  page also claims touches that hit a dot outside the pattern's placement box, so a gesture that
  starts on a corner dot is no longer ignored.
- Theme (`gui/theme/portrait_hdpi/themes/navbar.xml`): gesture navigation is off by default and
  the screen height no longer adds 96 px for a hidden navigation bar.

## Applying

```bash
cd <OrangeFox source tree>/bootable/recovery
git checkout cbcc4f713dbef98d76d6d2cfd019b1ebfd9418e9
git apply <this repository>/patches/bootable_recovery.diff
```

`navbar.xml` uses CRLF line endings upstream; the diff keeps them, so apply it without
converting line endings.
