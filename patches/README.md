# Changes outside the device tree

The releases of this repository are built from OrangeFox Recovery `fox_12.1` with one patch
applied outside `device/samsung/jackpotlte`. The base revision is listed in `BASE_REVISION`.

## bootable_recovery.diff

Applies to OrangeFox `bootable/recovery`, commit `cbcc4f713dbef98d76d6d2cfd019b1ebfd9418e9`.
TWRP and OrangeFox are licensed under the GNU General Public License, version 3 or later, and so
are these changes (see `COPYING`).

The same source tree builds [Gursu-Bilisim/tucana-orangefox](https://github.com/Gursu-Bilisim/tucana-orangefox)
and [Gursu-Bilisim/bramble-orangefox](https://github.com/Gursu-Bilisim/bramble-orangefox), so the
patch is the same file in all three repositories. The image in each release is built with this
patch applied.

Made for jackpotlte:

- `minuitwrp/resources.cpp`, `minuitwrp/include/minuitwrp/minui.h`, `gui/nanosvg.cpp`,
  `gui/resources.cpp`: new function `res_swap_red_blue()`, which returns 1 when the build uses
  `TARGET_RECOVERY_PIXEL_FORMAT := ABGR_8888`. With that setting `gr_color()` and the PNG loader
  (`png_set_bgr`) put blue in the first byte of each pixel, but the SVG rasterizer, the `tint`
  attribute and `createShape()` put red there. On jackpotlte (fbdev, `red.offset` 16) the orange
  accent, the logo and the shapes were drawn blue while text and PNG icons had the right colors.
  These three places now swap red and blue when the function returns 1. Builds with another
  pixel format are unchanged.

Made for tucana and bramble (no effect on jackpotlte unless stated):

- `partitionmanager.cpp`: when the ROM's fstab is copied to `/etc/additional.fstab`,
  `/dev/block/bootdevice/by-name/` paths are rewritten to `/dev/block/by-name/`. jackpotlte
  uses `/dev/block/platform/13500000.dwmmc0/by-name/` paths, which this does not touch.
- `partitionmanager.cpp`: when `/data` uses file-based encryption, the Qualcomm `persist` and
  `modem` partitions are mounted read-only before decryption (the modem name gets the slot
  suffix on A/B devices). This build has no decryption and jackpotlte has no such partitions,
  so the code does not run.
- `gui/patternpassword.cpp`, `gui/objects.hpp`: `GUIPatternPassword::IsInRegion`. The pattern
  page also claims touches that hit a dot outside the pattern's placement box, so a gesture that
  starts on a corner dot is no longer ignored.
- `orangefox.mk`, `data.cpp`, `gui/pages.cpp`: new build variable `OF_SCREEN_BOTTOM_INSET`
  (pixels, default 0). The theme variables `screen_original_h` and `screen_h` become
  `OF_SCREEN_H` minus the inset, so the lock-screen swipe, the navigation buttons and the bottom
  menu move up by that amount, while the theme is still scaled to the full `OF_SCREEN_H` (new
  constant `screen_full_h`). jackpotlte does not set it, so nothing changes here.
- Theme (`pages/templates/templates.xml`, `resources/vars.xml`): the "show password" eye icon on
  the decrypt page only reacted to touches on its 64x46 px image. An invisible 144x144 px button
  centred on the icon now does the same. jackpotlte does not show the decrypt page.
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
