#!/usr/bin/env bash
set -euo pipefail
# TREE: <device tree folder>, the folder this script is in (device/samsung/jackpotlte).
# FOX_TREE: <OrangeFox source tree>, three levels above it. Set FOX_TREE to override.
# Before running: update test-notes.md for this build (including the tested image's
# SHA-256), commit and push.
TREE=$(cd "$(dirname "$0")" && pwd)
FOX_TREE=${FOX_TREE:-$(cd "$TREE/../../.." && pwd)}
OUT=$FOX_TREE/out/target/product/jackpotlte
IMG=$(ls -t "$OUT"/OrangeFox-*-jackpotlte.img 2>/dev/null | head -1 || true)
ZIP=${IMG%.img}.zip
TAR=$IMG.tar
[ -n "$IMG" ] && [ -f "$ZIP" ] && [ -f "$TAR" ] || { echo "No OrangeFox build (.img, .zip, .img.tar) found in $OUT. Set FOX_TREE=<OrangeFox source tree>." >&2; exit 1; }
[ -f "$TREE/test-notes.md" ] || { echo "test-notes.md is missing." >&2; exit 1; }
if [ "$TREE/test-notes.md" -ot "$IMG" ]; then
  echo "test-notes.md is older than $(basename "$IMG"). Update it for this build first." >&2; exit 1
fi
SUM=$(sha256sum "$IMG" | cut -d' ' -f1)
grep -q "$SUM" "$TREE/test-notes.md" || {
  echo "The SHA-256 of $(basename "$IMG") ($SUM) is not in test-notes.md. Test this build and record its hash first." >&2; exit 1; }

# The recovery is built from OrangeFox bootable/recovery with patches/bootable_recovery.diff.
BASE=$(awk '/^bootable_recovery.diff/{f=1} f&&/^commit:/{print $2; exit}' "$TREE/patches/BASE_REVISION")
if ! git -C "$FOX_TREE/bootable/recovery" diff "$BASE" | cmp -s - "$TREE/patches/bootable_recovery.diff"; then
  echo "bootable/recovery differs from patches/bootable_recovery.diff. Regenerate the patch, commit it and push." >&2; exit 1
fi

REPO=Gursu-Bilisim/jackpotlte-orangefox

# The release tag must point at the device tree the image was built from. gh creates a missing
# tag from the default branch, so pass the commit explicitly and require it to be on GitHub.
REMOTE=${REMOTE:-$(git -C "$TREE" remote -v | awk '/Gursu-Bilisim\/jackpotlte-orangefox/ && /\(push\)/ {print $1; exit}')}
[ -n "$REMOTE" ] || { echo "No git remote points at $REPO. Set REMOTE=<remote name>." >&2; exit 1; }
HEAD=$(git -C "$TREE" rev-parse HEAD)
if [ -n "$(git -C "$TREE" status --porcelain --untracked-files=no)" ]; then
  echo "The device tree has uncommitted changes. Commit and push them first." >&2; exit 1
fi
git -C "$TREE" fetch -q "$REMOTE" || { echo "git fetch $REMOTE failed." >&2; exit 1; }
if [ -z "$(git -C "$TREE" branch -r --contains "$HEAD" | grep -F "$REMOTE/")" ]; then
  echo "Commit $HEAD is not on $REPO. Push it first." >&2; exit 1
fi

TAG="v$(date +%Y.%m.%d)${1:+-$1}"
NAME="OrangeFox-jackpotlte-$TAG-treble"
W=$(mktemp -d)
cp "$IMG" "$W/$NAME.img"
cp "$ZIP" "$W/$NAME.zip"
# Odin tar from the OrangeFox build: it must hold recovery.img, identical to the image
tar -xOf "$TAR" recovery.img | cmp -s - "$IMG" || {
  echo "$(basename "$TAR") does not contain this recovery.img." >&2; exit 1; }
cp "$TAR" "$W/$NAME.tar"
cp "$TREE/patch-check.ps1" "$TREE/recovery-inspect.ps1" "$W/"
cp "$TREE/test-notes.md" "$W/TEST-NOTES.md"
(cd "$W" && sha256sum *.img *.tar *.zip *.ps1 TEST-NOTES.md > SHA256SUMS)
{
cat <<NOTES
OrangeFox R12.0 for the Samsung Galaxy A8 2018 (SM-A530F, jackpotlte). Installed to the RECOVERY partition.

**For the Treble partition layout only.** The device was tested after conversion to the Treble
layout (physical VENDOR, ODM, PRODUCT, PRISM and OPTICS partitions). On the stock partition table
the SYSTEM and VENDOR entries do not match.

- /data decryption is not included. The image does not depend on the ROM's security patch or
  kernel; on a ROM that encrypts /data the data partition stays unreadable.
- \`.tar\`: Odin, AP slot
- \`.img\`: "Install Image" to Recovery from a running TWRP or OrangeFox
- \`.zip\`: install from a running OrangeFox
- \`recovery-inspect.ps1 -Img <img, tar or zip>\`, \`patch-check.ps1 -RecoveryImg <img>\`

Source: device tree in this repository at tag $TAG; changes to OrangeFox in \`patches/\`.
Credits: see NOTICE.

NOTES
cat "$TREE/test-notes.md"
} > "$W/notes.md"
gh release create "$TAG" "$W"/*.img "$W"/*.tar "$W"/*.zip "$W"/*.ps1 "$W/TEST-NOTES.md" "$W/SHA256SUMS" \
  --repo "$REPO" --target "$HEAD" --title "$TAG" --notes-file "$W/notes.md"
echo "Published: $TAG"
