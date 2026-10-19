# recovery-inspect.ps1
# Lists what a jackpotlte (Samsung Galaxy A8 2018, SM-A530F) OrangeFox recovery image
# contains, without flashing it. Works in Windows PowerShell 5.1+ and PowerShell 7
# (Windows, Linux).
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File recovery-inspect.ps1 -Img <recovery.img | .tar | OrangeFox zip>
#
# Each check prints OK or MISSING; INFO lines describe the build. This image is made for
# the Treble partition layout (physical SYSTEM, VENDOR, PRODUCT, ODM, PRISM, OPTICS) and
# does not decrypt /data.

param(
  [Parameter(Mandatory = $true)][string]$Img
)

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$RecoveryPartitionSize = 39845888   # RECOVERY on SM-A530F
if (-not ([System.Management.Automation.PSTypeName]'FoxUnpack3').Type) {
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.IO.Compression;
public static class FoxUnpack3 {
  static void Grow(ref byte[] b, int need) {
    if (need <= b.Length) return;
    int n = b.Length * 2; while (n < need) n *= 2;
    Array.Resize(ref b, n);
  }
  static int Block(byte[] src, int ip, int end, ref byte[] dst, int op) {
    while (ip < end) {
      int token = src[ip++];
      int lit = token >> 4;
      if (lit == 15) { int b; do { b = src[ip++]; lit += b; } while (b == 255); }
      Grow(ref dst, op + lit);
      Buffer.BlockCopy(src, ip, dst, op, lit); ip += lit; op += lit;
      if (ip >= end) break;
      int off = src[ip] | (src[ip + 1] << 8); ip += 2;
      int ml = token & 15;
      if (ml == 15) { int b; do { b = src[ip++]; ml += b; } while (b == 255); }
      ml += 4;
      Grow(ref dst, op + ml);
      int m = op - off;
      if (off >= ml) { Buffer.BlockCopy(dst, m, dst, op, ml); op += ml; }
      else { for (int i = 0; i < ml; i++) dst[op++] = dst[m + i]; }
    }
    return op;
  }
  // LZ4 legacy, LZ4 frame, LZMA (.lzma), gzip or uncompressed data.
  public static byte[] Decompress(byte[] src, int start, int len) {
    int end = start + len;
    if (len >= 4 && src[start] == 0x02 && src[start + 1] == 0x21 && src[start + 2] == 0x4C && src[start + 3] == 0x18) {
      byte[] dst = new byte[Math.Max(len * 3, 1 << 20)]; int op = 0; int ip = start + 4;
      while (ip + 4 <= end) {
        uint n = BitConverter.ToUInt32(src, ip);
        if (n == 0x184C2102) { ip += 4; continue; }
        if (n == 0 || ip + 4 + n > end) break;
        op = Block(src, ip + 4, ip + 4 + (int)n, ref dst, op);
        ip += 4 + (int)n;
      }
      Array.Resize(ref dst, op); return dst;
    }
    if (len >= 4 && src[start] == 0x04 && src[start + 1] == 0x22 && src[start + 2] == 0x4D && src[start + 3] == 0x18) {
      int ip = start + 4; int flg = src[ip]; ip += 2;
      if ((flg & 0x08) != 0) ip += 8;
      if ((flg & 0x01) != 0) ip += 4;
      ip += 1;
      bool bsum = (flg & 0x10) != 0;
      byte[] dst = new byte[Math.Max(len * 3, 1 << 20)]; int op = 0;
      while (ip + 4 <= end) {
        uint n = BitConverter.ToUInt32(src, ip); ip += 4;
        if (n == 0) break;
        int sz = (int)(n & 0x7FFFFFFF);
        if ((n & 0x80000000u) != 0) { Grow(ref dst, op + sz); Buffer.BlockCopy(src, ip, dst, op, sz); op += sz; }
        else op = Block(src, ip, ip + sz, ref dst, op);
        ip += sz; if (bsum) ip += 4;
      }
      Array.Resize(ref dst, op); return dst;
    }
    if (FoxLzma.IsLzma(src, start, len)) return FoxLzma.Decode(src, start, len);
    if (len >= 2 && src[start] == 0x1F && src[start + 1] == 0x8B) {
      using (var ms = new MemoryStream(src, start, len))
      using (var gz = new GZipStream(ms, CompressionMode.Decompress))
      using (var o = new MemoryStream()) { gz.CopyTo(o); return o.ToArray(); }
    }
    byte[] r = new byte[len]; Buffer.BlockCopy(src, start, r, 0, len); return r;
  }
  // Returns the release from the kernel banner ("Linux version <release> (").
  public static string KernelRelease(byte[] k) {
    byte[] pat = System.Text.Encoding.ASCII.GetBytes("Linux version ");
    for (int i = 0; i + pat.Length + 2 < k.Length; i++) {
      int j = 0; while (j < pat.Length && k[i + j] == pat[j]) j++;
      if (j < pat.Length) continue;
      int s = i + pat.Length;
      if (k[s] < (byte)'0' || k[s] > (byte)'9') continue;
      int e = s; while (e < k.Length && k[e] != (byte)' ' && k[e] != 0) e++;
      if (e + 1 < k.Length && k[e] == (byte)' ' && k[e + 1] == (byte)'(')
        return System.Text.Encoding.ASCII.GetString(k, s, e - s);
    }
    return null;
  }
  public static bool Contains(byte[] data, int start, int len, byte[] pat) {
    int last = start + len - pat.Length;
    for (int i = start; i <= last; i++) {
      int j = 0; while (j < pat.Length && data[i + j] == pat[j]) j++;
      if (j == pat.Length) return true;
    }
    return false;
  }
}
// LZMA ("alone" / .lzma) decoder, ported from the public domain LzmaSpec.cpp
// reference decoder by Igor Pavlov. C# 5 compatible (Windows PowerShell 5.1 Add-Type).
public static class FoxLzma {
  sealed class Dec {
    byte[] src; int ip, end;
    uint range, code;
    byte[] outb; int op;
    public Dec(byte[] s, int start, int len) { src = s; ip = start; end = start + len; }
    byte Next() { if (ip >= end) throw new Exception("LZMA: unexpected end of input"); return src[ip++]; }
    void InitRange() {
      if (Next() != 0) throw new Exception("LZMA: bad range coder start");
      code = 0; range = 0xFFFFFFFF;
      for (int i = 0; i < 4; i++) code = (code << 8) | Next();
      if (code == range) throw new Exception("LZMA: bad range coder start");
    }
    void Normalize() { if (range < (1u << 24)) { range <<= 8; code = (code << 8) | Next(); } }
    int Bit(ushort[] p, int i) {
      uint v = p[i];
      uint bound = (range >> 11) * v;
      int symbol;
      if (code < bound) { v += ((1u << 11) - v) >> 5; range = bound; symbol = 0; }
      else { v -= v >> 5; code -= bound; range -= bound; symbol = 1; }
      p[i] = (ushort)v;
      Normalize();
      return symbol;
    }
    uint Direct(int numBits) {
      uint res = 0;
      do {
        range >>= 1; code -= range;
        uint t = 0 - (code >> 31);
        code += range & t;
        if (code == range) throw new Exception("LZMA: corrupted data");
        Normalize();
        res <<= 1; res += t + 1;
      } while (--numBits > 0);
      return res;
    }
    int Tree(ushort[] p, int b, int numBits) {
      int m = 1;
      for (int i = 0; i < numBits; i++) m = (m << 1) + Bit(p, b + m);
      return m - (1 << numBits);
    }
    int TreeRev(ushort[] p, int b, int numBits) {
      int m = 1, sym = 0;
      for (int i = 0; i < numBits; i++) { int bit = Bit(p, b + m); m <<= 1; m += bit; sym |= bit << i; }
      return sym;
    }
    static ushort[] Probs(int n) { ushort[] p = new ushort[n]; for (int i = 0; i < n; i++) p[i] = 1024; return p; }

    // length decoder: [0] choice, [1] choice2, [2..] low (16 x 8), mid (16 x 8), high (256)
    int Len(ushort[] p, int posState) {
      if (Bit(p, 0) == 0) return Tree(p, 2 + posState * 8, 3);
      if (Bit(p, 1) == 0) return 8 + Tree(p, 2 + 128 + posState * 8, 3);
      return 16 + Tree(p, 2 + 256, 8);
    }
    void Put(byte b) {
      if (op == outb.Length) Array.Resize(ref outb, outb.Length * 2);
      outb[op++] = b;
    }

    public byte[] Run() {
      int d = Next();
      if (d >= 9 * 5 * 5) throw new Exception("LZMA: bad properties");
      int lc = d % 9; d /= 9; int lp = d % 5; int pb = d / 5;
      uint dictSize = 0;
      for (int i = 0; i < 4; i++) dictSize |= (uint)Next() << (8 * i);
      if (dictSize < 4096) dictSize = 4096;
      ulong unpackSize = 0; bool sizeKnown = false;
      for (int i = 0; i < 8; i++) { byte b = Next(); if (b != 0xFF) sizeKnown = true; unpackSize |= (ulong)b << (8 * i); }
      outb = new byte[sizeKnown ? (int)unpackSize : Math.Max((end - ip) * 3, 1 << 20)];
      InitRange();

      ushort[] lit = Probs(0x300 << (lc + lp));
      ushort[] isMatch = Probs(12 << 4), isRep = Probs(12), isRepG0 = Probs(12), isRepG1 = Probs(12), isRepG2 = Probs(12), isRep0Long = Probs(12 << 4);
      ushort[] posSlot = Probs(4 << 6), posDec = Probs(1 + 128 - 14), align = Probs(1 << 4);
      ushort[] lenDec = Probs(2 + 256 + 256), repLenDec = Probs(2 + 256 + 256);
      uint rep0 = 0, rep1 = 0, rep2 = 0, rep3 = 0;
      int state = 0;
      int pbMask = (1 << pb) - 1, lpMask = (1 << lp) - 1;

      for (;;) {
        if (sizeKnown && (ulong)op == unpackSize && code == 0) break;
        int posState = op & pbMask;
        if (Bit(isMatch, (state << 4) + posState) == 0) {
          if (sizeKnown && (ulong)op == unpackSize) throw new Exception("LZMA: data after end");
          int prev = op > 0 ? outb[op - 1] : 0;
          int b0 = 0x300 * (((op & lpMask) << lc) + (prev >> (8 - lc)));
          int sym = 1;
          if (state >= 7) {
            int matchByte = outb[op - (int)rep0 - 1];
            do {
              int matchBit = (matchByte >> 7) & 1; matchByte <<= 1;
              int bit = Bit(lit, b0 + ((1 + matchBit) << 8) + sym);
              sym = (sym << 1) | bit;
              if (matchBit != bit) break;
            } while (sym < 0x100);
          }
          while (sym < 0x100) sym = (sym << 1) | Bit(lit, b0 + sym);
          Put((byte)(sym - 0x100));
          state = state < 4 ? 0 : (state < 10 ? state - 3 : state - 6);
          continue;
        }
        int len;
        if (Bit(isRep, state) != 0) {
          if (op == 0) throw new Exception("LZMA: rep at start");
          if (Bit(isRepG0, state) == 0) {
            if (Bit(isRep0Long, (state << 4) + posState) == 0) {
              state = state < 7 ? 9 : 11;
              Put(outb[op - (int)rep0 - 1]);
              continue;
            }
          } else {
            uint dist;
            if (Bit(isRepG1, state) == 0) dist = rep1;
            else {
              if (Bit(isRepG2, state) == 0) dist = rep2;
              else { dist = rep3; rep3 = rep2; }
              rep2 = rep1;
            }
            rep1 = rep0; rep0 = dist;
          }
          len = Len(repLenDec, posState);
          state = state < 7 ? 8 : 11;
        } else {
          rep3 = rep2; rep2 = rep1; rep1 = rep0;
          len = Len(lenDec, posState);
          state = state < 7 ? 7 : 10;
          int lenState = len > 3 ? 3 : len;
          int slot = Tree(posSlot, lenState << 6, 6);
          if (slot < 4) rep0 = (uint)slot;
          else {
            int nd = (slot >> 1) - 1;
            uint dist = (uint)((2 | (slot & 1)) << nd);
            if (slot < 14) dist += (uint)TreeRev(posDec, (int)dist - slot, nd);
            else { dist += Direct(nd - 4) << 4; dist += (uint)TreeRev(align, 0, 4); }
            rep0 = dist;
          }
          if (rep0 == 0xFFFFFFFF) {
            if (code != 0) throw new Exception("LZMA: bad end marker");
            break;
          }
          if (sizeKnown && (ulong)op == unpackSize) throw new Exception("LZMA: data after end");
          if (rep0 >= dictSize || rep0 >= (uint)op) throw new Exception("LZMA: bad distance");
        }
        len += 2;
        int from = op - (int)rep0 - 1;
        for (int i = 0; i < len; i++) {
          if (sizeKnown && (ulong)op == unpackSize) throw new Exception("LZMA: match past end");
          Put(outb[from + i]);
        }
      }
      Array.Resize(ref outb, op);
      return outb;
    }
  }

  // .lzma "alone" header: properties byte (lc/lp/pb) followed by the dictionary size.
  public static bool IsLzma(byte[] s, int start, int len) {
    return len >= 13 && s[start] == 0x5D && s[start + 1] == 0x00 && s[start + 2] == 0x00;
  }
  public static byte[] Decode(byte[] s, int start, int len) { return new Dec(s, start, len).Run(); }
}
'@
}

function Get-ImageBytes([string]$path) {
  $full = (Resolve-Path $path).Path
  $ext = [IO.Path]::GetExtension($full).ToLowerInvariant()
  if ($ext -eq '.zip') {
    $zf = [IO.Compression.ZipFile]::OpenRead($full)
    try {
      $e = $zf.GetEntry('recovery.img')
      if (-not $e) { $e = $zf.Entries | Where-Object { $_.FullName -like '*.img' } | Select-Object -First 1 }
      if (-not $e) { throw 'No .img found in the zip' }
      $ms = New-Object IO.MemoryStream
      $s = $e.Open(); $s.CopyTo($ms); $s.Close()
      return ,$ms.ToArray()
    } finally { $zf.Dispose() }
  }
  $d = [IO.File]::ReadAllBytes($full)
  if ($ext -eq '.tar' -or $ext -eq '.md5') {
    # Odin tar (ustar): 512-byte headers, file data padded to 512 bytes
    $p = 0
    while ($p + 512 -le $d.Length) {
      $name = [Text.Encoding]::ASCII.GetString($d, $p, 100).TrimEnd([char]0)
      if (-not $name) { break }
      $size = [Convert]::ToInt64([Text.Encoding]::ASCII.GetString($d, $p + 124, 12).Trim([char]0, ' '), 8)
      if ($name -like '*.img') {
        $r = New-Object byte[] $size
        [Array]::Copy($d, $p + 512, $r, 0, $size)
        return ,$r
      }
      $p += 512 + [int]([math]::Ceiling($size / 512) * 512)
    }
    throw 'No .img found in the tar'
  }
  return ,$d
}

function Read-BootHeader([byte[]]$d) {
  $magic = [Text.Encoding]::ASCII.GetString($d, 0, 8)
  $other = 'This recovery-inspect.ps1 is the jackpotlte version. For other devices use the recovery-inspect.ps1 from that device''s release.'
  if ($magic -eq 'VNDRBOOT') { throw "This is a vendor_boot image; jackpotlte has its recovery in a recovery.img. $other" }
  if ($magic -ne 'ANDROID!') { throw "Not an Android boot image (a jackpotlte recovery.img starts with ANDROID!). $other" }
  $hv = [BitConverter]::ToUInt32($d, 40)
  if ($hv -ge 1 -and $hv -le 4) { throw "Boot image header v$hv; a jackpotlte recovery.img uses header v0 with a Samsung DT. $other" }
  $ks = [BitConverter]::ToUInt32($d, 8)
  $rs = [BitConverter]::ToUInt32($d, 16)
  $ss = [BitConverter]::ToUInt32($d, 24)
  $page = [BitConverter]::ToUInt32($d, 36)
  $dt = [BitConverter]::ToUInt32($d, 40)
  if ($dt -le 4) { $dt = 0 }   # a header version, not a Samsung DT size
  $al = { param($x) [long]([math]::Ceiling($x / $page) * $page) }
  $kOff = [long]$page
  $rOff = $kOff + (& $al $ks)
  $used = $rOff + (& $al $rs) + (& $al $ss) + (& $al $dt)
  [pscustomobject]@{
    PageSize      = $page
    KernelSize    = $ks
    RamdiskOffset = [int]$rOff
    RamdiskSize   = [int]$rs
    DtSize        = $dt
    Used          = $used
    Cmdline       = [Text.Encoding]::ASCII.GetString($d, 64, 512).Split([char]0)[0]
    Trailer       = if ($used + 16 -le $d.Length) { [Text.Encoding]::ASCII.GetString($d, [int]$used, 16) } else { '' }
    Kernel        = [FoxUnpack3]::KernelRelease([FoxUnpack3]::Decompress($d, [int]$kOff, [int]$ks))
  }
}

function Read-Ramdisk([byte[]]$d, $h) {
  $raw = [FoxUnpack3]::Decompress($d, $h.RamdiskOffset, $h.RamdiskSize)
  $magic = [Text.Encoding]::ASCII.GetString($raw, 0, 6)
  if ($magic -ne '070701' -and $magic -ne '070702') { throw 'Ramdisk is not a newc cpio archive after decompression' }
  $files = @{}
  $p = 0
  while ($p -lt $raw.Length) {
    $hdr = [Text.Encoding]::ASCII.GetString($raw, $p, 110)
    $mode  = [Convert]::ToInt32($hdr.Substring(14, 8), 16)
    $fsize = [Convert]::ToInt32($hdr.Substring(54, 8), 16)
    $nsize = [Convert]::ToInt32($hdr.Substring(94, 8), 16)
    $p += 110
    $name = [Text.Encoding]::ASCII.GetString($raw, $p, $nsize - 1)
    $p = ($p + $nsize + 3) -band -bnot 3
    if ($name -eq 'TRAILER!!!') { break }
    if (($mode -band 0xF000) -eq 0x8000) { $files[$name.TrimStart('/')] = @($p, $fsize) }
    $p = ($p + $fsize + 3) -band -bnot 3
  }
  return @{ Data = $raw; Files = $files }
}

function Get-Text($rd, [string]$name) {
  $f = $rd.Files[$name]
  if (-not $f) { return $null }
  return [Text.Encoding]::ASCII.GetString($rd.Data, $f[0], $f[1])
}

$results = New-Object System.Collections.Generic.List[object]
function Add-Result([string]$group, [string]$check, [bool]$ok, [string]$detail) {
  $results.Add([pscustomobject]@{ Group = $group; Check = $check; Result = $(if ($ok) { 'OK' } else { 'MISSING' }); Detail = $detail })
}
function Add-Info([string]$group, [string]$check, [string]$detail) {
  $results.Add([pscustomobject]@{ Group = $group; Check = $check; Result = 'INFO'; Detail = $detail })
}

$bytes = Get-ImageBytes $Img
$h = Read-BootHeader $bytes
$rd = Read-Ramdisk $bytes $h

$props = Get-Text $rd 'prop.default'
function Get-Prop([string]$key) {
  if (-not $props) { return '' }
  return ([regex]::Match($props, "(?m)^$([regex]::Escape($key))=(.*)$")).Groups[1].Value.Trim()
}
$device = Get-Prop 'ro.product.device'
if (-not $device) { $device = Get-Prop 'ro.product.system.device' }

Write-Host "Image          : $(Split-Path $Img -Leaf)"
Write-Host "Header         : Android boot image v0, page $($h.PageSize), kernel $($h.KernelSize), ramdisk $($h.RamdiskSize), DT $($h.DtSize) bytes"
Write-Host "Kernel         : $(if ($h.Kernel) { $h.Kernel } else { '(release not found)' })"
Write-Host "Device         : $device, build $(Get-Prop 'ro.build.display.id')"
Write-Host "OrangeFox base : $(Get-Prop 'ro.build.fox_codebase')"
Write-Host ''

# Image layout (Samsung bootloader, RECOVERY partition)
Add-Result 'Boot' 'kernel' ($h.KernelSize -gt 0 -and [bool]$h.Kernel) $h.Kernel
Add-Result 'Boot' 'DT appended (mkbootimg --dt)' ($h.DtSize -gt 0) "$($h.DtSize) bytes"
Add-Result 'Boot' 'cmdline androidboot.hardware' ($h.Cmdline -match 'androidboot\.hardware=samsungexynos7885') 'samsungexynos7885'
Add-Result 'Boot' 'SEANDROIDENFORCE after the image' ($h.Trailer -eq 'SEANDROIDENFORCE') 'Samsung bootloader warns without it'
Add-Result 'Boot' 'fits the RECOVERY partition' ($h.Used + 16 -le $RecoveryPartitionSize) "$($h.Used + 16) of $RecoveryPartitionSize bytes"

# Recovery for the Treble layout
Add-Result 'Recovery' 'built for jackpotlte' ($device -eq 'jackpotlte') "ro.product.device=$device"
Add-Result 'Recovery' 'device init' ($rd.Files.ContainsKey('init.recovery.samsungexynos7885.rc')) 'init.recovery.samsungexynos7885.rc'
Add-Result 'Recovery' 'device ueventd rules' ($rd.Files.ContainsKey('ueventd.samsungexynos7885.rc')) 'ueventd.samsungexynos7885.rc'
Add-Result 'Recovery' 'lowercase by-name links' ($rd.Files.ContainsKey('system/bin/link.sh')) 'system/bin/link.sh'
$flags = Get-Text $rd 'system/etc/twrp.flags'
$want = @('SYSTEM', 'VENDOR', 'PRODUCT', 'ODM', 'PRISM', 'OPTICS', 'EFS')
$absent = @($want | Where-Object { -not ($flags -and $flags -match "by-name/$_\b") })
Add-Result 'Recovery' 'twrp.flags: Treble partitions and EFS' ($absent.Count -eq 0) $(if ($absent) { 'missing: ' + ($absent -join ', ') } else { $want -join ', ' })
$fstab = Get-Text $rd 'system/etc/recovery.fstab'
Add-Result 'Recovery' 'recovery.fstab: /data and /cache' ([bool]$fstab -and $fstab -match 'by-name/USERDATA\s+/data' -and $fstab -match 'by-name/CACHE\s+/cache') 'USERDATA, CACHE (ext4 and f2fs)'
Add-Result 'Recovery' 'OrangeFox files' (@($rd.Files.Keys -like 'FFiles/*').Count -gt 0) 'FFiles'

# Battery
$hman = Get-Text $rd 'vendor/etc/vintf/manifest/android.hardware.health@2.1.xml'
Add-Result 'Battery' 'health HAL 2.1 service' ($rd.Files.ContainsKey('system/bin/android.hardware.health@2.1-service')) 'system/bin'
Add-Result 'Battery' 'manifest declares health 2.1' ([bool]$hman -and $hman -match '@2\.1::IHealth') ''

# Flashlight
$rc = Get-Text $rd 'init.recovery.samsungexynos7885.rc'
Add-Result 'Flashlight' 'rear flash bridged to /tmp/flashlight' ([bool]$rc -and $rc -match 'mkdir\s+/tmp/flashlight' -and $rc -match 'symlink\s+/sys/class/camera/flash/rear_flash\s+/tmp/flashlight/brightness') 'OF_FL_PATH1=/tmp/flashlight'
Add-Result 'Flashlight' 'max_brightness written' ([bool]$rc -and $rc -match 'write\s+/tmp/flashlight/max_brightness\s+"?1"?') '1'

# Display colors: the framebuffer is BGRA (red.offset 16); ABGR_8888 plus the
# res_swap_red_blue() patch draw the orange accent orange instead of blue
$fmt = Get-Prop 'ro.minui.pixel_format'
Add-Result 'Display' 'pixel format ABGR_8888' ($fmt -eq 'ABGR_8888') "ro.minui.pixel_format=$fmt"
$lib = $rd.Files['system/lib64/libminuitwrp.so']
$swap = $false
if ($lib) {
  $libText = [Text.Encoding]::ASCII.GetString($rd.Data, $lib[0], $lib[1])
  $swap = $libText.Contains('res_swap_red_blue')
}
Add-Result 'Display' 'libminuitwrp with the accent color patch' $swap $(if (-not $lib) { 'libminuitwrp.so missing' } elseif ($swap) { 'res_swap_red_blue' } else { 'old library, accent drawn blue' })

# USB
$usb = Get-Text $rd 'init.recovery.usb.rc'
Add-Result 'USB' 'configfs USB gadget' ([bool]$usb -and $usb -match '/config/usb_gadget') ''
Add-Result 'USB' 'MTP function' ([bool]$usb -and $usb -match 'functions/mtp\.gs0') ''

# Decryption (not part of this build)
$km = @($rd.Files.Keys | Where-Object { $_ -match 'keymaster|gatekeeper|mcDriverDaemon|mobicore' })
if ($km.Count -eq 0) {
  Add-Info 'Decryption' 'keymaster, gatekeeper, Trustonic services' 'not included; this image does not decrypt /data'
} else {
  Add-Info 'Decryption' 'keymaster, gatekeeper, Trustonic services' ($km -join ', ')
}

$results | Format-Table -AutoSize Group, Check, Result, Detail | Out-String -Width 200 | Write-Host
$bad = @($results | Where-Object { $_.Result -eq 'MISSING' }).Count
if ($bad -eq 0) {
  Write-Host 'RESULT: all checks OK. Image for the Treble partition layout; /data is not decrypted.' -ForegroundColor Green
} else {
  Write-Host "RESULT: $bad check(s) MISSING; see the table above." -ForegroundColor Yellow
}
