# recovery-inspect.ps1
# Lists what an OrangeFox recovery image contains, without flashing it: boot image
# layout, device files, display, USB and, for devices that decrypt /data, the
# decryption chain. One script for every Gursu-Bilisim OrangeFox device; the device is
# read from the image's prop.default. Images of other devices get the common checks.
# Works in Windows PowerShell 5.1+ and PowerShell 7 (Windows, Linux).
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File recovery-inspect.ps1 -Img <image>
#   <image>: recovery.img, vendor_boot.img, Odin .tar or OrangeFox .zip
#
# Device profiles: bramble (vendor_boot), tucana (recovery), jackpotlte (RECOVERY).
# Each check prints OK or MISSING; INFO lines describe the build.

param(
  [Parameter(Mandatory = $true)][string]$Img
)

$ScriptVersion = '2026.10.19'
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

if (-not ([System.Management.Automation.PSTypeName]'FoxInspect').Type) {
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.IO.Compression;
public static class FoxInspect {
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
    if (FoxInspectLzma.IsLzma(src, start, len)) return FoxInspectLzma.Decode(src, start, len);
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
public static class FoxInspectLzma {
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
      if (-not $e) { $e = $zf.GetEntry('vendor_boot.img') }
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

function Read-ImageHeader([byte[]]$d) {
  $magic = [Text.Encoding]::ASCII.GetString($d, 0, 8)
  $al = { param($x, $pg) [long]([math]::Ceiling($x / $pg) * $pg) }
  $avb = ($d.Length -ge 64 -and [Text.Encoding]::ASCII.GetString($d, $d.Length - 64, 4) -eq 'AVBf')
  if ($magic -eq 'VNDRBOOT') {
    $hv = [BitConverter]::ToUInt32($d, 8)
    if ($hv -ne 3 -and $hv -ne 4) { throw "vendor_boot header v$hv is not supported" }
    $page = [BitConverter]::ToUInt32($d, 12)
    $rs = [BitConverter]::ToUInt32($d, 24)
    $hs = [BitConverter]::ToUInt32($d, 2096)
    $dtb = [BitConverter]::ToUInt32($d, 2100)
    $rOff = & $al $hs $page
    return [pscustomobject]@{
      Type = 'vendor_boot'; Version = $hv; PageSize = $page; KernelSize = 0; KernelOffset = 0
      RamdiskOffset = [int]$rOff; RamdiskSize = [int]$rs; DtbSize = $dtb; SamsungDt = 0
      Used = $rOff + (& $al $rs $page) + (& $al $dtb $page); AvbFooter = $avb; Trailer = ''
      Cmdline = [Text.Encoding]::ASCII.GetString($d, 28, 2048).Split([char]0)[0]
    }
  }
  if ($magic -ne 'ANDROID!') { throw "Not an Android boot, recovery or vendor_boot image (first bytes $(([BitConverter]::ToString($d, 0, 8)) -replace '-', ' '))" }
  $hv = [BitConverter]::ToUInt32($d, 40)
  if ($hv -eq 3 -or $hv -eq 4) {
    $page = 4096
    $ks = [BitConverter]::ToUInt32($d, 8)
    $rs = [BitConverter]::ToUInt32($d, 12)
    $kOff = [long]$page
    $rOff = $kOff + (& $al $ks $page)
    return [pscustomobject]@{
      Type = 'boot'; Version = $hv; PageSize = $page; KernelSize = $ks; KernelOffset = [int]$kOff
      RamdiskOffset = [int]$rOff; RamdiskSize = [int]$rs; DtbSize = 0; SamsungDt = 0
      Used = $rOff + (& $al $rs $page); AvbFooter = $avb; Trailer = ''
      Cmdline = [Text.Encoding]::ASCII.GetString($d, 44, 1536).Split([char]0)[0]
    }
  }
  # Header v0, v1 or v2. Samsung v0 images keep a DT size where the header version is.
  $ks = [BitConverter]::ToUInt32($d, 8)
  $rs = [BitConverter]::ToUInt32($d, 16)
  $ss = [BitConverter]::ToUInt32($d, 24)
  $page = [BitConverter]::ToUInt32($d, 36)
  $samsungDt = 0
  if ($hv -gt 4) { $samsungDt = $hv; $hv = 0 }
  $kOff = [long]$page
  $rOff = $kOff + (& $al $ks $page)
  $used = $rOff + (& $al $rs $page) + (& $al $ss $page) + (& $al $samsungDt $page)
  $dtb = 0
  if ($hv -ge 1) { $used += & $al ([BitConverter]::ToUInt32($d, 1632)) $page }
  if ($hv -ge 2) { $dtb = [BitConverter]::ToUInt32($d, 1648); $used += & $al $dtb $page }
  $trailer = ''
  if ($used + 16 -le $d.Length) { $trailer = [Text.Encoding]::ASCII.GetString($d, [int]$used, 16) }
  [pscustomobject]@{
    Type = 'boot'; Version = $hv; PageSize = $page; KernelSize = $ks; KernelOffset = [int]$kOff
    RamdiskOffset = [int]$rOff; RamdiskSize = [int]$rs; DtbSize = $dtb; SamsungDt = $samsungDt
    Used = $used; AvbFooter = $avb; Trailer = $trailer
    Cmdline = ([Text.Encoding]::ASCII.GetString($d, 64, 512).Split([char]0)[0] + [Text.Encoding]::ASCII.GetString($d, 608, 1024).Split([char]0)[0])
  }
}

function Read-Ramdisk([byte[]]$d, $h) {
  $raw = [FoxInspect]::Decompress($d, $h.RamdiskOffset, $h.RamdiskSize)
  $magic = [Text.Encoding]::ASCII.GetString($raw, 0, 6)
  if ($magic -ne '070701' -and $magic -ne '070702') { throw 'Ramdisk is not a newc cpio archive after decompression' }
  $files = @{}
  $p = 0
  while ($p + 110 -le $raw.Length) {
    $hdr = [Text.Encoding]::ASCII.GetString($raw, $p, 110)
    if ($hdr.Substring(0, 6) -ne '070701' -and $hdr.Substring(0, 6) -ne '070702') { break }
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
function Test-Bytes($rd, [string]$name, [string]$text) {
  $f = $rd.Files[$name]
  if (-not $f) { return $false }
  return [FoxInspect]::Contains($rd.Data, $f[0], $f[1], [Text.Encoding]::ASCII.GetBytes($text))
}
function Find-File($rd, [string[]]$names) {
  foreach ($n in $names) { if ($rd.Files.ContainsKey($n)) { return $n } }
  return $null
}
function Get-Missing($rd, [string]$dir, [string[]]$names) {
  return @($names | Where-Object { -not $rd.Files.ContainsKey("$dir/$_") })
}

$results = New-Object System.Collections.Generic.List[object]
function Add-Result([string]$group, [string]$check, [bool]$ok, [string]$detail) {
  $results.Add([pscustomobject]@{ Group = $group; Check = $check; Result = $(if ($ok) { 'OK' } else { 'MISSING' }); Detail = $detail; Seq = $results.Count })
}
function Add-Info([string]$group, [string]$check, [string]$detail) {
  $results.Add([pscustomobject]@{ Group = $group; Check = $check; Result = 'INFO'; Detail = $detail; Seq = $results.Count })
}

# ---------------------------------------------------------------------------
# Device profiles. Each one names the partition the image is installed to, its
# size, and the checks specific to that device. Unknown devices get the common
# checks only.
# ---------------------------------------------------------------------------
$Profiles = @{
  'bramble' = @{
    Name = 'Google Pixel 4a 5G (bramble)'; Partition = 'vendor_boot'; PartitionSize = 100663296
    Critical = @('Decryption', 'Titan M')
    Summary = 'all decryption and Titan M components present. Check the ROM build with patch-check.ps1 before flashing.'
    Checks = {
      Add-Result 'Boot' 'boot device on cmdline' ($h.Cmdline -match 'androidboot\.boot_devices=soc/1d84000\.ufshc') 'androidboot.boot_devices=soc/1d84000.ufshc'
      Add-Result 'Boot' 'DTB present' ($h.DtbSize -gt 0) "$($h.DtbSize) bytes"
      Add-Result 'Boot' 'first stage fstab' ($rd.Files.ContainsKey('first_stage_ramdisk/fstab.sm7250')) 'first_stage_ramdisk/fstab.sm7250'
      $load = Get-Text $rd 'lib/modules/modules.load'
      $listed = @()
      if ($load) { $listed = @($load -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ } | ForEach-Object { (Split-Path $_ -Leaf) -replace '\.ko$', '' }) }
      $absent = @($listed | Where-Object {
        -not ($rd.Files.ContainsKey("lib/modules/$_.ko") -or $rd.Files.ContainsKey("lib/modules/$($_ -replace '-', '_').ko") -or $rd.Files.ContainsKey("lib/modules/$($_ -replace '_', '-').ko"))
      })
      Add-Result 'Boot' 'every module in modules.load present' ([bool]$load -and $listed.Count -gt 0 -and $absent.Count -eq 0) $(if (-not $load) { 'lib/modules/modules.load not found' } elseif ($absent) { 'missing: ' + ($absent[0..4] -join ', ') } else { "$($listed.Count) modules" })

      Add-Result 'Decryption' '/dev/block/bootdevice link created by init' ($rcText -match '(?m)symlink\s+\S+\s+/dev/block/bootdevice\s*$') ''
      Add-Result 'Decryption' 'modem firmware mount (slot suffix)' ($rcText -match 'modem\$\{ro\.boot\.slot_suffix\}\s+/vendor/firmware_mnt') '/vendor/firmware_mnt'
      Add-Result 'Decryption' 'qcom decrypt init (twrp-common)' ($rd.Files.ContainsKey('init.recovery.qcom_decrypt.rc')) 'init.recovery.qcom_decrypt.rc'
      $n = Find-File $rd @('system/bin/prepdecrypt.sh', 'vendor/bin/prepdecrypt.sh'); Add-Result 'Decryption' 'prepdecrypt script' ([bool]$n) $n
      $n = Find-File $rd @('system/bin/qseecomd', 'vendor/bin/qseecomd'); Add-Result 'Decryption' 'qseecomd' ([bool]$n) $n
      $n = Find-File $rd @('vendor/lib64/libQSEEComAPI.so', 'system/lib64/libQSEEComAPI.so'); Add-Result 'Decryption' 'QSEECom library' ([bool]$n) $n
      $missing = Get-Missing $rd 'vendor/lib64' @('librpmb.so', 'libssd.so', 'libops.so', 'libGPreqcancel.so', 'libGPreqcancel_svc.so', 'libdrmtime.so', 'libtime_genoff.so', 'libqisl.so', 'libsecureui.so')
      Add-Result 'Decryption' 'qseecomd listener libraries' ($missing.Count -eq 0) $(if ($missing) { 'missing: ' + ($missing -join ', ') } else { '9 listeners' })
      $n = Find-File $rd @('system/bin/android.hardware.keymaster@4.0-service-qti', 'vendor/bin/hw/android.hardware.keymaster@4.0-service-qti'); Add-Result 'Decryption' 'QTI keymaster 4.0 service' ([bool]$n) $n
      $n = Find-File $rd @('system/bin/android.hardware.gatekeeper@1.0-service-qti', 'vendor/bin/hw/android.hardware.gatekeeper@1.0-service-qti'); Add-Result 'Decryption' 'QTI gatekeeper 1.0 service' ([bool]$n) $n
      Add-Result 'Decryption' 'QTI gatekeeper implementation' ($rd.Files.ContainsKey('vendor/lib64/hw/android.hardware.gatekeeper@1.0-impl-qti.so')) 'vendor/lib64/hw'
      $manVer = if ($man) { ([regex]::Match($man, 'manifest\s+version="([^"]+)"')).Groups[1].Value } else { '' }
      Add-Result 'Decryption' 'device VINTF manifest readable by recovery' ([bool]$man -and $manVer -and [double]$manVer -le 4) $(if ($man) { "manifest version $manVer" } else { 'vendor/etc/vintf/manifest.xml not found' })
      Add-Result 'Decryption' 'manifest declares keymaster' ([bool]$man -and $man -match 'android\.hardware\.keymaster') ''
      Add-Result 'Decryption' 'manifest declares keystore2 (AIDL)' ([bool]$man -and $man -match 'android\.system\.keystore2') ''
      $fman = Get-Text $rd 'system/etc/vintf/manifest.xml'
      Add-Result 'Decryption' 'framework manifest declares hidl manager' ([bool]$fman -and $fman -match 'android\.hidl\.manager') 'needed by keystore2'

      Add-Result 'Titan M' 'Titan M init' ($rd.Files.ContainsKey('init.recovery.titan.rc')) 'init.recovery.titan.rc'
      $missing = Get-Missing $rd 'system/bin' @('vndservicemanager', 'citadeld', 'android.hardware.weaver@1.0-service.citadel', 'linker64_a16')
      Add-Result 'Titan M' 'services and Android 16 linker' ($missing.Count -eq 0) $(if ($missing) { 'missing: ' + ($missing -join ', ') } else { 'vndservicemanager, citadeld, weaver, linker64_a16' })
      $missing = Get-Missing $rd 'system/lib64/a16' @('ld-android.so', 'libc.so', 'libdl.so', 'liblog.so', 'libm.so', 'libbinder_ndk.so', 'libselinux.so', 'libvndksupport.so', 'libpcre2.so', 'libpackagelistparser.so', 'libdl_android.so')
      Add-Result 'Titan M' 'Android 16 runtime libraries' ($missing.Count -eq 0) $(if ($missing) { 'missing: ' + ($missing -join ', ') } else { 'system/lib64/a16 (11)' })
      Add-Result 'Titan M' 'libapexsupport' ($rd.Files.ContainsKey('vendor/lib64/libapexsupport.so')) 'vendor/lib64'
      Add-Result 'Titan M' 'manifest declares weaver' ([bool]$man -and $man -match 'android\.hardware\.weaver') ''
      Add-Result 'Titan M' 'manifest declares authsecret' ([bool]$man -and $man -match 'android\.hardware\.authsecret') 'weaver aborts without it'

      $bootImpl = 'system/lib64/hw/android.hardware.boot@1.0-impl-1.2-qti.so'
      Add-Result 'Boot control' 'QTI boot control 1.2 implementation' ($rd.Files.ContainsKey($bootImpl)) $bootImpl
      Add-Result 'Boot control' 'boot HAL service without vendor library path' ($rcText -match '(?m)^service\s+boot-hal-1-2\s+/system/bin/android\.hardware\.boot@1\.2-service') 'init.recovery.bramble.rc'
      Add-Result 'Boot control' 'slot count ignores the boot link' (Test-Bytes $rd $bootImpl "`0boot_`0") 'BOOT_IMG_PTN_NAME "boot_"'

      Add-Result 'Recovery' 'battery read from sysfs' (Test-Bytes $rd 'system/bin/recovery' '/sys/class/power_supply/battery/capacity') 'TW_USE_LEGACY_BATTERY_SERVICES'
      Add-Result 'Recovery' 'bootdevice paths rewritten in ROM fstab' (Test-Bytes $rd 'system/bin/recovery' 'Rewrote bootdevice paths') 'recovery binary'
      Add-Result 'Recovery' 'touch event debug logging off' (-not (Test-Bytes $rd 'system/bin/recovery' 'TOUCH_START:')) 'gui.cpp _EVENT_LOGGING'
      Add-Result 'USB' 'MTP function linked in mtp,adb mode' ([bool]$usb -and $usb -match 'functions/mtp\.gs0\s+\S+/configs/b\.1/f') ''
    }
  }

  'tucana' = @{
    Name = 'Xiaomi Mi Note 10 / CC9 Pro (tucana)'; Partition = 'recovery'; PartitionSize = 134217728
    Critical = @('Decryption')
    Summary = 'all decryption components present. Check the ROM build with patch-check.ps1 before flashing.'
    Checks = {
      Add-Result 'Boot' 'boot image header v2' ($h.Type -eq 'boot' -and $h.Version -eq 2) "v$($h.Version)"
      Add-Result 'Boot' 'DTB present' ($h.DtbSize -gt 0) "$($h.DtbSize) bytes"
      Add-Result 'Boot' 'boot device on cmdline' ($h.Cmdline -match 'androidboot\.bootdevice=1d84000\.ufshc') 'androidboot.bootdevice=1d84000.ufshc'

      Add-Result 'Decryption' 'qcom decrypt init (twrp-common)' ($rd.Files.ContainsKey('init.recovery.qcom_decrypt.rc')) 'init.recovery.qcom_decrypt.rc'
      Add-Result 'Decryption' 'qcom FBE decrypt init' ($rd.Files.ContainsKey('init.recovery.qcom_decrypt.fbe.rc')) 'init.recovery.qcom_decrypt.fbe.rc'
      $n = Find-File $rd @('system/bin/prepdecrypt.sh', 'vendor/bin/prepdecrypt.sh'); Add-Result 'Decryption' 'prepdecrypt script' ([bool]$n) $n
      $n = Find-File $rd @('system/bin/qseecomd', 'vendor/bin/qseecomd'); Add-Result 'Decryption' 'qseecomd' ([bool]$n) $n
      $n = Find-File $rd @('system/bin/android.hardware.keymaster@4.1-service-qti', 'system/bin/android.hardware.keymaster@4.0-service-qti')
      Add-Result 'Decryption' 'QTI keymaster service' ([bool]$n) $n
      Add-Result 'Decryption' 'QTI keymaster library' ($rd.Files.ContainsKey('vendor/lib64/libqtikeymaster4.so')) 'vendor/lib64/libqtikeymaster4.so'
      $n = Find-File $rd @('system/bin/android.hardware.gatekeeper@1.0-service-qti', 'vendor/bin/hw/android.hardware.gatekeeper@1.0-service-qti'); Add-Result 'Decryption' 'QTI gatekeeper 1.0 service' ([bool]$n) $n
      Add-Result 'Decryption' 'QTI gatekeeper implementation' ($rd.Files.ContainsKey('vendor/lib64/hw/android.hardware.gatekeeper@1.0-impl-qti.so')) 'vendor/lib64/hw'
      Add-Result 'Decryption' 'manifest declares keymaster' ([bool]$man -and $man -match 'android\.hardware\.keymaster') 'vendor/etc/vintf/manifest.xml'
      Add-Result 'Decryption' 'manifest declares gatekeeper' ([bool]$man -and $man -match 'android\.hardware\.gatekeeper') ''

      Add-Result 'Battery' 'health HAL 2.1 service' ($rd.Files.ContainsKey('system/bin/android.hardware.health@2.1-service')) 'system/bin'
    }
  }

  'jackpotlte' = @{
    Name = 'Samsung Galaxy A8 2018 (SM-A530F, jackpotlte), Treble partition layout'; Partition = 'RECOVERY'; PartitionSize = 39845888
    Critical = @()
    Summary = 'all checks OK. Image for the Treble partition layout; /data is not decrypted.'
    Checks = {
      Add-Result 'Boot' 'kernel' ($h.KernelSize -gt 0 -and [bool]$kernel) $kernel
      Add-Result 'Boot' 'DT appended (mkbootimg --dt)' ($h.SamsungDt -gt 0) "$($h.SamsungDt) bytes"
      Add-Result 'Boot' 'cmdline androidboot.hardware' ($h.Cmdline -match 'androidboot\.hardware=samsungexynos7885') 'samsungexynos7885'
      Add-Result 'Boot' 'SEANDROIDENFORCE after the image' ($h.Trailer -eq 'SEANDROIDENFORCE') 'Samsung bootloader warns without it'

      Add-Result 'Recovery' 'device init' ($rd.Files.ContainsKey('init.recovery.samsungexynos7885.rc')) 'init.recovery.samsungexynos7885.rc'
      Add-Result 'Recovery' 'device ueventd rules' ($rd.Files.ContainsKey('ueventd.samsungexynos7885.rc')) 'ueventd.samsungexynos7885.rc'
      Add-Result 'Recovery' 'lowercase by-name links' ($rd.Files.ContainsKey('system/bin/link.sh')) 'system/bin/link.sh'
      $flags = Get-Text $rd 'system/etc/twrp.flags'
      $want = @('SYSTEM', 'VENDOR', 'PRODUCT', 'ODM', 'PRISM', 'OPTICS', 'EFS')
      $absent = @($want | Where-Object { -not ($flags -and $flags -match "by-name/$_\b") })
      Add-Result 'Recovery' 'twrp.flags: Treble partitions and EFS' ($absent.Count -eq 0) $(if ($absent) { 'missing: ' + ($absent -join ', ') } else { $want -join ', ' })
      $fstab = Get-Text $rd 'system/etc/recovery.fstab'
      Add-Result 'Recovery' 'recovery.fstab: /data and /cache' ([bool]$fstab -and $fstab -match 'by-name/USERDATA\s+/data' -and $fstab -match 'by-name/CACHE\s+/cache') 'USERDATA, CACHE (ext4 and f2fs)'

      $hman = Get-Text $rd 'vendor/etc/vintf/manifest/android.hardware.health@2.1.xml'
      Add-Result 'Battery' 'health HAL 2.1 service' ($rd.Files.ContainsKey('system/bin/android.hardware.health@2.1-service')) 'system/bin'
      Add-Result 'Battery' 'manifest declares health 2.1' ([bool]$hman -and $hman -match '@2\.1::IHealth') ''

      $rc = Get-Text $rd 'init.recovery.samsungexynos7885.rc'
      Add-Result 'Flashlight' 'rear flash bridged to /tmp/flashlight' ([bool]$rc -and $rc -match 'mkdir\s+/tmp/flashlight' -and $rc -match 'symlink\s+/sys/class/camera/flash/rear_flash\s+/tmp/flashlight/brightness') 'OF_FL_PATH1=/tmp/flashlight'
      Add-Result 'Flashlight' 'max_brightness written' ([bool]$rc -and $rc -match 'write\s+/tmp/flashlight/max_brightness\s+"?1"?') '1'
      Add-Result 'Display' 'pixel format ABGR_8888' ($pixFmt -eq 'ABGR_8888') 'framebuffer is BGRA (red.offset 16)'

      $km = @($rd.Files.Keys | Where-Object { $_ -match 'keymaster|gatekeeper|mcDriverDaemon|mobicore' })
      if ($km.Count -eq 0) { Add-Info 'Decryption' 'keymaster, gatekeeper, Trustonic services' 'not included; this image does not decrypt /data' }
      else { Add-Info 'Decryption' 'keymaster, gatekeeper, Trustonic services' ($km -join ', ') }
    }
  }
}

# ---------------------------------------------------------------------------
$bytes = Get-ImageBytes $Img
$h = Read-ImageHeader $bytes
$rd = Read-Ramdisk $bytes $h

$props = Get-Text $rd 'prop.default'
if (-not $props) { $props = Get-Text $rd 'system/etc/prop.default' }
function Get-Prop([string]$key) {
  if (-not $props) { return '' }
  return ([regex]::Match($props, "(?m)^$([regex]::Escape($key))=(.*)$")).Groups[1].Value.Trim()
}
$device = ''
foreach ($k in @('ro.product.device', 'ro.product.vendor.device', 'ro.build.product', 'ro.product.system.device')) {
  $device = Get-Prop $k
  if ($device) { break }
}
$profile = $Profiles[$device]
$pixFmt = Get-Prop 'ro.minui.pixel_format'
$kernel = $null
if ($h.KernelSize -gt 0) {
  try { $kernel = [FoxInspect]::KernelRelease([FoxInspect]::Decompress($bytes, $h.KernelOffset, [int]$h.KernelSize)) } catch { $kernel = $null }
}
$rcText = ($rd.Files.Keys | Where-Object { $_ -like '*.rc' } | ForEach-Object { Get-Text $rd $_ }) -join "`n"
$man = Get-Text $rd 'vendor/etc/vintf/manifest.xml'

$hdrText = if ($h.Type -eq 'vendor_boot') { "vendor_boot v$($h.Version), page $($h.PageSize), ramdisk $($h.RamdiskSize), DTB $($h.DtbSize) bytes" }
           elseif ($h.SamsungDt -gt 0) { "boot image v0 (Samsung), page $($h.PageSize), kernel $($h.KernelSize), ramdisk $($h.RamdiskSize), DT $($h.SamsungDt) bytes" }
           else { "boot image v$($h.Version), page $($h.PageSize), kernel $($h.KernelSize), ramdisk $($h.RamdiskSize), DTB $($h.DtbSize) bytes" }
Write-Host "recovery-inspect $ScriptVersion"
Write-Host "Image          : $(Split-Path $Img -Leaf) ($($bytes.Length) bytes)"
Write-Host "Header         : $hdrText, AVB footer $(if ($h.AvbFooter) { 'yes' } else { 'no' })"
if ($h.KernelSize -gt 0) { Write-Host "Kernel         : $(if ($kernel) { $kernel } else { '(release not found)' })" }
Write-Host "Device         : $(if ($device) { $device } else { '(not found)' })$(if ($profile) { ', ' + $profile.Name } else { ', no device profile: common checks only' })"
Write-Host "Android        : $(Get-Prop 'ro.build.version.release'), security patch $(Get-Prop 'ro.build.version.security_patch')"
Write-Host "OrangeFox base : $(Get-Prop 'ro.build.fox_codebase')"
Write-Host ''

# Common checks
if ($profile) {
  $size = if ($h.AvbFooter) { $bytes.Length } else { $h.Used + $(if ($h.Trailer -eq 'SEANDROIDENFORCE') { 16 } else { 0 }) }
  Add-Result 'Image' "fits the $($profile.Partition) partition" ($size -le $profile.PartitionSize) "$size of $($profile.PartitionSize) bytes"
}
Add-Result 'Recovery' 'device name in prop.default' ([bool]$device) $device
Add-Result 'Recovery' 'recovery binary' ($rd.Files.ContainsKey('system/bin/recovery')) 'system/bin/recovery'
Add-Result 'Recovery' 'OrangeFox files' (@($rd.Files.Keys -like 'FFiles/*').Count -gt 0) 'FFiles'

# Display: OrangeFox draws SVGs, tint and shapes itself; with ABGR_8888 it needs the
# res_swap_red_blue() patch, and a recovery built with that patch needs the matching
# libminuitwrp.so (TWRP's relink step can leave an old copy in the ramdisk).
$lib = 'system/lib64/libminuitwrp.so'
if (-not $rd.Files.ContainsKey($lib)) { $lib = 'system/lib/libminuitwrp.so' }
$libOk = $rd.Files.ContainsKey($lib)
$libSwap = $libOk -and (Test-Bytes $rd $lib 'res_swap_red_blue')
$recPacked = Test-Bytes $rd 'system/bin/recovery' 'UPX!'
$recSwap = Test-Bytes $rd 'system/bin/recovery' 'res_swap_red_blue'
Add-Info 'Display' 'pixel format' $(if ($pixFmt) { "ro.minui.pixel_format=$pixFmt" } else { 'not set' })
Add-Result 'Display' 'libminuitwrp.so in the ramdisk' $libOk $lib
if ($pixFmt -eq 'ABGR_8888') {
  Add-Result 'Display' 'accent color patch (ABGR_8888)' $libSwap $(if ($libSwap) { 'res_swap_red_blue' } else { 'old libminuitwrp, accent drawn blue' })
} elseif ($recPacked) {
  Add-Info 'Display' 'libminuitwrp matches recovery' "recovery is UPX-packed; libminuitwrp $(if ($libSwap) { 'has' } else { 'does not have' }) res_swap_red_blue"
} else {
  Add-Result 'Display' 'libminuitwrp matches recovery' ((-not $recSwap) -or $libSwap) $(if ($recSwap -and -not $libSwap) { 'recovery needs res_swap_red_blue, libminuitwrp is older' } elseif ($recSwap) { 'both have res_swap_red_blue' } else { 'recovery built without the accent color patch' })
}

# USB
$usb = Get-Text $rd 'init.recovery.usb.rc'
Add-Result 'USB' 'configfs USB gadget' ([bool]$usb -and $usb -match '/config/usb_gadget') ''
Add-Result 'USB' 'MTP function' ([bool]$usb -and $usb -match 'functions/mtp\.gs0') ''

if ($profile) { & $profile.Checks }

$groupOrder = @('Image', 'Boot', 'Recovery', 'Display', 'Decryption', 'Titan M', 'Boot control', 'Battery', 'Flashlight', 'USB')
$results | Sort-Object @{ Expression = { $i = [array]::IndexOf($groupOrder, $_.Group); if ($i -lt 0) { 99 } else { $i } } }, Seq |
  Format-Table -AutoSize Group, Check, Result, Detail | Out-String -Width 200 | Write-Host

$notOk = @($results | Where-Object { $_.Result -eq 'MISSING' })
if (-not $profile) {
  if ($notOk.Count -eq 0) { Write-Host 'RESULT: common checks OK. No device profile for this image, so device files were not checked.' -ForegroundColor Green }
  else { Write-Host "RESULT: $($notOk.Count) common check(s) MISSING; see the table above." -ForegroundColor Yellow }
} else {
  $crit = @($notOk | Where-Object { $profile.Critical -contains $_.Group })
  $other = @($notOk | Where-Object { $profile.Critical -notcontains $_.Group })
  if ($crit.Count -gt 0) {
    Write-Host "RESULT: $($crit.Count) $($profile.Critical -join ' or ') component(s) missing; this image is not expected to decrypt /data." -ForegroundColor Yellow
  } elseif ($other.Count -eq 0) {
    Write-Host "RESULT: $($profile.Summary)" -ForegroundColor Green
  }
  if ($other.Count -gt 0) {
    if ($profile.Critical.Count -eq 0) {
      Write-Host "RESULT: $($other.Count) check(s) MISSING; see the table above." -ForegroundColor Yellow
    } else {
      if ($crit.Count -eq 0) { Write-Host "RESULT: all $($profile.Critical -join ' and ') components present." -ForegroundColor Green }
      Write-Host "NOTE: $($other.Count) other check(s) MISSING; see the table above." -ForegroundColor Yellow
    }
  }
}
