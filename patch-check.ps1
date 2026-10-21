# patch-check.ps1
# Reads the security patch level of an OTA package and, optionally, compares it
# with a recovery image. Works in Windows PowerShell 5.1+ and PowerShell 7.
#
# Recovery images:
#   - recovery.img / boot.img (header "ANDROID!", e.g. tucana): Android version and
#     patch level are read from the image header.
#     Samsung images built with "mkbootimg --dt" (e.g. jackpotlte) keep the DT size where
#     newer headers keep the header version; they are read as header v0.
#   - vendor_boot.img (header "VNDRBOOT", e.g. bramble): the kernel modules in the
#     ramdisk are compared with the ROM kernel, because vendor_boot is used for the
#     normal Android boot as well; this comparison gives the verdict. The clang version
#     of the modules is compared with the kernel banner too: the same release string
#     built with another compiler is a rebuilt kernel. Android version and patch level
#     from prop.default decide the DECRYPT line.
#     With an A/B package (-Zip), the script also reads the payload.bin manifest and says
#     what a ROM install leaves in vendor_boot (ROM INSTALL line): the LineageOS Updater
#     and OrangeFox both write the package to the inactive slot.
#
# Supported inputs:
#   - A-only OTA zip with boot.img at its root (tucana, most retrofit devices)
#   - A/B OTA zip with payload.bin (needs payload-dumper-go)
#   - A bare payload.bin
#   - A boot.img you extracted yourself (e.g. with Multi Image Kitchen) via -BootImg
#
# Recovery images that do not decrypt /data (listed in $NoDecrypt below, e.g. jackpotlte) do
# not depend on the ROM's patch level or kernel. For them -RecoveryImg alone is enough.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File patch-check.ps1 -Zip <ota.zip> [-RecoveryImg <recovery.img>]
#   powershell -ExecutionPolicy Bypass -File patch-check.ps1 -BootImg <boot.img> [-RecoveryImg <recovery.img>]
#   powershell -ExecutionPolicy Bypass -File patch-check.ps1 -RecoveryImg <recovery.img>
# -RecoveryImg also accepts an OrangeFox installer zip; the image inside it is checked.
# Optional: -PayloadTool <path to a payload tool .exe>
#           -GoDumper <path to payload-dumper-go.exe>
#           -MikDir <path to your Multi Image Kitchen folder>
#           -WorkDir <folder for temporary files>. Only used for A/B (payload.bin) zips;
#           if omitted there, the script shows the space needed and asks.
#           Without -PayloadTool, -GoDumper or -MikDir, the script looks for a payload tool
#           next to itself and in PATH.
# Supported payload tools: payload-dumper-go (fast, extracts only boot)
#                          payload_dumper by vm03 (bundled with MIK, extracts all, stopped after boot)

param(
  [string]$Zip,
  [string]$BootImg,
  [string]$RecoveryImg,
  [string]$PayloadTool,
  [string]$GoDumper,   # <path to payload-dumper-go.exe>
  [string]$MikDir,     # <path to your Multi Image Kitchen folder>
  [string]$WorkDir = $env:TEMP
)

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

# Devices whose released recovery images do not decrypt /data (ro.product.device in the
# recovery ramdisk). Their images do not depend on the ROM's security patch or kernel.
$NoDecrypt = @{
  'jackpotlte' = 'Samsung Galaxy A8 2018 (SM-A530F), built for the Treble partition layout (physical SYSTEM, VENDOR, PRODUCT, ODM)'
}

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
  // Returns the clang version named in the kernel banner, or null.
  public static string KernelCompiler(byte[] k) {
    byte[] pat = System.Text.Encoding.ASCII.GetBytes("Linux version ");
    byte[] cv = System.Text.Encoding.ASCII.GetBytes("clang version ");
    for (int i = 0; i + pat.Length + 2 < k.Length; i++) {
      int j = 0; while (j < pat.Length && k[i + j] == pat[j]) j++;
      if (j < pat.Length) continue;
      int s = i + pat.Length;
      if (k[s] < (byte)'0' || k[s] > (byte)'9') continue;
      int end = Math.Min(k.Length - cv.Length, s + 400);
      for (int q = s; q < end; q++) {
        int t = 0; while (t < cv.Length && k[q + t] == cv[t]) t++;
        if (t < cv.Length) continue;
        int a = q + cv.Length, b = a;
        while (b < k.Length && ((k[b] >= (byte)'0' && k[b] <= (byte)'9') || k[b] == (byte)'.')) b++;
        return b > a ? System.Text.Encoding.ASCII.GetString(k, a, b - a) : null;
      }
      return null;
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

if (-not ([System.Management.Automation.PSTypeName]'FoxPayload1').Type) {
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Collections.Generic;
using System.Text;

// Partition names from the manifest of an A/B payload.bin (update_engine format,
// DeltaArchiveManifest field 13 "partitions", PartitionUpdate field 1 "partition_name").
public static class FoxPayload1 {
  static byte[] ReadN(Stream s, long n) {
    byte[] b = new byte[n]; long r = 0;
    while (r < n) { int k = s.Read(b, (int)r, (int)Math.Min(n - r, 1 << 20)); if (k <= 0) throw new EndOfStreamException(); r += k; }
    return b;
  }
  static ulong BE(byte[] b, int o, int n) { ulong v = 0; for (int i = 0; i < n; i++) v = (v << 8) | b[o + i]; return v; }
  static ulong Var(byte[] b, ref int p) {
    ulong v = 0; int sh = 0;
    while (true) { byte x = b[p++]; v |= (ulong)(x & 0x7F) << sh; if ((x & 0x80) == 0) return v; sh += 7; }
  }
  public static string[] Partitions(Stream s) {
    byte[] h = ReadN(s, 20);
    if (Encoding.ASCII.GetString(h, 0, 4) != "CrAU") throw new InvalidDataException("not a payload.bin");
    ulong ver = BE(h, 4, 8);
    ulong msize = BE(h, 12, 8);
    if (msize == 0 || msize > (64UL << 20)) throw new InvalidDataException("manifest size " + msize);
    if (ver >= 2) ReadN(s, 4);
    byte[] m = ReadN(s, (long)msize);
    List<string> names = new List<string>();
    int p = 0;
    while (p < m.Length) {
      ulong key = Var(m, ref p); int field = (int)(key >> 3); int wt = (int)(key & 7);
      if (wt == 0) { Var(m, ref p); }
      else if (wt == 1) { p += 8; }
      else if (wt == 5) { p += 4; }
      else if (wt == 2) {
        int len = (int)Var(m, ref p); int end = p + len;
        if (field == 13) {
          int q = p;
          while (q < end) {
            ulong k2 = Var(m, ref q); int f2 = (int)(k2 >> 3); int w2 = (int)(k2 & 7);
            if (w2 == 0) { Var(m, ref q); }
            else if (w2 == 1) { q += 8; }
            else if (w2 == 5) { q += 4; }
            else if (w2 == 2) {
              int l2 = (int)Var(m, ref q);
              if (f2 == 1) { names.Add(Encoding.UTF8.GetString(m, q, l2)); break; }
              q += l2;
            }
            else throw new InvalidDataException("wire type " + w2);
          }
        }
        p = end;
      }
      else throw new InvalidDataException("wire type " + wt);
    }
    return names.ToArray();
  }
}
'@
}

$workDirGiven = $PSBoundParameters.ContainsKey('WorkDir')

if (-not $Zip -and -not $BootImg -and -not $RecoveryImg) { throw 'Give -Zip <ota.zip | payload.bin> or -BootImg <boot.img>, and optionally -RecoveryImg <recovery.img>' }

function Read-Head([IO.Stream]$s, [int]$n) {
  $buf = New-Object byte[] $n
  $read = 0
  while ($read -lt $n) {
    $k = $s.Read($buf, $read, $n - $read)
    if ($k -le 0) { break }
    $read += $k
  }
  return ,$buf
}

function Read-OsVersion([byte[]]$h) {
  $magic = [Text.Encoding]::ASCII.GetString($h, 0, 8)
  if ($magic -ne 'ANDROID!') { throw "Not an Android boot image (magic: $magic)" }
  $hv  = [BitConverter]::ToUInt32($h, 40)
  if ($hv -gt 4) { $hv = 0 }  # Samsung "mkbootimg --dt": DT size at this offset, header v0
  $off = if ($hv -ge 3) { 16 } else { 44 }
  $v   = [BitConverter]::ToUInt32($h, $off)
  $lvl = $v -band 0x7FF
  $y   = ($lvl -shr 4) + 2000
  $m   = $lvl -band 0xF
  $a   = ($v -shr 25) -band 0x7F
  $b   = ($v -shr 18) -band 0x7F
  $c   = ($v -shr 11) -band 0x7F
  [pscustomobject]@{
    HeaderVersion = $hv
    OsVersion     = "$a.$b.$c"
    PatchLevel    = ('{0:D4}-{1:D2}' -f $y, $m)
  }
}

# Release and compiler (clang version) from the kernel banner of a boot image.
function Get-BootKernelInfo([byte[]]$d) {
  $none = [pscustomobject]@{ Release = $null; Compiler = $null }
  $hv = [BitConverter]::ToUInt32($d, 40)
  if ($hv -gt 4) { $hv = 0 }
  $kSize = [BitConverter]::ToUInt32($d, 8)
  $page = if ($hv -ge 3) { 4096 } else { [BitConverter]::ToUInt32($d, 36) }
  if ($kSize -eq 0 -or $page + $kSize -gt $d.Length) { return $none }
  try {
    $k = [FoxUnpack3]::Decompress($d, [int]$page, [int]$kSize)
    return [pscustomobject]@{ Release = [FoxUnpack3]::KernelRelease($k); Compiler = [FoxUnpack3]::KernelCompiler($k) }
  } catch { return $none }
}

function Read-VendorBoot([byte[]]$d) {
  $hv = [BitConverter]::ToUInt32($d, 8)
  if ($hv -ne 3) { throw "vendor_boot header v$hv is not supported (v3 expected)" }
  $page = [BitConverter]::ToUInt32($d, 12)
  $rSize = [BitConverter]::ToUInt32($d, 24)
  $hSize = [BitConverter]::ToUInt32($d, 2096)
  $rOff = [int]([math]::Ceiling($hSize / $page) * $page)
  $raw = [FoxUnpack3]::Decompress($d, $rOff, [int]$rSize)
  $prop = $null; $vermagic = $null; $kmodCompiler = $null
  $p = 0
  while ($p -lt $raw.Length -and ($null -eq $prop -or $null -eq $vermagic)) {
    $hdr = [Text.Encoding]::ASCII.GetString($raw, $p, 110)
    if (-not $hdr.StartsWith('07070')) { break }
    $fsize = [Convert]::ToInt32($hdr.Substring(54, 8), 16)
    $nsize = [Convert]::ToInt32($hdr.Substring(94, 8), 16)
    $p += 110
    $name = [Text.Encoding]::ASCII.GetString($raw, $p, $nsize - 1).TrimStart('/')
    $p = ($p + $nsize + 3) -band -bnot 3
    if ($name -eq 'TRAILER!!!') { break }
    if ($name -eq 'prop.default') { $prop = [Text.Encoding]::ASCII.GetString($raw, $p, $fsize) }
    elseif ($null -eq $vermagic -and $name -like 'lib/modules/*.ko') {
      $koText = [Text.Encoding]::ASCII.GetString($raw, $p, $fsize)
      $m = [regex]::Match($koText, 'vermagic=([^\x00 ]+)')
      if ($m.Success) { $vermagic = $m.Groups[1].Value }
      $c = [regex]::Match($koText, 'clang version ([0-9.]+)')
      if ($c.Success) { $kmodCompiler = $c.Groups[1].Value }
    }
    $p = ($p + $fsize + 3) -band -bnot 3
  }
  if (-not $prop) { throw 'prop.default not found in the vendor_boot ramdisk' }
  $rel = ([regex]::Match($prop, '(?m)^ro\.build\.version\.release=(.*)$')).Groups[1].Value.Trim()
  $spl = ([regex]::Match($prop, '(?m)^ro\.build\.version\.security_patch=(.*)$')).Groups[1].Value.Trim()
  $parts = @($rel.Split('.')) + @('0', '0')
  $dev = $null
  foreach ($k in 'ro.product.device', 'ro.product.system.device', 'ro.product.vendor.device') {
    $m = [regex]::Match($prop, '(?m)^' + [regex]::Escape($k) + '=(.*)$')
    if ($m.Success) { $dev = $m.Groups[1].Value.Trim(); break }
  }
  [pscustomobject]@{
    Kind          = 'vendor_boot'
    Device        = $dev
    HeaderVersion = $hv
    OsVersion     = '{0}.{1}.{2}' -f $parts[0], $parts[1], $parts[2]
    PatchLevel    = if ($spl.Length -ge 7) { $spl.Substring(0, 7) } else { $spl }
    PatchDate     = $spl
    Vermagic      = $vermagic
    KmodCompiler  = $kmodCompiler
  }
}

# ro.product.device from the ramdisk of a boot or recovery image (header v0-v2).
# Returns $null when the ramdisk cannot be read.
function Get-RamdiskDevice([byte[]]$d) {
  try {
    $hv = [BitConverter]::ToUInt32($d, 40)
    if ($hv -gt 4) { $hv = 0 }
    if ($hv -ge 3) { return $null }
    $kSize = [BitConverter]::ToUInt32($d, 8)
    $rSize = [BitConverter]::ToUInt32($d, 16)
    $page = [BitConverter]::ToUInt32($d, 36)
    $rOff = [int]($page + [math]::Ceiling($kSize / $page) * $page)
    if ($rSize -eq 0 -or $rOff + $rSize -gt $d.Length) { return $null }
    $raw = [FoxUnpack3]::Decompress($d, $rOff, [int]$rSize)
    $p = 0
    while ($p + 110 -le $raw.Length) {
      $hdr = [Text.Encoding]::ASCII.GetString($raw, $p, 110)
      if (-not $hdr.StartsWith('07070')) { break }
      $mode  = [Convert]::ToInt32($hdr.Substring(14, 8), 16)
      $fsize = [Convert]::ToInt32($hdr.Substring(54, 8), 16)
      $nsize = [Convert]::ToInt32($hdr.Substring(94, 8), 16)
      $p += 110
      $name = [Text.Encoding]::ASCII.GetString($raw, $p, $nsize - 1).TrimStart('/')
      $p = ($p + $nsize + 3) -band -bnot 3
      if ($name -eq 'TRAILER!!!') { break }
      if (($name -eq 'prop.default' -or $name -eq 'default.prop') -and ($mode -band 0xF000) -eq 0x8000) {
        $prop = [Text.Encoding]::ASCII.GetString($raw, $p, $fsize)
        $m = [regex]::Match($prop, '(?m)^ro\.product\.device=(.*)$')
        if (-not $m.Success) { $m = [regex]::Match($prop, '(?m)^ro\.product\.system\.device=(.*)$') }
        if ($m.Success) { return $m.Groups[1].Value.Trim() }
        return $null
      }
      $p = ($p + $fsize + 3) -band -bnot 3
    }
  } catch { }
  return $null
}

function Read-ImgBytes([byte[]]$d) {
  $magic = [Text.Encoding]::ASCII.GetString($d, 0, 8)
  if ($magic -eq 'VNDRBOOT') { return Read-VendorBoot $d }
  $info = Read-OsVersion $d
  $info | Add-Member -NotePropertyName Kind -NotePropertyValue 'boot'
  $ki = Get-BootKernelInfo $d
  $info | Add-Member -NotePropertyName KernelRelease -NotePropertyValue $ki.Release
  $info | Add-Member -NotePropertyName KernelCompiler -NotePropertyValue $ki.Compiler
  return $info
}

function Read-ImgFile([string]$path) {
  return Read-ImgBytes ([IO.File]::ReadAllBytes($path))
}

# Bytes of a recovery image, or of the image inside an OrangeFox installer zip
# (recovery.img, or the first .img entry with an ANDROID! or VNDRBOOT header).
function Read-RecoveryBytes([string]$path) {
  $full = (Resolve-Path $path).Path
  $b = [IO.File]::ReadAllBytes($full)
  if ($b.Length -lt 4 -or $b[0] -ne 0x50 -or $b[1] -ne 0x4B) { return ,$b }
  $zf = [IO.Compression.ZipFile]::OpenRead($full)
  try {
    $entries = @($zf.Entries | Where-Object { $_.FullName -ieq 'recovery.img' }) + @($zf.Entries | Where-Object { $_.FullName -like '*.img' -and $_.FullName -ine 'recovery.img' })
    foreach ($e in $entries) {
      $ms = New-Object IO.MemoryStream
      $s = $e.Open()
      try { $s.CopyTo($ms) } finally { $s.Close() }
      $d = $ms.ToArray()
      if ($d.Length -ge 8) {
        $magic = [Text.Encoding]::ASCII.GetString($d, 0, 8)
        if ($magic -eq 'ANDROID!' -or $magic -eq 'VNDRBOOT') {
          Write-Host "Recovery zip   : using $($e.FullName) from $(Split-Path $full -Leaf)"
          return ,$d
        }
      }
    }
  } finally { $zf.Dispose() }
  throw "No recovery image (ANDROID! or VNDRBOOT header) found in $full"
}

function Find-PayloadTool {
  if ($PayloadTool) {
    if (Test-Path $PayloadTool) { return (Resolve-Path $PayloadTool).Path }
    throw "PayloadTool not found: $PayloadTool"
  }
  if ($GoDumper -and (Test-Path $GoDumper)) { return (Resolve-Path $GoDumper).Path }
  foreach ($name in 'payload-dumper-go.exe', 'payload_dumper.exe') {
    $local = Join-Path $PSScriptRoot $name
    if (Test-Path $local) { return $local }
  }
  $cmd = Get-Command 'payload-dumper-go' -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  if ($MikDir -and (Test-Path $MikDir)) {
    $all = Get-ChildItem $MikDir -Recurse -Include 'payload-dumper*.exe', 'payload_dumper*.exe' -ErrorAction SilentlyContinue
    $go = $all | Where-Object { $_.Name -like 'payload-dumper-go*' } | Select-Object -First 1
    if ($go) { return $go.FullName }
    $any = $all | Select-Object -First 1
    if ($any) { return $any.FullName }
  }
  return $null
}

function Select-WorkDir([long]$needBytes) {
  $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -gt 0 }
  $tempDrive = (Split-Path -Qualifier $env:TEMP).TrimEnd(':')
  $tempFree = ($drives | Where-Object { $_.Name -eq $tempDrive } | Select-Object -First 1).Free
  Write-Host ('This is an A/B package: payload.bin needs about {0:N1} GB of temporary space.' -f ($needBytes / 1GB))
  foreach ($d in $drives) { Write-Host ('  {0}: {1:N1} GB free' -f $d.Name, ($d.Free / 1GB)) }
  $default = $env:TEMP
  if (-not $tempFree -or $tempFree -lt $needBytes) {
    $best = $drives | Sort-Object Free -Descending | Select-Object -First 1
    $default = Join-Path $best.Root 'tmp'
    Write-Host "Not enough space on ${tempDrive}:, suggesting $default"
  }
  $ans = Read-Host "Temporary folder (Enter = $default)"
  if ([string]::IsNullOrWhiteSpace($ans)) { $ans = $default }
  $ans = $ans.Trim('"')
  if ($ans -match '^[A-Za-z]:?$') { $ans = $ans.Substring(0, 1) + ':\tmp' }
  return $ans
}

function Get-PayloadFile([string]$zipPath, [string]$tmp) {
  Write-Host 'Extracting payload.bin from the zip (this can take a while)...'
  $pl = Join-Path $tmp 'payload.bin'
  $zf = [IO.Compression.ZipFile]::OpenRead($zipPath)
  try { [IO.Compression.ZipFileExtensions]::ExtractToFile($zf.GetEntry('payload.bin'), $pl) }
  finally { $zf.Dispose() }
  return $pl
}

# Partition names written by an A/B package, read from the payload.bin manifest only
# (no extraction). Returns $null when the manifest cannot be read.
function Get-PayloadPartitions([string]$zipPath, [string]$payloadPath) {
  try {
    if ($zipPath) {
      $zf = [IO.Compression.ZipFile]::OpenRead($zipPath)
      try {
        $s = $zf.GetEntry('payload.bin').Open()
        try { return ,[FoxPayload1]::Partitions($s) } finally { $s.Close() }
      } finally { $zf.Dispose() }
    }
    $s = [IO.File]::OpenRead($payloadPath)
    try { return ,[FoxPayload1]::Partitions($s) } finally { $s.Close() }
  } catch { return $null }
}

function Invoke-GoDumper([string]$tool, [string]$inputPath, [string]$zipPath, [string]$out, [string]$tmp) {
  & $tool -p boot -o $out $inputPath | Out-Host
  $img = Get-ChildItem $out -Recurse -Filter 'boot.img' -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $img -and $zipPath) {
    $pl = Get-PayloadFile $zipPath $tmp
    & $tool -p boot -o $out $pl | Out-Host
    $img = Get-ChildItem $out -Recurse -Filter 'boot.img' -ErrorAction SilentlyContinue | Select-Object -First 1
  }
  return $img
}

function Invoke-Vm03Dumper([string]$tool, [string]$payloadPath, [string]$out) {
  Write-Host 'This tool extracts every partition in order; it will be stopped as soon as boot.img is complete.'
  $argList = @('--out', ('"' + $out + '"'), ('"' + $payloadPath + '"'))
  $p = Start-Process -FilePath $tool -ArgumentList $argList -WorkingDirectory (Split-Path $out) -NoNewWindow -PassThru
  $boot = Join-Path $out 'boot.img'
  while (-not $p.HasExited) {
    if (Test-Path $boot) {
      $bootTime = (Get-Item $boot).LastWriteTime
      $next = Get-ChildItem $out -Filter '*.img' -ErrorAction SilentlyContinue |
              Where-Object { $_.Name -ne 'boot.img' -and $_.CreationTime -ge $bootTime }
      if ($next) {
        Write-Host 'boot.img complete, stopping the payload tool.'
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        break
      }
    }
    Start-Sleep -Milliseconds 500
  }
  $p.WaitForExit()
  if (Test-Path $boot) { return Get-Item $boot }
  return $null
}

function Get-BootFromPayload([string]$inputPath, [string]$zipPath) {
  $tool = Find-PayloadTool
  if (-not $tool) {
    throw "payload.bin found but no payload tool was found. Use -PayloadTool or -MikDir, or extract boot.img with Multi Image Kitchen and pass it with -BootImg."
  }
  Write-Host "Using payload tool: $tool"
  $tmp = Join-Path $WorkDir ('patchcheck_' + [guid]::NewGuid().ToString('N'))
  $out = Join-Path $tmp 'out'
  New-Item -ItemType Directory -Path $out -Force | Out-Null
  $oldTmp = $env:TMP; $oldTemp = $env:TEMP
  $env:TMP = $tmp; $env:TEMP = $tmp
  try {
    if ((Split-Path $tool -Leaf) -like 'payload-dumper-go*') {
      $img = Invoke-GoDumper $tool $inputPath $zipPath $out $tmp
    }
    else {
      $pl = if ($zipPath) { Get-PayloadFile $zipPath $tmp } else { $inputPath }
      $img = Invoke-Vm03Dumper $tool $pl $out
    }
    if (-not $img) { throw 'payload tool ran but no boot.img was produced. Extract it with Multi Image Kitchen and use -BootImg.' }
    return Read-ImgFile $img.FullName
  }
  finally {
    $env:TMP = $oldTmp; $env:TEMP = $oldTemp
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
  }
}

if (-not $Zip -and -not $BootImg) {
  $rbytes = Read-RecoveryBytes $RecoveryImg
  $rinfo = Read-ImgBytes $rbytes
  $rdev = if ($rinfo.Kind -eq 'boot') { Get-RamdiskDevice $rbytes } else { $null }
  Write-Host "Recovery header: Android $($rinfo.OsVersion), patch $($rinfo.PatchLevel)"
  if ($rdev) { Write-Host "Recovery device: $rdev" }
  if ($rdev -and $NoDecrypt.ContainsKey($rdev)) {
    Write-Host "RESULT: this $rdev recovery does not decrypt /data, so it does not depend on the ROM's security patch or kernel. $($NoDecrypt[$rdev]). On a ROM that encrypts /data, the data partition stays unreadable in this recovery." -ForegroundColor Green
    exit 0
  }
  throw 'This recovery depends on the ROM build. Give -Zip <ota.zip | payload.bin> or -BootImg <boot.img> as well.'
}

$metaPatch = $null
$metaDevice = $null
$boot = $null
$payloadParts = $null

if ($BootImg) {
  $boot = Read-ImgFile (Resolve-Path $BootImg).Path
}
else {
  $zipFull = (Resolve-Path $Zip).Path
  if ([IO.Path]::GetFileName($zipFull) -ieq 'payload.bin') {
    $payloadParts = Get-PayloadPartitions $null $zipFull
    $boot = Get-BootFromPayload $zipFull $null
  }
  else {
    $zf = [IO.Compression.ZipFile]::OpenRead($zipFull)
    $hasPayload = $false
    try {
      $meta = $zf.GetEntry('META-INF/com/android/metadata')
      if ($meta) {
        $sr = New-Object IO.StreamReader($meta.Open())
        $text = $sr.ReadToEnd()
        $sr.Close()
        $line = ($text -split "`r?`n") | Where-Object { $_ -like 'post-security-patch-level=*' } | Select-Object -First 1
        if ($line) { $metaPatch = $line.Split('=')[1].Trim() }
        $dline = ($text -split "`r?`n") | Where-Object { $_ -like 'pre-device=*' } | Select-Object -First 1
        if ($dline) { $metaDevice = $dline.Split('=')[1].Split(',')[0].Trim() }
      }
      $bootEntry = $zf.GetEntry('boot.img')
      if ($bootEntry) {
        $ms = New-Object IO.MemoryStream
        $s = $bootEntry.Open()
        try { $s.CopyTo($ms) } finally { $s.Close() }
        $boot = Read-ImgBytes $ms.ToArray()
      }
      elseif ($zf.GetEntry('payload.bin')) {
        $hasPayload = $true
        $payloadSize = $zf.GetEntry('payload.bin').Length
      }
      else { throw 'Neither boot.img nor payload.bin found in the zip' }
    }
    finally { $zf.Dispose() }
    if ($hasPayload) {
      $payloadParts = Get-PayloadPartitions $zipFull $null
      if (-not $workDirGiven) { $WorkDir = Select-WorkDir ([long]($payloadSize * 1.05) + 200MB) }
      $boot = Get-BootFromPayload $zipFull $zipFull
    }
  }
}

if ($metaDevice) { Write-Host "OTA device     : $metaDevice" }
if ($metaPatch) { Write-Host "OTA metadata   : security patch $metaPatch" }
Write-Host "Boot header    : Android $($boot.OsVersion), patch $($boot.PatchLevel) (header v$($boot.HeaderVersion))"
if ($boot.KernelRelease) { Write-Host "Boot kernel    : $($boot.KernelRelease)$(if ($boot.KernelCompiler) { ", clang $($boot.KernelCompiler)" })" }
if ($payloadParts) {
  $bootParts = @($payloadParts | Where-Object { $_ -in 'boot', 'init_boot', 'vendor_boot', 'dtbo', 'recovery' })
  Write-Host ("OTA writes     : {0} partitions, including {1}" -f $payloadParts.Count, ($bootParts -join ', '))
}

if ($RecoveryImg) {
  $recBytes = Read-RecoveryBytes $RecoveryImg
  $rec = Read-ImgBytes $recBytes
  $kernelProblem = $null
  if ($rec.Kind -eq 'vendor_boot') {
    Write-Host "Recovery props : Android $($rec.OsVersion), patch $($rec.PatchDate) (vendor_boot v$($rec.HeaderVersion))"
    Write-Host "Recovery kmods : $(if ($rec.Vermagic) { $rec.Vermagic } else { '(no modules found)' })$(if ($rec.KmodCompiler) { ", clang $($rec.KmodCompiler)" })"
    if (-not $boot.KernelRelease) {
      $kernelProblem = 'the ROM kernel release could not be read from boot.img; compare the module version by hand'
    }
    elseif ($rec.Vermagic -and $rec.Vermagic -ne $boot.KernelRelease) {
      $kernelProblem = "the kernel modules in this vendor_boot were built for $($rec.Vermagic), the ROM kernel is $($boot.KernelRelease). vendor_boot is also used for the normal Android boot, so flashing it can stop Android from booting"
    }
    # Same release string, different compiler: the kernel was rebuilt (bramble: LineageOS 23.2
    # with clang 21.0.0, 24.0 with clang 22.0.2, both 4.19.325-cip136-st20-g2af5306961ae, all
    # 221 modules differ).
    $kernelRebuilt = (-not $kernelProblem) -and $rec.KmodCompiler -and $boot.KernelCompiler -and ($rec.KmodCompiler -ne $boot.KernelCompiler)
  }
  else {
    Write-Host "Recovery header: Android $($rec.OsVersion), patch $($rec.PatchLevel)"
  }
  $recDevice = $null
  if ($rec.Kind -eq 'boot') {
    $recDevice = Get-RamdiskDevice $recBytes
  }
  elseif ($rec.Device) { $recDevice = $rec.Device }
  if ($recDevice) { Write-Host "Recovery device: $recDevice" }
  $skipPatchCheck = $recDevice -and $NoDecrypt.ContainsKey($recDevice)
  $recName = Split-Path $RecoveryImg -Leaf
  $deviceMismatch = $metaDevice -and $(if ($recDevice) { $recDevice -ne $metaDevice } else { $recName -notmatch [regex]::Escape($metaDevice) })
  $patchMatch = ($rec.OsVersion -eq $boot.OsVersion -and $rec.PatchLevel -eq $boot.PatchLevel)
  $target = if ($metaPatch) { $metaPatch } else { "$($boot.PatchLevel)-01 (check the exact day)" }
  if ($deviceMismatch) {
    if ($recDevice) { Write-Host "WARNING: the recovery is built for '$recDevice', the OTA for '$metaDevice'." -ForegroundColor Red }
    else { Write-Host "WARNING: the recovery file name does not mention '$metaDevice'." -ForegroundColor Red }
    if ($patchMatch) {
      Write-Host "RESULT: patch levels match, but the files appear to belong to different devices. Do not flash this recovery for $metaDevice." -ForegroundColor Red
    }
    else {
      Write-Host "RESULT: patch levels differ and the files appear to belong to different devices. A $metaDevice recovery needs PLATFORM_SECURITY_PATCH := $target" -ForegroundColor Red
    }
  }
  elseif ($skipPatchCheck) {
    Write-Host "RESULT: this $recDevice recovery does not decrypt /data, so the ROM's security patch and kernel do not have to match. $($NoDecrypt[$recDevice]). On a ROM that encrypts /data, the data partition stays unreadable in this recovery." -ForegroundColor Green
  }
  elseif ($rec.Kind -eq 'vendor_boot') {
    # vendor_boot recovery: the boot verdict comes from the kernel modules. The patch level in
    # prop.default decides decryption: the QTI keymaster binds the metadata key to the patch
    # level of the system that last used it. Tested on bramble (LineageOS 23.2-20261010, key
    # upgraded to 2026-10 by Android; recovery 2026-09-01): begin returned -62
    # (KEY_REQUIRES_UPGRADE), upgradeKey -38, /data stayed encrypted, the key was not changed.
    if (-not $boot.KernelRelease) {
      Write-Host "RESULT: $kernelProblem." -ForegroundColor Yellow
    }
    elseif ($kernelProblem) {
      Write-Host "RESULT: do not flash: $kernelProblem." -ForegroundColor Red
    }
    elseif ($kernelRebuilt) {
      Write-Host "RESULT: do not flash: the version strings match, but the ROM kernel was built with clang $($boot.KernelCompiler) and the modules in this vendor_boot with clang $($rec.KmodCompiler). The kernel was rebuilt; these modules have not been tested with it. Use an image built from this ROM's vendor_boot." -ForegroundColor Red
    }
    else {
      Write-Host 'RESULT: match, the kernel modules fit this ROM kernel' -ForegroundColor Green
    }
    if (-not $patchMatch) {
      $recMonth = if ($rec.PatchDate.Length -ge 7) { $rec.PatchDate.Substring(0, 7) } else { $rec.PatchDate }
      $recOs = [int]($rec.OsVersion.Split('.')[0]); $romOs = [int]($boot.OsVersion.Split('.')[0])
      if ($recOs -lt $romOs -and [string]::CompareOrdinal($recMonth, $boot.PatchLevel) -le 0) {
        Write-Host "DECRYPT: no. The recovery reports Android $recOs, the ROM Android $romOs. Keymaster binds the metadata key to the Android version as well as the patch level; once the ROM has started, a recovery with a lower value is expected to fail as it does with a lower patch (error -38, measured), and /data stays encrypted. Build the recovery with PLATFORM_VERSION := $romOs." -ForegroundColor Yellow
      }
      elseif ($recOs -gt $romOs) {
        Write-Host "DECRYPT: do not decrypt with this image. The recovery reports Android $recOs, higher than the ROM's Android $romOs; keymaster can upgrade the metadata key, and the ROM can then no longer unlock /data." -ForegroundColor Red
      }
      elseif ([string]::CompareOrdinal($recMonth, $boot.PatchLevel) -lt 0) {
        Write-Host "DECRYPT: no. The recovery reports patch $($rec.PatchDate), the ROM $($boot.PatchLevel). Once the ROM has started, keymaster refuses the metadata key in this recovery (error -38) and /data stays encrypted; the key is not changed. Android still starts if RESULT is a match. Decryption needs a recovery built with PLATFORM_SECURITY_PATCH := $target." -ForegroundColor Yellow
      }
      elseif ([string]::CompareOrdinal($recMonth, $boot.PatchLevel) -gt 0) {
        Write-Host "DECRYPT: do not decrypt with this image. The recovery reports patch $($rec.PatchDate), higher than the ROM's $($boot.PatchLevel); keymaster can upgrade the metadata key to that level, and the ROM can then no longer unlock /data." -ForegroundColor Red
      }
      else {
        Write-Host "NOTE: the recovery reports Android $($rec.OsVersion), the ROM boot header Android $($boot.OsVersion); the patch level matches." -ForegroundColor Yellow
      }
    }
    # What a ROM install leaves in vendor_boot. An A/B package (LineageOS Updater, or
    # installing the zip in OrangeFox) writes the inactive slot. For FOX_VENDOR_BOOT_RECOVERY
    # with BOARD_BOOT_HEADER_VERSION 3, fox_12.1 orangefox.mk sets
    # OF_NO_REFLASH_CURRENT_ORANGEFOX, so tw_auto_reflashtwrp defaults to 0 and is hidden, and
    # orangefox.cpp does not call Flash_Current_Twrp() after the ROM install.
    if ($payloadParts -and ($payloadParts -contains 'vendor_boot')) {
      Write-Host 'ROM INSTALL: Android starts. The package writes its own vendor_boot to the inactive slot, whether the LineageOS Updater or OrangeFox installs it, and OrangeFox does not write itself back there. OrangeFox is gone from that slot until it is installed again; RESULT above says whether this image may be.' -ForegroundColor Green
    }
    elseif ($payloadParts) {
      if ($kernelProblem -or $kernelRebuilt) {
        Write-Host 'ROM INSTALL: the package does not write vendor_boot, so the new slot keeps the vendor_boot it has. If that slot holds this image, its modules do not fit and Android may not start (see RESULT). Flash a vendor_boot that matches the ROM kernel to that slot first.' -ForegroundColor Red
      }
      else {
        Write-Host 'ROM INSTALL: the package does not write vendor_boot, so the new slot keeps the vendor_boot it has. With this image there, the modules fit and Android starts; check any other image in that slot with this script.' -ForegroundColor Yellow
      }
    }
    elseif (-not $Zip) {
      Write-Host 'ROM INSTALL: not checked. Give the ROM package with -Zip to see whether it writes vendor_boot.'
    }
  }
  elseif ($kernelProblem -and $boot.KernelRelease) {
    Write-Host "RESULT: do not flash: $kernelProblem." -ForegroundColor Red
    if (-not $patchMatch) { Write-Host "The patch level also differs; a rebuild needs PLATFORM_SECURITY_PATCH := $target" -ForegroundColor Red }
  }
  elseif ($patchMatch) {
    if ($kernelProblem) {
      Write-Host "RESULT: patch levels match, but $kernelProblem." -ForegroundColor Yellow
    } else {
      Write-Host 'RESULT: match, no rebuild needed' -ForegroundColor Green
    }
  }
  else {
    Write-Host "RESULT: mismatch, rebuild with PLATFORM_SECURITY_PATCH := $target" -ForegroundColor Yellow
  }
}
