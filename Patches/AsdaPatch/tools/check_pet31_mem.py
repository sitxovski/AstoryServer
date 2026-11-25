# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# check_pet31_mem.py — ТОЛЬКО ЧТЕНИЕ: что реально загрузил каждый GameServer стойки из PetData_Info\PetInfo_Table.txt
#   (29.10.2026, строка 31 «SnowLion», build_pet31.py / deploy_pet31.py). По SSH читает память процессов GameServer.exe
#   (ReadProcessMemory, PROCESS_VM_READ): ищет в образе пару «указатель на таблицу + счётчик int16» загрузчика
#   как в server_work; до выкладки счётчик был 31), проверяет,
#   что запись 0 = «none», и печатает счётчик и запись 31 (60 б: id, имя, +18…+21, +22/+26/+30, 3 пары, +52, +56).
#   Гейт Recv_IncubatorReq `0 ≤ тип < счётчик` (:34623) для яйца 76338 (тип 31) проходит, если счётчик ≥ 32.
# Запуск: python check_pet31_mem.py. Ничего не пишет ни на сервере, ни в процессах.
import base64
import subprocess
import sys

SSH = ["ssh", "-i", r"C:\Users\@@ASTORY_DEV_USER@@\.ssh\@@ASTORY_SSH_KEY_NAME@@", "-o", "BatchMode=yes", "Administrator@@@ASTORY_SERVER_VPN_IP@@"]

PS = r'''
Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public static class Rpm {
  [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(int a, bool b, int pid);
  [DllImport("kernel32.dll")] public static extern bool ReadProcessMemory(IntPtr h, IntPtr adr, byte[] buf, int n, out int rd);
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
  public static byte[] Read(IntPtr h, long adr, int n) { var b = new byte[n]; int rd; if (!ReadProcessMemory(h, new IntPtr(adr), b, n, out rd) || rd != n) return null; return b; }
}
"@
foreach ($p in Get-Process GameServer -ErrorAction SilentlyContinue) {
  $dir = Split-Path (Split-Path $p.Path -Parent) -Leaf
  $h = [Rpm]::OpenProcess(0x0410, $false, $p.Id)
  $lo = 0x7C0000; $n = 0x40000
  $blk = [Rpm]::Read($h, $lo, $n)
  $found = $false
  if ($blk -ne $null) {
    for ($o = 0; $o -le $n - 8; $o += 4) {
      $ptr = [BitConverter]::ToUInt32($blk, $o); $cnt = [BitConverter]::ToInt16($blk, $o + 4)
      if ($cnt -lt 20 -or $cnt -gt 400 -or $ptr -lt 0x10000) { continue }
      $r0 = [Rpm]::Read($h, $ptr, 60)
      if ($r0 -eq $null -or [BitConverter]::ToInt16($r0, 0) -ne 0 -or [Text.Encoding]::ASCII.GetString($r0, 2, 4) -ne 'none') { continue }
      $line = "{0}|pid {1}|table@0x{2:X} ptr 0x{3:X} count {4}" -f $dir, $p.Id, ($lo + $o), $ptr, $cnt
      if ($cnt -gt 31) {
        $r = [Rpm]::Read($h, $ptr + 60 * 31, 60)
        $nm = [Text.Encoding]::ASCII.GetString($r, 2, 16).Split([char]0)[0]
        $v = @([BitConverter]::ToInt16($r, 0), $nm, $r[18], $r[19], $r[20], $r[21], [BitConverter]::ToInt32($r, 22), [BitConverter]::ToInt32($r, 26), [BitConverter]::ToInt32($r, 30))
        for ($j = 0; $j -lt 3; $j++) { $v += [BitConverter]::ToInt16($r, 34 + 6 * $j); $v += [BitConverter]::ToInt32($r, 36 + 6 * $j) }
        $v += [BitConverter]::ToInt32($r, 52); $v += [BitConverter]::ToInt32($r, 56)
        $line += "|rec31 " + ($v -join ' ')
      }
      Write-Output $line; $found = $true; break
    }
  }
  if (-not $found) { Write-Output ("{0}|pid {1}|таблица не найдена" -f $dir, $p.Id) }
  [void][Rpm]::CloseHandle($h)
}
'''

WANT = "31 SnowLion 2 0 4 20 17 13 22 10 18 13 18 0 0 7 56571"


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    enc = base64.b64encode(PS.encode("utf-16-le")).decode()
    p = subprocess.run(SSH + ["powershell -NoProfile -EncodedCommand " + enc], capture_output=True, timeout=180)
    txt = p.stdout.decode("cp866", "replace")
    good = 0
    rows = [l for l in txt.splitlines() if "|pid " in l]
    for l in rows:
        ok = " count 32|" in l and l.endswith("rec31 " + WANT)
        good += ok
        print(("OK   " if ok else "НЕТ  ") + l)
    if not rows:
        print(txt, p.stderr.decode("cp866", "replace"))
    print("ИТОГ: %d из %d GameServer держат строку 31 «SnowLion»" % (good, len(rows)))
    return 0 if rows and good == len(rows) else 5


if __name__ == "__main__":
    sys.exit(main())
