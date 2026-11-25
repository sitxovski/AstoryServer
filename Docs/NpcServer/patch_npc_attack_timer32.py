# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# patch_npc_attack_timer32.py — ПОЧИНКА АНТИЧИТА СКОРОСТИ АТАКИ (16-битный счётчик → 32-битный).
#
# ЧТО ЧИНИМ
#   NpcServer проверяет, не слишком ли часто игрок бьёт. Момент последнего удара он ХРАНИТ как
#   32-битный тик (`mov [ebp+0FE90h], eax` — 4 байта), а СРАВНИВАЕТ по младшим 16 битам:
#
#       mov  dx, di                      ; dx = младшие 16 бит текущего тика
#       sub  dx, [ebp+0FE90h]            ; ← 16-битное вычитание
#       add  dx, 64h                     ; +100 мс допуска
#       movzx ecx, dx
#       movzx ecx, cx
#       cmp  ecx, eax                    ; eax = требуемый интервал (+0FE94h, знаковое слово)
#       jge  <удар засчитан>
#
#   Арифметика по модулю 65536 работает верно, ПОКА реальная пауза меньше ~65,4 с. Стоит игроку
#   не бить дольше — разность заворачивается и выходит маленькой. Тогда:
#     [--] удар МОЛЧА отбрасывается (ни урона, ни ответа клиенту — единственный такой silent drop
#       в боевом пути),
#     [--] счётчик нарушений `+0FE60h` увеличивается на 1,
#     [--] поле «момент последнего удара» в этой ветке НЕ обновляется, поэтому следующие удары
#       ещё какое-то время тоже попадают в завёрнутое окно — отбрасывается СЕРИЯ,
#     [--] при счётчике > 30 сервер шлёт 8905 и выкидывает игрока.
#
#   Симптом в игре: после паузы дольше минуты первые удары «не проходят» — персонаж бьёт, а
#   ничего не происходит. Ровно жалоба владельца «то атакует, то не атакует».
#
# ЧТО ДЕЛАЕМ
#   Переводим вычисление в 32 бита — ровно то, чем оно и должно быть, раз тик хранится 32-битным.
#   Длина кода сохраняется байт в байт, хвост добивается `nop`, переходы и границы функций не
#   двигаются. Логика проверки НЕ меняется: тот же порог, тот же допуск 100 мс, тот же счётчик.
#
# ГДЕ (VA, образ NpcServer.exe md5 d292e4ec4edfd5040d8fb39382664eab — совпадает с живым)
#   Площадка 1 — `CAi::Process_AttackedToMonster`, VA 0x45F5A4, 20 байт.
#   Площадка 2 — функция-двойник (второй «SpeedHack Check»), VA 0x460151, 17 байт,
#                плюс VA 0x460169 — 3 байта повторного усечения `movzx ecx, cx`.
#
# ЗАПУСК
#   python patch_npc_attack_timer32.py <исходный NpcServer.exe> <куда_писать.exe>
#   Без аргументов берёт `RE/ida/npc_work/NpcServer.exe` и пишет `out/NpcServer.timer32.exe`.
#
# ★ Скрипт НИЧЕГО не пишет на серверную шару и не трогает живой сервер. Он только готовит файл;
#   подменяет и перезапускает процесс ВЛАДЕЛЕЦ.
import os, sys, struct, hashlib

# Консоль Windows бывает в cp1251 — не роняем скрипт на непечатаемом символе.
try:
    sys.stdout.reconfigure(errors="replace")
except Exception:
    pass

SRC_MD5 = "d292e4ec4edfd5040d8fb39382664eab"   # образ, на котором патч выверен (= живой сервер)

# (VA, ожидаемые байты, новые байты, пояснение)
PATCHES = [
    (0x45F5A4,
     bytes.fromhex("66 8b d7 66 2b 95 90 fe 00 00 66 83 c2 64 0f b7 ca 0f b7 c9".replace(" ", "")),
     bytes.fromhex("8b d7 2b 95 90 fe 00 00 83 c2 64 8b ca 90 90 90 90 90 90 90".replace(" ", "")),
     "Process_AttackedToMonster: mov dx,di / sub dx / add dx,100 / movzx*2 => 32-битный аналог"),
    (0x460151,
     bytes.fromhex("66 8b c7 66 2b 85 90 fe 00 00 66 05 64 00 0f b7 c8".replace(" ", "")),
     bytes.fromhex("8b c7 2b 85 90 fe 00 00 83 c0 64 8b c8 90 90 90 90".replace(" ", "")),
     "двойник: mov ax,di / sub ax / add ax,100 / movzx => 32-битный аналог"),
    (0x460169,
     bytes.fromhex("0fb7c9"),
     bytes.fromhex("909090"),
     "двойник: убрать повторное усечение movzx ecx,cx (иначе 32 бита снова обрежутся)"),
]


def sections(d):
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    n = struct.unpack_from("<H", d, pe + 6)[0]
    opt = struct.unpack_from("<H", d, pe + 20)[0]
    ib = struct.unpack_from("<I", d, pe + 24 + 28)[0]
    out = []
    for i in range(n):
        o = pe + 24 + opt + 40 * i
        vsz, va, rsz, ptr = struct.unpack_from("<IIII", d, o + 8)
        out.append((va, vsz, ptr, rsz))
    return ib, out


def va2off(ib, secs, va):
    for s_va, vsz, ptr, rsz in secs:
        if ib + s_va <= va < ib + s_va + vsz:
            return ptr + (va - ib - s_va)
    return None


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    src = sys.argv[1] if len(sys.argv) > 1 else os.path.normpath(
        os.path.join(here, "..", "..", "..", "ida", "npc_work", "NpcServer.exe"))
    dst = sys.argv[2] if len(sys.argv) > 2 else os.path.join(here, "out", "NpcServer.timer32.exe")

    if not os.path.isfile(src):
        print("НЕТ исходного файла: %s" % src)
        return 1
    data = bytearray(open(src, "rb").read())
    got = hashlib.md5(data).hexdigest()
    print("исходный:  %s" % src)
    print("md5:       %s%s" % (got, "" if got == SRC_MD5 else "   [!] НЕ совпадает с выверенным %s" % SRC_MD5))
    if got != SRC_MD5:
        print("[!] Патч выверен на другом образе. Проверка байтов ниже всё равно выполнится —")
        print("  если хоть одна площадка не совпадёт, файл записан НЕ БУДЕТ.")

    ib, secs = sections(data)
    applied = 0
    for va, old, new, why in PATCHES:
        off = va2off(ib, secs, va)
        if off is None:
            print("[!!] VA %#x вне секций — патч отменён" % va)
            return 2
        cur = bytes(data[off:off + len(old)])
        if cur == new:
            print("[--] VA %#x уже пропатчен, пропуск" % va)
            continue
        if cur != old:
            print("[!!] VA %#x: байты не совпали — патч отменён" % va)
            print("    ожидалось: %s" % old.hex(" "))
            print("    в файле:   %s" % cur.hex(" "))
            return 3
        data[off:off + len(old)] = new
        applied += 1
        print("[OK] VA %#x (%d b) - %s" % (va, len(old), why))

    if applied == 0:
        print("Менять нечего.")
        return 0

    os.makedirs(os.path.dirname(dst), exist_ok=True)
    open(dst, "wb").write(bytes(data))
    print()
    print("записан:   %s" % dst)
    print("md5:       %s" % hashlib.md5(bytes(data)).hexdigest())
    print()
    print("ДАЛЬШЕ (делает владелец, сервер останавливать и запускать ему):")
    print("  1. Сохранить резервную копию живого NpcServer.exe рядом, с датой в имени.")
    print("  2. Подменить NpcServer.exe этим файлом.")
    print("  3. Проверка — см. Docs/Port/systems/COMBAT_FIX_VERIFICATION.md, пачка 12.")
    print("  ОТКАТ: вернуть резервную копию.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
