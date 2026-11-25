# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# patch_npc_hate_clear_damage.py — РЕСПАУН МОНСТРА ЧИСТИТ НАКОПЛЕННЫЙ УРОН В СПИСКЕ УГРОЗЫ.
#
# ЧТО ЧИНИМ
#   У монстра есть список угрозы: 20 записей по 16 байт, начало `+31352`.
#       +0  i16  индекс игрока (0xFFFF = запись пуста)
#       +4  i32
#       +8  i32
#       +12 i32  накопленный урон  ← им решается, КОМУ достанется опыт и добыча
#
#   При респауне (`sub_43E300`) список чистится циклом, который обнуляет +0, +4 и +8, а **+12 не
#   трогает**. Значение переживает смерть монстра.
#
#   А поиск победителя (`NpcServer.exe.c:41195-41215`) начинается ТАК:
#       v3 = 0;                          // победитель по умолчанию — запись 0
#       v4 = *(int *)(a1 + 31364);       // её накопленный урон, БЕЗ проверки занятости
#       v6 = (int *)(a1 + 31380);        // дальше сравниваем с записями 1..19
#       do { if ( *((WORD *)v6 - 6) != 0xFFFF ) { … } … }   // ← занятость проверяется только у 1..19
#
#   То есть у записи 0 занятость не проверяется никогда. Если в ней остался мусор от прошлой
#   жизни монстра и он не меньше урона настоящих участников боя, победителем объявляется пустая
#   запись 0. Дальше сервер получает некорректный индекс владельца и уходит в раннюю ошибку —
#   теряются опыт, добыча и квестовый прогресс.
#
#   Реальное срабатывание найдено в журнале ошибок живого сервера: `Exception_20260803.txt:705`
#   («ItemOwnerIndex is invalid»). Полной потери за месяц логов не было — спасал запасной путь,
#   но добыча уходила игроку с индексом 0, то есть потенциально не тому.
#
# ЧТО ДЕЛАЕМ
#   Добавляем в цикл очистки обнуление +12. Ничего больше. Поиск победителя НЕ трогаем: без
#   мусора в записи 0 он перестаёт ошибаться на этом сценарии, а переписывать сам поиск негде —
#   свободной площадки в секции кода нет.
#
#   Цикл переписан так, чтобы уложиться в ТЕ ЖЕ 18 байт:
#       было:  nop / mov [eax+4],esi / mov [eax],esi / mov word [eax-4],di
#              add eax,16 / sub ecx,1 / jnz
#       стало: mov [eax+4],esi / mov [eax],esi / mov [eax+8],esi / mov word [eax-4],di
#              add eax,16 / dec ecx / jnz
#   Освободили байт выравнивания (nop) и два байта на замене `sub ecx,1` на `dec ecx` — ровно
#   три байта, сколько и нужно на новую запись. `esi` в этом месте уже равен нулю (им же
#   обнуляются два других поля), `di` = 0xFFFF. `dec` не трогает флаг переноса, а следующая за
#   циклом инструкция флаги не читает — поведение не меняется.
#
# ГДЕ
#   VA 0x43E42F, 18 байт (тело цикла в `sub_43E300`).
#
# ЗАПУСК
#   python patch_npc_hate_clear_damage.py <исходный.exe> <куда_писать.exe>
#   Без аргументов берёт `out/NpcServer.timer32.exe` (то, что сейчас на сервере) и пишет
#   `out/NpcServer.timer32_hate.exe`.
#
# ★ Скрипт НИЧЕГО не пишет на серверную шару и не трогает живой сервер. Он только готовит файл;
#   подменяет и перезапускает процесс ВЛАДЕЛЕЦ.
import os, sys, struct, hashlib

try:
    sys.stdout.reconfigure(errors="replace")
except Exception:
    pass

# Оба известных основания: сток и уже пропатченный таймер атаки.
KNOWN_BASES = {
    "d292e4ec4edfd5040d8fb39382664eab": "сток (= живой сервер до 24.08.2026)",
    "fbaacc45bd15335d9440218ddbec73ec": "после patch_npc_attack_timer32",
}

PATCHES = [
    (0x43E42F,
     bytes.fromhex("908970048930668978fc83c01083e90175ef"),
     bytes.fromhex("8970048930897008668978fc83c0104975ee"),
     "sub_43E300: цикл очистки списка угрозы теперь обнуляет и накопленный урон (+12)"),
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
    # По умолчанию берём то, что реально лежит в out/ (владелец мог переименовать при выкладке).
    src = sys.argv[1] if len(sys.argv) > 1 else None
    if src is None:
        for cand in ("NpcServer.timer32.exe", "NpcServer.exe"):
            p_ = os.path.join(here, "out", cand)
            if os.path.isfile(p_) and hashlib.md5(open(p_, "rb").read()).hexdigest() in KNOWN_BASES:
                src = p_
                break
        if src is None:
            src = os.path.join(here, "out", "NpcServer.timer32.exe")
    dst = sys.argv[2] if len(sys.argv) > 2 else os.path.join(here, "out", "NpcServer.timer32_hate.exe")

    if not os.path.isfile(src):
        print("НЕТ исходного файла: %s" % src)
        return 1
    data = bytearray(open(src, "rb").read())
    got = hashlib.md5(data).hexdigest()
    print("исходный:  %s" % src)
    print("md5:       %s  (%s)" % (got, KNOWN_BASES.get(got, "[!] основание НЕИЗВЕСТНО")))

    ib, secs = sections(data)
    applied = 0
    for va, old, new, why in PATCHES:
        off = va2off(ib, secs, va)
        if off is None:
            print("[!!] VA %#x вне секций - патч отменён" % va)
            return 2
        cur = bytes(data[off:off + len(old)])
        if cur == new:
            print("[--] VA %#x уже пропатчен, пропуск" % va)
            continue
        if cur != old:
            print("[!!] VA %#x: байты не совпали - патч отменён" % va)
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
    print("ДАЛЬШЕ (делает владелец):")
    print("  1. Сохранить резервную копию текущего NpcServer.exe с датой в имени.")
    print("  2. Подменить NpcServer.exe этим файлом, перезапустить процесс.")
    print("  3. Проверка - см. Docs/Port/systems/COMBAT_FIX_VERIFICATION.md, пачка 13.")
    print("  ОТКАТ: вернуть резервную копию.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
