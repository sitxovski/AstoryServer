# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# patch_quest_level_cap.py — СНЯТИЕ ВЕРХНЕЙ ГРАНИЦЫ УРОВНЯ У ПРИЁМА ЗАДАНИЙ.
#
# ЧТО ДЕЛАЕТ
#   Читает ОРИГИНАЛЬНЫЙ `NpcServer\Quest\ConditionTable.Bin` и пишет рядом копию, в которой у
#   каждой записи с включённой проверкой уровня (`+36 == 1`) верхняя граница `+38` поднята до
#   150. Нижняя граница `+37` НЕ трогается: «рано брать» остаётся запретом.
#
# ПОЧЕМУ ИМЕННО 150
#   Это НЕ произвольное число. `NpcServer!sub_41FD70` («CheckCondition») бракует запись, если
#   `iMax_Level > 0x96` (=150) — то есть 150 это максимум, который сервер вообще принимает:
#       if ( !BYTE1(a13) || BYTE2(a13) > 0x96u || (v33 = *(BYTE*)(a2+30858)) == 0 || v33 > 0x96u )
#           -> Error_Log "CheckCondition() CheckLevel Exception..."  и код 10
#       if ( BYTE1(a13) > v33 || BYTE2(a13) < v33 )   -> код 11
#   Кроме того, 150 — это значение, которым САМИ АВТОРЫ данных обозначают «потолка нет»:
#   у 487 из 806 записей с проверкой уровня верхняя граница уже равна 150.
#
# РАСКЛАДКА ЗАПИСИ (снята с дизассемблера, не с документации)
#   Запись 146 б. `sub_421020` передаёт в `sub_41FD70` DWORD, лежащий на `+36`:
#       a13 = *(int*)&cond[36]   ->  LOBYTE = «проверять уровень», BYTE1 = min, BYTE2 = max,
#                                    HIBYTE = «проверять класс» (это уже `+39`).
#   Загрузчик (`sub_421360`) кладёт запись НЕ по позиции в файле, а по её собственному индексу
#   `*(DWORD*)+0`. У всех непустых записей эти числа совпадают (проверено), поэтому позиция в
#   файле = индекс условия.
#
# ЗАПУСК
#   python patch_quest_level_cap.py <исходный ConditionTable.Bin> <куда_писать.Bin>
#   По умолчанию берёт файл рядом со скриптом в `out\ConditionTable.orig.Bin`.
#
# ★ Скрипт НИЧЕГО не пишет на серверную шару. Он только готовит файл; подменяет владелец.
import os, sys, struct, hashlib, collections

STRIDE   = 146   # размер записи ConditionTable.Bin
OFF_SELF = 0     # i32 собственный индекс записи
OFF_FLAG = 36    # u8  «проверять уровень» (1 = да)
OFF_MIN  = 37    # u8  минимальный уровень
OFF_MAX  = 38    # u8  максимальный уровень
NO_CAP   = 150   # 0x96 — максимум, который принимает sub_41FD70


def patch(src_path, dst_path):
    """Возвращает (сколько записей тронуто, список (idx, было, стало))."""
    data = bytearray(open(src_path, "rb").read())
    if len(data) % STRIDE:
        raise SystemExit("!! размер %d не кратен %d — это не ConditionTable.Bin" % (len(data), STRIDE))
    n = len(data) // STRIDE
    touched = []
    for i in range(n):
        base = i * STRIDE
        if data[base + OFF_FLAG] != 1:
            continue                                   # проверка уровня выключена — не трогаем
        old = data[base + OFF_MAX]
        if old >= NO_CAP:
            continue                                   # потолка и так нет
        self_idx = struct.unpack_from("<i", data, base + OFF_SELF)[0]
        touched.append((i, self_idx, data[base + OFF_MIN], old))
        data[base + OFF_MAX] = NO_CAP
    open(dst_path, "wb").write(bytes(data))
    return touched, n


def md5(p):
    return hashlib.md5(open(p, "rb").read()).hexdigest()


if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    src = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "out", "ConditionTable.orig.Bin")
    dst = sys.argv[2] if len(sys.argv) > 2 else os.path.join(here, "out", "ConditionTable.Bin")
    touched, n = patch(src, dst)
    print("исходник : %s  (%d записей, MD5 %s)" % (src, n, md5(src)))
    print("результат: %s  (MD5 %s)" % (dst, md5(dst)))
    print("поднято потолков: %d" % len(touched))
    hist = collections.Counter((mn, mx) for _, _, mn, mx in touched)
    print("самые частые снятые диапазоны [min..max] -> [min..150]:")
    for k, v in hist.most_common(15):
        print("   %-10s x%d" % ("%d..%d" % k, v))
    print("первые 10 записей: " + ", ".join("#%d %d..%d" % (s, mn, mx) for _, s, mn, mx in touched[:10]))
