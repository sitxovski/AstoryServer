# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# asdamap.py — однозначная привязка стабов AsdaPatch.dll по MAP-файлу компоновщика (integ2, 2026-10-12).
#   build.bat пишет out\AsdaPatch.map (/MAP). Сигнатурный поиск коротких стабов (pushad/push/call/popad/jmp [..])
#   стал неоднозначным, когда в DLL появились стабы того же вида у других патчей; MAP даёт адрес по имени И объекту.
#   Для сверки «MAP ↔ DLL» map_matches_dll() сравнивает метку времени MAP и PE (MAP от другой сборки — ошибка).
# Использование:
#   from asdamap import DllMap
#   m = DllMap(dll_path)                  # MAP рядом с DLL: <имя>.map
#   va = m.sym("St_Cool", "p56_combat_limits")   # VA при базе из MAP (Preferred load address)
#   m.owner(va) -> ("?St_Cool@?A0x..@@YAXXZ", "p56_combat_limits.obj")
import os
import re

_LINE = re.compile(r"^\s*([0-9a-fA-F]{4}):([0-9a-fA-F]{8})\s+(\S+)\s+([0-9a-fA-F]{8})\s+(?:f\s+)?(?:i\s+)?(\S+)\s*$")


class DllMap:
    def __init__(self, dll_path, map_path=None):
        self.map_path = map_path or os.path.splitext(dll_path)[0] + ".map"
        if not os.path.exists(self.map_path):
            raise FileNotFoundError("нет MAP-файла %s (собрать build.bat с /MAP)" % self.map_path)
        self.base = None
        self.stamp = None
        self.syms = []            # (va, decorated, obj)
        with open(self.map_path, encoding="latin-1") as f:
            for ln in f:
                if self.stamp is None:
                    m = re.match(r"^\s*Timestamp is ([0-9a-fA-F]+)", ln)
                    if m:
                        self.stamp = int(m.group(1), 16)
                        continue
                if self.base is None:
                    m = re.match(r"^\s*Preferred load address is ([0-9a-fA-F]+)", ln)
                    if m:
                        self.base = int(m.group(1), 16)
                        continue
                m = _LINE.match(ln)
                if m and m.group(1) != "0000":
                    self.syms.append((int(m.group(4), 16), m.group(3), m.group(5)))
        self.syms.sort()

    @staticmethod
    def _plain(decorated):
        # ?St_Cool@?A0x5b46b12d@@YAXXZ -> St_Cool ; _P62_GetSendNext@4 -> P62_GetSendNext ; _Foo -> Foo
        if decorated.startswith("?"):
            return decorated[1:].split("@", 1)[0]
        d = decorated[1:] if decorated.startswith("_") else decorated
        return d.split("@", 1)[0]

    def find(self, name, obj=None):
        """Все (va, decorated, obj) с именем name (и объектом, если задан: подстрока имени .obj)."""
        return [s for s in self.syms if self._plain(s[1]) == name and (obj is None or obj.lower() in s[2].lower())]

    def sym(self, name, obj=None):
        """VA единственного символа name[@obj]; ValueError при 0 или >1 совпадении."""
        c = self.find(name, obj)
        if len(c) != 1:
            raise ValueError("символ %s%s: совпадений %d %s" % (name, "@" + obj if obj else "", len(c), [(hex(v), d, o) for v, d, o in c]))
        return c[0][0]

    def owner(self, va):
        """(decorated, obj) функции/символа, в котором лежит va (ближайший символ с началом <= va)."""
        lo, hi, best = 0, len(self.syms) - 1, None
        while lo <= hi:
            mid = (lo + hi) // 2
            if self.syms[mid][0] <= va:
                best = self.syms[mid]
                lo = mid + 1
            else:
                hi = mid - 1
        return (best[1], best[2]) if best else (None, None)


def map_matches_dll(dll_map, pe):
    """MAP от той же сборки, что и DLL: совпадают метка времени и предпочтительная база."""
    return dll_map.stamp == pe.FILE_HEADER.TimeDateStamp and dll_map.base == pe.OPTIONAL_HEADER.ImageBase


def resolve(dmap, name, obj, cands):
    """Однозначный выбор стаба среди кандидатов сигнатуры по MAP. Возврат (va|None, ok, сообщение).
    ok — символ есть в MAP ровно один раз, он среди кандидатов сигнатуры, а все прочие кандидаты — другие
    именованные функции (стабы того же вида других патчей или того же патча), то есть неоднозначность поиска, а не дубль."""
    try:
        va = dmap.sym(name, obj)
    except ValueError as e:
        return None, False, str(e)
    others = [(c, dmap.owner(c)) for c in cands if c != va]
    # Прочие кандидаты — ДРУГИЕ именованные стабы (чужих патчей или того же патча под другим именем), не второй экземпляр.
    foreign = all(o[0] and DllMap._plain(o[0]) != name for _, o in others)
    msg = "%s: MAP 0x%08X (%s), сигнатура совпадает=%s; прочие кандидаты сигнатуры %d — %s" % (
        name, va, obj, va in cands, len(others),
        ", ".join("0x%08X %s/%s" % (c, o[1], DllMap._plain(o[0] or "?")) for c, o in others) or "нет")
    return (va if va in cands else None), (va in cands and foreign), msg
