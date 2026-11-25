# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# p91_monster_exp.py — ДАННЫЕ волны exprate (решение владельца 26.10): опыт мобов Inferion и рейдовых копий боссов
#   в Monster.ai (оригинал: опыт 1). Разбор и таблица «было → стало → обоснование»: Reports/exprate/MOB_EXP_AUDIT.md §9.
#
# ЗАКОНОМЕРНОСТЬ ОРИГИНАЛА (проверяется подкомандой validate на стоке Donors/GameServer_stock/MonsterData_Info):
#   опыт моба = семейство × F(ур.), где F(ур.) — опыт рядового полевого моба этого уровня (семейство ×1), и он НЕ зависит
#   от HP: у мобов ×1 одного уровня опыт одинаков при любом HP (ур. 18: HP 927…3072 — все 33). F(ур.) берётся ровно из стока —
#   самое частое значение опыта на уровне по спаунам (66 → 183, 67 → 187, 68 → 191, 69 → 195, 70 → 200, 71 → 205).
#   Боссы и их копии: семейство оригинала (×5 / ×20 / ×30 / ×40) × F(уровня копии) — так оригинал уже сделал свои копии
#   591 Кайя (ур. 20, 185 = 5×37) и 592 Король Пик (ур. 31, 305 = 5×61).
#
# Подкоманды (ничего не пишет на сервер; выкладка — deploy_p91.py):
#   python p91_monster_exp.py validate            — проверка закономерности на стоке (сколько мобов ×1 = F(ур.) точно)
#   python p91_monster_exp.py apply <вход> <выход> — записать новые значения в копию Monster.ai (сверка: старое = 1,
#                                                    размер 850 × 479, меняется только поле +0x35 указанных записей)
#   python p91_monster_exp.py table               — таблица изменений (markdown)
import collections
import glob
import os
import struct
import sys

REC = 479
OFF_ID, OFF_LVL, OFF_HP, OFF_EXP = 0x00, 0x04, 0x2D, 0x35
STOCK_DIR = r"@@ASTORY_DEV_ROOT@@\Donors\GameServer_stock\MonsterData_Info"

# F(ур.) — опыт рядового моба (семейство ×1) по стоку; проверяется validate.
F_STOCK = {66: 183, 67: 187, 68: 191, 69: 195, 70: 200, 71: 205}

INF = "Inferion: заготовка оригинала (HP ровно 50 000 у всех, опыт 1); HP 50 000 = HP рядовых ×1 ур. 66–71 стока " \
      "(43 905…58 905) → семейство ×1, опыт = F(ур.) стока"
# id → (новый опыт, обоснование). Старое значение у всех — 1 (сверяется при записи).
CHANGES = {}
_inf_lvl = {762: 66, 763: 66, 764: 67, 765: 67, 766: 67, 767: 68, 768: 68, 769: 69, 770: 69, 771: 69, 772: 70, 773: 70,
            774: 67, 775: 67, 776: 68, 777: 68, 778: 68, 779: 69, 780: 69, 781: 70, 782: 70, 783: 70, 784: 71, 785: 71,
            786: 67, 787: 67, 788: 68, 789: 68, 790: 68, 791: 69, 792: 69, 793: 70, 794: 70, 795: 70, 796: 71, 797: 71}
for _i, _l in _inf_lvl.items():
    CHANGES[_i] = (F_STOCK[_l], _l, INF)
CHANGES.update({
    752: (380, 36, "копия 433 «Горящая Кайя» (t_Palace_of_Queen): тот же ур. 36 и HP 186 000 → опыт оригинала 380 (= ×5 × F(36) 76)"),
    753: (500, 44, "копия 436 «Демонический Король Пик» (t_Castle_of_chess): тот же ур. 44 и HP 158 400 → опыт оригинала 500 (= ×5 × F(44) 100)"),
    754: (3760, 42, "копия 228 «Зверун» (LostValley, ур. 30, 2320 = ×40 × F(30) 58) на ур. 42 → ×40 × F(42) 94"),
    755: (5560, 55, "копия 260 «Черная птица» (Night_Valley, ур. 40, 3520 = ×40 × F(40) 88) на ур. 55 → ×40 × F(55) 139"),
    756: (5010, 62, "копия 733 «Латунный рыцарь Виглаф» (StagnantDesert, ур. 58, 4530 = ×30 × F(58) 151) на ур. 62 → ×30 × F(62) 167"),
    757: (7480, 67, "копия 735 «Гильгамеш» (StagnantDesert, ур. 60, 6360 = ×40 × F(60) 159) на ур. 67 → ×40 × F(67) 187"),
    240: (6040, 58, "рейдовый босс «Йети» (덕해머 대장, Alpen ×5), оригинала-образца нет: HP 10 000 000 = 505 × HP рядового ур. 58 — "
                    "больше, чем у боссов ×40 (Гильгамеш 323×, Черная птица 212×) → верхняя ступень обычных боссов ×40 × F(58) 151"),
    241: (6040, 58, "двойник 240 «Йети» (та же запись, не заспаунен) — то же значение"),
    115: (456, 36, "«Блуждающий иллюминатик» (Night_Valley): его отрядный двойник 487 — ур. 35, ТОТ ЖЕ HP 13 403, опыт 438 = ×6 × F(35); "
                   "все рядовые ×6 ур. 36 Night_Valley (85 HP 12 549, 473/499 HP 14 588) — 456 = ×6 × F(36); 582 — значение вожаков "
                   "749/750 (у вожака иллюминатиков ровно 582, HP 87 961) — перенос числа из строки вожака. Уровень 36 не трогаем → ×6 × F(36)"),
})
OLD = {115: 582}   # старое значение не 1 (у остальных — 1)

# ★ Вторая партия (решение владельца 26.10, после выкладки P91): именные чемпионы Inferion — как боссы ×20 × F(72).
#   F(72) в стоке не встречается (рядовых ур. 72 нет): шаг стока на верху шкалы — +5 за уровень (69 → 195, 70 → 200,
#   71 → 205) → F(72) = 210. Подтверждение шага: при F(73) = 215, F(74) = 220, F(75) = 225 опыт финальных боссов стока —
#   целые кратные: 836 Транспан ур. 73 — 19 350 = ×90, 837/838 ур. 74 — 19 800 = ×90, 839 Селон ур. 75 — 39 600 = ×176
#   (по «норме» 4·ур.−81 вышли бы дробные ×91,7 / ×92,1 / ×180,8).
F72 = 210
CHANGES_B = {
    840: (20 * F72, 72, "«Death Champion Drusnan» (Inferion, 1 спаун): решение владельца — босс ×20 × F(72) 210 (F(72) — шаг стока +5)"),
    841: (20 * F72, 72, "«Death Visitor Kalderas» (Inferion, 1 спаун): решение владельца — босс ×20 × F(72) 210 (F(72) — шаг стока +5)"),
}


def rec_off(data, mob_id):
    """Смещение записи по id (поле +0)."""
    for i in range(len(data) // REC):
        if struct.unpack_from("<i", data, i * REC + OFF_ID)[0] == mob_id:
            return i * REC
    return -1


def apply(src, dst, changes=None):
    data = bytearray(open(src, "rb").read())
    if len(data) != 850 * REC:
        sys.exit("размер %s = %d, ожидалось %d" % (src, len(data), 850 * REC))
    orig = bytes(data)
    changes = CHANGES if changes is None else changes
    for mob_id, (new, lvl, _) in sorted(changes.items()):
        o = rec_off(data, mob_id)
        if o < 0:
            sys.exit("нет записи id %d" % mob_id)
        old = struct.unpack_from("<i", data, o + OFF_EXP)[0]
        if data[o + OFF_LVL] != lvl:
            sys.exit("id %d: уровень %d, ожидался %d" % (mob_id, data[o + OFF_LVL], lvl))
        if old not in (OLD.get(mob_id, 1), new):
            sys.exit("id %d: опыт %d — не %d (не оригинал) и не %d, ничего не пишу" % (mob_id, old, OLD.get(mob_id, 1), new))
        struct.pack_into("<i", data, o + OFF_EXP, new)
    diff = [i for i in range(len(data)) if data[i] != orig[i]]
    touched = {rec_off(data, k) + OFF_EXP + j for k in changes for j in range(4)}
    if any(i not in touched for i in diff):
        sys.exit("изменились байты вне поля опыта — стоп")
    os.makedirs(os.path.dirname(os.path.abspath(dst)), exist_ok=True)
    open(dst, "wb").write(data)
    print("записано %s: изменено байт %d в %d записях" % (dst, len(diff), len(changes)))


def validate():
    """Закономерность на СТОКЕ: опыт ×1 = F(ур.), не зависит от HP; копии боссов = семейство оригинала × F(ур. копии)."""
    data = open(os.path.join(STOCK_DIR, "Monster.ai"), "rb").read()
    mobs = {}
    for i in range(len(data) // REC):
        r = data[i * REC:(i + 1) * REC]
        mobs[struct.unpack_from("<i", r, OFF_ID)[0]] = (r[OFF_LVL], struct.unpack_from("<i", r, OFF_HP)[0], struct.unpack_from("<i", r, OFF_EXP)[0])
    spawns = collections.Counter()
    for p in glob.glob(os.path.join(STOCK_DIR, "*.svr")):
        d = open(p, "rb").read()
        n = struct.unpack_from("<i", d, 0)[0] & 0xFFFF
        for k in range(n):
            o = 4 + 74 * k
            if o + 74 <= len(d):
                spawns[struct.unpack_from("<i", d, o + 16)[0]] += 1
    # F(ур.) — самое частое значение опыта на уровне по спаунам
    w = collections.defaultdict(collections.Counter)
    for t, c in spawns.items():
        if t in mobs and mobs[t][2] > 1 and mobs[t][1] > 1:
            w[mobs[t][0]][mobs[t][2]] += c
    # F(ур.) — значение уровня, ближайшее к кусочной норме поля (ур.+1; 2·ур.−3; 3·ур.−32; 4·ур.−81) не дальше 5 %: на
    #   уровнях подземелий самое частое значение — кратное (×6/×17), поэтому берём «рядовое» по соседней норме.
    def norm(L):
        return L + 1 if L <= 4 else 2 * L - 3 if L <= 29 else 3 * L - 32 if L <= 49 else 4 * L - 81
    F = {}
    for L, c in w.items():
        v = min(c, key=lambda e: abs(e - norm(L)) / norm(L))
        if abs(v - norm(L)) / norm(L) <= 0.05:
            F[L] = v
    bad = 0
    for L, v in F_STOCK.items():
        ok = F.get(L) == v
        bad += not ok
        print("  [%s] F(%d) по стоку = %s (в скрипте %d)" % ("OK" if ok else "!!", L, F.get(L), v))
    # мобы ×1 (опыт = F) — сколько точно; отклонение F от нормы; разброс HP внутри уровня
    exact = sum(1 for t in spawns if t in mobs and mobs[t][0] in F and mobs[t][2] == F[mobs[t][0]])
    off = [(L, F[L], norm(L)) for L in sorted(F) if F[L] != norm(L)]
    print("  уровней с рядовым значением F: %d; из них не равно кусочной норме: %d (%s)"
          % (len(F), len(off), ", ".join("ур.%d %d≠%d" % x for x in off)))
    hp_spread = []
    for L in sorted(F):
        hps = sorted({mobs[t][1] for t in spawns if t in mobs and mobs[t][0] == L and mobs[t][2] == F[L]})
        if len(hps) > 1:
            hp_spread.append((L, hps[0], hps[-1]))
    print("  заспауненных типов с опытом = F(ур.) своего уровня: %d; уровней, где при ОДНОМ опыте разный HP: %d (пример: %s)"
          % (exact, len(hp_spread), ", ".join("ур.%d HP %d…%d" % s for s in hp_spread[:4])))
    # копии оригинала: 591 Кайя ур. 20, 592 Король Пик ур. 31 — ×5 × F(ур. копии)
    for cid, oid in ((591, 286), (592, 290)):
        cl, chp, cexp = mobs[cid]; ol, ohp, oexp = mobs[oid]
        fam = round(oexp / F[ol]) if ol in F else None
        ok = fam is not None and cexp == fam * F.get(cl, -1)
        bad += not ok
        print("  [%s] копия оригинала %d (ур. %d, опыт %d) = ×%s семейства %d (ур. %d, опыт %d) × F(%d) %s"
              % ("OK" if ok else "!!", cid, cl, cexp, fam, oid, ol, oexp, cl, F.get(cl)))
    for oid, fam_want in ((433, 5), (436, 5), (228, 40), (260, 40), (733, 30), (735, 40)):
        ol, ohp, oexp = mobs[oid]
        ok = ol in F and oexp == fam_want * F[ol]
        bad += not ok
        print("  [%s] оригинал %d: ур. %d, опыт %d = ×%d × F(%d) %s" % ("OK" if ok else "!!", oid, ol, oexp, fam_want, ol, F.get(ol)))
    for cid, fam in ((752, 5), (753, 5), (754, 40), (755, 40), (756, 30), (757, 40), (240, 40), (241, 40), (115, 6)):
        L = mobs[cid][0]
        ok = L in F and CHANGES[cid][0] == fam * F[L]
        bad += not ok
        print("  [%s] новое значение %d (ур. %d) = ×%d × F(%d) %s" % ("OK" if ok else "!!", cid, L, fam, L, F.get(L)))
    for mob_id, (new, lvl, why) in sorted(CHANGES.items()):
        if 762 <= mob_id <= 797 and new != F.get(lvl):
            bad += 1
            print("  [!!] Inferion %d: %d ≠ F(%d) %s" % (mob_id, new, lvl, F.get(lvl)))
        ok = mobs[mob_id][2] == OLD.get(mob_id, 1) and mobs[mob_id][0] == lvl
        bad += not ok
        if not ok:
            print("  [!!] id %d в стоке: ур. %d опыт %d (ожидалось ур. %d, опыт 1)" % (mob_id, mobs[mob_id][0], mobs[mob_id][2], lvl))
    # вторая партия: F(72) = шаг +5; финальные боссы 73–75 — целые кратные при этом шаге
    step_ok = F.get(69) == 195 and F.get(70) == 200 and F.get(71) == 205 and 72 not in F
    fin = [(i, mobs[i][0], mobs[i][2], mobs[i][2] / (F72 + 5 * (mobs[i][0] - 72))) for i in (836, 837, 838, 839)]
    fin_ok = all(abs(k - round(k)) < 1e-9 for _, _, _, k in fin)
    bad += not (step_ok and fin_ok and CHANGES_B[840][0] == 4200)
    print("  [%s] F(72): рядовых ур. 72 в стоке нет, шаг 69→70→71 = +5 → %d; финальные боссы при F(73..75) = 215/220/225: %s"
          % ("OK" if step_ok and fin_ok else "!!", F72, ", ".join("%d ур.%d %d = ×%g" % x for x in fin)))
    for mob_id, (new, lvl, why) in sorted(CHANGES_B.items()):
        ok = mobs[mob_id][2] == 1 and mobs[mob_id][0] == lvl
        bad += not ok
        print("  [%s] вторая партия %d: в стоке ур. %d опыт %d → %d" % ("OK" if ok else "!!", mob_id, mobs[mob_id][0], mobs[mob_id][2], new))
    print("== ИТОГ validate: %s (провалов %d)" % ("ВСЁ СОШЛОСЬ" if not bad else "ЕСТЬ РАСХОЖДЕНИЯ", bad))
    return 1 if bad else 0


def table():
    print("| id | ур. | было | стало | обоснование |")
    print("|---|---|---|---|---|")
    for mob_id, (new, lvl, why) in sorted(CHANGES.items()):
        print("| %d | %d | %d | %d | %s |" % (mob_id, lvl, OLD.get(mob_id, 1), new, why))


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    if len(sys.argv) >= 2 and sys.argv[1] == "validate":
        sys.exit(validate())
    if len(sys.argv) >= 4 and sys.argv[1] == "apply":
        apply(sys.argv[2], sys.argv[3])
        sys.exit(0)
    if len(sys.argv) >= 4 and sys.argv[1] == "apply-b":      # вторая партия (840/841) поверх файлов первой
        apply(sys.argv[2], sys.argv[3], CHANGES_B)
        sys.exit(0)
    if len(sys.argv) >= 2 and sys.argv[1] == "table-b":
        print("| id | ур. | было | стало | обоснование |")
        print("|---|---|---|---|---|")
        for mob_id, (new, lvl, why) in sorted(CHANGES_B.items()):
            print("| %d | %d | 1 | %d | %s |" % (mob_id, lvl, new, why))
        sys.exit(0)
    if len(sys.argv) >= 2 and sys.argv[1] == "table":
        table()
        sys.exit(0)
    print(__doc__ if __doc__ else "validate | apply <вход> <выход> | table")
    sys.exit(2)
