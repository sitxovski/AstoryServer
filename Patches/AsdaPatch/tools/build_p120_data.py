# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# build_p120_data.py — ДАННЫЕ КАРТЫ «ШАХТА» (карта 23 ^MineWar^) ДЛЯ P120 (09.11.2026, пачка 20; документ
#   AstoryServer/Docs/GameServer/mine-travel-p120.md, отчёт Reports/batch20/mine/REPORT.md).
#   База — ЖИВЫЕ файлы стойки из зеркала tools/_srv_mirror (srv_mirror по SSH, только чтение); донор геометрии — клиент-эталон
#   Donors/AsdaChroniclesInterlude/map/mine (mine.SIM = стоковый MapData_Info/MineWar.SIM, md5 7095c685; mine.BIN = MineWar.BIN 90d8b553).
#   Вывод: tools/p120_data/files/<папка стойки>/<путь> + tools/p120_data/manifest.json {путь стойки: [md5 базы | "none", md5 нового]}.
#   Что строится (по каждой папке из stack_layout):
#     GameServer ×3 (поле, Ch2, Indun): MapData_Info\MapInfo.txt (строка 23: 5 пар точек прибытия вместо нулей — CharMake), MapWarpCost.txt
#       (N 23→24, строка/столбец 23 = -1: кристаллом 5477 в шахту и из неё нельзя), OpenMapInfo.ini ([MAP_23] Use=1; у Indun файла нет —
#       не создаётся), PortalIP_Info\Total_PortalConfig.Ini (count 23→24 + PORTAL_INFO_23, IP/PORT — как у записи 22 этой же папки),
#       новые: MapData_Info\^MineWar^.SIM, MonsterData_Info\^MineWar^.svr (0 мобов), NpcData_Info\^MineWar^.npc (стражи 202/203/204),
#       PortalIP_Info\^MineWar^_PortalConfig.Ini (count 0), ConnectIP_Info\^MineWar^_ConnectIP.ini (= Inferion_ConnectIP.ini этой папки).
#     NpcServer ×3: ini\MapInfo.ini (MapCount 23→24 + блок 023), ini\SectorInfo.ini (+[^MineWar^], сектор 256), новые: Map\^MineWar^.SIM/.BIN,
#       Monster\^MineWar^.svr (0) / .Aif (клиент mine.Aif), NpcInfo\^MineWar^.npc, MiningItemTable\^MineWar^00/01.mng (пустой шаблон —
#       = quizstage00.mng, md5 14d5b967: у шахты своей таблицы добычи в данных нет).
#     ChannelManager: ini\Indun_Info.ini (START_INFO MapCount 23→24 + MapStartX_23/Z_23).
#   Запуск: py -3.13 build_p120_data.py  (без ключей — собрать и напечатать сводку; --no-fetch — не обновлять зеркало).
import hashlib
import json
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout   # единый состав стойки

OUT = os.path.join(HERE, "p120_data")
FILES = os.path.join(OUT, "files")
MIRROR = os.path.join(HERE, "_srv_mirror", "v2")
DONOR = r"@@ASTORY_DEV_ROOT@@\Donors\AsdaChroniclesInterlude\map\mine"
NAME = "^MineWar^"            # имя карты 23 в MapInfo.txt (оригинал, не меняем)
MAP = 23
DONOR_MD5 = {"mine.SIM": "7095c685e3493451c1c67bd5167577a9", "mine.BIN": "90d8b55309cd2ac35d3591931571bb7f"}
EMPTY_MNG = "14d5b96795e0f480e9c64c9349bd06a2"   # quizstage00.mng = battlefield/eventfield/fieldofhonor/t_* (добычи нет)

# Точки — клетки .SIM (проходимы с запасом 5×5).
ARRIVAL = (261, 41)                               # прибытие из Альпии — в 3 клетках от стража 202 (база «Света», север): с точки прибытия можно сразу вернуться
# ★ Точки стражей — ОРИГИНАЛ: клиент-эталон Data/NPC/npc_list.BIN (запись 0x88 с +0x14: +0x6C карта, +0x70/+0x74 X/Z float, +0x78 поворот);
#   тайл = X//100, Z//100 — то же правило, что у P119 и запечённых стражей уровня mine клиента (сессия NPC, 09.11). Все три тайла проходимы.
NPCS = [  # (тип, x, z, поворот) — поле +12 записи .npc
    (202, 261, 38, 0),                            # 빛의_경비병 «Страж Света»  (X 26100, Z 3800)
    (203, 44, 466, 135),                          # 어둠의_경비병 «Страж Тьмы»  (X 4400, Z 46600)
    (204, 457, 471, 225),                         # 혼돈의_경비병 «Страж Хаоса» (X 45700, Z 47100)
]

FETCH = []   # пути зеркала, которые нужны (заполняется ниже)
for d in stack_layout.GS_FOLDERS:
    FETCH += [d + "/MapData_Info/MapInfo.txt", d + "/MapData_Info/MapWarpCost.txt", d + "/PortalIP_Info/Total_PortalConfig.Ini",
              d + "/ConnectIP_Info/Inferion_ConnectIP.ini", d + "/PortalIP_Info/quizstage_PortalConfig.Ini"]
    if d != "Indun_GameServer":
        FETCH.append(d + "/MapData_Info/OpenMapInfo.ini")
FETCH += ["GameServer/NpcData_Info/quizstage.npc", "GameServer/MonsterData_Info/quizstage.svr"]
for d in stack_layout.NPC_FOLDERS:
    FETCH += [d + "/ini/MapInfo.ini", d + "/ini/SectorInfo.ini"]
FETCH += ["NpcServer/MiningItemTable/quizstage00.mng", "ChannelManager/ini/Indun_Info.ini"]


def md5b(b):
    """md5 байт."""
    return hashlib.md5(b).hexdigest()


def rd(rel):
    """Байты файла из зеркала."""
    with open(os.path.join(MIRROR, rel.replace("/", os.sep)), "rb") as f:
        return f.read()


def text(b):
    """ini/txt стойки — cp1251, CRLF (как есть)."""
    return b.decode("cp1251")


def nl(t):
    """Разделитель строк файла."""
    return "\r\n" if "\r\n" in t else "\n"


def map_info(b):
    """MapInfo.txt: строка 23 — 5 пар точек = прибытие (вместо нулей). Остальное побайтно."""
    t = text(b)
    e = nl(t)
    rows = t.split(e)
    idx = [i for i, r in enumerate(rows) if r.split("\t")[:2] == [str(MAP), NAME]]
    assert len(idx) == 1, "строка 23 ^MineWar^ не найдена"
    c = rows[idx[0]].split("\t")
    assert c[6] == "6", "тип карты 23 не 6: %s" % c[6]
    assert c[20] == "5", "число пар у карты 23 не 5: %s" % c[20]
    for j in range(5):                    # колонки 21…30 — пары (x_j, z_j), loader: +98+2j / +108+2j
        c[21 + 2 * j] = str(ARRIVAL[0])
        c[22 + 2 * j] = str(ARRIVAL[1])
    rows[idx[0]] = "\t".join(c)
    return e.join(rows).encode("cp1251")


def warp_cost(b):
    """MapWarpCost.txt: N 23→24, строка и столбец 23 = -1 (запрет 5477)."""
    t = text(b)
    e = nl(t)
    rows = t.split(e)
    n = int(rows[0].strip())
    assert n == 23, "MapWarpCost N=%d, ожидалось 23" % n
    body = [r for r in rows[1:] if r.strip()]
    assert len(body) == 23
    sep = "\t"
    out = ["24"]
    for r in body:
        cells = r.rstrip().split(sep)
        assert len(cells) == 23, "в строке MapWarpCost %d ячеек" % len(cells)
        out.append(sep.join(cells + ["-1"]))
    out.append(sep.join(["-1"] * 24))
    tail = e if t.endswith(e) else ""
    return (e.join(out) + tail).encode("cp1251")


def open_map(b):
    """OpenMapInfo.ini: + [MAP_23] Name = ^MineWar^, Use = 1 (MapCount — флаг/верхняя граница, остаётся меньше слотов P30)."""
    t = text(b)
    e = nl(t)
    assert "[MAP_23]" not in t
    body = t.rstrip("\r\n")
    return (body + e + "[MAP_23] " + e + "Name = mine" + e + "Use = 1" + e).encode("cp1251")


def total_portal(b):
    """Total_PortalConfig.Ini: count 23→24 + PORTAL_INFO_23 (IP/PORT — как у записи 22 этой папки, STARTPOS — прибытие)."""
    t = text(b)
    e = nl(t)
    m = re.search(r"count\s*=\s*(\d+)", t)
    assert m and m.group(1) == "23"
    t = t[:m.start()] + "count = 24" + t[m.end():]
    r22 = re.search(r"\[PORTAL_INFO_22\][^\n]*\n(.*?)(?:\r?\n\r?\n|\Z)", t, re.S)
    assert r22
    ip = re.search(r'IP\s*=\s*"([^"]+)"', r22.group(1)).group(1)
    port = re.search(r"PORT\s*=\s*(\d+)", r22.group(1)).group(1)
    rec = ["[PORTAL_INFO_23] //MineWar", "Use = 1", "Index = 23", 'IP = "%s"' % ip, "PORT = %s" % port,
           "STARTPOSX = %d" % ARRIVAL[0], "STARTPOSZ = %d" % ARRIVAL[1], ""]
    body = t.rstrip("\r\n")
    return (body + e + e + e.join(rec) + e).encode("cp1251"), ip, port


def npc_file(tmpl):
    """^MineWar^.npc: записи 221 б по образцу записи quizstage.npc (+0 номер, +4 тип, +8 x, +10 z, +12 направление)."""
    assert len(tmpl) % 221 == 0 and len(tmpl) >= 221
    base = bytearray(tmpl[:221])
    out = b""
    for i, (t, x, z, d) in enumerate(NPCS):
        r = bytearray(base)
        struct.pack_into("<h", r, 0, i)
        struct.pack_into("<h", r, 4, t)
        struct.pack_into("<hhh", r, 8, x, z, d)
        out += bytes(r)
    return out


def npc_map_info(b):
    """NpcServer ini\\MapInfo.ini: MapCount 23→24 + блок 023 (по образцу блока 022)."""
    t = text(b)
    e = nl(t)
    m = re.search(r"MapCount\s*=\s*(\d+)", t)
    assert m and m.group(1) == "23"
    t = t[:m.start()] + "MapCount = 24" + t[m.end():]
    blk = re.search(r'(ServerName_022=.*?ZoneInfo_022="[^"]*"[^\r\n]*)', t, re.S)
    assert blk
    new = blk.group(1).replace("_022", "_023").replace("quizstage", NAME)
    assert "quizstage" not in new
    body = t.rstrip("\r\n")
    return (body + e + e + new + e).encode("cp1251")


def sector_info(b):
    """SectorInfo.ini: + [^MineWar^] 512×512, сектор 256 (как у всех карт)."""
    t = text(b)
    e = nl(t)
    assert "[%s]" % NAME not in t
    body = t.rstrip("\r\n")
    rec = ["[%s]" % NAME, "Map_Width=512", "Map_Height=512", "Sector_Width=256", "Sector_Height=256"]
    return (body + e + e + e.join(rec) + e).encode("cp1251")


def indun_info(b):
    """ChannelManager ini\\Indun_Info.ini: [START_INFO] MapCount 23→24 + MapStartX_23/Z_23 после MapStartZ_22."""
    t = text(b)
    e = nl(t)
    m = re.search(r"(\[START_INFO\]\s*\r?\nMapCount\s*=\s*)(\d+)", t)
    assert m and m.group(2) == "23"
    t = t[:m.start(2)] + "24" + t[m.end(2):]
    z22 = re.search(r"MapStartZ_22=\d+", t)
    assert z22 and "MapStartX_23" not in t
    ins = e + "MapStartX_23=%d" % ARRIVAL[0] + e + "MapStartZ_23=%d" % ARRIVAL[1]
    return (t[:z22.end()] + ins + t[z22.end():]).encode("cp1251")


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    if "--no-fetch" not in sys.argv:
        import srv_mirror
        rc = srv_mirror.update(["v2/" + r for r in FETCH], log=lambda s: None)
        if rc != 0:
            print("СТОП: зеркало не обновилось (код %d)" % rc)
            return 2
    donor = {}
    for f, want in DONOR_MD5.items():
        donor[f] = open(os.path.join(DONOR, f), "rb").read()
        assert md5b(donor[f]) == want, "%s md5 не %s" % (f, want)
    donor["mine.Aif"] = open(os.path.join(DONOR, "mine.Aif"), "rb").read()
    mng = rd("NpcServer/MiningItemTable/quizstage00.mng")
    assert md5b(mng) == EMPTY_MNG
    npc = npc_file(rd("GameServer/NpcData_Info/quizstage.npc"))
    svr = struct.pack("<i", 0)

    out = {}   # путь стойки (через \) → (байты нового, байты базы или None)
    for d in stack_layout.GS_FOLDERS:
        out[d + r"\MapData_Info\MapInfo.txt"] = (map_info(rd(d + "/MapData_Info/MapInfo.txt")), rd(d + "/MapData_Info/MapInfo.txt"))
        out[d + r"\MapData_Info\MapWarpCost.txt"] = (warp_cost(rd(d + "/MapData_Info/MapWarpCost.txt")), rd(d + "/MapData_Info/MapWarpCost.txt"))
        if d != "Indun_GameServer":
            out[d + r"\MapData_Info\OpenMapInfo.ini"] = (open_map(rd(d + "/MapData_Info/OpenMapInfo.ini")), rd(d + "/MapData_Info/OpenMapInfo.ini"))
        tp, ip, port = total_portal(rd(d + "/PortalIP_Info/Total_PortalConfig.Ini"))
        out[d + r"\PortalIP_Info\Total_PortalConfig.Ini"] = (tp, rd(d + "/PortalIP_Info/Total_PortalConfig.Ini"))
        print("%s: PORTAL_INFO_23 IP %s PORT %s STARTPOS %s" % (d, ip, port, ARRIVAL))
        out[d + "\\MapData_Info\\%s.SIM" % NAME] = (donor["mine.SIM"], None)
        out[d + "\\MonsterData_Info\\%s.svr" % NAME] = (svr, None)
        out[d + "\\NpcData_Info\\%s.npc" % NAME] = (npc, None)
        out[d + "\\PortalIP_Info\\%s_PortalConfig.Ini" % NAME] = (rd(d + "/PortalIP_Info/quizstage_PortalConfig.Ini"), None)
        out[d + "\\ConnectIP_Info\\%s_ConnectIP.ini" % NAME] = (rd(d + "/ConnectIP_Info/Inferion_ConnectIP.ini"), None)
    for d in stack_layout.NPC_FOLDERS:
        out[d + r"\ini\MapInfo.ini"] = (npc_map_info(rd(d + "/ini/MapInfo.ini")), rd(d + "/ini/MapInfo.ini"))
        out[d + r"\ini\SectorInfo.ini"] = (sector_info(rd(d + "/ini/SectorInfo.ini")), rd(d + "/ini/SectorInfo.ini"))
        out[d + "\\Map\\%s.SIM" % NAME] = (donor["mine.SIM"], None)
        out[d + "\\Map\\%s.BIN" % NAME] = (donor["mine.BIN"], None)
        out[d + "\\Monster\\%s.svr" % NAME] = (svr, None)
        out[d + "\\Monster\\%s.Aif" % NAME] = (donor["mine.Aif"], None)
        out[d + "\\NpcInfo\\%s.npc" % NAME] = (npc, None)
        out[d + "\\MiningItemTable\\%s00.mng" % NAME] = (mng, None)
        out[d + "\\MiningItemTable\\%s01.mng" % NAME] = (mng, None)
    out[r"ChannelManager\ini\Indun_Info.ini"] = (indun_info(rd("ChannelManager/ini/Indun_Info.ini")), rd("ChannelManager/ini/Indun_Info.ini"))

    man = {}
    for rel, (new, base) in sorted(out.items()):
        p = os.path.join(FILES, rel.replace("\\", os.sep))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(new)
        man[rel] = [md5b(base) if base is not None else "none", md5b(new)]
        print("  %-62s %s -> %s %7d б" % (rel, man[rel][0][:8], man[rel][1][:8], len(new)))
    with open(os.path.join(OUT, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump({"_comment": "build_p120_data.py: путь стойки → [md5 базы | none (новый файл), md5 нового]; файлы — files/<путь>",
                   "files": man}, f, ensure_ascii=False, indent=1)
    print("файлов: %d (новых %d, правок %d) → %s" % (len(man), sum(1 for v in man.values() if v[0] == "none"),
                                                   sum(1 for v in man.values() if v[0] != "none"), OUT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
