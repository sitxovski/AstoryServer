# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# srv_paths.py — единый корень файлов dev-стойки для инструментов серверных патчей (22.10.2026, слово владельца:
#   «Если [шара] не доступна — ssh»). Сетевая папка \\@@ASTORY_SERVER_HOSTNAME@@ висла целиком (даже листинг), поэтому:
#   • по умолчанию корень = ЛОКАЛЬНОЕ ЗЕРКАЛО tools/_srv_mirror/ (структура путей — относительно @@ASTORY_SERVER_ROOT@@\Working_ASDA),
#     его наполняет и обновляет srv_mirror.py по SSH (только чтение; run_checks.py зовёт его сам в начале прогона);
#   • шара — ТОЛЬКО явным ключом ASDA_USE_SMB=1 (старые выкладки и правки данных, помеченные «устарело: шара»);
#   • ASDA_SRV_ROOT — явный другой корень (например, папка-зеркало ревизора); имеет приоритет над зеркалом по умолчанию.
# Пути — с прямыми слешами, как прежние константы скриптов (V2 оканчивается слешем: V2 + "GameServer/GameServer.exe").
import os
import sys

SMB_ROOT = "//@@ASTORY_SERVER_HOSTNAME@@/h(@@ASTORY_SERVER_HOSTNAME@@_ns)/ASDA/Working_ASDA"                       # сетевая папка (только по ASDA_USE_SMB=1)
MIRROR_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_srv_mirror").replace("\\", "/")   # зеркало по SSH
USE_SMB = os.environ.get("ASDA_USE_SMB") == "1"                              # явный выбор шары
ROOT = SMB_ROOT if USE_SMB else (os.environ.get("ASDA_SRV_ROOT") or MIRROR_ROOT).replace("\\", "/").rstrip("/")
V2 = ROOT + "/v2/"                                                          # корень v2 (со слешем на конце)
STOCK_GS = ROOT + "/AsdaStory/GameServer/GameServer.exe_before_mine_patch.exe"   # сток GameServer 4e20f0ad
STOCK_NPC = ROOT + "/AsdaStory/NpcServer/NpcServer.exe"                     # сток NpcServer


def require_smb(script):
    """Устаревший скрипт, ПИШУЩИЙ на шару: без ASDA_USE_SMB=1 — отказ с понятным сообщением (не висеть на \\\\@@ASTORY_SERVER_HOSTNAME@@)."""
    if not USE_SMB:
        try:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
        sys.stderr.write(
            "%s: УСТАРЕЛО — скрипт работает через сетевую папку \\\\@@ASTORY_SERVER_HOSTNAME@@, которая висит (22.10.2026).\n"
            "  Выкладка — только по SSH по образцу deploy_p77.py (restart_stack.py --deploy ...).\n"
            "  Если шара точно доступна и нужен именно этот скрипт: ASDA_USE_SMB=1 python %s ...\n"
            % (os.path.basename(script), os.path.basename(script)))
        sys.exit(3)
