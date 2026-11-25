# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# stack_layout.py — ЕДИНЫЙ список папок dev-стойки v2 (26.10.2026, второй полевой канал; план Reports/channel2/PLAN.md).
#
# Зачем: до 26.10 каждый deploy_p*.py и скрипт данных держал свой список ["GameServer", "Indun_GameServer"] — третья
# копия (канал 2) при следующей выкладке молча разошлась бы с полем. Теперь папки и число процессов — ТОЛЬКО отсюда:
#   from stack_layout import GS_FOLDERS, NPC_FOLDERS, RELAY_FOLDERS, EXPECT, expand_paths, expand_list
# Канал 2 (Ch2_*) — копия ПОЛЕВЫХ папок: данные и патчи обязаны совпадать с GameServer/NpcServer/RelayServer
# побайтно, кроме поканальных файлов (CHANNEL_FILES); сверка — stack_parity.py (её зовёт restart_stack.py до старта).
# Модуль без побочных эффектов (памятка tools-no-import-side-effects).

# ── индексы каналов (ChannelManager ini\Server_Info.ini ChannelCount = 4) ──────────────────────────────────────────
#   0 — поле «канал 1» (GameServer / NpcServer / RelayServer, порты 15601 / 15701 / 15801)
#   1 — поле «канал 2» (Ch2_GameServer / Ch2_NpcServer / Ch2_RelayServer, порты 15621 / 15721 / 15821)
#   2 — пусто (слот 3 клиента серый)
#   3 — Indun (Indun_GameServer / Indun_NpcServer / Indun_RelayServer, 15651 / 15751 / 15851) — вне 3 слотов клиента
CHANNEL_COUNT = 4                                                           # ChannelManager ChannelCount

GS_FOLDERS = ["GameServer", "Indun_GameServer", "Ch2_GameServer"]          # все GameServer (AsdaPatch.dll, patches.ini)
NPC_FOLDERS = ["NpcServer", "Indun_NpcServer", "Ch2_NpcServer"]            # все NpcServer (AddonNPC.dll)
RELAY_FOLDERS = ["RelayServer", "Indun_RelayServer", "Ch2_RelayServer"]    # все RelayServer
FIELD_GS_FOLDERS = ["GameServer", "Ch2_GameServer"]                        # полевые GameServer (без Indun)

# Копия → поле, с которого она снята. Данные копии = данные поля; поэтому значения из словарей «путь поля → …»
# (md5 базы, md5 нового, локальный файл) переносятся на копию без изменений (expand_paths).
TWINS = {"Ch2_GameServer": "GameServer", "Ch2_NpcServer": "NpcServer", "Ch2_RelayServer": "RelayServer"}

# Исполняемые файлы копий, которые НЕ равны полю (переименованы строки именованных таймеров — иначе копии делят
# таймеры ядра с полем: PLAN.md §3, Docs/Indun_NpcServer/waitable-timer-name-collision.md). Площадки AddonNPC/P-патчей
# в этих байтах не лежат: копия отличается от поля только строками таймеров.
EXE_MD5 = {
    r"NpcServer\NpcServer.exe":           "c02486d62e803e98eb6fb4fa98d1fcd6",   # живой, импорт AddonNPC
    r"Indun_NpcServer\NpcServer.exe":     "0de2c55932c2966537e2a8c539decdcd",   # + имена таймеров Indun_* (03.08)
    r"Ch2_NpcServer\NpcServer.exe":       "7f79b5daf74c7754d622853cb1335718",   # + имена таймеров Ch2_* (26.10)
    # ★ 15.11.2026 P126: импорт SrvDbPatch.dll (до P126: a8cd94ba… и Ch2 075c41a5…)
    r"RelayServer\RelayServer.exe":       "6851e00055560fefc04f44c68956b9a5",
    r"Indun_RelayServer\RelayServer.exe": "6851e00055560fefc04f44c68956b9a5",
    r"Ch2_RelayServer\RelayServer.exe":   "418b24a21bf4c2cd222a56d0da53e19b",   # + 'Ch2WaitTimer' @0x19038 (26.10)
    r"GameServer\GameServer.exe":         "e7b4ac38e8328aaa847bbd9bf261bb01",
    r"Indun_GameServer\GameServer.exe":   "e7b4ac38e8328aaa847bbd9bf261bb01",
    r"Ch2_GameServer\GameServer.exe":     "e7b4ac38e8328aaa847bbd9bf261bb01",
}

# Поканальные файлы копий (относительно папки) — у копии СВОИ, в паритет не входят.
CHANNEL_FILES = {
    "Ch2_GameServer": [r"ConfigSet\ServerIPPORT.txt", r"ConfigSet\ConnectIPPORT.ini", r"ConfigSet\ChannelInfo.ini",
                       r"ConfigSet\VillageServerConfig.Ini", r"MapData_Info\GroupInfo.ini", "ConnectIP_Info\\", "PortalIP_Info\\",
                       r"ConfigSet\ac_kick_counter.ini", r"ConfigSet\ac_integrity_counter.ini", r"asdapatch_boot.log",
                       r"Event\EventLog.txt", r"NpcData_Info\flabis.npc", r"NpcData_Info\Inferion.npc", r"NpcData_Info\t_castle_of_chess.npc"],
    "Ch2_NpcServer": [r"ini\ServerIPPORT.txt", r"ini\AIInfo.ini", "NpcServer.exe", "asdapatch_boot.log"],
    "Ch2_RelayServer": [r"ini\ServerIPPORT.txt", r"ini\ChannelInfo.ini", "RelayServer.exe"],
}
# Папки журналов (файлы в них пишет сам процесс) — в паритет не входят. В Log\ лежат и Log_Patch (PatchLog_*.txt наших DLL,
# AsdaPatch Log.cpp:53) и Log_AcJournal (запасной журнал P53, AcJournal.cpp:693); Error_Log — SpeedHack_*.txt NpcServer,
# журналы Relay; OLEDB_LOG — журналы ODBC Relay/LoginManager; Log_IocpNet — сеть всех стоковых серверов.
LOG_DIRS = ["Log", "Logs", "Log_IocpNet", "PatchLog", "OLEDB_LOG", "Error_Log", "logs"]

# ★ 26.10.2026 (инцидент 18:55: restart_stack встал с кодом 6 из-за Ch2_NpcServer\Event\EventLog.txt): файлы, которые
#   серверы ПИШУТ во время работы, у каждой копии свои — в паритет (сверку и --sync) НЕ входят ни у поля, ни у копии.
#   Шаблон имени (fnmatch, без учёта регистра) → обоснование:
RUNTIME_FILES = {
    "EventLog.txt":       "Event\\EventLog.txt — стоковые GameServer и NpcServer дописывают «… -> Read» при чтении Event.dat "
                          "(изменён у всех 6 процессов после старта 18:56)",
    "*.log":              "asdapatch_boot.log (dllmain.cpp:46 AsdaPatch/AddonNPC, переписывается при каждом старте), "
                          "dbpatch/loginpatch_boot.log и прочие журналы",
    "ErrTrace.txt":       "стоковый GameServer создаёт/обнуляет при старте (0 б, 18:56)",
    "*.dmp":              "аварийные дампы GameServer/NpcServer",
    "ac_*_counter.ini":   "счётчики P48/P69 — ведёт только GameServer\\ConfigSet (CounterFile=..\\GameServer\\…), копии в других папках не используются",
    "*_upload":           "временные файлы заливки (*.p91_upload, *.srvio_upload, …)",
    "*.part":             "временные файлы зеркала",
}


def is_runtime_file(name):
    """Имя файла (без пути) — из тех, что серверы пишут во время работы (RUNTIME_FILES)."""
    import fnmatch
    n = name.lower()
    return any(fnmatch.fnmatchcase(n, p.lower()) for p in RUNTIME_FILES)


# ★ 26.10.2026: расхождение в этих файлах — СУЩЕСТВЕННОЕ (код и настройки патчей): restart_stack после остановки стойки
#   не стартует только при нём; прочие расхождения данных — предупреждение (стойка стартует, отчёт «ЕСТЬ ПРОБЛЕМЫ»).
ESSENTIAL_PATTERNS = ["*.exe", "*.dll", "*patches.ini"]


def is_essential(rel):
    """Путь (от папки) — существенный для паритета (exe/dll/patches.ini)."""
    import fnmatch
    n = rel.replace("/", "\\").lower()
    return any(fnmatch.fnmatchcase(n, p.lower()) for p in ESSENTIAL_PATTERNS)

# ★ 26.10.2026 (инцидент: сухой прогон удалил 12 общих ini — псевдоним PowerShell Rd = Remove-Item): файлы, без которых
#   стойку НЕ запускать. restart_stack.py перед start.bat проверяет: есть и не пустой; иначе СТОП (код 5).
CRITICAL_FILES = [
    # 12 общих файлов (их правит deploy_channel2.py; бэкап v2\_backup\2026-10-26_channel2)
    r"start.bat", r"ChannelManager\ini\Server_Info.ini",
    r"LoginManager\GameServerIP\GameServerIP.ini", r"LoginManager\GameServerIP\0_0_ServerIP.ini",
    r"LoginManager\GameServerIP\0_1_ServerIP.ini", r"LoginManager\GameServerIP\CreateGameServerIP.ini",
    r"GameServer\ConfigSet\ChannelInfo.ini", r"Indun_GameServer\ConfigSet\ChannelInfo.ini",
    r"Indun_GameServer\MapData_Info\GroupInfo.ini", r"Indun_RelayServer\ini\ChannelInfo.ini", r"Indun_NpcServer\ini\AIInfo.ini",
    r"EacServer\EacServer.ini",
] + [d + r"\ConfigSet\patches.ini" for d in GS_FOLDERS] \
  + [d + r"\ConfigSet\patches.ini" for d in NPC_FOLDERS] \
  + [d + "\\" + f for d, files in CHANNEL_FILES.items() for f in files
     if not f.endswith("\\") and "counter" not in f and not f.endswith(".log") and "EventLog" not in f and not f.endswith(".npc")]

# ★ 26.10.2026 (канал 2: порт 15621 был закрыт): брандмауэр Windows на @@ASTORY_SERVER_HOSTNAME@@ пускает процессы стойки по ПРАВИЛАМ НА ПУТЬ EXE
#   (входящие Allow, профиль Private — сеть «Ethernet» на сервере Private; TCP и UDP; порт Any). У поля и Indun правила
#   создала сама Windows («TCP/UDP Query User{…}<путь>» — по запросу при первом старте), у Ch2_* их добавил координатор
#   26.10 (имена «Ch2_GameServer TCP/UDP» и т. д.). НОВАЯ КОПИЯ ПАПКИ = НОВЫЕ ПРАВИЛА: без них процесс копии недоступен ни
#   снаружи (проброс роутера бесполезен), ни из LAN. Проверка — restart_stack.py шаг 0 (firewall_missing), создание — по
#   образцу: New-NetFirewallRule -DisplayName "<папка> TCP" -Direction Inbound -Action Allow -Profile Private
#   -Protocol TCP -Program "<путь exe>" (и то же для UDP).
FIREWALL_EXES = ([d + r"\GameServer.exe" for d in GS_FOLDERS] + [d + r"\NpcServer.exe" for d in NPC_FOLDERS]
                 + [d + r"\RelayServer.exe" for d in RELAY_FOLDERS]
                 + [r"ChannelManager\ChannelManager.exe", r"DBManager\DBManager.exe", r"ItemRelayServer\ItemRelayServer.exe",
                    r"LoginManager\LoginManager.exe", r"OperationServer\OperationServer.exe",
                    r"OverlapCheckServer\OverlapCheckServer.exe"])

# Процессы стойки и сколько их должно быть после старта (restart_stack.py).
PROCS = ["ChannelManager", "DBManager", "OperationServer", "OverlapCheckServer", "RelayServer", "ItemRelayServer",
         "LoginManager", "NpcServer", "GameServer"]
EXPECT = {"ChannelManager": 1, "DBManager": 1, "OperationServer": 1, "OverlapCheckServer": 1,
          "RelayServer": len(RELAY_FOLDERS), "ItemRelayServer": 1, "LoginManager": 1,
          "NpcServer": len(NPC_FOLDERS), "GameServer": len(GS_FOLDERS)}
TOTAL_PROCS = sum(EXPECT.values())                                          # 15


def twin_of(folder):
    """Поле, с которого снята копия (или сама папка, если это не копия)."""
    return TWINS.get(folder, folder)


def _twin_path(rel, field, twin):
    """Путь поля → путь копии с тем же разделителем ('\\' или '/'); None, если путь не из папки поля."""
    for sep in ("\\", "/"):
        if rel == field or rel.startswith(field + sep):
            return twin + rel[len(field):]
    return None


def expand_paths(d):
    """Словарь «путь от v2 → значение»: для каждой копии добавить её путь со ЗНАЧЕНИЕМ поля (если ключа ещё нет).
    Значения (md5 базы/нового, локальный файл) у копии те же, что у поля: копия снята с поля побайтно."""
    out = dict(d)
    for rel, val in d.items():
        for twin, field in TWINS.items():
            key = _twin_path(rel, field, twin)
            if key:
                out.setdefault(key, val)
    return out


def expand_list(lst):
    """Список путей от v2: добавить пути копий (порядок сохраняется, без повторов)."""
    out = list(lst)
    for rel in lst:
        for twin, field in TWINS.items():
            key = _twin_path(rel, field, twin)
            if key and key not in out:
                out.append(key)
    return out


def expand_folder_dict(d):
    """Словарь «папка → значение» (например, список файлов с регистром имени, как на стойке): копия получает
    значение своего поля ({'GameServer': [...], 'Indun_GameServer': [...]} → + 'Ch2_GameServer': [... поля])."""
    out = dict(d)
    for twin, field in TWINS.items():
        if field in d:
            out.setdefault(twin, d[field])
    return out


def expand_pairs(pairs):
    """Список пар (папка, …): для каждой пары поля — такая же пара копии (порядок сохраняется, без повторов)."""
    out = list(pairs)
    for pr in pairs:
        for twin, field in TWINS.items():
            if pr[0] == field:
                np = (twin,) + tuple(pr[1:])
                if np not in out:
                    out.append(np)
    return out


def tools_dir():
    """Папка этого модуля — для sys.path в скриптах вне tools/ (AstoryServer/Tools/Anticheat, Server/Docs/…)."""
    import os
    return os.path.dirname(os.path.abspath(__file__))


def expand_folders(folders):
    """Список папок: добавить копии полевых (['GameServer','Indun_GameServer'] → + 'Ch2_GameServer')."""
    out = list(folders)
    for twin, field in TWINS.items():
        if field in folders and twin not in out:
            out.append(twin)
    return out
