# Copyright (c) 2026 @sitxovski (Discord)
# Одноразовая вставка P125 в исходники LoginPatch и DBPatch (15.11.2026, сессия srv-db-reconnect).
# Бэкап до правки: @@ASTORY_DEV_ROOT@@\_backup\2026-11-15_db_reconnect\. Повторный запуск ничего не меняет.
import io, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def edit(rel, pairs):
    p = os.path.join(ROOT, rel)
    raw = open(p, 'rb').read()
    crlf = b'\r\n' in raw
    s = raw.decode('utf-8')
    if 'P125' in s:
        print('уже есть:', rel); return
    s = s.replace('\r\n', '\n')
    for old, new in pairs:
        if s.count(old) != 1:
            sys.exit('не найдено ровно одно вхождение в %s: %r' % (rel, old[:60]))
        s = s.replace(old, new)
    if crlf: s = s.replace('\n', '\r\n')
    open(p, 'wb').write(s.encode('utf-8'))
    print('исправлен:', rel)

KEYS = r'''
    // ── [P125_DbReconnect] (15.11.2026): повторное подключение к SQL Server после обрыва связи ──
    const IniKey kDbReconnect[] =
    {
        { L"Enabled", L"1",
          L"; * Главный выключатель. 0 = как в стоке: после обрыва связи с базой каждая сессия отвечает\r\n"
          L";   ошибкой до перезапуска процесса.\r\n" },
        { L"Retry", L"1",
          L"; * 1 = после удачного переподключения запрос повторяется ОДИН раз. 0 = сессия открывается заново,\r\n"
          L";   но запрос, на котором обнаружен обрыв, отдаёт ошибку стоку (следующие запросы уже работают).\r\n"
          L";   Обрыв на отправке запроса повторять безопасно; при обрыве на приёме ответа сервер мог успеть\r\n"
          L";   выполнить запрос — повтор выполнит его второй раз.\r\n" },
        { L"Probe", L"1",
          L"; * 1 = если по сведениям об ошибке неясно, жива ли связь, сессия проверяется запросом SELECT 1.\r\n"
          L";   0 = переподключение только при SQLSTATE 08xxx или сетевом коде ошибки.\r\n" },
        { L"ReleaseOld", L"1",
          L"; * 1 = объекты оборванной сессии освобождаются. 0 = остаются висеть (на случай зависания драйвера\r\n"
          L";   при закрытии мёртвого соединения).\r\n" },
        { L"RetryIntervalMs", L"3000",
          L"; * После НЕудачной попытки открыть сессию заново следующая попытка на этой сессии — не раньше чем\r\n"
          L";   через столько миллисекунд (рабочий поток не ждёт подключения на каждом запросе).\r\n" },
        { L"ConnectTimeoutSec", L"5",
          L"; * Предел ожидания нового подключения, секунд (0 — как у драйвера).\r\n" },
        { L"LogPerMinute", L"30",
          L"; * Строк PatchLog о переподключениях в минуту, не больше.\r\n" },
    };
'''
KEYS_LM = KEYS.replace('''L"1",
          L"; * Главный''', '''L"1",
          L"; * Главный''')

SECT_DB = r'''
        { L"P125_DbReconnect",
          L"; * НАША правка (15.11.2026, дефект оригинала). После обрыва связи с SQL Server (14.11.2026 21:08 — обновление\r\n"
          L";   Tailscale, через адрес которого шли соединения) DBManager отвечал ошибкой 80004005 на каждый запрос до\r\n"
          L";   перезапуска: сток открывает источник и 10 сессий один раз при старте и никогда не открывает заново.\r\n"
          L";   Патч: вызов Execute в sub_447720 (0x447B49, 5 б) идёт через DBPatch — при обрыве сессия открывается\r\n"
          L";   заново и запрос повторяется один раз. Описание: AstoryServer\\Docs\\_Common\\db-reconnect-p125.md\r\n",
          kDbReconnect, ARRAYSIZE(kDbReconnect) },
'''
SECT_LM = r'''        { L"P125_DbReconnect",
          L"; === P125 (дефект оригинала, НАША ПРАВКА, 15.11.2026) =====================\r\n"
          L"\r\n"
          L"; После обрыва связи с SQL Server LoginManager отвечал на каждый вход «Login failed. Error 0»\r\n"
          L"; ([LOGIN] UPUserLogin Error) до перезапуска: сток открывает источник и 10 сессий один раз при\r\n"
          L"; старте и никогда не открывает заново. Патч: вызов Execute в sub_40F440 (0x40F7A9, 5 б) идёт\r\n"
          L"; через LoginPatch — при обрыве сессия открывается заново и запрос повторяется один раз.\r\n"
          L"; Описание: AstoryServer\\Docs\\_Common\\db-reconnect-p125.md\r\n",
          kDbReconnect, ARRAYSIZE(kDbReconnect) },
'''

# ── DBPatch ──
edit('DBPatch/src/Config.cpp', [
    ('    const IniSection kSections[] =\n', KEYS.lstrip('\n') + '\n    const IniSection kSections[] =\n'),
    ('          kShellRows, ARRAYSIZE(kShellRows) },\n    };\n', '          kShellRows, ARRAYSIZE(kShellRows) },\n' + SECT_DB + '    };\n'),
])
edit('DBPatch/src/Config.h', [
    ('    constexpr int kVersion = 10;\n',
     '    //   11 — [P125_DbReconnect] (15.11.2026): повторное подключение сессии к SQL Server после обрыва связи.\n'
     '    //       ⚠ Откат: прежняя DLL (Version 10) сама понизит Version; секция P125 останется и будет проигнорирована.\n'
     '    constexpr int kVersion = 11;\n'),
])
edit('DBPatch/src/Registry.cpp', [
    ('PatchResult P96_DbShellRows();', 'PatchResult P125_DbReconnect(); // ★ 15.11.2026 повторное подключение к SQL Server после обрыва связи (p125_db_reconnect.cpp)\nPatchResult P96_DbShellRows();'),
    ('          &P96_DbShellRows,\n          L"dbmanager.exe" },\n',
     '          &P96_DbShellRows,\n          L"dbmanager.exe" },\n\n'
     '        // ★ P125 — DBManager (15.11.2026, дефект оригинала): после обрыва связи с SQL Server сессия открывается\n'
     '        //   заново, запрос повторяется один раз. Площадка — вызов Execute внутри sub_447720 (0x447B49, 5 б);\n'
     '        //   с P28 (вход 0x447720) и бинарным P17 (0x4478B9) не пересекается. Общий модуль с LoginPatch:\n'
     '        //   AstoryServer/Patches/DbReconnect/src/DbReconnectCore.cpp.\n'
     '        { L"P125_DbReconnect",\n'
     '          L"база: после обрыва связи сессия открывается заново, запрос повторяется один раз (сток — ошибка до перезапуска)",\n'
     '          &P125_DbReconnect,\n'
     '          L"dbmanager.exe" },\n'),
])
edit('DBPatch/build.bat', [
    ('   /I src /I ..\\AsdaPatch\\src /I ..\\AsdaPatch\\src\\patches ^\n', '   /I src /I ..\\AsdaPatch\\src /I ..\\AsdaPatch\\src\\patches /I ..\\DbReconnect\\src ^\n'),
    ('src\\p96_db_shell_rows.cpp ^\n', 'src\\p96_db_shell_rows.cpp src\\p125_db_reconnect.cpp ^\n   ..\\DbReconnect\\src\\DbReconnectCore.cpp ^\n'),
    ('/OUT:out\\DBPatch.dll kernel32.lib user32.lib\n', '/OUT:out\\DBPatch.dll kernel32.lib user32.lib ole32.lib oleaut32.lib\n'),
    ('rem ---------------------------------------------------------------------------\nsetlocal', 'rem  P125 (15.11.2026): + ..\\DbReconnect\\src\\DbReconnectCore.cpp, ole32/oleaut32.\nrem ---------------------------------------------------------------------------\nsetlocal'),
])

# ── LoginPatch ──
edit('LoginPatch/src/Config.cpp', [
    ('    const IniSection kSections[] =\n', KEYS.lstrip('\n') + '\n    const IniSection kSections[] =\n'),
    ('        // Секции патчей добавляются сюда (по одной на патч, имя = PatchEntry::section).\n', SECT_LM + '        // Секции патчей добавляются сюда (по одной на патч, имя = PatchEntry::section).\n'),
    ('        { L"Version", L"9",\n', '        //   10 — P125 (15.11.2026): секция [P125_DbReconnect].\n        { L"Version", L"10",\n'),
])
edit('LoginPatch/src/Config.h', [
    ('    constexpr int kVersion = 9;\n',
     '    //   10 — P125: секция [P125_DbReconnect] (15.11.2026; откат — DLL v9 понизит Version, секцию проигнорирует)\n'
     '    constexpr int kVersion = 10;\n'),
])
edit('LoginPatch/src/patches/Patches.h', [
    ('PatchResult L08_ListenArrayLeak();', 'PatchResult P125_DbReconnect();      // ★ [ОРИГИНАЛ] после обрыва связи с SQL Server сессия открывается заново, запрос повторяется один раз\nPatchResult L08_ListenArrayLeak();'),
])
edit('LoginPatch/src/patches/Registry.cpp', [
    ('          &L08_ListenArrayLeak, nullptr },\n',
     '          &L08_ListenArrayLeak, nullptr },\n'
     '        // ★ P125 (15.11.2026): площадка — вызов Execute внутри sub_40F440 (0x40F7A9); с L02 (0x40F5C2) и L03/L06\n'
     '        //   (вызов sub_40F440 @0x407263) не пересекается. Общий модуль с DBPatch: ..\\DbReconnect\\src.\n'
     '        { L"P125_DbReconnect",\n'
     '          L"база: после обрыва связи сессия открывается заново, запрос повторяется один раз (сток — «Login failed. Error 0» до перезапуска)",\n'
     '          &P125_DbReconnect, nullptr },\n'),
])
edit('LoginPatch/build.bat', [
    ('   /I src /I ..\\AsdaPatch\\src /I ..\\AsdaSecure\\src ^\n', '   /I src /I ..\\AsdaPatch\\src /I ..\\AsdaSecure\\src /I ..\\DbReconnect\\src ^\n'),
    ('   ..\\AsdaPatch\\src\\Log.cpp ..\\AsdaPatch\\src\\Hook.cpp ..\\AsdaPatch\\src\\AcJournal.cpp ^\n', '   ..\\AsdaPatch\\src\\Log.cpp ..\\AsdaPatch\\src\\Hook.cpp ..\\AsdaPatch\\src\\AcJournal.cpp ^\n   ..\\DbReconnect\\src\\DbReconnectCore.cpp ^\n'),
    ('kernel32.lib user32.lib bcrypt.lib\n', 'kernel32.lib user32.lib bcrypt.lib ole32.lib oleaut32.lib\n'),
])
