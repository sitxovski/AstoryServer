// Copyright (c) 2026 @sitxovski (Discord)
// Registry.cpp — список патчей LoginManager в порядке установки.
//
//   этап 0 (СДЕЛАН 12.10.2026): каркас — DLL грузится через таблицу импорта, создаёт
//     ConfigSet\patches.ini, пишет журнал и паспорт образа. Реестр ПУСТ.
//
//   этап 1 (впереди, план `Reports/anticheat/00_PLAN.md`, строка «2»): экранирование/отказ
//     по апострофу и набору символов логина, сверка UserIndex с сессией в 1005 и 1016 (режимы 0/1, потом соулмейт),
//     MAC в UPUserLogin, маска пароля в OTP_Report.
//
// Как добавить патч: файл patches\lNN_<имя>.cpp с функцией `PatchResult LNN_<Имя>()`,
// объявление в Patches.h, строка в kPatches ниже, секция в Config.cpp (+1 к Config::kVersion),
// адреса — в LoginApi.h. build.bat собирает patches\*.cpp сам.
#include "Patches.h"

namespace
{
    const PatchEntry kPatches[] =
    {
        { L"L01_LoginLogMask",
          L"журнал входа: хеш пароля замаскирован, MAC отдельным ограниченным полем (OTP_Report)",
          &L01_LoginLogMask, nullptr },
        { L"L03_LoginSqlRefuse",
          L"вход: апостроф в логине/пароле => отказ до сборки SQL (второй рубеж к процедуре)",
          &L03_LoginSqlRefuse, nullptr },
        { L"L02_LoginSqlLogMask",
          L"журнал ошибок базы: текст EXEC UPUserLogin маскируется (логин/MD5/IP/MAC)",
          &L02_LoginSqlLogMask, nullptr },
        { L"L04_LoginIdentity",
          L"привязка UserIndex к сессии: 1005 (список персонажей) + 1016 режимы 0/1 (обычный/«душа») + режим 2 (соулмейт: только своя пара)",
          &L04_LoginIdentity, nullptr },
        { L"L05_LogoutMd5Len",
          L"1010/1028: MD5 тела считается по 32 байтам, как подписывает клиент (сток считал по 61 — не сходилось никогда)",
          &L05_LogoutMd5Len, nullptr },
        // ★ L06 обязан стоять ПОСЛЕ L03: та же площадка 0x407263, встаёт цепочкой поверх L03.
        { L"L06_LoginMac",
          L"вход: MAC клиента (cred+113) уходит 5-м аргументом EXEC UPUserLogin (@Mac → LogInfo.Mac; сток слал пусто)",
          &L06_LoginMac, nullptr },
        { L"L07_TrafficEncryption",
          L"шифрование трафика: прослойка AsdaSecure (ECDH P-256 + ECDSA + AES-256-GCM), Enabled=0 по умолчанию",
          &L07_TrafficEncryption, nullptr },
        { L"L08_ListenArrayLeak",
          L"массив подключений: без дублей слота, ранний разрыв снимается сразу, сироты чистятся перед пинг-сторожем (окно 1098 при входе)",
          &L08_ListenArrayLeak, nullptr },
        // ★ P125 (15.11.2026): площадка — вызов Execute внутри sub_40F440 (0x40F7A9); с L02 (0x40F5C2) и L03/L06
        //   (вызов sub_40F440 @0x407263) не пересекается. Общий модуль с DBPatch: ..\DbReconnect\src.
        { L"P125_DbReconnect",
          L"база: после обрыва связи сессия открывается заново, запрос повторяется один раз (сток — «Login failed. Error 0» до перезапуска)",
          &P125_DbReconnect, nullptr },
        // ★ L09 (21.11.2026, админ-центр А5.3): площадки — call отправки 1004 в обработчике входа (0x407B2F) и ★ ревизия 43 С-1 —
        //   call EXEC UPCharSoulState в 1016 (0x40B41A); ни с одной из площадок выше не пересекаются (L01 0x407079, L03/L06 0x407263,
        //   L04 0x407FD2/0x40B1AB/0x40B3AF, L05 0x40D1E0/0x40D40E). ★ ревизия 43б: запрос гейта идёт через sub_40F440 целиком — L02
        //   (0x40F5C2, маска журнала) и P125 (0x40F7A9, повтор после обрыва) действуют и на него (так и нужно). Режим 2 (соулмейт) L09
        //   решает внутри трамплина L04c (0x40B3AF, до sub_4037B0) через L04c_SetMaintGate — поэтому L04 стоит в реестре раньше L09.
        { L"L09_LoginMaintenance",
          L"режим обслуживания: вход (статус 28 процедуры) и вход в мир (adm.LoginMaintenanceGate) => стоковый отказ 4101 код 28 (нотис 7017)",
          &L09_LoginMaintenance, nullptr },
    };
}

const PatchEntry* g_patches    = kPatches;
const int         g_patchCount = ARRAYSIZE(kPatches);
