// Copyright (c) 2026 @sitxovski (Discord)
// Registry.cpp — список патчей SrvDbPatch в порядке установки.
//
// Как добавить патч: файл pNNN_<имя>.cpp с функцией `PatchResult PNNN_<Имя>()`, объявление в Patches.h,
// строка в kPatches ниже (hosts — для каких exe), секция в Config.cpp (+1 к Config::kVersion), файл — в build.bat.
#include "Patches.h"

namespace
{
    const PatchEntry kPatches[] =
    {
        // ★ P126 (15.11.2026): площадка — вызов Execute в функции запроса класса базы (у каждого образа свой адрес,
        //   таблица — p126_db_reconnect.cpp). Общий модуль с LoginPatch/DBPatch (P125): ..\DbReconnect\src.
        { L"P126_DbReconnect",
          L"база: после обрыва связи сессия открывается заново, запрос повторяется один раз (сток — «Execute Error» до перезапуска)",
          &P126_DbReconnect, L"relayserver.exe;itemrelayserver.exe;operationserver.exe" },
    };
}

const PatchEntry* g_patches    = kPatches;
const int         g_patchCount = ARRAYSIZE(kPatches);
