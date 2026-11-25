// Copyright (c) 2026 @sitxovski (Discord)
// LoginApi.h — адреса и константы ОБРАЗА LoginManager.exe.
//
// Полный аналог `AsdaPatch/src/SrvApi.h` (GameServer) и `AddonNPC/src/NpcApi.h` (NpcServer).
// Держим отдельно: адреса образов не имеют между собой ничего общего, и перепутать их —
// верный способ записать байты не туда.
//
// ⚠ Значения выверены на ЖИВОМ образе LoginManager.exe md5 12dcd9f14359610dcc045b7317102e81
//   (245 760 б, \\@@ASTORY_SERVER_HOSTNAME@@\h(@@ASTORY_SERVER_HOSTNAME@@_ns)\ASDA\Working_ASDA\v2\LoginManager, сверено 12.10.2026).
//   Это НЕ чистый сток: в нём уже стоят 4 байтовые правки обхода авторизации
//   (AstoryServer/Docs/LoginManager/auth-ip-secret-bypass.md). Базой берём именно его,
//   чтобы не потерять действующие правки.
#pragma once
#include <windows.h>

namespace Login
{
    constexpr DWORD kImageBase = 0x00400000;   // фиксированная база (DllCharacteristics = 0, без ASLR)
    constexpr DWORD kFileSize  = 245760;       // размер файла; инъекция импорта его НЕ меняет
    constexpr DWORD kEntryRva  = 0x0001F83B;   // AddressOfEntryPoint

    namespace Hooks
    {
        // L01 — маскировка хеша пароля в журнале входа (OTP_Report) + MAC отдельным полем.
        //   В обработчике входа 1003 (`sub_406C20`) строка-журнал пишется вызовом
        //   `sub_41B760(2, "Login User ID %s/%s, Pass %s/%s, IP %s", id1,id2,pass1,pass2,ip)`.
        //   Второй аргумент пароля `pass2` указывает в сырое поле пакета (`Buf1[81]`, 32 б БЕЗ
        //   завершающего нуля), поэтому `%s` переполняет чтение в соседнее поле MAC (`Buf1[113]`)
        //   и далее — MD5 пароля и MAC случайно попадают в открытый журнал.
        //   Патч заменяет ЭТОТ вызов на свой трамплин: пароль не пишется (маска), MAC читается
        //   отдельно с ограничением 17 байт и выводится своим полем.
        constexpr DWORD kLoginLogCall = 0x00407079;   // `call sub_41B760` (5 б: e8 e2 46 01 00)
        constexpr DWORD kLogFunc      = 0x0041B760;    // сама функция журнала `sub_41B760`
        constexpr DWORD kLoginLogRet  = 0x0040707E;    // возврат (`add esp,0x1C` — снятие 7 аргументов)
        // Раскладка аргументов `pass2`: хеш 32 б, сразу за ним поле MAC (17 б, "xx-xx-..-xx").
        constexpr int   kMacOffset    = 32;            // MAC = pass2 + 32 (= Buf1[113])
        constexpr int   kMacLen       = 17;            // "xx-xx-xx-xx-xx-xx"

        // L03 — отказ по апострофу в логине/пароле (второй рубеж к проверке в процедуре).
        //   Хук на КОНКРЕТНОМ вызове сборщика SQL в обработчике входа 1003 (`sub_406C20`):
        //   `call sub_40F440` @0x407263 для запроса `EXEC UPUserLogin '%s','%s',…`.
        //   Перехватом именно этого вызова мы не трогаем остальные запросы (где апостроф
        //   легитимен), а при апострофе в логине/пароле возвращаем отказ ШТАТНЫМ путём:
        //   `*out = 0` ⇒ обработчик входа уходит в ветку «UPUserLogin Error» (отказ клиенту).
        constexpr DWORD kLoginSqlCall = 0x00407263;   // `call sub_40F440` (5 б: e8 d8 81 00 00)
        constexpr DWORD kSqlBuilder   = 0x0040F440;    // сам сборщик `sub_40F440`
        //   Смещения аргументов на стеке на момент вызова (после нашего `call` — +ret):
        //     [esp+0x08] out(a2)   [esp+0x1C] login(Str)   [esp+0x20] password(v46)

        // L06 — MAC клиента в 5-й '%s' `EXEC UPUserLogin` (@Mac → LogInfo.Mac). ТА ЖЕ площадка, что L03
        //   (kLoginSqlCall); цепочка site → L06 → L03 → sub_40F440 при ЛЮБОМ порядке установки ([fix13]: L03 после L06
        //   встаёт в слот L06 через L06_ChainNext, узнавая его трамплин по L06_TrampolineAddr).
        //   Дизасм площадки (0x40720C..0x407263, cdecl справа налево): 14-й `lea eax,[ebp-0x2568]` (&v16) …
        //   11-й `lea eax,[ebp-0x2530]; push eax` @0x407221 (&v33) … 1-й `push 0x43acd8`; `add esp,0x38` @0x407268.
        //   После `call`: [esp+0x2C] = &v33 — 11-й аргумент = 5-й '%s'. Под v33 в кадре 12 б
        //   (v33 @-0x2530 … v36, затем v37 @-0x2524) — 17+NUL не влезают ⇒ указатель подменяется на буфер трамплина.
        //   ★ Источник MAC: cred-блок Buf1 = ebp-0x110 (`memcpy(Buf1, a5+33, 0xF3)`: `push 0xf3 … lea eax,[ebp-0x110]`
        //     @0x406E3C/0x406E50), MAC = Buf1[113] = ebp-0x9F. НЕ «[esp+0x20]+32»: 2-й аргумент здесь v46 = ebp-0x2508 —
        //     КОПИЯ пароля (`push 0x20; lea eax,[ebp-0xbf]; lea ecx,[ebp-0x2508]` @0x406FA0), v46[32] = 0.
        //     (В L01 «pass2+32» верно, потому что там pass2 = &Buf1[81] = ebp-0xBF.)
        constexpr int   kLoginSqlMacArg = 0x2C;          // [esp+0x2C] после call — 11-й аргумент (&v33)
        constexpr int   kLoginFrameBuf1 = 0x110;         // Buf1 = ebp-0x110 (243 б cred-блока)
        constexpr int   kLoginBuf1MacOff = 113;          // Buf1[113] — поле MAC (17 б, без гарантии NUL)
        constexpr int   kLoginFrameMac  = kLoginFrameBuf1 - kLoginBuf1MacOff;   // 0x9F: MAC = ebp-0x9F

        // L02 — маскировка текста `EXEC UPUserLogin …` в журнале ошибок базы (OLEDB_LOG).
        //   Врезка в `sub_40F440` СРАЗУ ПОСЛЕ `MultiByteToWideChar` (@0x40F5BC — это уже
        //   трамплин P17): к этому моменту узкий буфер `MultiByteStr` (ebp-0x1020) для
        //   ИСПОЛНЕНИЯ больше не нужен (запрос исполняется из ШИРОКОГО буфера), а при ошибке
        //   он уходит в лог как есть — с логином, MD5 пароля, IP и MAC. Маскируем узкий
        //   буфер на месте (только если это запрос UPUserLogin) — исполнение не затронуто.
        constexpr DWORD kSqlAfterMbtwc = 0x0040F5C2;   // `mov [ebp-0x1028],eax` (6 б: 89 85 d8 ef ff ff)
        constexpr DWORD kSqlMaskRet    = 0x0040F5C8;   // возврат из врезки
        constexpr int   kSqlMbStrOff   = 0x1020;       // MultiByteStr = ebp-0x1020

        // L04 — привязка номера учётки к сессии (личность владельца соединения).
        //   Сессия хранит подтверждённый на входе UserIndex в слоте
        //   `*(DWORD*)(&dword_66B4DA0 + 143*session + 759878)`; читает его `sub_4038B0@0x4038B0`
        //   (__thiscall this=&dword_66B4DA0, a2=session), пишет `sub_4037B0@0x4037B0`.
        //
        //   L04a (1016, выбор персонажа `sub_40AD30`): гейт сверки UserIndex с сессией стоял
        //   только на режиме 0 (`!LOBYTE(v109[0])`). Правим условие так, чтобы сверка шла для
        //   режимов 0 И 1, а пропускался только режим 2 (соулмейт, отдельная логика):
        //     0x40B1AB  85 c0            test eax,eax      ->  3c 02        cmp al,2
        //     0x40B1AD  0f 85 a6 000000  jne 0x40B259      ->  0f 84 …      je  0x40B259
        //   8 байт `85 c0 0f 85 a6 00 00 00` -> `3c 02 0f 84 a6 00 00 00`.
        constexpr DWORD kSelModeGate = 0x0040B1AB;
        constexpr DWORD kGetSessUser = 0x004038B0;   // sub_4038B0 (__thiscall) — UserIndex сессии
        constexpr DWORD kSessionObj  = 0x066B4DA0;   // &dword_66B4DA0 (объект сессий)

        //   L04b (1005, список персонажей `sub_407CE0`): UserIndex (word[ebp-0x24]) брался из
        //   пакета и НЕ сверялся с сессией — список персонажей любой учётки. Перехватываем
        //   `call sub_40F440` (UPCharExist) @0x407FD2: если UserIndex != UserIndex сессии —
        //   запрос не выполняется, `*out = 0` (штатная ветка «нет персонажа»), утечки нет.
        constexpr DWORD kCharListCall = 0x00407FD2;   // call sub_40F440 (5 б: e8 69 74 00 00)
        constexpr DWORD kSqlBuilder40F440 = 0x0040F440;
        //   [esp+0x08]=out  [esp+0x1C]=UserIndex(из пакета, 7-й арг)  [esp+0x20]=group (8-й арг)  ;  session a2 = [ebp+8]
        //   (cdecl, справа налево: дизасм 0x407F9F push group → push UserIndex → … ; ★ в первой сборке читался 0x20 — ошибка)

        //   L04c (1016, режим 2 = вход персонажем СОУЛМЕЙТА; режимы: 0 обычный, 1 «душа», 2 соулмейт —
        //   байт режима уходит 4-м аргументом в UPCharSoulState). Сток после UPPreSMConnect зовёт
        //   `sub_4037B0(session, UserIndex_из_пакета)` @0x40B3AF — переписывает личность сессии чужим
        //   номером без проверки, что это именно соулмейт. Перехватываем ЭТОТ call: трамплин берёт
        //   UserIndex сессии (sub_4038B0), выполняет `EXEC UPCharExist %d,%d` (UserIndex, Seridx) —
        //   порядок как в 1005 (LoginManager.c:2895) — и сверяет result[4..7] (MateUserindex, как читает
        //   1005: memcpy(&v46,&v44[4],4)) с UserIndex из пакета. Несовпадение — штатный отказ 1016:
        //   1027 (651 б, код 3 «нет активной пары») через sub_415A40, снятие секции, эпилог.
        //   Кадр sub_40AD30 (дизасм стока 0x40B259..0x40B3B4):
        //     [ebp+8] session(word)  [ebp+0xC] hdr a3(word)  [ebp+0x10] db a4
        //     [ebp-0x28] байт режима  [ebp-0x27] UserIndex(dword, невыровнен)  [ebp-0x22] group(word)
        //     [ebp-0x618] буфер отказа 1027 (651 б)  [ebp-0x1C] крит. секция  [ebp-4] SEH-индекс
        constexpr DWORD kSelMateCall  = 0x0040B3AF;   // call sub_4037B0 (5 б: e8 fc 83 ff ff)
        constexpr DWORD kSetSessUser  = 0x004037B0;   // sub_4037B0 (__thiscall this, session, UserIndex; ret 8)
        constexpr DWORD kDbSrcOfGroup = 0x004060A0;   // sub_4060A0 (__stdcall group) -> индекс источника БД
        constexpr DWORD kSqlCtx       = 0x0043ACD8;   // &unk_43ACD8 — 1-й аргумент sub_40F440
        constexpr DWORD kSendPacket   = 0x00415A40;   // sub_415A40 (__thiscall this, opcode, size, slot, body, hdr, pad)
        constexpr DWORD kNetObj       = 0x005CFFD8;   // this для sub_415A40 (mov ecx,0x5cffd8 @0x40B383)
        constexpr DWORD kLeaveCs      = 0x00401040;   // sub_401040 (__thiscall) — выход из секции обработчика
        constexpr DWORD kSelEpilogue  = 0x0040C8CF;   // эпилог sub_40AD30 (esp = база кадра, как у стока @0x40B39C)
        constexpr int   kSelFrameUi   = 0x27;          // [ebp-0x27] UserIndex из пакета
        constexpr int   kSelFrameGrp  = 0x22;          // [ebp-0x22] group
        constexpr int   kSelFrameBody = 0x618;         // [ebp-0x618] буфер 1027
        constexpr int   kSelBodyLen   = 0x28B;         // 651

        // L09 — режим обслуживания (21.11.2026, админ-центр А5.3). Обработчик входа 1003 (`sub_406C20`) после switch по статусу
        //   UPUserLogin (LoginManager.c:2601-2719) для статусов 2/3 (не 4-й подряд), 4 и ЛЮБОГО неизвестного (default) приходит
        //   к одному вызову отправки ответа: `sub_415A40(1004, 8, slot, &v69, a3, 1)` — дизасм 0x407B10..0x407B2F:
        //     push 1; mov ax,[ebp+0xC]; push eax; lea ecx,[ebp-0x118]; push ecx; mov dx,[ebp+8]; push edx; push 8; push 0x3ec;
        //     mov ecx,0x5cffd8; call 0x415a40   (__thiscall, 6 аргументов, вызываемый снимает 0x18).
        //   Тело v69 — 8 байт, [0] = статус. Патч заменяет ЭТОТ call: статус «обслуживание» (по умолчанию 28 — его отдаёт врезка
        //   L09 в UPUserLogin) уходит стоковым отказом 4101 код 28 (как ProcConnect по AcceptIp.ini, LoginManager.c:2017:
        //   `sub_415A40(4101, 1, slot, &code, 0, 1)`); всё прочее — как было. Ветки 1/5/6/7 и 4-й отказ 2/3 этой площадки не
        //   проходят (у них свои вызовы и return).
        constexpr DWORD kLoginReplyCall = 0x00407B2F;   // `call sub_415A40` (5 б: e8 0c df 00 00)
        constexpr WORD  kOpLoginReply   = 1004;         // 0x3EC — ответ на вход
        constexpr WORD  kOpLoginRefuse  = 4101;         // 0x1005 — отказ / кик с кодом
        //   ★ ревизия 43 С-1 — второй гейт: ВХОД В МИР с выбора персонажа (1016, `sub_40AD30`). Первый запрос к базе, общий для
        //   режимов 0/1/2 и раньше всех записей, — `EXEC UPCharSoulState %d,%d,%d,%d` (LoginManager.c:4193; до него — только проверки
        //   пакета и сессии, L04a/L04c, и чтение UPPreSMConnect в режиме 2). Дизасм 0x40B3DD..0x40B41F: push mode / charidx /
        //   [ebp-0x27] UserIndex / [ebp-0x22] group, push 0x430320 (формат), dst [ebp-0x2a8c], push [ebp+0x10] (db), push sub_4060A0(group),
        //   out [ebp-0x2aa0], push 0x43acd8; `call sub_40F440` @0x40B41A; `add esp,0x28`; `cmp [ebp-0x2aa0],0; je` → «UPCharSoulState Error»
        //   (1027/651 б код 0, выход из секции, return). После call: [esp+8]=out, [esp+0xC]=dbsrc, [esp+0x10]=db, [esp+0x20]=UserIndex;
        //   сессия — [ebp+8], заголовок — [ebp+0xC]. Отказ режима: 4101/28 этой сессии, `*out = 0`, возврат 0 — дальше стоковый путь
        //   ошибки (без записей; клиент получит ещё 1027 код 0).
        constexpr DWORD kSelSoulStateCall = 0x0040B41A; // `call sub_40F440` (5 б: e8 21 40 00 00)
        //   ★ ревизия 43б: Н-1 — гейт идёт на соединение 0 (база входа, как EXEC UPUserLogin @0x407263 и UPChannelCount в этом же 1016),
        //   а не на dbsrc = sub_4060A0(group); Н-2 — режим 2 решается в трамплине L04c (0x40B3AF) до sub_4037B0 по ОБЕИМ учёткам
        //   (L04c зовёт L09_MateGate), на этой площадке режим 2 тогда пропускается. Байт режима — [ebp-0x28] (movzx @0x40B3DD).
        constexpr int   kSelFrameMode = 0x28;          // [ebp-0x28] байт режима 1016 (0 обычный, 1 «душа», 2 соулмейт)

        // L05 — длина MD5-проверки тел 1010 (Recv_ClientLogOut, sub_40D0A0) и 1028 (UPBackUser, sub_40D310).
        //   Сток считает MD5 по 0x3D (61) байтам тела с a5+33 (`push 0x3d` перед call sub_4060E0), а
        //   клиент (эталон login_charselect.c:1771 и порт SendSecured) подписывает ровно 32 байта
        //   блока — проверка не сходится НИКОГДА, обход этого и стоял (jne→jmp @0x40D1F0/@0x40D41E).
        //   После отката обхода оба опкода отклонялись бы всегда. Лечим причину: длина 0x3D → 0x20.
        constexpr DWORD kLogoutMd5LenPush = 0x0040D1E0;   // `push 0x3d` (6a 3d) в 1010; правится байт +1
        constexpr DWORD kBackMd5LenPush   = 0x0040D40E;   // `push 0x3d` (6a 3d) в 1028; правится байт +1

        // L07 — ★ шифрование трафика (прослойка AsdaSecure): точки врезки IOCP-слоя LoginManager.
        //   Способ — замена call-инструкций (как у остальных патчей) + один детур входа SetConnectFlag.
        //   Межсерверные слоты (10000..10099) НЕ трогаем — связь наших под-серверов (отдельная волна).
        //
        //   Приём клиента: в IoWorkerThread (sub_4161E0) единственная socket-recv клиентского слота —
        //     `call sub_415600` @0x4165B5 (ecx=this CCircleQ; стек [+4]=buf, [+8]=size, [+0xC]=slot).
        //     sub_415600 — стоковый переходник (this=ecx; buf,size,slot; ret 0xC). Синтетические вбросы
        //     accept/disc (0x415594/0x4156EE/0x415804) НЕ хукаем — это локальные кадры, не с провода.
        constexpr DWORD kRecvClientCall = 0x004165B5;   // call sub_415600 (5 б: e8 46 f0 ff ff)
        constexpr DWORD kRecvSink       = 0x00415600;   // сам sub_415600
        //   Отправка: Ciocp::Send (sub_413AB0, this=ecx; slot, Src, nBytes; ret 0xC). Ровно два call-site,
        //     оба в сетевом слое; SendTemp (sub_4141D0) лишь дослыает УЖЕ зашифрованный буфер — не хукаем.
        constexpr DWORD kSendCallA      = 0x004159F8;   // call sub_413AB0 (5 б: e8 b3 e0 ff ff)
        constexpr DWORD kSendCallB      = 0x00415F1E;   // call sub_413AB0 (5 б: e8 8d db ff ff)
        constexpr DWORD kSendFunc       = 0x00413AB0;   // сам Ciocp::Send (зовётся напрямую для ServerHello)
        //   Reset канала: детур входа Ciocp::SetConnectFlag (accept flag=1 / disc flag=0) — оба зовут его.
        constexpr DWORD kSetConnEntry   = 0x004144A0;   // вход (5 б украсть: 55 8b ec 6a ff)
        constexpr DWORD kSetConnResume  = 0x004144A5;   // продолжение тела после украденных 5 байт
        //   ★ В7d — активный разрыв при нарушении целостности: ШТАТНЫЙ путь стока «клиент закрыл соединение»
        //     (ветка нулевого приёма в IoWorkerThread @0x41643E..0x416463, дизасм lm_live 12dcd9f1):
        //       push slot; mov ecx,[ebp-24h]; call 0x414550 (GetConnectFlag); test eax,eax; je;
        //       push slot; mov ecx,[ebp-24h]; call 0x4138D0 (Ciocp::DisConnect); 0x416463: jmp 0x416472 → цикл.
        //     ecx на площадке приёма тот же [ebp-24h] (Ciocp this). Обе функции thiscall(this, slot), ret 4.
        //     DisConnect под локом Ciocp: флаг 0, сокет закрыт (closesocket, поле сокета = -1), вброс
        //     BufferingDisConnect (опкод 10 разборщику) → SetConnectFlag(slot,0) → наш Reset канала.
        //     После разрыва трамплин возвращается НЕ на 0x4165BA (там счётчик и ReadFile на закрытом сокете),
        //     а на 0x416463 — ровно туда, куда приходит стоковая ветка разрыва (esp одинаков: обе точки — границы
        //     операторов одного кадра IoWorkerThread, аргументы сняты ret).
        constexpr DWORD kGetConnFlag    = 0x00414550;   // Ciocp::GetConnectFlag (thiscall this,slot; ret 4)
        constexpr DWORD kDisConnect     = 0x004138D0;   // Ciocp::DisConnect     (thiscall this,slot; ret 4)
        constexpr DWORD kKillResume     = 0x00416463;   // `jmp 0x416472` (eb 0d) — хвост стоковой ветки разрыва
        constexpr DWORD kGetSocket      = 0x00416830;   // сокет слота (thiscall this,slot; ret 4) — для IP в журнал

        // L08 — ★ ИСПРАВЛЕНИЕ [ОРИГИНАЛ]: массив активных подключений CUser (dword_66B4DA0) копил «мёртвые» копии слота.
        //   Разбор: Reports/loginmanager_l08/L08_REPORT.md. Дизасм lm_live 12dcd9f1 (work/text.asm), образ 51db86b2.
        //   Кадры 20000 (accept, BufferingAccept 0x415630) и 10000 (разрыв, BufferingDisConnect 0x415500) идут в ОДНУ очередь
        //   CCircleQ, но разбирают её 10 потоков (StartAddress 0x4022D0, v10[210621] = 10 в sub_402CC0, LoginManager.c:839; потоки — sub_4041B0):
        //   ProcConnect 0x405A90 ждёт замок CUserProc (0x43AC88+0x1C) и зовёт SetEmpty, ClearConnect 0x405FE0 замка не берёт и
        //   зовёт Clear сразу → у закрытого сразу соединения Clear раньше SetEmpty («failed 1»), а SetEmpty добавляет запись.
        //   Площадки (все — call rel32, 5 б; меняется только адрес назначения):
        constexpr DWORD kSetEmptyCall   = 0x00405E25;   // ProcConnect: call sub_403160 (e8 36 d3 ff ff), ecx=0x66B4DA0, [a2 (cx), Str1]
        constexpr DWORD kSetEmptyFunc   = 0x00403160;   // SetEmpty_ListenArray (thiscall this, short slot, char* ip; ret 8) → 1/2/3
        constexpr DWORD kQueueClearCall = 0x00406048;   // ClearConnect (кадр 10000): call sub_4034A0 (e8 53 d4 ff ff), ecx=0x66B4DA0
        constexpr DWORD kClearFunc      = 0x004034A0;   // ClearListenArrayIndex (thiscall this, int slot; ret 4)
        constexpr DWORD kSweepCall      = 0x00401BFB;   // WndProc WM_TIMER id 2 (8000 мс): call sub_406560 (e8 60 49 00 00), ecx=0x43AC88
        constexpr DWORD kSweepFunc      = 0x00406560;   // CUserProc::Check_DisconnectUser (thiscall this; ret) — пинг-сторож
        constexpr DWORD kUserProcObj    = 0x0043AC88;   // this CUserProc (ecx на площадке сторожа)
        //   Раскладка объекта пользователей (this = kSessionObj 0x66B4DA0; дизасм 0x403160/0x4034A0):
        constexpr DWORD kUsrCs       = 0x000CDA8C;   // CRITICAL_SECTION (this+842380) — все SetEmpty/Clear/геттеры под ней
        constexpr DWORD kUsrUsers    = 0x000000A8;   // LONG число подключений (this+168, Interlocked; = count+1)
        constexpr DWORD kUsrArr      = 0x000000AC;   // int arr[550] — слоты активных подключений (this+172), хвост −1
        constexpr DWORD kUsrCount    = 0x00000944;   // LONG индекс последней записи arr (this+2372, «CurrentUserCount»; пусто = −1)
        constexpr int   kMaxUsers    = 550;          // 0x226 — слотов клиентов
        constexpr int   kSlotStride  = 143;          // запись слота: this + 143*slot + поле
        constexpr DWORD kSlotNum     = 0x000B9844;   // short номер (= slot; −1 свободен)                         759876
        constexpr DWORD kSlotIdent   = 0x000B9846;   // int UserIndex сессии (−1; L04)                              759878
        constexpr DWORD kSlotF1      = 0x000B984A;   // int (обнуляют SetEmpty/Clear)                               759882
        constexpr DWORD kSlotF2      = 0x000B984E;   // int SecretProc-счётчик                                      759886
        constexpr DWORD kSlotF3      = 0x000B9852;   // int GetMD5_Cmp-счётчик                                      759890
        constexpr DWORD kSlotPing    = 0x000B9856;   // int PingCount (Plus_PingCount 0x403910 / Init 0x403950)    759894
        constexpr DWORD kSlotPos     = 0x000B985A;   // int позиция слота в arr (−1 нет)                           759898
        constexpr DWORD kSlotW1      = 0x000B985E;   // short (обнуляют SetEmpty/Clear)                             759902
        constexpr DWORD kSlotW2      = 0x000B9860;   // short (обнуляют SetEmpty/Clear)                             759904
        constexpr DWORD kSlotIp      = 0x000B9862;   // char[20] IP (strncpy 0x14)                                  759906
        constexpr DWORD kSlotBlkA    = 0x000B9876;   // 0x3D б (memset в Clear)                                    759926
        constexpr DWORD kSlotBlkB    = 0x000B98B3;   // 0x20 б (memset в Clear)                                    759987
        //   Флаг соединения IOCP (Ciocp::GetConnectFlag 0x414550 → 0x4145E0): [g_cIocp 0x5CFFD8 + 0x60D1870 + 0x28] + 0xA0BE*slot + 4.
        //   DisConnect 0x4138D0 ставит 0 ДО вброса кадра 10000; accept 0x415630 — 1 сразу после вброса 20000.
        constexpr DWORD kIocpSlotsPtr   = 0x066A1870;   // DWORD — база массива слотов CSocketManager (0x5CFFD8 + 0x60D1898)
        constexpr DWORD kIocpSlotStride = 0x0000A0BE;   // 41150 — размер слота
        constexpr DWORD kIocpFlagOff    = 4;            // +4 — флаг соединения (1 accept … 0 разрыв)
        constexpr DWORD kIocpSockOff    = 0;            // +0 — сокет слота: accept 0x41887F пишет его (и флаг 1 @0x418892) ДО вброса
                                                        //   20000; DisConnect → 0x4183F0 closesocket и −1 @0x41846C ДО вброса 10000
        //   Слот «уже разорван» ⇔ сокет −1 (флаг не берём: BufferingAccept 0x415630 ставит 1 на каждый кадр данных).
        //   ★ IoWorker «тип 0xA» (0x4163F1 вброс 10000 → 0x416410 close) закрывает сокет ПОСЛЕ вброса — L08 на 0x406048 ждёт.
        constexpr DWORD kSlotInitFunc   = 0x00402F00;   // CUser: начальная разметка 550 слотов (thiscall this) — для стенда

        // Ориентиры (не патчатся, нужны для сверки образа в журнале)
        constexpr DWORD kEntryPoint = kImageBase + kEntryRva;   // call __security_init_cookie; jmp __tmainCRTStartup
    }
}
