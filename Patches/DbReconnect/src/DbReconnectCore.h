// Copyright (c) 2026 @sitxovski (Discord)
// DbReconnectCore.h — P125: повторное подключение сессии OLE DB после обрыва связи с SQL Server.
//
// Общий модуль трёх DLL: LoginPatch.dll (LoginManager.exe) и DBPatch.dll (DBManager.exe) — P125;
// SrvDbPatch.dll (RelayServer.exe, ItemRelayServer.exe, OperationServer.exe) — P126 (15.11.2026).
// Во всех пяти образах один и тот же класс работы с базой (провайдер MSDASQL поверх DSN), разные сборки:
//   LM/DB — 20 источников по 0x14410 байт, в каждом 10 сессий по 0x2050 байт со смещения 0xF0;
//   Relay/ItemRelay/Operation — 10 источников по 0xA410 байт, 10 сессий по 0x1050 байт со смещения 0xF0.
//   Запись сессии (поля +0/+4/+8/+0xC/+0x50) и источник (+0, +8, +0xD8) у всех одинаковы.
// Сток при ошибке ICommand::Execute только пишет строку в OLEDB_LOG и возвращает 0 —
// соединение не открывается заново НИКОГДА, сервер «глохнет» до перезапуска процесса.
//
// Модуль не знает ни о журнале патчей, ни о конфиге: всё передаётся через Configure().
// Так его можно собрать в стенд без DLL (tools\stand_p125.cpp).
#pragma once
#include <windows.h>

namespace DbReconnect
{
    // Раскладка класса стока. Умолчания = LoginManager/DBManager (P125), доказаны декомпилом обоих.
    // P126 (15.11.2026): у RelayServer / ItemRelayServer / OperationServer та же запись сессии, но меньше массивы:
    //   10 источников по 0xA410 б, 10 сессий по 0x1050 б, счётчик +0x668A0 (декомпил RE/ida/relay_work).
    struct Layout
    {
        DWORD srcSize   = 0x14410;    // размер одного источника
        DWORD sessSize  = 0x2050;     // размер одной сессии
        DWORD maxSrc    = 20;         // источников в объекте (не больше kMaxSrc)
        DWORD maxSess   = 10;         // сессий в источнике (не больше kMaxSess)
        DWORD countOff  = 0x195140;   // число открытых источников (сразу за массивом)
    };

    // Описание образа-хозяина.
    struct Host
    {
        // Адрес объекта класса работы с базой в образе (LM 0x43ACD8, DB 0x534E7F0, Relay 0x427A30, Operation 0x414660).
        // 0 — объект не один и не на постоянном месте (ItemRelayServer: по объекту на поток NPC в куче + временный
        // на стеке). Тогда источник сессии ищется по самой записи: DBPROPSET источника указывает внутрь
        // своего же источника (rgProperties = источник + 8, 4 свойства, набор DBPROPSET_DBINIT) — см. Locate.
        DWORD          objBase;
        const wchar_t* tag;       // метка в строках журнала («P125», «P126»)
        Layout         layout = {};
    };

    // Настройки (читаются из ini один раз при установке патча).
    struct Settings
    {
        bool retry;               // после удачного переподключения повторить запрос один раз
        bool probe;               // если по сведениям об ошибке непонятно, жива ли связь — проверить «SELECT 1»
        bool releaseOld;          // освобождать объекты оборванной сессии (иначе оставить висеть)
        bool comInit;             // инициализировать COM на рабочем потоке перед первым запросом (нужно для сведений об ошибке)
        int  retryIntervalMs;     // после НЕудачного переподключения не пробовать снова на этой сессии столько мс
        int  connectTimeoutSec;   // предел ожидания нового подключения, с (0 — как у драйвера)
        int  logPerMinute;        // строк журнала в минуту, не больше
    };

    // Счётчики (для стенда и для строки в журнале).
    struct Stats
    {
        LONG execFail;        // Execute вернул ошибку
        LONG deadByState;     // обрыв определён по SQLSTATE 08xxx / коду сети
        LONG deadByProbe;     // обрыв определён проверкой «SELECT 1»
        LONG aliveByState;    // обычная ошибка SQL по SQLSTATE — поведение стока
        LONG aliveByProbe;    // проверка прошла — обычная ошибка SQL, поведение стока
        LONG reconnectOk;     // сессия открыта заново
        LONG reconnectFail;   // открыть заново не удалось — поведение стока
        LONG throttled;       // попытка пропущена (пауза после неудачи)
        LONG retryOk;         // повтор запроса удался
        LONG retryFail;       // повтор запроса не удался — поведение стока
        LONG passthrough;     // запись сессии не опознана — поведение стока
        LONG exceptions;      // исключение внутри модуля — поведение стока
    };

    // Приёмник строк журнала (уже отформатированная строка без перевода строки).
    typedef void (*LogFn)(const wchar_t* line);

    // Включить модуль. До вызова ExecuteHook ведёт себя как сток (просто зовёт Execute).
    void Configure(const Host& host, const Settings& settings, LogFn log);

    // Замена косвенного вызова ICommand::Execute в функции запроса стока.
    // Соглашение и аргументы — ровно как у Execute (6 аргументов, стек чистит вызываемый).
    HRESULT __stdcall ExecuteHook(void* cmd, void* outer, const GUID* riid,
                                  void* params, void* rows, void** ppRowset);

    void GetStats(Stats* out);

    // Общее для всех пяти образов (LoginManager, DBManager, RelayServer, ItemRelayServer, OperationServer; декомпил всех).
    // Размеры массивов — в Layout (у каждого образа свои).
    constexpr DWORD kSessOff    = 0xF0;      // смещение массива сессий в источнике
    constexpr DWORD kMaxSrc     = 20;        // предел таблицы состояний для объекта на постоянном месте
    constexpr DWORD kMaxSess    = 10;        // то же, сессий в источнике
    constexpr DWORD kMaxLoose   = 256;       // записей сессий в таблице режима поиска (objBase = 0)
    constexpr DWORD kPropSetOff = 0xD8;      // DBPROPSET источника (указатель на 4 свойства, счётчик, GUID)
    constexpr DWORD kPropsOff   = 0x08;      // массив 4 DBPROP источника (на него указывает DBPROPSET)
    constexpr DWORD kRecCreate  = 0x00;      // IDBCreateSession*
    constexpr DWORD kRecSession = 0x04;      // IDBCreateCommand* (объект сессии)
    constexpr DWORD kRecRowset  = 0x08;      // IRowset* результата
    constexpr DWORD kRecCommand = 0x0C;      // ICommandText*
    constexpr DWORD kRecText    = 0x50;      // текст запроса (широкие символы, завершён нулём)
}
