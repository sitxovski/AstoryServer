// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  L01 — ★ ИСПРАВЛЕНИЕ (безопасность): маскировка хеша пароля в журнале входа
//        и вывод MAC отдельным ограниченным полем.
//
//  ЭТО НАША ПРАВКА (не перенос). Укрепление собственного LoginManager.
//
//  ── ЧТО НЕ ТАК В ОРИГИНАЛЕ ──
//  Обработчик входа 1003 (`sub_406C20@0x406C20`) пишет в журнал `OTP_Report`:
//      sub_41B760(2, "Login User ID %s/%s, Pass %s/%s, IP %s",
//                 id1, id2, pass1, pass2, ip);
//  где `pass2` = `&Buf1[81]` — СЫРОЕ поле пакета, 32 байта MD5 БЕЗ завершающего
//  нуля. `%s` читает дальше нуля и захватывает соседнее поле MAC (`Buf1[113]`),
//  а `pass1` (`&v46`) — тот же MD5, уже с нулём. Итог: в открытый текстовый
//  журнал попадают MD5 пароля (без соли) и MAC машины игрока.
//  (детектирование: `Reports/anticheat/04_detection_response.md` §6.3)
//
//  ── ЧЕМ ЛЕЧИМ ──
//  Заменяем ровно ЭТОТ вызов журнала (`call sub_41B760` @0x407079, 5 байт) на
//  `call` нашего трамплина. Трамплин:
//    • пароль НЕ пишет — на его месте литерал «(masked)»;
//    • MAC читает отдельно от `pass2+32`, с жёстким ограничением 17 байт и до
//      первого нуля, непечатаемые байты заменяет на '?', результат завершает
//      нулём в локальном буфере — переполнения чтения больше нет;
//    • зовёт НАСТОЯЩУЮ функцию журнала с безопасным форматом и теми же логином
//      и IP, в тот же канал (level=2, тот же файл).
//
//  Трамплин объявлен `__cdecl` с теми же 7 аргументами, что лежат на стеке на
//  момент оригинального вызова. Компилятор формирует стандартный cdecl-эпилог
//  (`ret` без снятия аргументов) — исходный `add esp,0x1C` на `0x40707E` снимает
//  аргументы, как и прежде. Ассемблер не нужен.
//
//  ── ГРАНИЦЫ И БЕЗОПАСНОСТЬ ──
//  • Единственная площадка: строка формата `0x42F308` в образе ссылается только
//    отсюда (проверено сканом бинаря).
//  • Запись НИКУДА не идёт, кроме локального буфера MAC; таблицы и память хоста
//    не трогаются.
//  • Всё тело обёрнуто в SEH: при негодном указателе трамплин выводит строку
//    без логина/MAC и не роняет процесс.
//  • Enabled=0 — вызов остаётся стоковым (журнал как в оригинале).
//
//  ⚠ Старые строки уже лежащих журналов не трогаются — патч влияет только на
//    НОВЫЕ записи после рестарта сервера.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "Hook.h"
#include "Log.h"
#include "Config.h"
#include "LoginApi.h"

namespace
{
    // Тип настоящей функции журнала: LONG __cdecl sub_41B760(int level, const char* fmt, ...).
    using LogFn = long(__cdecl*)(int, const char*, ...);

    // Указатель на настоящую функцию журнала. По умолчанию — адрес в образе.
    // ★ Вынесен в переменную, чтобы юнит-тест мог подменить сток своей заглушкой
    //   и проверить итоговую строку без запуска сервера.
    LogFn g_realLog = (LogFn)Login::Hooks::kLogFunc;

    bool g_logMac = true;    // писать ли поле MAC (из ini)

    // Безопасная выборка MAC: до 17 байт, до первого нуля, непечатаемое → '?'.
    // out обязан вмещать kMacLen + 1.
    void CopyMacSafe(const char* src, char* out)
    {
        int n = 0;
        if (src)
        {
            for (; n < Login::Hooks::kMacLen; ++n)
            {
                const unsigned char c = (unsigned char)src[n];
                if (c == 0) { break; }
                out[n] = (c >= 0x20 && c < 0x7F) ? (char)c : '?';
            }
        }
        out[n] = 0;
    }

    // ── трамплин замены вызова журнала входа ────────────────────────────────
    // Аргументы — ровно те, что оригинал кладёт на стек перед call @0x407079.
    long __cdecl LoginLogTrampoline(int level, const char* /*fmt*/,
                                    const char* id1, const char* id2,
                                    const char* /*pass1*/, const char* pass2,
                                    const char* ip)
    {
        __try
        {
            char mac[Login::Hooks::kMacLen + 1];
            CopyMacSafe(pass2 ? pass2 + Login::Hooks::kMacOffset : nullptr, mac);

            if (g_logMac)
            {
                return g_realLog(level, "Login User ID %s/%s, Pass (masked), MAC %s, IP %s",
                                 id1 ? id1 : "", id2 ? id2 : "", mac, ip ? ip : "");
            }
            return g_realLog(level, "Login User ID %s/%s, Pass (masked), IP %s",
                             id1 ? id1 : "", id2 ? id2 : "", ip ? ip : "");
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            // Негодный указатель — пишем хотя бы факт входа без деталей.
            return g_realLog(level, "Login User (masked)");
        }
    }

    // Исходные 5 байт площадки: call rel32 на sub_41B760.
    const BYTE kOrig[5] = { 0xE8, 0xE2, 0x46, 0x01, 0x00 };
}

// Экспонируется для юнит-теста (см. tools/test_l01.cpp).
extern "C" long __cdecl L01_TestInvoke(void* realLog, int macOn,
                                       const char* id1, const char* id2,
                                       const char* pass1, const char* pass2,
                                       const char* ip)
{
    g_realLog = (LogFn)realLog;
    g_logMac  = (macOn != 0);
    return LoginLogTrampoline(2, "fmt", id1, id2, pass1, pass2, ip);
}

PatchResult L01_LoginLogMask()
{
    if (!Config::GetBool(L"L01_LoginLogMask", L"Enabled", true))
    {
        return PatchResult::Disabled;
    }
    g_logMac = Config::GetBool(L"L01_LoginLogMask", L"LogMac", true);

    // Сверка оригинала: на площадке должен стоять ровно call sub_41B760.
    if (!Hook::Verify(Login::Hooks::kLoginLogCall, kOrig, sizeof(kOrig)))
    {
        wchar_t hex[32];
        Hook::Dump(Login::Hooks::kLoginLogCall, sizeof(kOrig), hex, 32);
        Log::Line(L"    L01: оригинал не совпал на 0x%08X (в образе %s) — пропуск",
                  Login::Hooks::kLoginLogCall, hex);
        return PatchResult::Mismatch;
    }

    // Заменяем call sub_41B760 -> call наш трамплин (5 байт, та же длина).
    g_realLog = (LogFn)Login::Hooks::kLogFunc;
    if (!Hook::WriteCall(Login::Hooks::kLoginLogCall, (void*)&LoginLogTrampoline, sizeof(kOrig)))
    {
        Log::Line(L"    L01: не удалось записать трамплин на 0x%08X", Login::Hooks::kLoginLogCall);
        return PatchResult::Failed;
    }
    Log::Line(L"    L01: журнал входа — пароль замаскирован, MAC%s отдельным полем",
              g_logMac ? L"" : L" НЕ пишется");
    return PatchResult::Applied;
}
