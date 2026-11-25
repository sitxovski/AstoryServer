// Copyright (c) 2026 @sitxovski (Discord)
// ChatJournal.cpp — ЖУРНАЛ ЧАТА И КЭШ ЗАГЛУШЕК (P129, А6.12, 22.11.2026). Описание — ChatJournal.h.
//   Образец механики — AcJournal.cpp (P53): та же очередь Вьюкова, тот же ленивый ODBC в фоновом потоке, тот же файловый
//   журнал при недоступной базе. Отдельный модуль, а не новая таблица AcJournal: текст чата до 199 б не помещается в событие
//   AcJournal (text[64]), а AcJournal — общий исходник трёх DLL (DBPatch, AddonNPC), его поведение не меняем.
#include "ChatJournal.h"
#include "Config.h"
#include "Log.h"
#include <sql.h>
#include <sqlext.h>
#include <stdio.h>
#include <string.h>

namespace
{
    const wchar_t* kSec = L"P129_ChatLog";

    // ── настройки ([P129_ChatLog]) ──────────────────────────────────────────
    bool    g_started      = false;      // поток и очередь созданы
    bool    g_logOn        = false;      // журнал принимает события (LogEnabled=1)
    int     g_flushMs      = 2000;       // FlushIntervalMs — период записи пакета, мс
    int     g_batchMax     = 500;        // BatchMax — событий в одном пакете (≤ 1000 — предел VALUES у SQL Server)
    int     g_reconnectSec = 30;         // ReconnectSec — пауза между попытками подключения
    int     g_retention    = 90;         // RetentionDays — очистка журнала старше N суток (0 — не чистить)
    int     g_muteRefresh  = 15;         // MuteRefreshSec — период чтения заглушек из базы
    int     g_maxMutes     = 4096;       // MaxMutes — строк в кэше заглушек (больше — хвост отбрасывается с записью в PatchLog)
    int     g_textCp       = 1251;       // TextCodePage — кодовая страница текста без UTF-8 и без маркера cp1256
    int     g_loginTimeout = 5;          // LoginTimeoutSec
    int     g_queryTimeout = 15;         // QueryTimeoutSec
    bool    g_fileFallback = true;       // FileFallback — при недоступной базе писать пакеты в файл
    int     g_fileRowsPerMin = 3000;     // FileRowsPerMinute — событий в файл в минуту (0 — без предела)
    int     g_maxFileMB    = 256;        // MaxFileMB — потолок суточного файла, МБ (0 — без предела)
    wchar_t g_conn[1024]   = L"";        // строка подключения ODBC (с паролем — в журнал не пишется)
    wchar_t g_connMasked[1024] = L"";    // то же с PWD=***
    wchar_t g_server[64]   = L"";        // имя процесса-источника (папка exe)
    int     g_serverPort   = ChatJournal::kNone;   // порт сервера (ConfigSet\ServerIPPORT.txt, 3-я строка)
    wchar_t g_fileDir[MAX_PATH] = L"";   // <exe>\Log\Log_ChatJournal

    constexpr BYTE kCp1256Marker = 0x98;  // маркер клиента Astory «дальше cp1256» (AsdaLoginData.h:87 kCp1256Marker)

    constexpr int kColServer   = 64;
    constexpr int kColChanName = 48;
    constexpr int kColName     = 32;
    constexpr int kColText     = 400;

    // ── очередь MPMC (Вьюков) — как AcJournal ─────────────────────────────────
    struct Cell
    {
        volatile LONG      seq;
        ChatJournal::Event ev;
    };
    Cell*         g_cells    = nullptr;
    LONG          g_mask     = 0;
    volatile LONG g_enq      = 0;
    volatile LONG g_deq      = 0;
    HANDLE        g_wake     = nullptr;   // авто-сброс: «пора писать»
    volatile LONG g_wakeSent = 0;         // SetEvent уже отправлен
    LONG          g_wakeAt   = 250;       // порог «пора писать» (BatchMax/2)
    HANDLE        g_thread   = nullptr;
    // ★ ревизия 60 М-4: пакет, снятый писателем с очереди, но ещё не записанный (выход процесса посреди записи — в файл).
    ChatJournal::Event* volatile g_inflight  = nullptr;
    volatile LONG                g_inflightN = 0;

    // ── статистика ───────────────────────────────────────────────────────────
    volatile LONG g_pushed = 0, g_dropped = 0, g_wDb = 0, g_wFile = 0, g_dbErr = 0, g_fileSkipped = 0;
    volatile LONG g_muteLoads = 0, g_muteErrors = 0, g_purges = 0, g_dbUp = 0;

    // ── кэш заглушек: два буфера + счётчики читателей ────────────────────────
    //   ★ stand_p129 race (22.11): первая версия (seqlock, 8 попыток чтения) при непрерывной подмене списка давала «нет
    //   заглушки» 240 раз из 80 000 — читатель сдавался. Теперь читатель НЕ сдаётся и НЕ ждёт: он отмечается в счётчике
    //   буфера и проверяет, что буфер всё ещё активный (иначе снимает отметку и берёт новый активный); писатель (фоновый
    //   поток) пишет только НЕактивный буфер и только когда в нём нет читателей — ждёт писатель, а не игровой поток.
    constexpr int kMuteCap = 16384;                       // жёсткий потолок MaxMutes
    ChatJournal::MuteRow* g_muteBuf[2] = { nullptr, nullptr };
    volatile LONG g_muteCount[2]   = { 0, 0 };
    volatile LONG g_muteReaders[2] = { 0, 0 };            // сколько игровых потоков сейчас читают буфер
    volatile LONG g_muteActive     = 0;                   // какой буфер читать
    SRWLOCK       g_mutePubLock    = SRWLOCK_INIT;        // публикация одна за раз (фоновый поток и стенд)

    // Опубликовать новый список заглушек (фоновый поток или стенд): пишется НЕактивный буфер без читателей.
    void PublishMutes(const ChatJournal::MuteRow* rows, int n)
    {
        if (!g_muteBuf[0] || !g_muteBuf[1]) { return; }
        if (n < 0) { n = 0; }
        if (n > g_maxMutes) { n = g_maxMutes; }
        AcquireSRWLockExclusive(&g_mutePubLock);
        const LONG b = 1 - g_muteActive;
        while (InterlockedCompareExchange(&g_muteReaders[b], 0, 0) != 0) { YieldProcessor(); SwitchToThread(); }   // дочитывают прежний
        for (int i = 0; i < n; ++i) { g_muteBuf[b][i] = rows[i]; }
        InterlockedExchange(&g_muteCount[b], n);
        InterlockedExchange(&g_muteActive, b);             // публикация (полный барьер)
        ReleaseSRWLockExclusive(&g_mutePubLock);
    }

    // ═══════════════════════════ построитель текста ═══════════════════════════
    struct WBuf
    {
        wchar_t* p = nullptr; int n = 0; int cap = 0;
        ~WBuf() { if (p) { HeapFree(GetProcessHeap(), 0, p); } }
        bool Reserve(int add)
        {
            if (n + add + 1 <= cap) { return true; }
            int nc = cap ? cap : 65536;
            while (nc < n + add + 1) { nc *= 2; }
            wchar_t* q = (wchar_t*)(p ? HeapReAlloc(GetProcessHeap(), 0, p, nc * sizeof(wchar_t))
                                      : HeapAlloc(GetProcessHeap(), 0, nc * sizeof(wchar_t)));
            if (!q) { return false; }
            p = q; cap = nc; return true;
        }
        void S(const wchar_t* s) { const int l = lstrlenW(s); if (Reserve(l)) { memcpy(p + n, s, l * sizeof(wchar_t)); n += l; p[n] = 0; } }
        void C(wchar_t c) { if (Reserve(1)) { p[n++] = c; p[n] = 0; } }
        void Int(int v)   { if (v == ChatJournal::kNone) { S(L"NULL"); return; } wchar_t t[16]; wsprintfW(t, L"%d", v); S(t); }
        void I64(__int64 v, bool has) { if (!has) { S(L"NULL"); return; } wchar_t t[32]; _snwprintf_s(t, _TRUNCATE, L"%I64d", v); S(t); }
        // N'…' с удвоением апострофов, обрезка до ширины колонки (пара суррогатов не рвётся); пусто → NULL (или N'' при notNull).
        void Str(const wchar_t* s, int maxChars, bool notNull = false)
        {
            if (!s || !*s) { S(notNull ? L"N''" : L"NULL"); return; }
            int len = 0;
            while (s[len] && len < maxChars) { ++len; }
            if (len == maxChars && s[len] && len > 0 && s[len - 1] >= 0xD800 && s[len - 1] <= 0xDBFF) { --len; }
            S(L"N'");
            for (int i = 0; i < len; ++i) { const wchar_t ch = s[i]; if (ch == L'\'') { C(L'\''); } C(ch < 0x20 ? L' ' : ch); }
            C(L'\'');
        }
        // 0x… (VARBINARY); пусто → NULL
        void Hex(const BYTE* d, int n)
        {
            if (!d || n <= 0) { S(L"NULL"); return; }
            static const wchar_t kH[] = L"0123456789ABCDEF";
            S(L"0x");
            for (int i = 0; i < n; ++i) { C(kH[d[i] >> 4]); C(kH[d[i] & 15]); }
        }
        void Clear() { n = 0; if (p) { p[0] = 0; } }
    };

    // FILETIME → '2026-11-22T13:45:01.123', '…' (UTC и местное).
    void AppendTimes(WBuf& b, __int64 ft)
    {
        FILETIME f; f.dwLowDateTime = (DWORD)ft; f.dwHighDateTime = (DWORD)(ft >> 32);
        SYSTEMTIME u = {}, l = {};
        FileTimeToSystemTime(&f, &u);
        if (!SystemTimeToTzSpecificLocalTime(nullptr, &u, &l)) { l = u; }
        wchar_t t[64];
        wsprintfW(t, L"'%04d-%02d-%02dT%02d:%02d:%02d.%03d', '%04d-%02d-%02dT%02d:%02d:%02d.%03d'",
                  u.wYear, u.wMonth, u.wDay, u.wHour, u.wMinute, u.wSecond, u.wMilliseconds,
                  l.wYear, l.wMonth, l.wDay, l.wHour, l.wMinute, l.wSecond, l.wMilliseconds);
        b.S(t);
    }

    // ★ Гибрид провода клиента Astory — РОВНО правило FAsdaLoginData::DecodeWireText (AsdaLoginData.cpp:321, IsStrictUtf8 :284):
    //   длина — до нуля в пределах поля; первый байт 0x98 — остальное cp1256 по таблице клиента GAsdaCp1256Hi (:118); иначе строгий
    //   UTF-8 (ведущие C2..DF/E0..EF/F0..F4, продолжения 80..BF, без overlong/суррогатов/>10FFFF) С ХОТЯ БЫ ОДНИМ многобайтным знаком,
    //   где обрубок допустим только в самом конце и только если все его байты после ведущего — продолжения (тогда он отрезается);
    //   иначе — cp1251. ★ ревизия 60 С-1: прежняя версия отрезала до трёх любых старших байт с конца и принимала остаток без
    //   многобайтного знака — «ok да» (cp1251) превращалось в «ok ». cp1251 — полная Windows-1251 (у клиента часть байт → '?';
    //   журналу важнее не терять знак), сырые байты всё равно в text_raw.
    const WORD kCp1256Hi[128] =
    {
        0x20AC, 0x067E, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0679, 0x2039, 0x0152, 0x0686, 0x0698, 0x0688,
        0x06AF, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, 0x06A9, 0x2122, 0x0691, 0x203A, 0x0153, 0x200C, 0x200D, 0x06BA,
        0x00A0, 0x060C, 0x00A2, 0x00A3, 0x00A4, 0x00A5, 0x00A6, 0x00A7, 0x00A8, 0x00A9, 0x06BE, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x00AF,
        0x00B0, 0x00B1, 0x00B2, 0x00B3, 0x00B4, 0x00B5, 0x00B6, 0x00B7, 0x00B8, 0x00B9, 0x061B, 0x00BB, 0x00BC, 0x00BD, 0x00BE, 0x061F,
        0x06C1, 0x0621, 0x0622, 0x0623, 0x0624, 0x0625, 0x0626, 0x0627, 0x0628, 0x0629, 0x062A, 0x062B, 0x062C, 0x062D, 0x062E, 0x062F,
        0x0630, 0x0631, 0x0632, 0x0633, 0x0634, 0x0635, 0x0636, 0x00D7, 0x0637, 0x0638, 0x0639, 0x063A, 0x0640, 0x0641, 0x0642, 0x0643,
        0x00E0, 0x0644, 0x00E2, 0x0645, 0x0646, 0x0647, 0x0648, 0x00E7, 0x00E8, 0x00E9, 0x00EA, 0x00EB, 0x0649, 0x064A, 0x00EE, 0x00EF,
        0x064B, 0x064C, 0x064D, 0x064E, 0x00F4, 0x064F, 0x0650, 0x00F7, 0x0651, 0x00F9, 0x0652, 0x00FB, 0x00FC, 0x200E, 0x200F, 0x06D2,
    };

    // IsStrictUtf8 клиента (bAllowTruncTail = true): true — строгий UTF-8; multi — есть многобайтный знак; valid — длина без обрубка.
    bool StrictUtf8(const BYTE* d, int len, bool* multi, int* valid)
    {
        *multi = false; *valid = 0;
        int i = 0;
        while (i < len)
        {
            const BYTE c = d[i];
            if (c < 0x80) { ++i; continue; }
            int need; DWORD cp, mn;
            if (c >= 0xC2 && c <= 0xDF)      { need = 1; cp = c & 0x1F; mn = 0x80; }
            else if (c >= 0xE0 && c <= 0xEF) { need = 2; cp = c & 0x0F; mn = 0x800; }
            else if (c >= 0xF0 && c <= 0xF4) { need = 3; cp = c & 0x07; mn = 0x10000; }
            else { *valid = i; return false; }
            if (i + need >= len)
            {
                bool tail = true;
                for (int k = i + 1; k < len && tail; ++k) { tail = (d[k] & 0xC0) == 0x80; }
                *valid = i;
                return tail;
            }
            for (int k = 1; k <= need; ++k)
            {
                const BYTE t = d[i + k];
                if ((t & 0xC0) != 0x80) { *valid = i; return false; }
                cp = (cp << 6) | (t & 0x3F);
            }
            if (cp < mn || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) { *valid = i; return false; }
            *multi = true;
            i += need + 1;
        }
        *valid = len;
        return true;
    }

    void WireText(const BYTE* s, int n, wchar_t* out, int cch)
    {
        out[0] = 0;
        int len = 0;
        while (len < n && s[len]) { ++len; }
        if (len <= 0) { return; }
        int w = 0;
        if (s[0] == kCp1256Marker)
        {
            for (int i = 1; i < len && w < cch - 1; ++i) { out[w++] = s[i] < 0x80 ? (wchar_t)s[i] : (wchar_t)kCp1256Hi[s[i] - 0x80]; }
        }
        else
        {
            bool multi = false; int valid = 0;
            if (StrictUtf8(s, len, &multi, &valid) && multi && valid > 0)
            {
                w = MultiByteToWideChar(CP_UTF8, 0, (const char*)s, valid, out, cch - 1);
            }
            else
            {
                w = MultiByteToWideChar(g_textCp, 0, (const char*)s, len, out, cch - 1);
            }
        }
        if (w < 0) { w = 0; }
        out[w] = 0;
        for (int i = 0; i < w; ++i) { if (out[i] < 0x20) { out[i] = L' '; } }
    }

    const wchar_t* ChannelName(const ChatJournal::Event& e)
    {
        switch (e.channel)
        {
        case ChatJournal::kChNormal:     return L"обычный";
        case ChatJournal::kChGlobal:     return L"глобальный";
        case ChatJournal::kChWide:
            if (e.sub == 1) { return L"широкий: поиск отряда"; }
            if (e.sub == 2) { return L"широкий: торговля"; }
            return L"широкий";
        case ChatJournal::kChWhisper:    return L"шёпот";
        case ChatJournal::kChParty:      return L"отряд";
        case ChatJournal::kChClan:       return L"клан";
        case ChatJournal::kChArmy:       return L"армия";
        case ChatJournal::kChStore:      return L"лавка";
        case ChatJournal::kChStoreShout: return L"крик лавки";
        case ChatJournal::kChShoutItem:  return L"крик предметом";
        }
        return L"?";
    }

    // ─── строка VALUES (порядок = kCols) ───
    const wchar_t* kCols =
        L"ev_utc, ev_local, server_name, server_port, map_index, channel, channel_name, sub_channel, opcode, user_num, "
        L"user_index, char_owner, char_slot, char_name, session_state, gm_flag, target_name, target_user_num, "
        L"text, text_raw, mute_state, mute_id";

    void AppendRow(WBuf& b, const ChatJournal::Event& e)
    {
        using ChatJournal::kNone;
        wchar_t name[48], target[48], text[kColText + 8];
        WireText((const BYTE*)e.name, ChatJournal::kNameMax, name, ARRAYSIZE(name));
        WireText((const BYTE*)e.target, ChatJournal::kNameMax, target, ARRAYSIZE(target));
        WireText(e.text, e.textLen, text, ARRAYSIZE(text));
        b.C(L'(');
        AppendTimes(b, e.utc);                                        b.S(L", ");
        b.Str(g_server, kColServer, true);                            b.S(L", ");
        b.Int(g_serverPort);                                          b.S(L", ");
        b.Int(e.mapIndex);                                            b.S(L", ");
        b.Int(e.channel);                                             b.S(L", ");
        b.Str(ChannelName(e), kColChanName, true);                    b.S(L", ");
        b.Int(e.sub == 0xFF ? kNone : (int)e.sub);                    b.S(L", ");
        b.Int(e.opcode);                                              b.S(L", ");
        b.Int(e.userNum);                                             b.S(L", ");
        b.Int(e.account);                                             b.S(L", ");
        b.Int(e.owner);                                               b.S(L", ");
        b.Int(e.charSlot);                                            b.S(L", ");
        b.Str(name, kColName);                                        b.S(L", ");
        b.Int(e.sessState == 0xFF ? kNone : (int)e.sessState);        b.S(L", ");
        b.S(e.gm ? L"1" : L"0");                                      b.S(L", ");
        b.Str(target, kColName);                                      b.S(L", ");
        b.Int(e.targetNum);                                           b.S(L", ");
        b.Str(text, kColText, true);                                  b.S(L", ");
        b.Hex(e.text, e.textLen);                                     b.S(L", ");
        b.Int(e.muteState);                                           b.S(L", ");
        b.I64(e.muteId, e.muteId != 0);
        b.C(L')');
    }

    void BuildBatch(WBuf& b, const ChatJournal::Event* ev, int n, bool fileGo = false)
    {
        b.Clear();
        b.S(L"SET NOCOUNT ON; SET XACT_ABORT ON; BEGIN TRAN;\r\nINSERT INTO chat.message (");
        b.S(kCols);
        b.S(L") VALUES\r\n  ");
        for (int i = 0; i < n; ++i)
        {
            if (i) { b.S(L",\r\n  "); }
            AppendRow(b, ev[i]);
        }
        b.S(L";\r\nCOMMIT TRAN;\r\n");
        if (fileGo) { b.S(L"GO\r\n"); }   // ★ ревизия 60 Н-4: в файле каждый пакет — отдельный батч sqlcmd (ODBC «GO» не понимает)
    }

    // ═══════════════════════════ файловый журнал (как AcJournal) ══════════════
    void EnsureDir(const wchar_t* path)
    {
        wchar_t buf[MAX_PATH];
        lstrcpynW(buf, path, MAX_PATH);
        for (wchar_t* p = buf; *p; ++p)
        {
            if (*p == L'\\' && p != buf && *(p - 1) != L':') { *p = 0; CreateDirectoryW(buf, nullptr); *p = L'\\'; }
        }
        CreateDirectoryW(buf, nullptr);
    }

    enum FileRc { kFileOk = 0, kFileFail = 1, kFileCapped = 2, kFileOff = 3 };
    int   g_capNoticeDay = 0;
    DWORD g_fileErrTick  = 0;

    char* ToUtf8(const wchar_t* w, int len, int* outLen)
    {
        *outLen = 0;
        if (!w || len <= 0) { return nullptr; }
        const int need = WideCharToMultiByte(CP_UTF8, 0, w, len, nullptr, 0, nullptr, nullptr);
        char* out = (char*)HeapAlloc(GetProcessHeap(), 0, need + 1);
        if (!out) { return nullptr; }
        WideCharToMultiByte(CP_UTF8, 0, w, len, out, need, nullptr, nullptr);
        *outLen = need;
        return out;
    }

    int AppendFile(const wchar_t* header, const wchar_t* body, int bodyLen)
    {
        if (!g_fileFallback || !g_fileDir[0]) { return kFileOff; }
        EnsureDir(g_fileDir);
        SYSTEMTIME st; GetLocalTime(&st);
        wchar_t path[MAX_PATH];
        wsprintfW(path, L"%s\\ChatJournal_%04d%02d%02d.sql", g_fileDir, st.wYear, st.wMonth, st.wDay);
        HANDLE h = CreateFileW(path, FILE_APPEND_DATA | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                               OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE)
        {
            const DWORD le = GetLastError(), now = GetTickCount();
            if (g_fileErrTick == 0 || (DWORD)(now - g_fileErrTick) >= 60000u)
            {
                g_fileErrTick = now ? now : 1;
                Log::Line(L"[P129] журнал чата: файл %s не открывается (ошибка %u) — события пакета потеряны", path, le);
            }
            return kFileFail;
        }
        int hl = 0, bl = 0;
        char* hu = ToUtf8(header, header ? lstrlenW(header) : 0, &hl);
        char* bu = ToUtf8(body, body ? bodyLen : 0, &bl);
        int rc = kFileOk;
        if ((header && !hu && lstrlenW(header) > 0) || (body && bodyLen > 0 && !bu)) { rc = kFileFail; }
        LARGE_INTEGER sz{};
        if (rc == kFileOk && g_maxFileMB > 0 && GetFileSizeEx(h, &sz)
            && sz.QuadPart + hl + bl > (LONGLONG)g_maxFileMB * 1024 * 1024)
        {
            rc = kFileCapped;
            const int day = st.wYear * 10000 + st.wMonth * 100 + st.wDay;
            if (g_capNoticeDay != day)
            {
                g_capNoticeDay = day;
                char note[200];
                const int nl = _snprintf_s(note, _TRUNCATE, "-- P129: достигнут потолок файла MaxFileMB=%d — события этого дня в файл больше не пишутся\r\n", g_maxFileMB);
                DWORD wr = 0;
                if (nl > 0) { WriteFile(h, note, (DWORD)nl, &wr, nullptr); }
                Log::Line(L"[P129] журнал чата: файл %s достиг потолка MaxFileMB=%d — до конца суток события в файл не пишутся", path, g_maxFileMB);
            }
        }
        if (rc == kFileOk)
        {
            DWORD wr = 0;
            if (hu && hl > 0 && !(WriteFile(h, hu, (DWORD)hl, &wr, nullptr) && wr == (DWORD)hl)) { rc = kFileFail; }
            if (rc == kFileOk && bu && bl > 0 && !(WriteFile(h, bu, (DWORD)bl, &wr, nullptr) && wr == (DWORD)bl)) { rc = kFileFail; }
        }
        if (hu) { HeapFree(GetProcessHeap(), 0, hu); }
        if (bu) { HeapFree(GetProcessHeap(), 0, bu); }
        CloseHandle(h);
        if (rc == kFileFail)
        {
            const DWORD now = GetTickCount();
            if (g_fileErrTick == 0 || (DWORD)(now - g_fileErrTick) >= 60000u)
            {
                g_fileErrTick = now ? now : 1;
                Log::Line(L"[P129] журнал чата: запись в файл %s не прошла — события пакета потеряны", path);
            }
        }
        return rc;
    }

    DWORD g_fileWinStart = 0;
    int   g_fileWinRows  = 0;
    int   g_fileWinSkip  = 0;

    void FileWindowTick()
    {
        if (g_fileRowsPerMin <= 0) { return; }
        DWORD now = GetTickCount(); if (now == 0) { now = 1; }
        if (g_fileWinStart != 0 && (DWORD)(now - g_fileWinStart) < 60000u) { return; }
        const int skipped = g_fileWinSkip;
        g_fileWinStart = now; g_fileWinRows = 0; g_fileWinSkip = 0;
        if (skipped > 0)
        {
            wchar_t note[200];
            _snwprintf_s(note, _TRUNCATE, L"-- P129 %s: за прошлую минуту пропущено %d событий (FileRowsPerMinute=%d)\r\n",
                         g_server, skipped, g_fileRowsPerMin);
            AppendFile(note, nullptr, 0);
            Log::Line(L"[P129] журнал чата: в файл за прошлую минуту не записано %d событий — предел FileRowsPerMinute=%d", skipped, g_fileRowsPerMin);
        }
    }

    int FileRowsAllow(int n)
    {
        if (g_fileRowsPerMin <= 0) { return n; }
        FileWindowTick();
        int room = g_fileRowsPerMin - g_fileWinRows;
        if (room < 0) { room = 0; }
        const int allow = n < room ? n : room;
        g_fileWinRows += allow;
        if (allow < n)
        {
            if (g_fileWinSkip == 0)
            {
                Log::Line(L"[P129] журнал чата: предел файла FileRowsPerMinute=%d достигнут — лишние события этой минуты в файл не пишутся",
                          g_fileRowsPerMin);
            }
            g_fileWinSkip += n - allow;
            InterlockedExchangeAdd(&g_fileSkipped, n - allow);
        }
        return allow;
    }

    // ═══════════════════════════ ODBC (лениво, только фоновый поток) ══════════
    typedef SQLRETURN (SQL_API *F_AllocHandle)(SQLSMALLINT, SQLHANDLE, SQLHANDLE*);
    typedef SQLRETURN (SQL_API *F_FreeHandle)(SQLSMALLINT, SQLHANDLE);
    typedef SQLRETURN (SQL_API *F_SetEnvAttr)(SQLHENV, SQLINTEGER, SQLPOINTER, SQLINTEGER);
    typedef SQLRETURN (SQL_API *F_SetConnectAttrW)(SQLHDBC, SQLINTEGER, SQLPOINTER, SQLINTEGER);
    typedef SQLRETURN (SQL_API *F_DriverConnectW)(SQLHDBC, SQLHWND, SQLWCHAR*, SQLSMALLINT, SQLWCHAR*, SQLSMALLINT, SQLSMALLINT*, SQLUSMALLINT);
    typedef SQLRETURN (SQL_API *F_ExecDirectW)(SQLHSTMT, SQLWCHAR*, SQLINTEGER);
    typedef SQLRETURN (SQL_API *F_MoreResults)(SQLHSTMT);
    typedef SQLRETURN (SQL_API *F_FreeStmt)(SQLHSTMT, SQLUSMALLINT);
    typedef SQLRETURN (SQL_API *F_SetStmtAttrW)(SQLHSTMT, SQLINTEGER, SQLPOINTER, SQLINTEGER);
    typedef SQLRETURN (SQL_API *F_Disconnect)(SQLHDBC);
    typedef SQLRETURN (SQL_API *F_GetDiagRecW)(SQLSMALLINT, SQLHANDLE, SQLSMALLINT, SQLWCHAR*, SQLINTEGER*, SQLWCHAR*, SQLSMALLINT, SQLSMALLINT*);
    typedef SQLRETURN (SQL_API *F_Fetch)(SQLHSTMT);
    typedef SQLRETURN (SQL_API *F_GetData)(SQLHSTMT, SQLUSMALLINT, SQLSMALLINT, SQLPOINTER, SQLLEN, SQLLEN*);

    struct Odbc
    {
        HMODULE           mod = nullptr;
        F_AllocHandle     AllocHandle = nullptr;
        F_FreeHandle      FreeHandle = nullptr;
        F_SetEnvAttr      SetEnvAttr = nullptr;
        F_SetConnectAttrW SetConnectAttr = nullptr;
        F_DriverConnectW  DriverConnect = nullptr;
        F_ExecDirectW     ExecDirect = nullptr;
        F_MoreResults     MoreResults = nullptr;
        F_FreeStmt        FreeStmt = nullptr;
        F_SetStmtAttrW    SetStmtAttr = nullptr;
        F_Disconnect      Disconnect = nullptr;
        F_GetDiagRecW     GetDiagRec = nullptr;
        F_Fetch           Fetch = nullptr;
        F_GetData         GetData = nullptr;
        SQLHENV env = SQL_NULL_HENV;
        SQLHDBC dbc = SQL_NULL_HDBC;
        bool    connected = false;
    } g_odbc;

    bool OdbcLoad()
    {
        if (g_odbc.mod) { return g_odbc.ExecDirect != nullptr && g_odbc.GetData != nullptr; }
        g_odbc.mod = LoadLibraryW(L"odbc32.dll");
        if (!g_odbc.mod) { return false; }
        HMODULE m = g_odbc.mod;
        g_odbc.AllocHandle    = (F_AllocHandle)    GetProcAddress(m, "SQLAllocHandle");
        g_odbc.FreeHandle     = (F_FreeHandle)     GetProcAddress(m, "SQLFreeHandle");
        g_odbc.SetEnvAttr     = (F_SetEnvAttr)     GetProcAddress(m, "SQLSetEnvAttr");
        g_odbc.SetConnectAttr = (F_SetConnectAttrW)GetProcAddress(m, "SQLSetConnectAttrW");
        g_odbc.DriverConnect  = (F_DriverConnectW) GetProcAddress(m, "SQLDriverConnectW");
        g_odbc.ExecDirect     = (F_ExecDirectW)    GetProcAddress(m, "SQLExecDirectW");
        g_odbc.MoreResults    = (F_MoreResults)    GetProcAddress(m, "SQLMoreResults");
        g_odbc.FreeStmt       = (F_FreeStmt)       GetProcAddress(m, "SQLFreeStmt");
        g_odbc.SetStmtAttr    = (F_SetStmtAttrW)   GetProcAddress(m, "SQLSetStmtAttrW");
        g_odbc.Disconnect     = (F_Disconnect)     GetProcAddress(m, "SQLDisconnect");
        g_odbc.GetDiagRec     = (F_GetDiagRecW)    GetProcAddress(m, "SQLGetDiagRecW");
        g_odbc.Fetch          = (F_Fetch)          GetProcAddress(m, "SQLFetch");
        g_odbc.GetData        = (F_GetData)        GetProcAddress(m, "SQLGetData");
        return g_odbc.AllocHandle && g_odbc.FreeHandle && g_odbc.SetEnvAttr && g_odbc.SetConnectAttr && g_odbc.DriverConnect
            && g_odbc.ExecDirect && g_odbc.MoreResults && g_odbc.FreeStmt && g_odbc.SetStmtAttr && g_odbc.Disconnect
            && g_odbc.GetDiagRec && g_odbc.Fetch && g_odbc.GetData;
    }

    void Diag(SQLSMALLINT type, SQLHANDLE h, wchar_t* out, int cch)
    {
        out[0] = 0;
        if (!g_odbc.GetDiagRec || !h) { return; }
        SQLWCHAR state[8] = {}, msg[512] = {};
        SQLINTEGER native = 0; SQLSMALLINT len = 0;
        if (SQL_SUCCEEDED(g_odbc.GetDiagRec(type, h, 1, state, &native, msg, ARRAYSIZE(msg), &len)))
        {
            _snwprintf_s(out, cch, _TRUNCATE, L"[%s/%d] %s", (wchar_t*)state, (int)native, (wchar_t*)msg);
            // ★ ревизия 65: перевод строки в тексте драйвера разрывал строку PatchLog (хвост терял префикс [P129])
            for (wchar_t* p = out; *p; ++p) { if (*p < 0x20) { *p = L' '; } }
        }
    }

    void OdbcClose()
    {
        if (g_odbc.dbc != SQL_NULL_HDBC)
        {
            if (g_odbc.connected) { g_odbc.Disconnect(g_odbc.dbc); }
            g_odbc.FreeHandle(SQL_HANDLE_DBC, g_odbc.dbc);
            g_odbc.dbc = SQL_NULL_HDBC;
        }
        if (g_odbc.env != SQL_NULL_HENV) { g_odbc.FreeHandle(SQL_HANDLE_ENV, g_odbc.env); g_odbc.env = SQL_NULL_HENV; }
        g_odbc.connected = false;
        InterlockedExchange(&g_dbUp, 0);
    }

    bool OdbcConnect(wchar_t* err, int cch)
    {
        err[0] = 0;
        if (!g_conn[0]) { lstrcpynW(err, L"строка подключения пуста (нет DbConfigFile/ConnectionString)", cch); return false; }
        if (!OdbcLoad()) { lstrcpynW(err, L"odbc32.dll не загружена", cch); return false; }
        OdbcClose();
        if (!SQL_SUCCEEDED(g_odbc.AllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &g_odbc.env))) { lstrcpynW(err, L"SQLAllocHandle(ENV)", cch); return false; }
        g_odbc.SetEnvAttr(g_odbc.env, SQL_ATTR_ODBC_VERSION, (SQLPOINTER)SQL_OV_ODBC3, 0);
        if (!SQL_SUCCEEDED(g_odbc.AllocHandle(SQL_HANDLE_DBC, g_odbc.env, &g_odbc.dbc))) { lstrcpynW(err, L"SQLAllocHandle(DBC)", cch); OdbcClose(); return false; }
        g_odbc.SetConnectAttr(g_odbc.dbc, SQL_ATTR_LOGIN_TIMEOUT, (SQLPOINTER)(INT_PTR)g_loginTimeout, 0);
        g_odbc.SetConnectAttr(g_odbc.dbc, SQL_ATTR_CONNECTION_TIMEOUT, (SQLPOINTER)(INT_PTR)g_queryTimeout, 0);
        SQLWCHAR outStr[1024]; SQLSMALLINT outLen = 0;
        const SQLRETURN r = g_odbc.DriverConnect(g_odbc.dbc, nullptr, (SQLWCHAR*)g_conn, SQL_NTS, outStr, ARRAYSIZE(outStr),
                                                 &outLen, SQL_DRIVER_NOPROMPT);
        if (!SQL_SUCCEEDED(r)) { Diag(SQL_HANDLE_DBC, g_odbc.dbc, err, cch); OdbcClose(); return false; }
        g_odbc.connected = true;
        InterlockedExchange(&g_dbUp, 1);
        return true;
    }

    bool OdbcExec(const wchar_t* sql, wchar_t* err, int cch)
    {
        err[0] = 0;
        SQLHSTMT st = SQL_NULL_HSTMT;
        if (!SQL_SUCCEEDED(g_odbc.AllocHandle(SQL_HANDLE_STMT, g_odbc.dbc, &st))) { Diag(SQL_HANDLE_DBC, g_odbc.dbc, err, cch); return false; }
        g_odbc.SetStmtAttr(st, SQL_ATTR_QUERY_TIMEOUT, (SQLPOINTER)(INT_PTR)g_queryTimeout, 0);
        SQLRETURN r = g_odbc.ExecDirect(st, (SQLWCHAR*)sql, SQL_NTS);
        bool ok = SQL_SUCCEEDED(r) || r == SQL_NO_DATA;
        if (!ok) { Diag(SQL_HANDLE_STMT, st, err, cch); }
        for (int guard = 0; ok && guard < 64; ++guard)
        {
            r = g_odbc.MoreResults(st);
            if (r == SQL_NO_DATA) { break; }
            if (!SQL_SUCCEEDED(r)) { ok = false; Diag(SQL_HANDLE_STMT, st, err, cch); }
        }
        g_odbc.FreeStmt(st, SQL_CLOSE);
        g_odbc.FreeHandle(SQL_HANDLE_STMT, st);
        if (!ok)
        {
            SQLHSTMT st2 = SQL_NULL_HSTMT;
            if (SQL_SUCCEEDED(g_odbc.AllocHandle(SQL_HANDLE_STMT, g_odbc.dbc, &st2)))
            {
                g_odbc.ExecDirect(st2, (SQLWCHAR*)L"IF @@TRANCOUNT > 0 ROLLBACK TRAN;", SQL_NTS);
                g_odbc.FreeHandle(SQL_HANDLE_STMT, st2);
            }
        }
        return ok;
    }

    // Прочитать действующие заглушки: EXEC chat.UP_ChatMuteActive → mute_id, scope, user_index, char_slot (−1), remain_sec.
    //   Срок — «осталось секунд» по часам БАЗЫ + текущее время сервера (одна машина; расхождение часов на срок не влияет).
    //   rows — буфер на g_maxMutes; *n — сколько прочитано; *overflow — строк больше, чем вмещает кэш.
    bool LoadMutes(ChatJournal::MuteRow* rows, int* n, int* overflow, wchar_t* err, int cch)
    {
        *n = 0; *overflow = 0; err[0] = 0;
        SQLHSTMT st = SQL_NULL_HSTMT;
        if (!SQL_SUCCEEDED(g_odbc.AllocHandle(SQL_HANDLE_STMT, g_odbc.dbc, &st))) { Diag(SQL_HANDLE_DBC, g_odbc.dbc, err, cch); return false; }
        g_odbc.SetStmtAttr(st, SQL_ATTR_QUERY_TIMEOUT, (SQLPOINTER)(INT_PTR)g_queryTimeout, 0);
        SQLRETURN r = g_odbc.ExecDirect(st, (SQLWCHAR*)L"SET NOCOUNT ON; EXEC chat.UP_ChatMuteActive;", SQL_NTS);
        bool ok = SQL_SUCCEEDED(r);
        if (!ok) { Diag(SQL_HANDLE_STMT, st, err, cch); }
        FILETIME nf; GetSystemTimeAsFileTime(&nf);
        const __int64 now = ((__int64)nf.dwHighDateTime << 32) | nf.dwLowDateTime;
        while (ok)
        {
            r = g_odbc.Fetch(st);
            if (r == SQL_NO_DATA) { break; }
            if (!SQL_SUCCEEDED(r)) { ok = false; Diag(SQL_HANDLE_STMT, st, err, cch); break; }
            SQLBIGINT id = 0, remain = 0; SQLINTEGER scope = 0, ui = 0, slot = -1; SQLLEN ind = 0;
            bool rowOk = true;
            rowOk = rowOk && SQL_SUCCEEDED(g_odbc.GetData(st, 1, SQL_C_SBIGINT, &id, 0, &ind)) && ind != SQL_NULL_DATA;
            rowOk = rowOk && SQL_SUCCEEDED(g_odbc.GetData(st, 2, SQL_C_SLONG, &scope, 0, &ind)) && ind != SQL_NULL_DATA;
            rowOk = rowOk && SQL_SUCCEEDED(g_odbc.GetData(st, 3, SQL_C_SLONG, &ui, 0, &ind)) && ind != SQL_NULL_DATA;
            rowOk = rowOk && SQL_SUCCEEDED(g_odbc.GetData(st, 4, SQL_C_SLONG, &slot, 0, &ind));
            if (rowOk && ind == SQL_NULL_DATA) { slot = -1; }
            rowOk = rowOk && SQL_SUCCEEDED(g_odbc.GetData(st, 5, SQL_C_SBIGINT, &remain, 0, &ind)) && ind != SQL_NULL_DATA;
            if (!rowOk || (scope != 1 && scope != 2) || ui <= 0 || remain <= 0) { continue; }
            if (*n >= g_maxMutes) { ++*overflow; continue; }
            ChatJournal::MuteRow& m = rows[(*n)++];
            m.id = id; m.scope = (BYTE)scope; m.userIndex = ui; m.charSlot = scope == 2 ? slot : -1;
            m.untilFt = now + (__int64)remain * 10000000LL;
        }
        g_odbc.FreeStmt(st, SQL_CLOSE);
        g_odbc.FreeHandle(SQL_HANDLE_STMT, st);
        return ok;
    }

    // ★ ревизия 62 М-2: ошибка связи — SQLSTATE класса 08 (соединение), HYT00/HYT01 (тайм-аут), 01002 (ошибка отключения).
    //   Diag пишет текст как «[SQLSTATE/native] …». Прочие ошибки (нет объекта, права) соединение не рвут.
    bool LinkError(const wchar_t* err)
    {
        if (!err || err[0] != L'[') { return true; }   // диагностики нет — считаем связью (безопаснее переоткрыть)
        return (err[1] == L'0' && err[2] == L'8') || (err[1] == L'H' && err[2] == L'Y' && err[3] == L'T')
            || !wcsncmp(err + 1, L"01002", 5);
    }

    // ★ ревизия 65 М-1: тайм-аут (HYT00/HYT01) — не обязательно обрыв (долгая блокировка). Сначала проверить связь SELECT 1:
    //   прошла — соединение живо, не переоткрывать.
    bool TimeoutError(const wchar_t* err)
    {
        return err && err[0] == L'[' && err[1] == L'H' && err[2] == L'Y' && err[3] == L'T';
    }
    bool LinkAlive()
    {
        wchar_t e2[256];
        return g_odbc.connected && OdbcExec(L"SELECT 1;", e2, ARRAYSIZE(e2));
    }
    // SQLSTATE из текста Diag «[SQLSTATE/native] …» (5 знаков) — для сравнения «та же ошибка или другая».
    void StateOf(const wchar_t* err, wchar_t* out)
    {
        out[0] = 0;
        if (!err || err[0] != L'[') { lstrcpyW(out, L"?"); return; }
        int i = 0; for (; i < 5 && err[1 + i] && err[1 + i] != L'/'; ++i) { out[i] = err[1 + i]; }
        out[i] = 0;
    }

    // ═══════════════════════════ очередь ═════════════════════════════════════
    bool Enqueue(const ChatJournal::Event& e)
    {
        if (!g_cells) { return false; }
        LONG pos = g_enq;
        Cell* c;
        for (;;)
        {
            c = &g_cells[pos & g_mask];
            const LONG seq = c->seq;
            const LONG dif = (LONG)((DWORD)seq - (DWORD)pos);
            if (dif == 0)
            {
                const LONG prev = InterlockedCompareExchange(&g_enq, pos + 1, pos);
                if (prev == pos) { break; }
                pos = prev;
            }
            else if (dif < 0) { return false; }       // очередь полна
            else { pos = g_enq; }
        }
        c->ev = e;
        InterlockedExchange(&c->seq, pos + 1);       // публикация (полный барьер)
        return true;
    }

    bool Dequeue(ChatJournal::Event* out)
    {
        const LONG pos = g_deq;
        Cell* c = &g_cells[pos & g_mask];
        const LONG seq = c->seq;
        if ((LONG)((DWORD)seq - (DWORD)(pos + 1)) < 0) { return false; }   // пусто
        *out = c->ev;
        g_deq = pos + 1;
        InterlockedExchange(&c->seq, pos + g_mask + 1);
        return true;
    }

    // ═══════════════════════════ фоновый поток ═══════════════════════════════
    DWORD WINAPI Writer(LPVOID)
    {
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
        ChatJournal::Event* batch = (ChatJournal::Event*)HeapAlloc(GetProcessHeap(), 0, sizeof(ChatJournal::Event) * g_batchMax);
        ChatJournal::MuteRow* load = (ChatJournal::MuteRow*)HeapAlloc(GetProcessHeap(), 0, sizeof(ChatJournal::MuteRow) * g_maxMutes);
        if (!batch || !load) { return 1; }
        WBuf sql;
        wchar_t err[600];
        DWORD nextTry = 0, lastPurge = 0, lastMute = 0, dropLogTick = 0;
        bool  everConnected = false, downReported = false, purgedOnce = false, triedOnce = false, mutedOnce = false;
        bool  muteErrReported = false;
        DWORD muteErrTick = 0;            // ★ ревизия 62 М-2: когда последний раз писали об ошибке чтения заглушек (не связи)
        wchar_t muteErrState[8] = L"";    // ★ ревизия 65 Н-2: SQLSTATE последней записанной в PatchLog ошибки чтения
        bool  muteErrLink = false;        //   и её класс (связь / не связь)
        LONG  droppedReported = 0;

        for (;;)
        {
            if ((LONG)(g_enq - g_deq) < g_wakeAt) { WaitForSingleObject(g_wake, (DWORD)g_flushMs); }
            InterlockedExchange(&g_wakeSent, 0);

            // Отброшенные при переполнении — строкой PatchLog не чаще раза в минуту (в базу не пишем: это не сообщение игрока).
            const LONG dr = g_dropped;
            if (dr != droppedReported && (dropLogTick == 0 || (DWORD)(GetTickCount() - dropLogTick) >= 60000u))
            {
                Log::Line(L"[P129] журнал чата: очередь переполнена — отброшено %d (всего %d, ёмкость %d)", dr - droppedReported, dr, g_mask + 1);
                droppedReported = dr; dropLogTick = GetTickCount() ? GetTickCount() : 1;
            }

            int n = 0;
            while (n < g_batchMax && Dequeue(&batch[n])) { ++n; }
            if (n > 0) { g_inflight = batch; InterlockedExchange(&g_inflightN, n); }

            const DWORD now = GetTickCount();
            if (!g_odbc.connected && (!triedOnce || (int)(now - nextTry) >= 0))
            {
                triedOnce = true;
                if (OdbcConnect(err, ARRAYSIZE(err)))
                {
                    Log::Line(L"[P129] журнал чата: подключено к базе (%s)%s", g_connMasked, everConnected && downReported ? L" — снова" : L"");
                    everConnected = true; downReported = false;
                    mutedOnce = false;   // сразу перечитать заглушки
                }
                else
                {
                    nextTry = now + (DWORD)g_reconnectSec * 1000u;
                    if (!downReported)
                    {
                        Log::Line(L"[P129] журнал чата: база недоступна — %s; запись в файл %s, кэш заглушек — последний прочитанный, повтор через %d с",
                                  err, g_fileFallback ? g_fileDir : L"(выкл)", g_reconnectSec);
                        downReported = true;
                    }
                }
            }

            if (n > 0)
            {
                BuildBatch(sql, batch, n);
                bool done = false;
                if (g_odbc.connected)
                {
                    if (OdbcExec(sql.p, err, ARRAYSIZE(err))) { InterlockedExchangeAdd(&g_wDb, n); done = true; }
                    else
                    {
                        InterlockedIncrement(&g_dbErr);
                        Log::Line(L"[P129] журнал чата: пакет из %d событий не записан в базу — %s; в файл", n, err);
                        OdbcClose();
                        nextTry = GetTickCount() + (DWORD)g_reconnectSec * 1000u;
                        downReported = true;
                    }
                }
                if (!done && g_fileFallback)
                {
                    const int allow = FileRowsAllow(n);
                    if (allow > 0)
                    {
                        BuildBatch(sql, batch, allow, true);
                        wchar_t hdr[800];
                        SYSTEMTIME st; GetLocalTime(&st);
                        _snwprintf_s(hdr, _TRUNCATE, L"-- %04d-%02d-%02d %02d:%02d:%02d %s: база недоступна, %d событий%s%s%s\r\nUSE joylog1;\r\nGO\r\n",
                                     st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, g_server, allow,
                                     allow < n ? L" (пакет урезан ограничителем FileRowsPerMinute)" : L"",
                                     err[0] ? L" — " : L"", err);
                        if (AppendFile(hdr, sql.p, sql.n) == kFileOk) { InterlockedExchangeAdd(&g_wFile, allow); }
                        else { InterlockedExchangeAdd(&g_fileSkipped, allow); }
                    }
                }
                else if (!done) { InterlockedExchangeAdd(&g_fileSkipped, n); }
                InterlockedExchange(&g_inflightN, 0);
            }

            FileWindowTick();

            // Кэш заглушек — сразу после подключения, затем раз в MuteRefreshSec.
            if (g_odbc.connected && (!mutedOnce || (DWORD)(GetTickCount() - lastMute) >= (DWORD)g_muteRefresh * 1000u))
            {
                int got = 0, over = 0;
                if (LoadMutes(load, &got, &over, err, ARRAYSIZE(err)))
                {
                    const LONG before = g_muteCount[g_muteActive];
                    PublishMutes(load, got);
                    InterlockedIncrement(&g_muteLoads);
                    if (!mutedOnce || before != got || muteErrReported)
                    {
                        Log::Line(L"[P129] заглушки: действует %d%s", got, over ? L" — ★ БОЛЬШЕ MaxMutes, хвост не загружен" : L"");
                    }
                    if (over) { Log::Line(L"[P129] заглушки: не вошло в кэш %d строк (MaxMutes=%d)", over, g_maxMutes); }
                    muteErrReported = false;
                }
                else
                {
                    InterlockedIncrement(&g_muteErrors);
                    bool link = LinkError(err);
                    bool alive = false;
                    if (link && TimeoutError(err) && LinkAlive()) { link = false; alive = true; }   // ★ ревизия 65 М-1
                    wchar_t st[8]; StateOf(err, st);
                    // ★ ревизия 65 Н-2: строка — при первой ошибке, при смене SQLSTATE или класса, иначе раз в сутки
                    if (!muteErrReported || lstrcmpW(st, muteErrState) != 0 || link != muteErrLink)
                    {
                        Log::Line(L"[P129] заглушки: чтение не удалось — %s; действует прежний список (%d)%s",
                                  err, (int)g_muteCount[g_muteActive],
                                  link ? L", связь с базой потеряна — соединение переоткрывается"
                                       : (alive ? L" (тайм-аут, соединение живо — SELECT 1 прошёл, не переоткрывается)"
                                                : L" (ошибка не связи — повтор через MuteRefreshSec, строка при смене ошибки или раз в сутки)"));
                        muteErrReported = true; muteErrTick = GetTickCount(); lstrcpyW(muteErrState, st); muteErrLink = link;
                    }
                    else if (!link && (DWORD)(GetTickCount() - muteErrTick) >= 86400000u)
                    {
                        Log::Line(L"[P129] заглушки: чтение по-прежнему не удаётся — %s (ошибок всего %d)", err, (int)g_muteErrors);
                        muteErrTick = GetTickCount();
                    }
                    // ★ ревизия 60 Н-1 / 62 М-2: при ошибке СВЯЗИ соединение закрыть и переоткрыть (раньше при LogEnabled=0 / пустой
                    //   маске писать было нечего — кэш после обрыва не обновлялся). Прочие ошибки соединение не рвут и журнал в файл
                    //   не переводят.
                    if (link)
                    {
                        OdbcClose();
                        nextTry = GetTickCount() + (DWORD)g_reconnectSec * 1000u;
                        // ★ ревизия 65 Н-2: обрыв обязательно виден в PatchLog — строка «база недоступна» здесь же (неудачные
                        //   переподключения дальше молчат до «подключено — снова»)
                        if (!downReported)
                        {
                            Log::Line(L"[P129] журнал чата: база недоступна — %s; запись в файл %s, кэш заглушек — последний прочитанный, повтор через %d с",
                                      err, g_fileFallback ? g_fileDir : L"(выкл)", g_reconnectSec);
                        }
                        downReported = true;
                    }
                }
                mutedOnce = true; lastMute = GetTickCount();
            }

            // Очистка старше RetentionDays — после подключения и затем раз в сутки.
            if (g_retention > 0 && g_odbc.connected && (!purgedOnce || (DWORD)(GetTickCount() - lastPurge) >= 86400000u))
            {
                wchar_t q[128]; wsprintfW(q, L"SET NOCOUNT ON; EXEC chat.UP_ChatJournalPurge @Days = %d;", g_retention);
                const bool ok = OdbcExec(q, err, ARRAYSIZE(err));
                if (ok) { InterlockedIncrement(&g_purges); }
                Log::Line(L"[P129] журнал чата: очистка старше %d сут — %s%s", g_retention, ok ? L"выполнена" : L"ошибка ", ok ? L"" : err);
                purgedOnce = true; lastPurge = GetTickCount();
                if (!ok)
                {
                    // ★ ревизия 60 Н-1 / 62 М-2: повтор очистки — через час; соединение переоткрывается только при ошибке связи
                    if (LinkError(err) && !(TimeoutError(err) && LinkAlive()))   // ★ ревизия 65 М-1
                    {
                        OdbcClose();
                        nextTry = GetTickCount() + (DWORD)g_reconnectSec * 1000u;
                        downReported = true;
                    }
                    lastPurge = GetTickCount() - 86400000u + 3600000u;
                }
            }
        }
    }

    // Строка подключения: ConnectionString или DSN/логин/пароль из ini DBManager (DBMng.ini) — как AcJournal (P53).
    void BuildConnection()
    {
        wchar_t cs[1024];
        Config::GetStr(kSec, L"ConnectionString", L"", cs, ARRAYSIZE(cs));
        wchar_t db[64];
        Config::GetStr(kSec, L"Database", L"joylog1", db, ARRAYSIZE(db));
        if (cs[0])
        {
            lstrcpynW(g_conn, cs, ARRAYSIZE(g_conn));
        }
        else
        {
            wchar_t rel[MAX_PATH], sec[64], path[MAX_PATH], full[MAX_PATH];
            Config::GetStr(kSec, L"DbConfigFile", L"..\\DBManager\\DBMng.ini", rel, ARRAYSIZE(rel));
            Config::GetStr(kSec, L"DbConfigSection", L"DB_DNS0_0", sec, ARRAYSIZE(sec));
            if (rel[0] && rel[1] == L':') { lstrcpynW(path, rel, MAX_PATH); } else { wsprintfW(path, L"%s%s", Config::BaseDir(), rel); }
            if (!GetFullPathNameW(path, MAX_PATH, full, nullptr)) { lstrcpynW(full, path, MAX_PATH); }
            wchar_t dsn[128] = L"", uid[128] = L"", pwd[256] = L"";
            if (GetFileAttributesW(full) != INVALID_FILE_ATTRIBUTES)
            {
                GetPrivateProfileStringW(sec, L"GAMEDNS",  L"", dsn, ARRAYSIZE(dsn), full);
                GetPrivateProfileStringW(sec, L"GAMEUSER", L"", uid, ARRAYSIZE(uid), full);
                GetPrivateProfileStringW(sec, L"GAMEPASS", L"", pwd, ARRAYSIZE(pwd), full);
            }
            if (!dsn[0]) { g_conn[0] = 0; lstrcpynW(g_connMasked, L"(нет: DbConfigFile не найден или без GAMEDNS)", ARRAYSIZE(g_connMasked)); return; }
            wchar_t pq[600]; int k = 0;
            for (const wchar_t* p = pwd; *p && k < ARRAYSIZE(pq) - 3; ++p) { if (*p == L'}') { pq[k++] = L'}'; } pq[k++] = *p; }
            pq[k] = 0;
            _snwprintf_s(g_conn, _TRUNCATE, L"DSN=%s;UID=%s;PWD={%s};DATABASE=%s;APP=AsdaChatJournal", dsn, uid, pq, db);
        }
        lstrcpynW(g_connMasked, g_conn, ARRAYSIZE(g_connMasked));
        for (wchar_t* p = g_connMasked; *p; ++p)
        {
            if ((p[0] == L'P' || p[0] == L'p') && (p[1] == L'W' || p[1] == L'w') && (p[2] == L'D' || p[2] == L'd') && p[3] == L'=')
            {
                wchar_t* s = p + 4; wchar_t* e = s;
                if (*e == L'{') { while (*e && !(e[0] == L'}' && e[1] != L'}')) { e += (e[0] == L'}' ? 2 : 1); } if (*e) { ++e; } }
                else { while (*e && *e != L';') { ++e; } }
                wchar_t tail[1024]; lstrcpynW(tail, e, ARRAYSIZE(tail));
                lstrcpyW(s, L"***"); lstrcatW(s, tail);
                break;
            }
        }
    }

    void ResolveServer()
    {
        wchar_t nm[64];
        Config::GetStr(kSec, L"ServerName", L"", nm, ARRAYSIZE(nm));
        if (nm[0]) { lstrcpynW(g_server, nm, ARRAYSIZE(g_server)); }
        else
        {
            wchar_t dir[MAX_PATH]; lstrcpynW(dir, Config::BaseDir(), MAX_PATH);
            int l = lstrlenW(dir);
            while (l > 0 && (dir[l - 1] == L'\\' || dir[l - 1] == L'/')) { dir[--l] = 0; }
            const wchar_t* last = dir;
            for (const wchar_t* p = dir; *p; ++p) { if (*p == L'\\' || *p == L'/') { last = p + 1; } }
            lstrcpynW(g_server, *last ? last : L"?", ARRAYSIZE(g_server));
        }
        wchar_t path[MAX_PATH]; wsprintfW(path, L"%sConfigSet\\ServerIPPORT.txt", Config::BaseDir());
        HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE)
        {
            char buf[256] = {}; DWORD rd = 0;
            ReadFile(h, buf, sizeof(buf) - 1, &rd, nullptr);
            CloseHandle(h);
            int line = 0; const char* p = buf;
            while (*p && line < 2) { if (*p == '\n') { ++line; } ++p; }
            int port = 0, digits = 0;
            while (*p == ' ' || *p == '\t') { ++p; }
            while (*p >= '0' && *p <= '9' && digits < 6) { port = port * 10 + (*p - '0'); ++p; ++digits; }
            if (digits && port > 0 && port < 65536) { g_serverPort = port; }
        }
    }

    int Clamp(int v, int lo, int hi) { return v < lo ? lo : (v > hi ? hi : v); }
}

namespace ChatJournal
{
    void Clear(Event& e)
    {
        memset(&e, 0, sizeof(e));
        e.opcode = kNone; e.account = kNone; e.owner = kNone; e.charSlot = kNone; e.mapIndex = kNone; e.targetNum = kNone;
        e.userNum = -1; e.sub = 0xFF; e.sessState = 0xFF;
    }

    bool Push(Event& e)
    {
        if (!g_logOn) { return false; }
        FILETIME ft; GetSystemTimeAsFileTime(&ft);
        e.utc = ((__int64)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
        if (!Enqueue(e)) { InterlockedIncrement(&g_dropped); return false; }
        InterlockedIncrement(&g_pushed);
        if ((LONG)(g_enq - g_deq) >= g_wakeAt && InterlockedExchange(&g_wakeSent, 1) == 0) { SetEvent(g_wake); }
        return true;
    }

    int Start()
    {
        if (g_started) { return g_logOn ? 0 : 1; }
        g_flushMs        = Clamp(Config::GetInt(kSec, L"FlushIntervalMs", 2000), 50, 60000);
        g_batchMax       = Clamp(Config::GetInt(kSec, L"BatchMax", 500), 1, 1000);
        g_reconnectSec   = Clamp(Config::GetInt(kSec, L"ReconnectSec", 30), 1, 3600);
        g_retention      = Clamp(Config::GetInt(kSec, L"RetentionDays", 90), 0, 3650);
        g_muteRefresh    = Clamp(Config::GetInt(kSec, L"MuteRefreshSec", 15), 2, 3600);
        g_maxMutes       = Clamp(Config::GetInt(kSec, L"MaxMutes", 4096), 16, kMuteCap);
        g_textCp         = Config::GetInt(kSec, L"TextCodePage", 1251);
        {
            CPINFO ci = {};   // ★ ревизия 60 М-3: только однобайтная кодовая страница (ветка «не UTF-8 и не маркер» клиента — cp1251)
            if (!GetCPInfo((UINT)g_textCp, &ci) || ci.MaxCharSize != 1) { Log::Line(L"    P129: TextCodePage=%d не однобайтная или неизвестна — взята 1251", g_textCp); g_textCp = 1251; }
        }
        g_loginTimeout   = Clamp(Config::GetInt(kSec, L"LoginTimeoutSec", 5), 1, 120);
        g_queryTimeout   = Clamp(Config::GetInt(kSec, L"QueryTimeoutSec", 15), 1, 600);
        g_fileFallback   = Config::GetBool(kSec, L"FileFallback", true);
        g_fileRowsPerMin = Clamp(Config::GetInt(kSec, L"FileRowsPerMinute", 3000), 0, 1000000);
        g_maxFileMB      = Clamp(Config::GetInt(kSec, L"MaxFileMB", 256), 0, 4096);
        const int cap    = Clamp(Config::GetInt(kSec, L"QueueCapacity", 16384), 256, 262144);
        int pow2 = 256; while (pow2 < cap) { pow2 <<= 1; }
        g_wakeAt = g_batchMax / 2 > 0 ? g_batchMax / 2 : 1;

        ResolveServer();
        BuildConnection();
        wchar_t fdir[MAX_PATH];
        Config::GetStr(kSec, L"FileDir", L"", fdir, ARRAYSIZE(fdir));
        if (!fdir[0])                        { wsprintfW(g_fileDir, L"%sLog\\Log_ChatJournal", Config::BaseDir()); }
        else if (fdir[0] && fdir[1] == L':') { lstrcpynW(g_fileDir, fdir, ARRAYSIZE(g_fileDir)); }
        else                                 { _snwprintf_s(g_fileDir, _TRUNCATE, L"%s%s", Config::BaseDir(), fdir); }

        g_cells = (Cell*)VirtualAlloc(nullptr, sizeof(Cell) * pow2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        g_muteBuf[0] = (MuteRow*)VirtualAlloc(nullptr, sizeof(MuteRow) * kMuteCap, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        g_muteBuf[1] = (MuteRow*)VirtualAlloc(nullptr, sizeof(MuteRow) * kMuteCap, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!g_cells || !g_muteBuf[0] || !g_muteBuf[1]) { return 3; }
        for (int i = 0; i < pow2; ++i) { g_cells[i].seq = i; }
        g_mask = pow2 - 1;
        g_wake = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        if (!g_wake) { return 3; }
        g_logOn = Config::GetBool(kSec, L"LogEnabled", true);

        // Поток создаётся из DllMain: стартует после снятия блокировки загрузчика; odbc32.dll грузит сам.
        g_thread = CreateThread(nullptr, 0, &Writer, nullptr, 0, nullptr);
        if (!g_thread) { g_logOn = false; return 3; }
        g_started = true;

        Log::Line(L"    P129: журнал чата %s — %s, сервер %s (порт %d), очередь %d, пакет %d, период %d мс, хранить %d сут, "
                  L"заглушки раз в %d с (не больше %d), файл %s (не больше %d событий/мин, потолок %d МБ/сут)",
                  g_logOn ? L"ВКЛ" : L"ВЫКЛ (LogEnabled=0; кэш заглушек читается)", g_connMasked, g_server,
                  g_serverPort == kNone ? 0 : g_serverPort, pow2, g_batchMax, g_flushMs, g_retention, g_muteRefresh, g_maxMutes,
                  g_fileFallback ? g_fileDir : L"выкл", g_fileRowsPerMin, g_maxFileMB);
        return g_logOn ? 0 : 1;
    }

    bool FindMute(int account, int owner, int charSlot, __int64 nowFt, MuteRow* out)
    {
        if (!g_muteBuf[0] || !g_muteBuf[1]) { return false; }
        LONG b;
        for (;;)
        {
            b = g_muteActive;
            InterlockedIncrement(&g_muteReaders[b]);       // отметиться (полный барьер)
            if (g_muteActive == b) { break; }              // буфер всё ещё активный — писатель его не тронет, пока мы здесь
            InterlockedDecrement(&g_muteReaders[b]);       // сменился между чтением и отметкой — взять новый активный
        }
        const int n = (int)g_muteCount[b];
        bool hit = false;
        MuteRow best = {};
        for (int i = 0; i < n; ++i)
        {
            const MuteRow& m = g_muteBuf[b][i];
            if (m.untilFt <= nowFt) { continue; }
            const bool match = (m.scope == 1 && account > 0 && m.userIndex == account)
                            || (m.scope == 2 && owner > 0 && m.userIndex == owner && m.charSlot == charSlot);
            if (match && (!hit || m.untilFt > best.untilFt)) { best = m; hit = true; }   // самая длинная из подходящих
        }
        InterlockedDecrement(&g_muteReaders[b]);
        if (hit && out) { *out = best; }
        return hit;
    }

    void GetStats(Stats* s)
    {
        s->pushed = g_pushed; s->dropped = g_dropped; s->writtenDb = g_wDb; s->writtenFile = g_wFile; s->dbErrors = g_dbErr;
        s->queued = g_cells ? (LONG)(g_enq - g_deq) : 0; s->fileSkipped = g_fileSkipped;
        s->muteRows = g_muteBuf[0] ? g_muteCount[g_muteActive] : 0; s->muteLoads = g_muteLoads; s->muteErrors = g_muteErrors;
        s->purges = g_purges; s->dbUp = g_dbUp != 0;
    }

    void Kick() { if (g_wake) { SetEvent(g_wake); } }

    void TestSetMutes(const MuteRow* rows, int n) { PublishMutes(rows, n); }

    void FlushToFileOnExit()
    {
        if (!g_started || !g_cells) { return; }
        ChatJournal::Event* batch = (ChatJournal::Event*)HeapAlloc(GetProcessHeap(), 0, sizeof(ChatJournal::Event) * 1000);
        if (!batch) { return; }
        WBuf sql;
        const LONG fly = InterlockedExchange(&g_inflightN, 0);
        if (fly > 0 && g_inflight)
        {
            BuildBatch(sql, g_inflight, fly, true);
            if (AppendFile(L"-- выход процесса: пакет, снятый писателем с очереди и не подтверждённый базой (возможен повтор уже записанного)\r\nUSE joylog1;\r\nGO\r\n",
                           sql.p, sql.n) == kFileOk)
            {
                InterlockedExchangeAdd(&g_wFile, fly);
            }
        }
        for (int guard = 0; guard < 300; ++guard)
        {
            int n = 0;
            while (n < 1000 && Dequeue(&batch[n])) { ++n; }
            if (n == 0) { break; }
            BuildBatch(sql, batch, n, true);
            if (AppendFile(L"-- выход процесса: остаток очереди журнала чата\r\nUSE joylog1;\r\nGO\r\n", sql.p, sql.n) == kFileOk)
            {
                InterlockedExchangeAdd(&g_wFile, n);
            }
        }
        HeapFree(GetProcessHeap(), 0, batch);
    }
}
