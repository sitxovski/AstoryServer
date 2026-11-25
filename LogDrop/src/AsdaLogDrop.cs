// Copyright (c) 2026 @sitxovski (Discord)
// AsdaLogDrop.cs — ★ 19.10.2026 приёмник запечатанных журналов клиента (POST /api/v1/ingest за Caddy).
//   Протокол: Reports/release_logs_2026-10-19/00_SPEC.md (часть B + «★ Дополнение»: конверт v2 с логином).
//   Описание, лимиты, развёртывание, откат — README.md рядом с src.
//
// Принципы:
//   * слушает ТОЛЬКО 127.0.0.1 (к нему ходит один Caddy); HTTP — свой строгий минимальный разбор: одна заявка на
//     соединение, обязательный Content-Length, никакого chunked, заголовок ≤ 16 КиБ, жёсткие сроки чтения;
//   * тело — строго конверт "ASLU" v2, каждый файл — строго контейнер AsdaLogSeal (магия, версия, keyId, ClientHello,
//     эфемерный ключ — точка на P-256, кадры с seq 1..n и длинами в границах — ровно до конца файла);
//     расшифровки нет и быть не может (закрытого ключа на сервере нет);
//   * хранятся только байты файлов под СЕРВЕРНЫМИ именами; логин попадает в путь только после проверки формата и
//     существования учётки (Us_member, только чтение); путь клиента не принимается вообще;
//   * отказ — короткий код без подробностей; причина — в журнал отказов (без тела).
// Сборка: build.bat (csc .NET Framework 4.x, C# 5). Служба: AsdaLogDrop (NT SERVICE\AsdaLogDrop).
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Security.Cryptography;
using System.ServiceProcess;
using System.Text;
using System.Threading;

namespace AsdaLogDrop
{
    // Настройки службы: LogDrop.ini рядом с exe (ключ=значение), иначе значения по умолчанию ниже.
    sealed class Config
    {
        public int Port = 8446;                                                 // порт на 127.0.0.1
        public string Root = @"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2\LogDrop";                // корень хранилища
        public string LogDir = @"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2\LogDrop\service\logs"; // журналы службы
        public string ServiceDirName = "service";                               // папка службы в корне (не считается в квоте)
        public HashSet<string> KeyIds = new HashSet<string>(StringComparer.Ordinal); // допустимые keyId (только из LogDrop.ini KeyIds; пусто = отказ запуска)
        public long QuotaBytes = 5L * 1024 * 1024 * 1024;                       // общий объём хранилища
        public int QuotaWarnPercent = 80;                                       // предупреждение в журнал службы при заполнении квоты
        public long MinFreeBytes = 2L * 1024 * 1024 * 1024;                     // минимум свободного места на томе
        public int MaxBody = 4 * 1024 * 1024 + 64 * 1024;                       // тело запроса (★ ревизия В1: один файл ≤ 4 МиБ + конверт)
        public int MaxFile = 4 * 1024 * 1024;                                   // один файл
        public int MaxFiles = 1;                                                // файлов в конверте (★ В1: ровно один; N>1 → 400)
        public int PerIpPerHour = 6;                                            // запросов с IP за час (засчитываются все попытки)
        public int PerInstallPerHour = 6;                                       // запросов с X-Asda-Install за час
        public int PerLoginPerHour = 12;                                        // принятых с существующим логином за час (★ М1: после проверки)
        public long IpBytesPerHour = 25L * 1024 * 1024;                         // ★ В1: принятых байт с IP за час (★ 31.10: 16→25 МиБ — 6 частей журнала по 4 МиБ; на dev выложено ini, exe не пересобран)
        public long InstallBytesPerHour = 25L * 1024 * 1024;                    // ★ В1: принятых байт с install за час (★ 31.10: 16→25 МиБ, как IP)
        public long LoginBytesPerDay = 64L * 1024 * 1024;                       // ★ В1: принятых байт на учётку за сутки (★ 31.10: 32→64 МиБ — 2 сессии по 6 частей)
        public long UnknownBytesPerDay = 256L * 1024 * 1024;                    // ★ В1: принятых байт в _unknown за сутки (всего)
        public long GlobalBytesPerDay = 1024L * 1024 * 1024;                    // ★ В1: принятых байт всего за сутки
        public int MaxConcurrent = 4;                                           // одновременных приёмов тела (★ В3)
        public int MaxConnections = 32;                                         // одновременных соединений
        public int HeadTimeoutMs = 10000;                                       // срок на заголовок
        public int BodyTimeoutMs = 55000;                                       // срок на всё тело (★ В3: < Caddy read_body 60s / write 70s)
        public int IoTimeoutMs = 5000;                                          // срок одной операции чтения/записи
        public int AccountCacheMinutes = 10;                                    // кэш проверки учётки
        public string Sql = @"Data Source=lpc:.\SQLEXPRESS;Initial Catalog=AsdaStoryOp;Integrated Security=SSPI;Connect Timeout=3;Application Name=AsdaLogDrop";
        public string SqlUser = "";                                             // ★ В6: SQL-вход (под restricted SID SSPI не работает)
        public string SqlPasswordFile = "";                                     // файл с паролем SqlUser (первая строка; ACL — только служба и админы)
        public HashSet<string> TestAccounts = null;                             // только --console: учётки без SQL

        // Итоговая строка подключения: Sql + (если задан SqlUser) вход по паролю из SqlPasswordFile. Пароль в журнал не попадает.
        public string SqlConnectionString()
        {
            SqlConnectionStringBuilder b = new SqlConnectionStringBuilder(Sql);
            if (SqlUser.Length > 0)
            {
                string pw = File.ReadAllLines(SqlPasswordFile, Encoding.UTF8)[0].Trim();
                if (pw.Length < 16) { throw new InvalidDataException("SqlPasswordFile: пароль короче 16"); }
                b.IntegratedSecurity = false;
                b.UserID = SqlUser;
                b.Password = pw;
                b.PersistSecurityInfo = false;
            }
            return b.ConnectionString;
        }

        // Прочитать файл настроек (нет файла — умолчания). Неизвестный ключ — ошибка (опечатка не должна молча ослаблять лимит).
        public static Config Load(string path)
        {
            Config c = new Config();
            if (!File.Exists(path)) { return c; }
            foreach (string raw in File.ReadAllLines(path, Encoding.UTF8))
            {
                string line = raw.Trim();
                if (line.Length == 0 || line[0] == ';' || line[0] == '#') { continue; }
                int eq = line.IndexOf('=');
                if (eq <= 0) { throw new InvalidDataException("LogDrop.ini: строка без '=': " + line); }
                string k = line.Substring(0, eq).Trim(), v = line.Substring(eq + 1).Trim();
                switch (k)
                {
                    case "Port": c.Port = int.Parse(v, CultureInfo.InvariantCulture); break;
                    case "Root": c.Root = v; break;
                    case "LogDir": c.LogDir = v; break;
                    case "KeyIds":
                        c.KeyIds = new HashSet<string>(StringComparer.Ordinal);
                        foreach (string s in v.Split(',')) { string t = s.Trim().ToLowerInvariant(); if (t.Length == 16) { c.KeyIds.Add(t); } }
                        break;
                    case "QuotaBytes": c.QuotaBytes = long.Parse(v, CultureInfo.InvariantCulture); break;
                    case "QuotaWarnPercent": c.QuotaWarnPercent = int.Parse(v, CultureInfo.InvariantCulture); break;
                    case "MinFreeBytes": c.MinFreeBytes = long.Parse(v, CultureInfo.InvariantCulture); break;
                    case "MaxBody": c.MaxBody = int.Parse(v, CultureInfo.InvariantCulture); break;
                    case "MaxFile": c.MaxFile = int.Parse(v, CultureInfo.InvariantCulture); break;
                    case "MaxFiles": c.MaxFiles = int.Parse(v, CultureInfo.InvariantCulture); break;
                    case "PerIpPerHour": c.PerIpPerHour = int.Parse(v, CultureInfo.InvariantCulture); break;
                    case "PerInstallPerHour": c.PerInstallPerHour = int.Parse(v, CultureInfo.InvariantCulture); break;
                    case "PerLoginPerHour": c.PerLoginPerHour = int.Parse(v, CultureInfo.InvariantCulture); break;
                    case "IpBytesPerHour": c.IpBytesPerHour = long.Parse(v, CultureInfo.InvariantCulture); break;
                    case "InstallBytesPerHour": c.InstallBytesPerHour = long.Parse(v, CultureInfo.InvariantCulture); break;
                    case "LoginBytesPerDay": c.LoginBytesPerDay = long.Parse(v, CultureInfo.InvariantCulture); break;
                    case "UnknownBytesPerDay": c.UnknownBytesPerDay = long.Parse(v, CultureInfo.InvariantCulture); break;
                    case "GlobalBytesPerDay": c.GlobalBytesPerDay = long.Parse(v, CultureInfo.InvariantCulture); break;
                    case "MaxConcurrent": c.MaxConcurrent = int.Parse(v, CultureInfo.InvariantCulture); break;
                    case "MaxConnections": c.MaxConnections = int.Parse(v, CultureInfo.InvariantCulture); break;
                    case "HeadTimeoutMs": c.HeadTimeoutMs = int.Parse(v, CultureInfo.InvariantCulture); break;
                    case "BodyTimeoutMs": c.BodyTimeoutMs = int.Parse(v, CultureInfo.InvariantCulture); break;
                    case "IoTimeoutMs": c.IoTimeoutMs = int.Parse(v, CultureInfo.InvariantCulture); break;
                    case "AccountCacheMinutes": c.AccountCacheMinutes = int.Parse(v, CultureInfo.InvariantCulture); break;
                    case "Sql": c.Sql = v; break;
                    case "SqlUser": c.SqlUser = v; break;
                    case "SqlPasswordFile": c.SqlPasswordFile = v; break;
                    default: throw new InvalidDataException("LogDrop.ini: неизвестный ключ " + k);
                }
            }
            if (c.KeyIds.Count == 0) { throw new InvalidDataException("LogDrop.ini: KeyIds пуст"); }
            if (c.MaxBody < 1024 || c.MaxFile < 1024 || c.MaxFile > c.MaxBody) { throw new InvalidDataException("LogDrop.ini: MaxBody/MaxFile"); }
            if (c.MaxFiles < 1 || c.MaxFiles > Envelope.MaxFiles) { throw new InvalidDataException("LogDrop.ini: MaxFiles"); }
            if (c.QuotaWarnPercent < 1 || c.QuotaWarnPercent > 100) { throw new InvalidDataException("LogDrop.ini: QuotaWarnPercent"); }
            if (c.MaxConcurrent < 1 || c.MaxConnections < c.MaxConcurrent) { throw new InvalidDataException("LogDrop.ini: MaxConcurrent/MaxConnections"); }
            return c;
        }
    }

    // Журналы службы: service_/rejects_/accepted_<дата>.log в LogDir; не больше 20 МиБ в сутки на вид (дальше — счётчик пропусков).
    static class Journal
    {
        static readonly object Lock = new object();
        static string dir;
        static readonly Dictionary<string, long> written = new Dictionary<string, long>();   // файл → записано байт
        static readonly Dictionary<string, long> dropped = new Dictionary<string, long>();   // файл → пропущено строк
        const long MaxPerDay = 20L * 1024 * 1024;
        public static bool ToConsole;                                                         // --console: дублировать в консоль

        public static void Init(string logDir) { dir = logDir; Directory.CreateDirectory(dir); }

        static void Write(string kind, string text)
        {
            DateTime now = DateTime.Now;
            string line = now.ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture) + " " + text + "\r\n";
            if (ToConsole) { Console.Write(kind + ": " + line); }
            lock (Lock)
            {
                try
                {
                    string path = Path.Combine(dir, kind + "_" + now.ToString("yyyyMMdd", CultureInfo.InvariantCulture) + ".log");
                    long n;
                    if (!written.TryGetValue(path, out n)) { n = File.Exists(path) ? new FileInfo(path).Length : 0; }
                    byte[] b = Encoding.UTF8.GetBytes(line);
                    if (n + b.Length > MaxPerDay)
                    {
                        long d; dropped.TryGetValue(path, out d); dropped[path] = d + 1;
                        written[path] = n;
                        return;
                    }
                    using (FileStream f = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read)) { f.Write(b, 0, b.Length); }
                    written[path] = n + b.Length;
                    if (written.Count > 64) { written.Clear(); dropped.Clear(); }   // старые сутки не держать
                }
                catch { /* журнал не должен ронять приём */ }
            }
        }

        public static void Service(string text) { Write("service", text); }

        // ★ М4: сколько строк пропущено из-за суточного предела (раз в час — в service_). Счётчики обнуляются.
        public static string TakeDroppedSummary()
        {
            lock (Lock)
            {
                StringBuilder sb = new StringBuilder();
                foreach (KeyValuePair<string, long> kv in dropped) { if (kv.Value > 0) { sb.Append(Path.GetFileName(kv.Key)).Append('=').Append(kv.Value).Append(' '); } }
                dropped.Clear();
                return sb.ToString().Trim();
            }
        }
        public static void Reject(string ip, string install, int code, string reason, long contentLength)
        {
            Write("rejects", Safe(ip) + " inst=" + Safe(install) + " code=" + code + " reason=" + Safe(reason) + " cl=" + contentLength);
        }
        public static void Accept(string text) { Write("accepted", text); }

        // В журнал — только печатные ASCII без пробелов, не длиннее 64 (значения и так проверены, это страховка).
        public static string Safe(string s)
        {
            if (string.IsNullOrEmpty(s)) { return "-"; }
            StringBuilder sb = new StringBuilder();
            foreach (char ch in s) { if (sb.Length >= 64) { break; } sb.Append(ch > 0x20 && ch < 0x7F ? ch : '?'); }
            return sb.ToString();
        }
    }

    // Скользящее окно «не больше max за window» по ключу. Попытка засчитывается всегда (и отклонённая).
    sealed class RateLimiter
    {
        readonly int max;
        readonly long windowTicks;
        readonly Dictionary<string, Queue<long>> map = new Dictionary<string, Queue<long>>(StringComparer.Ordinal);
        readonly object sync = new object();
        long lastSweep = DateTime.UtcNow.Ticks;
        const int MaxKeys = 200000;

        public RateLimiter(int maxPerWindow, TimeSpan window) { max = maxPerWindow; windowTicks = window.Ticks; }

        // Восстановление после перезапуска: засчитать прошлое событие (время — UTC ticks).
        public void Restore(string key, long at)
        {
            lock (sync)
            {
                Queue<long> q;
                if (!map.TryGetValue(key, out q)) { q = new Queue<long>(); map[key] = q; }
                q.Enqueue(at);
            }
        }

        // true — разрешено (и засчитано); false — лимит исчерпан.
        public bool Hit(string key)
        {
            long now = DateTime.UtcNow.Ticks;
            lock (sync)
            {
                if (now - lastSweep > TimeSpan.TicksPerMinute * 10) { Sweep(now); }
                Queue<long> q;
                if (!map.TryGetValue(key, out q))
                {
                    if (map.Count >= MaxKeys) { Sweep(now); if (map.Count >= MaxKeys) { return false; } }
                    q = new Queue<long>();
                    map[key] = q;
                }
                while (q.Count > 0 && now - q.Peek() >= windowTicks) { q.Dequeue(); }
                if (q.Count >= max) { return false; }
                q.Enqueue(now);
                return true;
            }
        }

        void Sweep(long now)
        {
            List<string> dead = new List<string>();
            foreach (KeyValuePair<string, Queue<long>> kv in map)
            {
                while (kv.Value.Count > 0 && now - kv.Value.Peek() >= windowTicks) { kv.Value.Dequeue(); }
                if (kv.Value.Count == 0) { dead.Add(kv.Key); }
            }
            foreach (string k in dead) { map.Remove(k); }
            lastSweep = now;
        }
    }

    // ★ В1: бюджет в байтах «не больше limit за window» по ключу; списывается только принятое (отказы бюджет не едят).
    sealed class ByteBudget
    {
        readonly long limit;
        readonly long windowTicks;
        readonly Dictionary<string, Queue<KeyValuePair<long, long>>> map = new Dictionary<string, Queue<KeyValuePair<long, long>>>(StringComparer.Ordinal);
        readonly Dictionary<string, long> sums = new Dictionary<string, long>(StringComparer.Ordinal);
        readonly object sync = new object();
        long lastSweep = DateTime.UtcNow.Ticks;
        const int MaxKeys = 200000;

        public ByteBudget(long limitBytes, TimeSpan window) { limit = limitBytes; windowTicks = window.Ticks; }

        void Trim(string key, long now)
        {
            Queue<KeyValuePair<long, long>> q;
            if (!map.TryGetValue(key, out q)) { return; }
            long sum = sums[key];
            while (q.Count > 0 && now - q.Peek().Key >= windowTicks) { sum -= q.Dequeue().Value; }
            if (q.Count == 0) { map.Remove(key); sums.Remove(key); } else { sums[key] = sum; }
        }

        // Влезет ли ещё n байт (без списания).
        public bool Fits(string key, long n)
        {
            long now = DateTime.UtcNow.Ticks;
            lock (sync)
            {
                if (now - lastSweep > TimeSpan.TicksPerMinute * 10) { Sweep(now); }
                Trim(key, now);
                long used;
                sums.TryGetValue(key, out used);
                return used + n <= limit;
            }
        }

        // Списать n байт (время — UTC ticks; 0 — сейчас).
        public void Charge(string key, long n, long at)
        {
            if (at == 0) { at = DateTime.UtcNow.Ticks; }
            lock (sync)
            {
                Queue<KeyValuePair<long, long>> q;
                if (!map.TryGetValue(key, out q))
                {
                    if (map.Count >= MaxKeys) { Sweep(DateTime.UtcNow.Ticks); }
                    q = new Queue<KeyValuePair<long, long>>();
                    map[key] = q;
                    sums[key] = 0;
                }
                q.Enqueue(new KeyValuePair<long, long>(at, n));
                sums[key] += n;
            }
        }

        void Sweep(long now)
        {
            foreach (string k in new List<string>(map.Keys)) { Trim(k, now); }
            lastSweep = now;
        }
    }

    // Проверка «точка на кривой P-256»: x,y < p и y² ≡ x³ − 3x + b (mod p). Кофактор P-256 = 1 — этого достаточно.
    static class P256
    {
        static readonly BigInteger P = BigInteger.Parse("00FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", NumberStyles.HexNumber);
        static readonly BigInteger B = BigInteger.Parse("005AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", NumberStyles.HexNumber);

        // 32 байта big-endian → неотрицательное число.
        static BigInteger FromBe(byte[] buf, int off)
        {
            byte[] le = new byte[33];
            for (int i = 0; i < 32; ++i) { le[i] = buf[off + 31 - i]; }
            return new BigInteger(le);
        }

        // buf[off..off+64) = X||Y (big-endian).
        public static bool OnCurve(byte[] buf, int off)
        {
            BigInteger x = FromBe(buf, off), y = FromBe(buf, off + 32);
            if (x >= P || y >= P) { return false; }
            BigInteger lhs = BigInteger.Remainder(y * y, P);
            BigInteger rhs = BigInteger.Remainder(x * x * x - 3 * x + B, P);
            if (rhs.Sign < 0) { rhs += P; }
            return lhs == rhs;
        }
    }

    // Итог проверки одного контейнера.
    sealed class ContainerInfo
    {
        public string KeyId;                      // keyId сегментов (все одинаковые)
        public int Segments;                      // сегментов
        public int Frames;                        // кадров всего
        public SortedSet<int> SegKinds = new SortedSet<int>();   // виды сегментов
    }

    // Строгий разбор контейнера AsdaLogSeal (формат — Tools/asda_logseal.py, клиент — Source/AsdaNet/Private/LogSeal).
    static class Container
    {
        static readonly byte[] SegMagic = Encoding.ASCII.GetBytes("ASLGSEG1");
        const int SegHdr = 128, FrameHdr = 12, Tag = 16, MaxPlain = 64 * 1024, MinPlain = 1, MaxSegments = 4096;
        public const int MinFileLen = SegHdr + FrameHdr + Tag + MinPlain;   // заголовок + один минимальный кадр

        // Какие виды сегментов допустимы в каком виде файла конверта (1 журнал игры, 2 журнал EAC, 3 падение).
        public static bool KindAllowed(int envKind, int segKind)
        {
            switch (envKind)
            {
                case 1: return segKind == 3;                   // журнал движка (★ М2: перенос старых — только в виде «падение»)
                case 2: return segKind == 1 || segKind == 2;   // журнал EAC; запасной маркер EAC
                case 3: return segKind == 4 || segKind == 5;   // пакет падения; перенос старой папки падения
                default: return false;
            }
        }

        static bool Eq(byte[] a, int off, byte[] m, int n) { for (int i = 0; i < n; ++i) { if (a[off + i] != m[i]) { return false; } } return true; }
        static uint U32(byte[] a, int o) { return (uint)(a[o] | (a[o + 1] << 8) | (a[o + 2] << 16) | (a[o + 3] << 24)); }
        static ulong U64(byte[] a, int o) { return U32(a, o) | ((ulong)U32(a, o + 4) << 32); }
        static string Hex(byte[] a, int o, int n) { StringBuilder sb = new StringBuilder(n * 2); for (int i = 0; i < n; ++i) { sb.Append(a[o + i].ToString("x2")); } return sb.ToString(); }

        // null — корректен (info заполнен); иначе — код причины для журнала отказов.
        public static string Validate(byte[] d, int off, int len, int envKind, HashSet<string> keyIds, out ContainerInfo info)
        {
            info = new ContainerInfo();
            int end = off + len, pos = off;
            if (len < MinFileLen) { return "file_short"; }
            while (pos < end)
            {
                if (info.Segments >= MaxSegments) { return "seg_too_many"; }
                if (end - pos < SegHdr) { return "seg_hdr_trunc"; }
                if (!Eq(d, pos, SegMagic, 8)) { return "seg_magic"; }
                if (d[pos + 8] != 1) { return "seg_version"; }
                int kind = d[pos + 9];
                if (!KindAllowed(envKind, kind)) { return "seg_kind"; }
                if (d[pos + 10] != 0 || d[pos + 11] != 0) { return "seg_reserved"; }
                string kid = Hex(d, pos + 12, 8);
                if (!keyIds.Contains(kid)) { return "seg_keyid"; }
                if (info.KeyId != null && info.KeyId != kid) { return "seg_keyid_mixed"; }
                info.KeyId = kid;
                // ClientHello AsdaSecure: A5 01 4C 00 | ePub 64 | nonce 16
                if (d[pos + 20] != 0xA5 || d[pos + 21] != 1 || d[pos + 22] != 0x4C || d[pos + 23] != 0) { return "seg_hello"; }
                if (!P256.OnCurve(d, pos + 24)) { return "seg_point"; }
                for (int i = 120; i < 128; ++i) { if (d[pos + i] != 0) { return "seg_reserved"; } }
                info.Segments++;
                info.SegKinds.Add(kind);
                pos += SegHdr;
                ulong expect = 1;
                while (pos < end && !(end - pos >= 4 && d[pos] == (byte)'A' && d[pos + 1] == (byte)'S' && d[pos + 2] == (byte)'L' && d[pos + 3] == (byte)'G'))
                {
                    if (end - pos < FrameHdr) { return "frame_hdr_trunc"; }
                    uint clen = U32(d, pos);
                    ulong seq = U64(d, pos + 4);
                    if (clen < Tag + MinPlain || clen > Tag + MaxPlain) { return "frame_len"; }
                    if (seq != expect) { return "frame_seq"; }
                    if ((long)(end - pos) < FrameHdr + (long)clen) { return "frame_trunc"; }
                    pos += FrameHdr + (int)clen;
                    expect++;
                    info.Frames++;
                }
                if (expect == 1) { return "seg_empty"; }   // сегмент без единого кадра (клиент пишет заголовок вместе с кадром сведений)
            }
            return pos == end ? null : "file_tail";
        }
    }

    // Один файл конверта.
    sealed class EnvFile
    {
        public int Kind;          // 1/2/3
        public string Login;      // заявленный логин, если формат верен; иначе null
        public bool LoginBad;     // логин был, но формат неверен
        public int Offset, Length;
        public ContainerInfo Info;
    }

    // Конверт "ASLU" v2: "ASLU" | u8 ver=2 | u8 N (1..4) | u16 0 | N × (u8 вид | u8 A (0..32) | A байт логина | u32 L (LE) | L байт).
    static class Envelope
    {
        public const int MaxFiles = 4, MaxLogin = 32, HeaderLen = 8;

        // Формат логина как в БД: [A-Za-z0-9_.@-]{1,32}.
        public static bool LoginFormatOk(byte[] d, int off, int n)
        {
            if (n < 1 || n > MaxLogin) { return false; }
            for (int i = 0; i < n; ++i)
            {
                byte c = d[off + i];
                bool ok = (c >= (byte)'A' && c <= (byte)'Z') || (c >= (byte)'a' && c <= (byte)'z') || (c >= (byte)'0' && c <= (byte)'9') ||
                          c == (byte)'_' || c == (byte)'.' || c == (byte)'@' || c == (byte)'-';
                if (!ok) { return false; }
            }
            return true;
        }

        // null — разобран; иначе код причины.
        public static string Parse(byte[] d, int len, int maxFile, int maxFiles, out List<EnvFile> files)
        {
            files = new List<EnvFile>();
            if (len < HeaderLen) { return "env_short"; }
            if (d[0] != (byte)'A' || d[1] != (byte)'S' || d[2] != (byte)'L' || d[3] != (byte)'U') { return "env_magic"; }
            if (d[4] != 2) { return "env_version"; }
            int n = d[5];
            if (n < 1 || n > maxFiles) { return "env_count"; }
            if (d[6] != 0 || d[7] != 0) { return "env_reserved"; }
            int pos = HeaderLen;
            for (int i = 0; i < n; ++i)
            {
                if (len - pos < 2) { return "env_trunc"; }
                EnvFile f = new EnvFile();
                f.Kind = d[pos];
                if (f.Kind < 1 || f.Kind > 3) { return "env_kind"; }
                int a = d[pos + 1];
                if (a > MaxLogin) { return "env_login_len"; }
                pos += 2;
                if (len - pos < a + 4) { return "env_trunc"; }
                if (a > 0)
                {
                    if (LoginFormatOk(d, pos, a)) { f.Login = Encoding.ASCII.GetString(d, pos, a); }
                    else { f.LoginBad = true; }
                }
                pos += a;
                long l = (long)(uint)(d[pos] | (d[pos + 1] << 8) | (d[pos + 2] << 16) | (d[pos + 3] << 24));
                pos += 4;
                if (l > maxFile) { return "env_file_big"; }
                if (l < Container.MinFileLen) { return "env_file_short"; }
                if (len - pos < l) { return "env_trunc"; }
                f.Offset = pos;
                f.Length = (int)l;
                pos += (int)l;
                files.Add(f);
            }
            return pos == len ? null : "env_tail";
        }
    }

    // Существование учётки: AsdaStoryOp.dbo.Us_member.Us_id (только SELECT по одному столбцу), кэш на AccountCacheMinutes.
    sealed class Accounts
    {
        readonly Config cfg;
        readonly Dictionary<string, KeyValuePair<bool, long>> cache = new Dictionary<string, KeyValuePair<bool, long>>(StringComparer.Ordinal);
        readonly object sync = new object();
        const int MaxCache = 50000;

        string connStr;                                                     // строка подключения (собирается при первом запросе)

        public Accounts(Config c) { cfg = c; }

        // true/false — есть/нет; исключение — БД недоступна (приём → 503, клиент повторит).
        public bool Exists(string login)
        {
            string key = login.ToLowerInvariant();
            long now = DateTime.UtcNow.Ticks, ttl = TimeSpan.TicksPerMinute * cfg.AccountCacheMinutes;
            lock (sync)
            {
                KeyValuePair<bool, long> hit;
                if (cache.TryGetValue(key, out hit) && now - hit.Value < ttl) { return hit.Key; }
            }
            bool exists;
            if (cfg.TestAccounts != null) { exists = cfg.TestAccounts.Contains(key); }
            else
            {
                if (connStr == null) { connStr = cfg.SqlConnectionString(); }
                using (SqlConnection con = new SqlConnection(connStr))
                using (SqlCommand cmd = new SqlCommand("SELECT TOP (1) 1 FROM dbo.Us_member WHERE Us_id = @id", con))
                {
                    cmd.CommandTimeout = 3;
                    cmd.Parameters.Add("@id", SqlDbType.VarChar, 61).Value = login;
                    con.Open();
                    object r = cmd.ExecuteScalar();
                    exists = r != null && r != DBNull.Value;
                }
            }
            lock (sync)
            {
                if (cache.Count >= MaxCache) { cache.Clear(); }
                cache[key] = new KeyValuePair<bool, long>(exists, now);
            }
            return exists;
        }
    }

    // Хранилище: Root\<логин|_unknown>\<ГГГГ-ММ-ДД>\<серверное имя>.(alog|acrash) + .json; квота по всем файлам кроме папки службы.
    sealed class Storage
    {
        readonly Config cfg;
        readonly string rootFull;
        readonly object sync = new object();
        long used;
        long lastScan;
        static readonly HashSet<string> Devices = new HashSet<string>(StringComparer.Ordinal)
        { "con", "prn", "aux", "nul", "com0", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
          "lpt0", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9" };
        public const string Unknown = "_unknown";

        public Storage(Config c)
        {
            cfg = c;
            rootFull = Path.GetFullPath(c.Root).TrimEnd('\\');
            Directory.CreateDirectory(rootFull);
        }

        public long Used { get { lock (sync) { return used; } } }

        // Восстановление бюджетов: вызывается для каждого .json за последние сутки (время UTC ticks, ip, install, папка, размер).
        public Action<long, string, string, string, long> OnRecent;
        int rescanning;                                                     // ★ М3: идёт пересчёт (Interlocked)
        long lastWarn;                                                      // последнее предупреждение о квоте (UTC ticks)
        static readonly System.Text.RegularExpressions.Regex JsField =
            new System.Text.RegularExpressions.Regex(@"""(received_utc|ip|install|size)"":(""([^""\\]{0,64})""|([0-9]{1,12}))");

        // Обход дерева без захода в reparse-точки (джанкшены/ссылки не считаются и не открываются).
        void Walk(string dir, int depth, ref long total, bool recent, string top)
        {
            if (depth > 4) { return; }
            foreach (string f in Directory.GetFiles(dir))
            {
                try
                {
                    FileInfo fi = new FileInfo(f);
                    if ((fi.Attributes & FileAttributes.ReparsePoint) != 0) { continue; }
                    total += fi.Length;
                    if (recent && OnRecent != null && fi.Length < 8192 && f.EndsWith(".json", StringComparison.OrdinalIgnoreCase) &&
                        DateTime.UtcNow - fi.LastWriteTimeUtc < TimeSpan.FromDays(1))
                    {
                        long at = 0, size = 0; string ip = null, inst = null;
                        foreach (System.Text.RegularExpressions.Match m in JsField.Matches(File.ReadAllText(f, Encoding.UTF8)))
                        {
                            string k = m.Groups[1].Value, v = m.Groups[3].Success ? m.Groups[3].Value : m.Groups[4].Value;
                            DateTime t;
                            if (k == "received_utc" && DateTime.TryParse(v, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out t)) { at = t.Ticks; }
                            else if (k == "ip") { ip = v; }
                            else if (k == "install") { inst = v; }
                            else if (k == "size") { long.TryParse(v, out size); }
                        }
                        if (at > 0 && size > 0) { OnRecent(at, ip, inst, top, size); }
                    }
                }
                catch { }
            }
            foreach (string d in Directory.GetDirectories(dir))
            {
                try { if ((new DirectoryInfo(d).Attributes & FileAttributes.ReparsePoint) != 0) { continue; } } catch { continue; }
                Walk(d, depth + 1, ref total, recent, top);
            }
        }

        // Пересчитать занятое (владелец мог удалить файлы). Папка службы не считается. recent — заодно восстановить бюджеты.
        public void Rescan(bool recent)
        {
            long total = 0;
            try
            {
                foreach (string d in Directory.GetDirectories(rootFull))
                {
                    string name = Path.GetFileName(d);
                    if (string.Equals(name, cfg.ServiceDirName, StringComparison.OrdinalIgnoreCase)) { continue; }
                    try { if ((new DirectoryInfo(d).Attributes & FileAttributes.ReparsePoint) != 0) { continue; } } catch { continue; }
                    Walk(d, 1, ref total, recent, name.ToLowerInvariant());
                }
                foreach (string f in Directory.GetFiles(rootFull)) { try { total += new FileInfo(f).Length; } catch { } }
            }
            catch (Exception e) { Journal.Service("rescan error " + e.GetType().Name); }
            lock (sync) { used = total; lastScan = DateTime.UtcNow.Ticks; }
            CheckWarn();
        }

        // ★ М3: пересчёт раз в 10 мин в отдельной нити, не больше одного одновременно.
        public void MaybeRescan()
        {
            if (DateTime.UtcNow.Ticks - lastScan <= TimeSpan.TicksPerMinute * 10) { return; }
            if (Interlocked.CompareExchange(ref rescanning, 1, 0) != 0) { return; }
            lastScan = DateTime.UtcNow.Ticks;
            ThreadPool.QueueUserWorkItem(delegate { try { Rescan(false); } finally { Interlocked.Exchange(ref rescanning, 0); } });
        }

        // ★ В1(в): предупреждение в журнал службы при заполнении квоты на QuotaWarnPercent % (не чаще раза в час).
        public void CheckWarn()
        {
            long u = Used;
            if (u * 100 < cfg.QuotaBytes * cfg.QuotaWarnPercent) { return; }
            long now = DateTime.UtcNow.Ticks;
            if (now - Interlocked.Read(ref lastWarn) < TimeSpan.TicksPerHour) { return; }
            Interlocked.Exchange(ref lastWarn, now);
            Journal.Service("QUOTA WARNING used=" + u + " quota=" + cfg.QuotaBytes + " (" + (u * 100 / cfg.QuotaBytes) + "%) — нужна чистка LogDrop (решение владельца)");
        }

        // Есть ли место под need байт (квота и свободное место тома).
        public bool HasRoom(long need)
        {
            lock (sync) { if (used + need > cfg.QuotaBytes) { return false; } }
            try
            {
                DriveInfo di = new DriveInfo(Path.GetPathRoot(rootFull));
                if (di.AvailableFreeSpace - need < cfg.MinFreeBytes) { return false; }
            }
            catch { return false; }
            return true;
        }

        // Имя папки учётки: проверенный логин нижним регистром, если он безопасен как имя папки Windows; иначе "_acct_<hex>".
        public string AccountDir(string login)
        {
            if (login == null) { return Unknown; }
            string l = login.ToLowerInvariant();
            bool safe = l.Length >= 1 && char.IsLetterOrDigit(l[0]) && l[l.Length - 1] != '.' && l.IndexOf("..", StringComparison.Ordinal) < 0 &&
                        !string.Equals(l, cfg.ServiceDirName, StringComparison.Ordinal);
            if (safe)
            {
                int dot = l.IndexOf('.');
                string stem = dot < 0 ? l : l.Substring(0, dot);
                if (Devices.Contains(stem)) { safe = false; }
            }
            foreach (char ch in l)
            {
                if (!((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '.' || ch == '@' || ch == '-')) { safe = false; }
            }
            if (safe) { return l; }
            StringBuilder sb = new StringBuilder("_acct_");
            foreach (byte b in Encoding.ASCII.GetBytes(l)) { sb.Append(b.ToString("x2")); }
            return sb.ToString();
        }

        static string RandomHex(int bytes)
        {
            byte[] b = new byte[bytes];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider()) { rng.GetBytes(b); }
            StringBuilder sb = new StringBuilder();
            foreach (byte x in b) { sb.Append(x.ToString("x2")); }
            return sb.ToString();
        }

        // Записать файл и его .json. Возврат: путь от корня (для журнала). Исключение — ошибка ввода-вывода.
        public string Store(byte[] data, int off, int len, string accountDir, string ext, string jsonBody, out string sha)
        {
            DateTime now = DateTime.Now;
            string dir = Path.Combine(rootFull, accountDir, now.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture));
            string name = now.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + "_" + RandomHex(8);
            string full = Path.GetFullPath(Path.Combine(dir, name + "." + ext));
            if (!full.StartsWith(rootFull + "\\", StringComparison.OrdinalIgnoreCase)) { throw new IOException("path escape"); }
            Directory.CreateDirectory(dir);
            // Папка учётки/даты не должна быть reparse-точкой (заранее подложенный джанкшен).
            if ((new DirectoryInfo(Path.Combine(rootFull, accountDir)).Attributes & FileAttributes.ReparsePoint) != 0 ||
                (new DirectoryInfo(dir).Attributes & FileAttributes.ReparsePoint) != 0) { throw new IOException("reparse"); }
            using (SHA256 h = SHA256.Create()) { sha = BitConverter.ToString(h.ComputeHash(data, off, len)).Replace("-", "").ToLowerInvariant(); }
            WriteNew(full, data, off, len);
            byte[] js = Encoding.UTF8.GetBytes(jsonBody.Replace("\"sha256\":\"\"", "\"sha256\":\"" + sha + "\"")
                                                       .Replace("\"file\":\"\"", "\"file\":\"" + name + "." + ext + "\""));
            WriteNew(Path.Combine(dir, name + ".json"), js, 0, js.Length);
            lock (sync) { used += len + js.Length; }
            CheckWarn();
            return accountDir + "\\" + Path.GetFileName(dir) + "\\" + name + "." + ext;
        }

        // Новый файл через .part (CreateNew) и переименование — недописанный файл не выглядит готовым.
        static void WriteNew(string path, byte[] data, int off, int len)
        {
            string part = path + ".part";
            using (FileStream f = new FileStream(part, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, FileOptions.WriteThrough))
            {
                f.Write(data, off, len);
            }
            File.Move(part, path);
        }
    }

    // Минимальный строгий HTTP/1.1 сервер на 127.0.0.1: одна заявка на соединение, ответ без тела, Connection: close.
    sealed class Server
    {
        readonly Config cfg;
        readonly Storage store;
        readonly Accounts accounts;
        readonly RateLimiter perIp, perInstall, perLogin;
        readonly ByteBudget ipBytes, installBytes, loginBytes, unknownBytes, globalBytes;   // ★ В1: бюджеты принятых байт
        readonly Semaphore ingestSlots;
        readonly HashSet<string> activeIps = new HashSet<string>(StringComparer.Ordinal); // ★ В3: один приём на IP одновременно
        Timer housekeeping;                                                                // раз в 10 мин: пересчёт, журнал пропусков
        TcpListener listener;
        Thread acceptThread;
        volatile bool stopping;
        int connections;
        const int MaxHead = 16 * 1024;
        public const string IngestPath = "/api/v1/ingest";

        public Server(Config c)
        {
            cfg = c;
            store = new Storage(c);
            accounts = new Accounts(c);
            perIp = new RateLimiter(c.PerIpPerHour, TimeSpan.FromHours(1));
            perInstall = new RateLimiter(c.PerInstallPerHour, TimeSpan.FromHours(1));
            perLogin = new RateLimiter(c.PerLoginPerHour, TimeSpan.FromHours(1));
            ipBytes = new ByteBudget(c.IpBytesPerHour, TimeSpan.FromHours(1));
            installBytes = new ByteBudget(c.InstallBytesPerHour, TimeSpan.FromHours(1));
            loginBytes = new ByteBudget(c.LoginBytesPerDay, TimeSpan.FromDays(1));
            unknownBytes = new ByteBudget(c.UnknownBytesPerDay, TimeSpan.FromDays(1));
            globalBytes = new ByteBudget(c.GlobalBytesPerDay, TimeSpan.FromDays(1));
            ingestSlots = new Semaphore(c.MaxConcurrent, c.MaxConcurrent);
            // Перезапуск службы не должен обнулять бюджеты: восстановить по .json за последние сутки.
            long hourAgo = DateTime.UtcNow.AddHours(-1).Ticks;
            int restored = 0;
            store.OnRecent = delegate (long at, string ip, string inst, string top, long size)
            {
                restored++;
                globalBytes.Charge("*", size, at);
                if (top == Storage.Unknown) { unknownBytes.Charge("*", size, at); } else { loginBytes.Charge(top, size, at); }
                if (at >= hourAgo)
                {
                    if (ip != null) { ipBytes.Charge(ip, size, at); }
                    if (inst != null) { installBytes.Charge(inst, size, at); }
                    if (top != Storage.Unknown) { perLogin.Restore(top, at); }
                }
            };
            store.Rescan(true);
            store.OnRecent = null;
            Journal.Service("budgets restored from " + restored + " file(s) of the last 24h");
        }

        public void Start()
        {
            int w, io;
            ThreadPool.GetMinThreads(out w, out io);
            ThreadPool.SetMinThreads(Math.Max(w, cfg.MaxConnections + 4), io);
            listener = new TcpListener(IPAddress.Loopback, cfg.Port);
            listener.ExclusiveAddressUse = true;
            listener.Start(64);
            acceptThread = new Thread(AcceptLoop);
            acceptThread.IsBackground = true;
            acceptThread.Name = "accept";
            acceptThread.Start();
            housekeeping = new Timer(delegate
            {
                try
                {
                    store.MaybeRescan();
                    string d = Journal.TakeDroppedSummary();
                    if (d.Length > 0) { Journal.Service("journal lines dropped (daily cap): " + d); }
                }
                catch { }
            }, null, TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(10));
            Journal.Service("start 127.0.0.1:" + cfg.Port + " root=" + cfg.Root + " used=" + store.Used + " quota=" + cfg.QuotaBytes +
                            " keyIds=" + string.Join(",", cfg.KeyIds) + (cfg.TestAccounts != null ? " TEST-ACCOUNTS" : ""));
        }

        public void Stop()
        {
            stopping = true;
            try { listener.Stop(); } catch { }
            if (housekeeping != null) { housekeeping.Dispose(); }
            for (int i = 0; i < 100 && Thread.VolatileRead(ref connections) > 0; ++i) { Thread.Sleep(100); }
            Journal.Service("stop");
        }

        void AcceptLoop()
        {
            while (!stopping)
            {
                Socket s;
                try { s = listener.AcceptSocket(); }
                catch (Exception e) { if (stopping) { return; } Journal.Service("accept error " + e.GetType().Name); Thread.Sleep(200); continue; }
                if (Interlocked.Increment(ref connections) > cfg.MaxConnections)
                {
                    Interlocked.Decrement(ref connections);
                    try { s.LingerState = new LingerOption(true, 0); s.Close(); } catch { }
                    continue;
                }
                ThreadPool.QueueUserWorkItem(delegate (object o)
                {
                    Socket sock = (Socket)o;
                    try { Handle(sock); }
                    catch (Exception e) { Journal.Service("handler error " + e.GetType().Name); }
                    finally
                    {
                        try { sock.Close(); } catch { }
                        Interlocked.Decrement(ref connections);
                    }
                }, s);
            }
        }

        static string Reason(int code)
        {
            switch (code)
            {
                case 100: return "Continue";
                case 204: return "No Content";
                case 400: return "Bad Request";
                case 404: return "Not Found";
                case 413: return "Payload Too Large";
                case 429: return "Too Many Requests";
                case 500: return "Internal Server Error";
                case 503: return "Service Unavailable";
                case 507: return "Insufficient Storage";
                default: return "Error";
            }
        }

        void Send(Socket s, int code, bool final)
        {
            string head = "HTTP/1.1 " + code + " " + Reason(code) + "\r\n";
            if (code != 100)
            {
                if (code != 204) { head += "Content-Length: 0\r\n"; }
                head += "Cache-Control: no-store\r\nConnection: close\r\n";
            }
            head += "\r\n";
            byte[] b = Encoding.ASCII.GetBytes(head);
            try
            {
                s.SendTimeout = cfg.IoTimeoutMs;
                s.Send(b);
                if (final)
                {
                    // Мягкое закрытие: FIN, затем коротко дочитать то, что ещё летит (иначе RST может съесть ответ у Caddy).
                    s.Shutdown(SocketShutdown.Send);
                    byte[] sink = new byte[65536];
                    s.ReceiveTimeout = 1000;
                    long drained = 0;
                    DateTime until = DateTime.UtcNow.AddSeconds(2);
                    while (drained < cfg.MaxBody && DateTime.UtcNow < until)
                    {
                        int n = s.Receive(sink);
                        if (n <= 0) { break; }
                        drained += n;
                    }
                }
            }
            catch { }
        }

        // Финальный ответ и строка в журнал отказов (для кодов ≥ 400).
        void Finish(Socket s, int code, string ip, string install, string reason, long cl)
        {
            if (code >= 400) { Journal.Reject(ip, install, code, reason, cl); }
            Send(s, code, true);
        }

        // Прочитать ровно n байт до срока. false — срок/обрыв.
        bool ReadExact(Socket s, byte[] buf, int off, int n, DateTime deadline)
        {
            while (n > 0)
            {
                int left = (int)(deadline - DateTime.UtcNow).TotalMilliseconds;
                if (left <= 0) { return false; }
                s.ReceiveTimeout = Math.Min(left, cfg.IoTimeoutMs);
                int got;
                try { got = s.Receive(buf, off, n, SocketFlags.None); }
                catch (SocketException) { return false; }
                if (got <= 0) { return false; }
                off += got;
                n -= got;
            }
            return true;
        }

        static bool IsTokenChar(char c)
        {
            return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || "!#$%&'*+-.^_`|~".IndexOf(c) >= 0;
        }

        static bool IsHex32(string v)
        {
            if (v == null || v.Length != 32) { return false; }
            foreach (char c in v) { if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) { return false; } }
            return true;
        }

        void Handle(Socket s)
        {
            if (!(s.RemoteEndPoint is IPEndPoint) || !IPAddress.IsLoopback(((IPEndPoint)s.RemoteEndPoint).Address)) { return; }
            s.NoDelay = true;
            // ── заголовок ──
            byte[] head = new byte[MaxHead];
            int have = 0, headEnd = -1;
            DateTime headDeadline = DateTime.UtcNow.AddMilliseconds(cfg.HeadTimeoutMs);
            while (headEnd < 0)
            {
                if (have >= MaxHead) { Finish(s, 400, null, null, "head_big", -1); return; }
                int left = (int)(headDeadline - DateTime.UtcNow).TotalMilliseconds;
                if (left <= 0) { Journal.Reject(null, null, 0, "head_timeout", -1); return; }
                s.ReceiveTimeout = Math.Min(left, cfg.IoTimeoutMs);
                int got;
                try { got = s.Receive(head, have, MaxHead - have, SocketFlags.None); }
                catch (SocketException) { Journal.Reject(null, null, 0, "head_timeout", -1); return; }
                if (got <= 0) { return; }
                int from = Math.Max(0, have - 3);
                have += got;
                for (int i = from; i + 3 < have; ++i)
                {
                    if (head[i] == '\r' && head[i + 1] == '\n' && head[i + 2] == '\r' && head[i + 3] == '\n') { headEnd = i; break; }
                }
            }
            for (int i = 0; i < headEnd; ++i)
            {
                byte c = head[i];
                if (!(c == '\r' || c == '\n' || c == '\t' || (c >= 0x20 && c < 0x7F))) { Finish(s, 400, null, null, "head_bytes", -1); return; }
            }
            string[] lines = Encoding.ASCII.GetString(head, 0, headEnd).Split(new string[] { "\r\n" }, StringSplitOptions.None);
            string[] rl = lines[0].Split(' ');
            if (rl.Length != 3 || (rl[2] != "HTTP/1.1" && rl[2] != "HTTP/1.0")) { Finish(s, 400, null, null, "request_line", -1); return; }
            Dictionary<string, string> h = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 1; i < lines.Length; ++i)
            {
                string ln = lines[i];
                int colon = ln.IndexOf(':');
                if (colon <= 0) { Finish(s, 400, null, null, "header_syntax", -1); return; }
                string name = ln.Substring(0, colon);
                foreach (char c in name) { if (!IsTokenChar(c)) { Finish(s, 400, null, null, "header_name", -1); return; } }
                string val = ln.Substring(colon + 1).Trim(' ', '\t');
                string prev;
                if (h.TryGetValue(name, out prev))
                {
                    if (string.Equals(name, "X-Forwarded-For", StringComparison.OrdinalIgnoreCase)) { h[name] = prev + "," + val; continue; }
                    Finish(s, 400, null, null, "header_dup", -1); return;
                }
                h[name] = val;
            }
            if (rl[0] != "POST" || rl[1] != IngestPath) { Finish(s, 404, null, null, "path", -1); return; }

            // ── кто ──
            string ip = ((IPEndPoint)s.RemoteEndPoint).Address.ToString();
            string xff;
            if (h.TryGetValue("X-Forwarded-For", out xff))
            {
                string[] parts = xff.Split(',');
                IPAddress a;
                if (IPAddress.TryParse(parts[parts.Length - 1].Trim(), out a)) { ip = a.ToString(); }
                else { Finish(s, 400, null, null, "xff", -1); return; }
            }
            // ★ В2: порядок — IP → install → (после проверки) логин → общий; общий бюджет списывается только принятым.
            if (!perIp.Hit(ip)) { Finish(s, 429, ip, null, "rate_ip", -1); return; }
            lock (activeIps)
            {
                if (activeIps.Contains(ip)) { Finish(s, 429, ip, null, "busy_ip", -1); return; }   // ★ В3: один приём на IP
                activeIps.Add(ip);
            }
            try { HandleIngest(s, h, head, have, headEnd, ip); }
            finally { lock (activeIps) { activeIps.Remove(ip); } }
        }

        // Приём после проверки пути и IP: install → длина/тип → бюджеты → слот → квота → тело → Process.
        void HandleIngest(Socket s, Dictionary<string, string> h, byte[] head, int have, int headEnd, string ip)
        {
            string install;
            h.TryGetValue("X-Asda-Install", out install);
            if (!IsHex32(install)) { Finish(s, 400, ip, null, "install_hdr", -1); return; }
            install = install.ToLowerInvariant();
            if (!perInstall.Hit(install)) { Finish(s, 429, ip, install, "rate_install", -1); return; }

            // ── тело: только Content-Length, без chunked ──
            if (h.ContainsKey("Transfer-Encoding")) { Finish(s, 400, ip, install, "chunked", -1); return; }
            string clStr;
            if (!h.TryGetValue("Content-Length", out clStr) || clStr.Length == 0 || clStr.Length > 10) { Finish(s, 400, ip, install, "no_length", -1); return; }
            foreach (char c in clStr) { if (c < '0' || c > '9') { Finish(s, 400, ip, install, "bad_length", -1); return; } }
            long cl = long.Parse(clStr, CultureInfo.InvariantCulture);
            if (cl > cfg.MaxBody) { Finish(s, 413, ip, install, "body_big", cl); return; }
            if (cl < Envelope.HeaderLen + 6 + Container.MinFileLen) { Finish(s, 400, ip, install, "body_short", cl); return; }
            string ct;
            if (!h.TryGetValue("Content-Type", out ct) || !string.Equals(ct, "application/octet-stream", StringComparison.OrdinalIgnoreCase))
            { Finish(s, 400, ip, install, "content_type", cl); return; }
            // Бюджеты в байтах — заранее, без списания (не читать тело, которое всё равно не примем).
            if (!ipBytes.Fits(ip, cl)) { Finish(s, 429, ip, install, "bytes_ip", cl); return; }
            if (!installBytes.Fits(install, cl)) { Finish(s, 429, ip, install, "bytes_install", cl); return; }
            if (!globalBytes.Fits("*", cl)) { Finish(s, 429, ip, install, "bytes_global", cl); return; }

            if (!ingestSlots.WaitOne(0)) { Finish(s, 429, ip, install, "busy", cl); return; }
            try
            {
                if (!store.HasRoom(cl * 2)) { Finish(s, 507, ip, install, "quota", cl); return; }
                string exp;
                if (h.TryGetValue("Expect", out exp))
                {
                    if (!string.Equals(exp, "100-continue", StringComparison.OrdinalIgnoreCase)) { Finish(s, 400, ip, install, "expect", cl); return; }
                    Send(s, 100, false);
                }
                byte[] body = new byte[cl];
                int already = have - (headEnd + 4);
                if (already > cl) { Finish(s, 400, ip, install, "body_extra", cl); return; }
                Buffer.BlockCopy(head, headEnd + 4, body, 0, already);
                if (!ReadExact(s, body, already, (int)cl - already, DateTime.UtcNow.AddMilliseconds(cfg.BodyTimeoutMs)))
                { Journal.Reject(ip, install, 0, "body_timeout", cl); return; }
                Process(s, body, ip, install);
            }
            finally { ingestSlots.Release(); }
        }

        static string Js(string s)
        {
            if (s == null) { return "null"; }
            StringBuilder sb = new StringBuilder("\"");
            foreach (char c in s)
            {
                if (c == '"' || c == '\\') { sb.Append('\\').Append(c); }
                else if (c < 0x20 || c > 0x7E) { sb.Append("\\u").Append(((int)c).ToString("x4")); }
                else { sb.Append(c); }
            }
            return sb.Append('"').ToString();
        }

        void Process(Socket s, byte[] body, string ip, string install)
        {
            List<EnvFile> files;
            string err = Envelope.Parse(body, body.Length, cfg.MaxFile, cfg.MaxFiles, out files);
            if (err != null) { Finish(s, err == "env_file_big" ? 413 : 400, ip, install, err, body.Length); return; }
            for (int i = 0; i < files.Count; ++i)
            {
                ContainerInfo info;
                string e = Container.Validate(body, files[i].Offset, files[i].Length, files[i].Kind, cfg.KeyIds, out info);
                if (e != null) { Finish(s, 400, ip, install, e + "@" + (i + 1), body.Length); return; }
                files[i].Info = info;
            }
            // Учётки — только для уже корректных файлов (мусор до БД не доходит).
            string[] status = new string[files.Count];
            string[] dirs = new string[files.Count];
            for (int i = 0; i < files.Count; ++i)
            {
                EnvFile f = files[i];
                if (f.Login == null) { status[i] = f.LoginBad ? "bad_format" : "none"; dirs[i] = Storage.Unknown; continue; }
                bool exists;
                try { exists = accounts.Exists(f.Login); }
                catch (Exception ex)
                {
                    // Текст ошибки SqlClient (без данных запроса) — однострочно и не длиннее 300 символов, для разбора отказов БД.
                    string msg = ex.Message.Replace('\r', ' ').Replace('\n', ' ');
                    SqlException se = ex as SqlException;
                    Journal.Service("sql error " + ex.GetType().Name + (se != null ? " n=" + se.Number : "") + " " + (msg.Length > 300 ? msg.Substring(0, 300) : msg));
                    Finish(s, 503, ip, install, "db", body.Length);
                    return;
                }
                status[i] = exists ? "ok" : "not_found";
                dirs[i] = exists ? store.AccountDir(f.Login) : Storage.Unknown;
            }
            // ★ М1/В2: лимиты логина — после проверки и только для существующей учётки; затем _unknown; затем общий.
            Dictionary<string, long> perDir = new Dictionary<string, long>(StringComparer.Ordinal);
            for (int i = 0; i < files.Count; ++i)
            {
                long n;
                perDir.TryGetValue(dirs[i], out n);
                perDir[dirs[i]] = n + files[i].Length;
            }
            foreach (KeyValuePair<string, long> kv in perDir)
            {
                if (kv.Key == Storage.Unknown)
                {
                    if (!unknownBytes.Fits("*", kv.Value)) { Finish(s, 429, ip, install, "bytes_unknown", body.Length); return; }
                }
                else
                {
                    if (!loginBytes.Fits(kv.Key, kv.Value)) { Finish(s, 429, ip, install, "bytes_login", body.Length); return; }
                    if (!perLogin.Hit(kv.Key)) { Finish(s, 429, ip, install, "rate_login", body.Length); return; }
                }
            }
            if (!globalBytes.Fits("*", body.Length)) { Finish(s, 429, ip, install, "bytes_global", body.Length); return; }
            long need = 0;
            foreach (EnvFile f in files) { need += f.Length + 1024; }
            if (!store.HasRoom(need)) { Finish(s, 507, ip, install, "quota", body.Length); return; }

            string reqId = Guid.NewGuid().ToString("N").Substring(0, 16);
            DateTime now = DateTime.Now;
            List<string> stored = new List<string>();
            try
            {
                for (int i = 0; i < files.Count; ++i)
                {
                    EnvFile f = files[i];
                    StringBuilder kinds = new StringBuilder();
                    foreach (int k in f.Info.SegKinds) { if (kinds.Length > 0) { kinds.Append(','); } kinds.Append(k); }
                    string json = "{\n" +
                        "  \"file\":\"\",\n" +
                        "  \"received_utc\":" + Js(now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture)) + ",\n" +
                        "  \"received_local\":" + Js(now.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)) + ",\n" +
                        "  \"request\":" + Js(reqId) + ",\n" +
                        "  \"index\":" + (i + 1) + ",\n" +
                        "  \"ip\":" + Js(ip) + ",\n" +
                        "  \"install\":" + Js(install) + ",\n" +
                        "  \"account_claimed\":" + Js(f.Login) + ",\n" +
                        "  \"account_status\":" + Js(status[i]) + ",\n" +
                        "  \"account_note\":\"claimed by client, not proven\",\n" +
                        "  \"kind\":" + f.Kind + ",\n" +
                        "  \"kind_name\":" + Js(f.Kind == 1 ? "game" : f.Kind == 2 ? "eac" : "crash") + ",\n" +
                        "  \"size\":" + f.Length + ",\n" +
                        "  \"key_id\":" + Js(f.Info.KeyId) + ",\n" +
                        "  \"segments\":" + f.Info.Segments + ",\n" +
                        "  \"frames\":" + f.Info.Frames + ",\n" +
                        "  \"segment_kinds\":[" + kinds + "],\n" +
                        "  \"sha256\":\"\"\n}\n";
                    string sha;
                    string rel = store.Store(body, f.Offset, f.Length, dirs[i], f.Kind == 3 ? "acrash" : "alog", json, out sha);
                    stored.Add(rel);
                    Journal.Accept("req=" + reqId + " ip=" + Journal.Safe(ip) + " inst=" + install + " acct=" + status[i] + " kind=" + f.Kind +
                                   " size=" + f.Length + " segs=" + f.Info.Segments + " -> " + rel);
                }
            }
            catch (Exception ex)
            {
                Journal.Service("store error " + ex.GetType().Name + " after " + stored.Count + " file(s), req=" + reqId);
                Finish(s, 500, ip, install, "store", body.Length);
                return;
            }
            // Бюджеты списываются только принятому.
            ipBytes.Charge(ip, body.Length, 0);
            installBytes.Charge(install, body.Length, 0);
            globalBytes.Charge("*", body.Length, 0);
            foreach (KeyValuePair<string, long> kv in perDir)
            {
                if (kv.Key == Storage.Unknown) { unknownBytes.Charge("*", kv.Value, 0); } else { loginBytes.Charge(kv.Key, kv.Value, 0); }
            }
            Send(s, 204, true);
        }
    }

    sealed class LogDropService : ServiceBase
    {
        readonly Config cfg;
        Server server;
        public LogDropService(Config c) { cfg = c; ServiceName = "AsdaLogDrop"; CanStop = true; CanShutdown = true; }
        protected override void OnStart(string[] args) { server = new Server(cfg); server.Start(); }
        protected override void OnStop() { if (server != null) { server.Stop(); } }
        protected override void OnShutdown() { OnStop(); }
    }

    static class Program
    {
        // Запуск: без аргументов — служба; --console [--config файл] [--test-accounts a,b] — консоль (проверки).
        static int Main(string[] args)
        {
            string exeDir = AppDomain.CurrentDomain.BaseDirectory;
            string cfgPath = Path.Combine(exeDir, "LogDrop.ini");
            bool console = false;
            string testAccounts = null;
            for (int i = 0; i < args.Length; ++i)
            {
                if (args[i] == "--console") { console = true; }
                else if (args[i] == "--config" && i + 1 < args.Length) { cfgPath = args[++i]; }
                else if (args[i] == "--test-accounts" && i + 1 < args.Length) { testAccounts = args[++i]; }
                else { Console.Error.WriteLine("неизвестный аргумент: " + args[i]); return 2; }
            }
            Config cfg = Config.Load(cfgPath);
            if (testAccounts != null)
            {
                if (!console) { Console.Error.WriteLine("--test-accounts только с --console"); return 2; }
                cfg.TestAccounts = new HashSet<string>(StringComparer.Ordinal);
                foreach (string a in testAccounts.Split(',')) { if (a.Trim().Length > 0) { cfg.TestAccounts.Add(a.Trim().ToLowerInvariant()); } }
            }
            Journal.Init(cfg.LogDir);
            if (!console)
            {
                ServiceBase.Run(new LogDropService(cfg));
                return 0;
            }
            Journal.ToConsole = true;
            Server srv = new Server(cfg);
            srv.Start();
            Console.WriteLine("AsdaLogDrop: 127.0.0.1:" + cfg.Port + " (Enter — стоп)");
            Console.ReadLine();
            srv.Stop();
            return 0;
        }
    }
}
