// Copyright (c) 2026 @sitxovski (Discord)
// AsdaSecure.h — криптографическая прослойка трафика AsdaStory (волна В7, 12.10.2026).
//
// Назначение: встать между сокетом и разборщиком старого кадра `FB|size|A|B|op…FE` на ОБЕИХ
// сторонах (серверная DLL под-сервера и сетевой модуль клиента UE), не меняя старый протокол.
//
// Схема (решения владельца, «Дополнение 11.10» в Reports/anticheat/00_PLAN.md):
//   1. У сервера постоянная пара ECDSA P-256: закрытый ключ — файл рядом с DLL, открытый — вшит в клиент.
//   2. На каждое подключение — эфемерный ECDH P-256 с обеих сторон, HKDF-SHA256 → ключи направлений.
//   3. Кадр — AES-256-GCM: [u32 len][u64 seq][ciphertext][tag16]; seq строго растёт, повтор/перестановка — отказ.
//   4. Прослойка различает «старый клиент без шифрования» по ПЕРВОМУ байту (0xFB = старый кадр,
//      0xA5 = приветствие клиента) — режим Legacy пропускает байты как есть (на время перехода).
//
// Криптография — ТОЛЬКО Windows CNG (bcrypt.dll): та же библиотека собирается /MT в серверные DLL
// (LoginPatch.dll, AsdaPatch.dll) и в клиент UE под Windows. Исключений в API нет: всё через bool/Err.
// Единственный источник исключений — std::vector при нехватке памяти (bad_alloc); в серверных DLL
// вызывающая сторона и так работает под SEH обёрткой патчей.
#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>

namespace AsdaSecure
{
    // ── Константы форматов ──────────────────────────────────────────────────────────────────
    constexpr uint8_t  kVersion        = 1;      // версия протокола прослойки (байт в приветствиях)
    constexpr uint8_t  kClientMagic    = 0xA5;   // первый байт ClientHello (≠ 0xFB старого кадра)
    constexpr uint8_t  kServerMagic    = 0x5A;   // первый байт ServerHello
    constexpr uint8_t  kLegacyMagic    = 0xFB;   // первый байт старого кадра — клиент без шифрования
    constexpr size_t   kPubLen         = 64;     // открытый ключ P-256: X||Y (сырой, без заголовка CNG)
    constexpr size_t   kPrivLen        = 32;     // скаляр d закрытого ключа P-256
    constexpr size_t   kSigLen         = 64;     // подпись ECDSA P-256: r||s
    constexpr size_t   kNonceLen       = 16;     // случайность каждой стороны в приветствии
    constexpr size_t   kKeyLen         = 32;     // ключ AES-256
    constexpr size_t   kIvLen          = 12;     // nonce GCM (96 бит): ivBase XOR seq
    constexpr size_t   kTagLen         = 16;     // тег GCM
    constexpr size_t   kFrameHdrLen    = 4 + 8;  // u32 len + u64 seq
    constexpr size_t   kFrameOverhead  = kFrameHdrLen + kTagLen;   // накладные байты на кадр = 28
    constexpr size_t   kMaxPlain       = 64 * 1024;                // предел полезной нагрузки одного кадра
    constexpr size_t   kMaxFrame       = kMaxPlain + kFrameOverhead;
    constexpr size_t   kBindLen        = 32;     // ★ EAC ред. 3: длина привязки канала (Session::ChannelBinding)
    // ClientHello: magic(1) ver(1) subServer(1) flags(1) ePub(64) nonce(16)
    constexpr size_t   kClientHelloLen = 4 + kPubLen + kNonceLen;               // 84
    // ServerHello: magic(1) ver(1) subServer(1) flags(1) ePub(64) nonce(16) sig(64)
    constexpr size_t   kServerHelloLen = 4 + kPubLen + kNonceLen + kSigLen;     // 148

    // Идентификаторы под-серверов (попадают в приветствие и под подпись — ключ логина не годится для игры).
    enum class SubServer : uint8_t
    {
        Login = 1,     // LoginManager 15001 (LoginPatch.dll)
        Game  = 2,     // GameServer 15601 (AsdaPatch.dll)
        Indun = 3,     // Indun_GameServer (тот же образ GameServer, та же DLL)
        Eac   = 4,     // ★ EAC Э1 (16.10.2026): сайдкар AsdaEacServer.exe, TCP 15901 (контракт eac/CONTRACT.md §3, ред. 2: 15701 занят NpcServer);
                       //   тот же долговременный ключ secure_server.key; значение 4 — и в клиентской копии заголовка
    };

    // Коды ошибок прослойки.
    enum class Err : int
    {
        Ok = 0,
        Arg,            // негодный аргумент/размер
        Cng,            // отказ bcrypt.dll (см. LastStatus)
        BadMagic,       // первый байт не приветствие и не старый кадр
        BadVersion,     // чужая версия протокола
        BadSubServer,   // приветствие адресовано другому под-серверу
        BadSignature,   // подпись сервера не сошлась (подмена ключа/посредник)
        BadTag,         // тег GCM не сошёлся (порча/подмена кадра)
        Replay,         // seq не больше последнего принятого (повтор/переупорядочивание)
        Format,         // длина кадра вне допустимого
        State,          // операция не в том состоянии (например, Seal до рукопожатия)
        Legacy,         // канал в режиме «старый клиент», шифрование не применяется
    };

    // Режим канала после разбора первого байта.
    enum class Mode : uint8_t { Unknown = 0, Secure = 1, Legacy = 2 };

    // Долговременный открытый ключ сервера (вшивается в клиент: keygen → server_public.h).
    struct PublicKey  { uint8_t xy[kPubLen]; };
    // Долговременный закрытый ключ сервера (файл рядом с DLL; в код НЕ попадает).
    struct PrivateKey { uint8_t d[kPrivLen]; uint8_t xy[kPubLen]; };

    // ── Инициализация и ключи ─────────────────────────────────────────────────────────────
    // Открыть провайдеры CNG один раз на процесс (ECDH_P256, ECDSA_P256, AES-GCM, HMAC-SHA256, RNG).
    // Потокобезопасно; повторный вызов — no-op. false = bcrypt недоступен (LastStatus).
    bool Init();
    // Последний NTSTATUS от bcrypt для диагностики (0 = не было ошибок).
    long LastStatus();
    // Криптослучайные байты (BCryptGenRandom, системный RNG).
    bool RandomBytes(void* out, size_t len);
    // Сгенерировать долговременную пару ECDSA P-256.
    bool GenerateLongTermKey(PrivateKey& out);
    // Файл закрытого ключа: формат «ASDAKEY1» + d(32) + xy(64) = 104 байта. Права на файл — за владельцем.
    bool SavePrivateKeyFile(const wchar_t* path, const PrivateKey& key);
    bool LoadPrivateKeyFile(const wchar_t* path, PrivateKey& out);
    // Записать server_public.h с массивом для клиента.
    bool WritePublicHeader(const wchar_t* path, const PublicKey& pub, const char* symbol);
    // Подпись/проверка (SHA-256 над данными, затем ECDSA). Нужны keygen-утилите и стенду.
    bool SignData(const PrivateKey& key, const uint8_t* data, size_t len, uint8_t sig[kSigLen]);
    bool VerifyData(const PublicKey& pub, const uint8_t* data, size_t len, const uint8_t sig[kSigLen]);
    // Затереть буфер ключа (SecureZeroMemory).
    void Wipe(void* p, size_t n);

    // ── ★ sec2 (15.10.2026, блок В плана альфы): УСКОРЕНИЕ РУКОПОЖАТИЯ СЕРВЕРА ──────────────────────────────────────
    //   Замер wave_PERF_secure_20261014 §2: ServerAccept ~1,9 мс CPU, из них импорт закрытого ECDSA-ключа на КАЖДОЕ рукопожатие
    //   0,39 мс и генерация эфемерной пары ECDH + экспорт 0,73 мс. Обе операции снимаются с нити IOCP:
    //   1) ServerSignerLoad — ключ подписи импортируется в CNG один раз; дескрипторы (до kSignerHandles) держатся в памяти
    //      процесса, каждый в данный момент — у одной нити (занят/свободен через Interlocked; одновременной подписи одним
    //      дескриптором нет). Все заняты — временный импорт (как раньше). Ключ на диск НЕ пишется (копия — только в памяти).
    //   2) EphemeralPoolStart — фоновая нить (пониженный приоритет) заранее готовит небольшой пул эфемерных пар ECDH P-256.
    //      Пара ОДНОРАЗОВАЯ: ServerAccept забирает её из пула (запись пула затирается), сессия уничтожает её после вывода
    //      ключей (DeriveKeys) или при сбросе — повторно никогда не выдаётся. Пул пуст / не запущен — генерация на месте.
    //      Пул живёт только в памяти процесса (дескрипторы CNG), на диск ничего не пишется; заготовка старше 10 мин не выдаётся
    //      (уничтожается и заменяется свежей) — пары не залёживаются.
    //   Протокол рукопожатия не меняется (ServerHello тот же; клиенту правка не нужна).
    constexpr int kSignerHandles = 16;       // дескрипторов ключа подписи (у GameServer 9 нитей IOCP)
    constexpr int kEphPoolMax    = 64;       // предел размера пула эфемерных пар
    bool ServerSignerLoad(const PrivateKey& key);   // false — импорт не удался (подпись пойдёт прежним путём)
    void ServerSignerClear();                       // забыть ключ, уничтожить дескрипторы (стенд); только без рукопожатий в полёте
    bool EphemeralPoolStart(int size);              // size 0 — выкл; >kEphPoolMax — к пределу. false — нить не создана
    void EphemeralPoolStop();                       // остановить нить, уничтожить пары пула (стенд); без рукопожатий в полёте
    struct AccelStats
    {
        long signCached;   // подписей кэшированным дескриптором
        long signImport;   // подписей с временным импортом (ключ не загружен / все дескрипторы заняты / чужой ключ)
        long signHandles;  // дескрипторов импортировано (≤ kSignerHandles)
        long ephPool;      // пар взято из пула
        long ephInline;    // пар сгенерировано на месте (пул пуст / выключен)
        long ephMade;      // пар сгенерировано фоновой нитью
        long ephDestroyed; // пар пула уничтожено без выдачи (старше 10 мин / останов пула)
        long poolNow;      // пар в пуле сейчас
        long poolTarget;   // размер пула (0 — выкл)
    };
    void GetAccelStats(AccelStats* s);

    // ── Низкий уровень: сессия (рукопожатие + кадры) ──────────────────────────────────────
    // Один объект на одно TCP-соединение. Не копируется. Все методы — только из потоков,
    // которые владелец сериализует сам (Ciocp::Send держит свою критическую секцию; приём
    // по одному сокету идёт строго последовательно — одна незавершённая ReadFile).
    class Session
    {
    public:
        Session();
        ~Session();
        Session(const Session&) = delete;
        Session& operator=(const Session&) = delete;

        // Сбросить всё состояние (ключи затираются). Зовётся при новом соединении и при разрыве.
        void Reset();

        // Клиент, шаг 1: эфемерная пара + ClientHello (ровно kClientHelloLen байт в out).
        bool ClientHello(SubServer sub, const PublicKey& serverPub, uint8_t out[kClientHelloLen]);
        // Сервер, шаг 2: принять ClientHello, выпустить ServerHello (подпись закрытым ключом сервера),
        // вывести ключи. hello — ровно kClientHelloLen байт.
        Err  ServerAccept(const uint8_t* hello, size_t len, SubServer sub, const PrivateKey& serverKey,
                          uint8_t out[kServerHelloLen]);
        // Клиент, шаг 3: проверить ServerHello (подпись вшитым открытым ключом), вывести ключи.
        Err  ClientFinish(const uint8_t* hello, size_t len);

        // Ключи выведены — можно шифровать.
        bool IsReady() const { return m_ready; }

        // ★ EAC ред. 3 (16.10.2026, контракт eac/CONTRACT.md §8.1): экспортёр привязки канала.
        //   bind = HKDF-Expand(prk, info_bind, 32) этого рукопожатия: info_bind — тот же массив info, что для ключей
        //   направлений, но последние 16 байт = "AsdaEacBind/v1\0\0" вместо "AsdaSecure/v1\0\0\0". Одинаков у клиента и
        //   сервера ОДНОГО соединения, у разных соединений — разный; из bind ключи канала не выводятся (другая метка HKDF).
        //   Ключи направлений и формат рукопожатия не меняются. Затирается в Reset()/деструкторе.
        //   false — рукопожатие не завершено (ключи не выведены), out не трогается.
        bool ChannelBinding(uint8_t out[kBindLen]) const;

        // Запечатать plain в кадр и ДОПИСАТЬ его в out. seq исходящего направления растёт на 1.
        Err  Seal(const uint8_t* plain, size_t len, std::vector<uint8_t>& out);
        // Потоковый приём: скормить принятые с сокета байты (любой нарезки).
        Err  Feed(const uint8_t* data, size_t len);
        // Вынуть следующий целый расшифрованный кадр в out (перезаписывается). false = целого кадра
        // пока нет (Err::Ok) либо ошибка (LastError ≠ Ok — канал надо закрывать).
        bool Next(std::vector<uint8_t>& out);
        // Ошибка последнего Feed/Next.
        Err  LastError() const { return m_lastErr; }

        // Счётчики для журналов/стенда.
        uint64_t SentSeq() const { return m_txSeq; }
        uint64_t RecvSeq() const { return m_rxSeq; }
        size_t   PendingBytes() const { return m_in.size(); }

    private:
        struct Impl;            // хэндлы CNG скрыты от заголовка (bcrypt.h не нужен включающим)
        Impl*    m_impl;
        bool     m_ready;
        Err      m_lastErr;
        uint64_t m_txSeq;       // последний отправленный seq (0 = ещё ничего)
        uint64_t m_rxSeq;       // последний принятый seq; окно повторов = «строго m_rxSeq+1» (TCP упорядочен,
                                //   любой иной seq — повтор, перестановка или потеря → канал закрывается)
        std::vector<uint8_t> m_in;   // накопитель принятых байт (шифротекст)
        size_t   m_inOff;            // сколько из m_in уже разобрано

        bool DeriveKeys(const uint8_t* clientHello, const uint8_t* serverHello, bool isClient);
        bool Open(const uint8_t* frame, size_t frameLen, std::vector<uint8_t>& out);
    };

    // ── Высокий уровень: канал с распознаванием старого клиента и очередью до рукопожатия ──
    // Серверная сторона. Один объект на слот сокета Ciocp (0..549). Схема использования:
    //   accept  → Reset()
    //   приём   → OnRecv(bytes, n, toParser, toSocket): toParser отдать в CCircleQ::CopyToWriteBuffer,
    //             toSocket (ServerHello) — в WriteFile того же сокета
    //   отправка→ OnSend(plain, n, toSocket): toSocket — вместо plain в WriteFile
    //   разрыв  → Reset()
    class ServerChannel
    {
    public:
        ServerChannel();
        void Reset();
        // Разрешить старый клиент (первый байт 0xFB → Legacy, байты идут без изменений).
        void SetAllowLegacy(bool allow) { m_allowLegacy = allow; }
        void SetIdentity(SubServer sub, const PrivateKey* key) { m_sub = sub; m_key = key; }
        Mode GetMode() const { return m_mode; }
        bool IsReady() const { return m_mode == Mode::Legacy || m_sess.IsReady(); }

        Err OnRecv(const uint8_t* data, size_t len, std::vector<uint8_t>& toParser, std::vector<uint8_t>& toSocket);
        Err OnSend(const uint8_t* plain, size_t len, std::vector<uint8_t>& toSocket);
        // ★ EAC ред. 3: привязка этого соединения (Session::ChannelBinding). false — режим Legacy/Unknown или
        //   рукопожатие не завершено. Вызывать там же, где сериализованы OnRecv/Reset этого слота.
        bool ChannelBinding(uint8_t out[kBindLen]) const;

    private:
        Session           m_sess;
        Mode              m_mode;
        bool              m_allowLegacy;
        SubServer         m_sub;
        const PrivateKey* m_key;
        std::vector<uint8_t> m_hello;        // накопление ClientHello (может прийти по частям)
        std::vector<uint8_t> m_pendingOut;   // исходящее, накопленное ДО завершения рукопожатия
    };

    // Клиентская сторона. Схема: Connect → Start(toSocket) (ClientHello уходит первым байтом в сокет);
    // OnRecv — до готовности копит ServerHello и проверяет подпись; OnSend — до готовности копит,
    // после — шифрует (очередь выталкивается в toSocket при первом же вызове после готовности).
    // Legacy-режим клиента (SetLegacy(true)) — всё пропускается как есть, приветствие не шлётся.
    class ClientChannel
    {
    public:
        ClientChannel();
        void Reset();
        void SetLegacy(bool legacy) { m_legacy = legacy; }
        bool IsLegacy() const { return m_legacy; }
        bool IsReady() const { return m_legacy || m_sess.IsReady(); }
        // Начать рукопожатие: ClientHello дописывается в toSocket.
        bool Start(SubServer sub, const PublicKey& serverPub, std::vector<uint8_t>& toSocket);
        Err  OnRecv(const uint8_t* data, size_t len, std::vector<uint8_t>& toParser);
        Err  OnSend(const uint8_t* plain, size_t len, std::vector<uint8_t>& toSocket);
        Err  LastError() const { return m_sess.LastError(); }
        // ★ В7d: есть ли исходящее, накопленное ДО готовности рукопожатия (ждёт Flush).
        bool HasPending() const { return !m_pendingOut.empty(); }
        // ★ В7d: вытолкнуть очередь, накопленную до рукопожатия, СРАЗУ после готовности (шифротекст в toSocket).
        //   Без этого кадр, отправленный до ServerHello (вход в мир 20000 сразу после connect), ждал бы
        //   следующей отправки. До готовности — Ok и пусто (ничего не делает).
        Err  Flush(std::vector<uint8_t>& toSocket);
        // ★ EAC ред. 3: привязка этого соединения (Session::ChannelBinding). false — Legacy или рукопожатие не завершено.
        bool ChannelBinding(uint8_t out[kBindLen]) const;

    private:
        Session   m_sess;
        bool      m_legacy;
        SubServer m_sub = SubServer::Game;   // под-сервер, которому шлём (входит в подпись)
        PublicKey m_serverPub{};             // вшитый открытый ключ сервера — проверка подписи
        uint8_t   m_clientPub[kPubLen]{};    // свой эфемерный открытый (для сверки подписи)
        std::vector<uint8_t> m_hello;        // накопление ServerHello
        std::vector<uint8_t> m_pendingOut;   // исходящее до готовности
    };

    // Текст ошибки для журнала.
    const char* ErrName(Err e);
}
