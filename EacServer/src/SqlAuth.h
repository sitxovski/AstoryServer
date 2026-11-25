// Copyright (c) 2026 @sitxovski (Discord)
// SqlAuth.h — проверки учётки для AsdaId через ODBC 17 (Joy1, логин eac_auth, только EXECUTE на процедуры EAC):
//   * dbo.UPEacAuth (@login, @pwmd5) → (Status, Userindex) — проверка пароля как в UPUserLogin (P52), только чтение;
//   * dbo.UPEacAuthStatus (@userindex) → (Status, PwTag) — ред. 3 (E1-19): состояние учётки (блок/состояние) и отпечаток
//     хранилища пароля для /refresh, только чтение;
//   * dbo.UPEacAuthFail (@login) → (Status) — ред. 3 (E1-06): засчитать неудачу пароля в us_pwfail/us_pwfail_at по логике
//     замка UPUserLogin (без счёта во время замка; повтор того же ввода игрока в течение 5 с не засчитывается).
#pragma once
#include <cstdint>
#include <string>
#include <memory>

namespace Eac
{
    // Итог проверки.
    enum class AuthVerdict { Ok, Denied, Error };

    // Результат: verdict, UserIndex (при Ok), status — код процедуры (журнал: 0 ок, 2 логин, 3 пароль/замок, 5 блок, 6 состояние).
    struct AuthResult
    {
        AuthVerdict verdict = AuthVerdict::Error;
        uint32_t    userIndex = 0;
        int         status = -1;
    };

    // Результат UPEacAuthStatus: verdict Ok — учётка может входить (status 0); Denied — нет (2 нет учётки, 5 блок, 6 состояние);
    // pwTag — 16 hex: первые 8 байт SHA2_256(us_pwhash) (смена пароля → другой отпечаток; пустой — пароль не задан).
    struct StatusResult
    {
        AuthVerdict verdict = AuthVerdict::Error;
        int         status = -1;
        std::string pwTag;
    };

    // Источник проверки. Один экземпляр — на одну нить (ODBC-соединение не делится).
    class IAuthBackend
    {
    public:
        virtual ~IAuthBackend() {}
        // login — уже проверенный набор символов, pwmd5 — 32 строчных hex.
        virtual AuthResult Check(const std::string& login, const std::string& pwmd5) = 0;
        // Состояние учётки по UserIndex (E1-19).
        virtual StatusResult CheckStatus(uint32_t userIndex) = 0;
        // Засчитать неудачу пароля (E1-06). status: 0 засчитана, 1 не засчитана (тот же ввод уже засчитан < 5 с назад),
        // 2 учётки нет / логин негоден, 4 учётка заперта (во время замка счётчик не растёт, как в UPUserLogin). false — ошибка БД.
        virtual bool RecordFail(const std::string& login, int& status) = 0;
    };

    // Фабрика ODBC-источника: connString — строка без пароля, password — из secrets\sql_eac_auth.txt.
    std::unique_ptr<IAuthBackend> MakeOdbcAuth(const std::string& connString, const std::string& password, int timeoutSec);

#ifdef ASDA_EAC_STAND
    // ★ Только сборка стенда (--fake-auth): фиксированная таблица учёток, без БД.
    //   stand_ok / md5("stand-pass") → 777; stand_op / md5("stand-pass") → 778; stand_blocked → статус 5; stand_dberror → ошибка БД;
    //   прочее → 2/3. CheckStatus(777/778): файл fake_block_<ui> в текущей папке процесса → статус 5; файл fake_pwtag_<ui> — его
    //   содержимое как отпечаток пароля (иначе "00000000000000aa"). RecordFail — только счётчик и строка журнала.
    std::unique_ptr<IAuthBackend> MakeFakeAuth();
#endif
}
