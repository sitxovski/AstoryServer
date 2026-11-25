// Copyright (c) 2026 @sitxovski (Discord)
// SqlAuth.cpp — ODBC-вызовы UPEacAuth / UPEacAuthStatus / UPEacAuthFail (см. SqlAuth.h).
#include "EacCommon.h"
#include "SqlAuth.h"
#include "Log.h"
#include <sql.h>
#include <sqlext.h>
#include <functional>
#include <map>
#include <mutex>

namespace Eac
{
    namespace
    {
        // Текст диагностики ODBC (без строки подключения — в ней нет пароля, но и не нужна).
        std::string OdbcDiag(SQLSMALLINT type, SQLHANDLE h)
        {
            std::string out;
            SQLWCHAR state[6], msg[512]; SQLINTEGER native = 0; SQLSMALLINT len = 0;
            for (SQLSMALLINT i = 1; i <= 3; ++i)
            {
                if (!SQL_SUCCEEDED(SQLGetDiagRecW(type, h, i, state, &native, msg, (SQLSMALLINT)(sizeof(msg) / sizeof(msg[0])), &len))) break;
                if (!out.empty()) out += " | ";
                out += Utf8(std::wstring((wchar_t*)state, 5)) + " " + std::to_string(native) + " " + Utf8(std::wstring((wchar_t*)msg));
            }
            return out;
        }

        // Экранирование значения для строки подключения ODBC: {…}, '}' удваивается.
        std::wstring OdbcBrace(const std::string& v)
        {
            std::wstring w = Wide(v), o = L"{";
            for (wchar_t c : w) { o += c; if (c == L'}') o += L'}'; }
            o += L'}';
            if (!w.empty()) SecureZeroMemory(&w[0], w.size() * sizeof(wchar_t));
            return o;
        }

        // Входной параметр процедуры: строка VARCHAR(64) или INT.
        struct Param
        {
            bool        isInt = false;
            std::string s;          // строковое значение
            SQLINTEGER  i = 0;      // целое значение
        };

        // ODBC-источник: ленивое соединение, переподключение после ошибки связи.
        class OdbcAuth : public IAuthBackend
        {
        public:
            OdbcAuth(const std::string& cs, const std::string& pw, int timeoutSec)
                : m_cs(cs), m_pw(pw), m_timeout(timeoutSec), m_env(SQL_NULL_HENV), m_dbc(SQL_NULL_HDBC) {}
            ~OdbcAuth() override { Disconnect(); if (m_env) SQLFreeHandle(SQL_HANDLE_ENV, m_env); if (!m_pw.empty()) SecureZeroMemory(&m_pw[0], m_pw.size()); }

            AuthResult Check(const std::string& login, const std::string& pwmd5) override
            {
                AuthResult r;
                std::vector<Param> ps(2); ps[0].s = login.substr(0, 64); ps[1].s = pwmd5.substr(0, 32);
                bool got = Exec(L"{CALL dbo.UPEacAuth(?, ?)}", ps, "UPEacAuth", [&](SQLHSTMT st) -> bool {
                    SQLINTEGER status = -1, ui = 0; SQLLEN ind1 = 0, ind2 = 0;
                    SQLRETURN g1 = SQLGetData(st, 1, SQL_C_SLONG, &status, 0, &ind1);
                    SQLRETURN g2 = SQLGetData(st, 2, SQL_C_SLONG, &ui, 0, &ind2);
                    if (!SQL_SUCCEEDED(g1) || !SQL_SUCCEEDED(g2) || ind1 == SQL_NULL_DATA || ind2 == SQL_NULL_DATA) return false;
                    r.status = (int)status;
                    if (status == 0 && ui > 0) { r.verdict = AuthVerdict::Ok; r.userIndex = (uint32_t)ui; }
                    else { r.verdict = AuthVerdict::Denied; r.userIndex = 0; }
                    return true; });
                SecureZeroMemory(&ps[1].s[0], ps[1].s.size());
                if (!got) r.verdict = AuthVerdict::Error;
                return r;
            }

            StatusResult CheckStatus(uint32_t userIndex) override
            {
                StatusResult r;
                std::vector<Param> ps(1); ps[0].isInt = true; ps[0].i = (SQLINTEGER)userIndex;
                bool got = Exec(L"{CALL dbo.UPEacAuthStatus(?)}", ps, "UPEacAuthStatus", [&](SQLHSTMT st) -> bool {
                    SQLINTEGER status = -1; SQLLEN ind1 = 0, ind2 = 0; char tag[40] = {};
                    SQLRETURN g1 = SQLGetData(st, 1, SQL_C_SLONG, &status, 0, &ind1);
                    SQLRETURN g2 = SQLGetData(st, 2, SQL_C_CHAR, tag, sizeof(tag), &ind2);
                    if (!SQL_SUCCEEDED(g1) || !SQL_SUCCEEDED(g2) || ind1 == SQL_NULL_DATA) return false;
                    r.status = (int)status;
                    r.pwTag = ind2 == SQL_NULL_DATA ? "" : std::string(tag);
                    r.verdict = status == 0 ? AuthVerdict::Ok : AuthVerdict::Denied;
                    return true; });
                if (!got) r.verdict = AuthVerdict::Error;
                return r;
            }

            bool RecordFail(const std::string& login, int& status) override
            {
                std::vector<Param> ps(1); ps[0].s = login.substr(0, 64);
                status = -1;
                return Exec(L"{CALL dbo.UPEacAuthFail(?)}", ps, "UPEacAuthFail", [&](SQLHSTMT st) -> bool {
                    SQLINTEGER s = -1; SQLLEN ind = 0;
                    SQLRETURN g = SQLGetData(st, 1, SQL_C_SLONG, &s, 0, &ind);
                    if (!SQL_SUCCEEDED(g) || ind == SQL_NULL_DATA) return false;
                    status = (int)s;
                    return true; });
            }

        private:
            std::string m_cs, m_pw;   // строка подключения и пароль
            int         m_timeout;    // таймаут входа/запроса
            SQLHENV     m_env;
            SQLHDBC     m_dbc;

            bool Connect()
            {
                if (!m_env)
                {
                    if (!SQL_SUCCEEDED(SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &m_env))) { m_env = SQL_NULL_HENV; LOGE("sql", "SQLAllocHandle(ENV) не удался"); return false; }
                    SQLSetEnvAttr(m_env, SQL_ATTR_ODBC_VERSION, (SQLPOINTER)SQL_OV_ODBC3, 0);
                }
                if (!SQL_SUCCEEDED(SQLAllocHandle(SQL_HANDLE_DBC, m_env, &m_dbc))) { m_dbc = SQL_NULL_HDBC; LOGE("sql", "SQLAllocHandle(DBC) не удался"); return false; }
                SQLSetConnectAttrW(m_dbc, SQL_ATTR_LOGIN_TIMEOUT, (SQLPOINTER)(intptr_t)m_timeout, 0);
                SQLSetConnectAttrW(m_dbc, SQL_ATTR_CONNECTION_TIMEOUT, (SQLPOINTER)(intptr_t)m_timeout, 0);
                std::wstring cs = Wide(m_cs);
                if (!cs.empty() && cs.back() != L';') cs += L';';
                cs += L"PWD=" + OdbcBrace(m_pw) + L";";
                SQLWCHAR outBuf[1024]; SQLSMALLINT outLen = 0;
                SQLRETURN rc = SQLDriverConnectW(m_dbc, nullptr, (SQLWCHAR*)cs.c_str(), (SQLSMALLINT)cs.size(),
                                                 outBuf, (SQLSMALLINT)(sizeof(outBuf) / sizeof(outBuf[0])), &outLen, SQL_DRIVER_NOPROMPT);
                SecureZeroMemory(&cs[0], cs.size() * sizeof(wchar_t));
                SecureZeroMemory(outBuf, sizeof(outBuf));
                if (!SQL_SUCCEEDED(rc))
                {
                    LOGE("sql", "подключение не удалось: %s", OdbcDiag(SQL_HANDLE_DBC, m_dbc).c_str());
                    SQLFreeHandle(SQL_HANDLE_DBC, m_dbc); m_dbc = SQL_NULL_HDBC;
                    return false;
                }
                LOGI("sql", "подключено к БД (процедуры EAC)");
                return true;
            }

            void Disconnect()
            {
                if (m_dbc) { SQLDisconnect(m_dbc); SQLFreeHandle(SQL_HANDLE_DBC, m_dbc); m_dbc = SQL_NULL_HDBC; }
            }

            // Выполнить процедуру с параметрами и прочитать первую строку первого набора колбэком row.
            // true — строка прочитана; false — ошибка (журнал записан). Одна повторная попытка после потери связи.
            bool Exec(const wchar_t* sql, const std::vector<Param>& ps, const char* what, const std::function<bool(SQLHSTMT)>& row)
            {
                for (int attempt = 0; attempt < 2; ++attempt)
                {
                    if (!m_dbc && !Connect()) return false;
                    bool connLost = false;
                    if (Call(sql, ps, what, row, connLost)) return true;
                    Disconnect();
                    if (!connLost) return false;
                }
                return false;
            }

            bool Call(const wchar_t* sql, const std::vector<Param>& ps, const char* what, const std::function<bool(SQLHSTMT)>& row, bool& connLost)
            {
                SQLHSTMT st = SQL_NULL_HSTMT;
                if (!SQL_SUCCEEDED(SQLAllocHandle(SQL_HANDLE_STMT, m_dbc, &st))) { connLost = true; return false; }
                SQLSetStmtAttrW(st, SQL_ATTR_QUERY_TIMEOUT, (SQLPOINTER)(intptr_t)m_timeout, 0);
                // Буферы параметров живут до SQLExecDirect включительно.
                std::vector<std::vector<char>> bufs(ps.size());
                std::vector<SQLLEN> lens(ps.size());
                std::vector<SQLINTEGER> ints(ps.size());
                SQLRETURN rc = SQL_SUCCESS;
                for (size_t i = 0; i < ps.size() && SQL_SUCCEEDED(rc); ++i)
                {
                    if (ps[i].isInt)
                    {
                        ints[i] = ps[i].i; lens[i] = 0;
                        rc = SQLBindParameter(st, (SQLUSMALLINT)(i + 1), SQL_PARAM_INPUT, SQL_C_SLONG, SQL_INTEGER, 0, 0, &ints[i], 0, &lens[i]);
                    }
                    else
                    {
                        bufs[i].assign(72, 0);
                        memcpy(bufs[i].data(), ps[i].s.data(), (std::min)(ps[i].s.size(), (size_t)64));
                        lens[i] = (SQLLEN)strlen(bufs[i].data());
                        rc = SQLBindParameter(st, (SQLUSMALLINT)(i + 1), SQL_PARAM_INPUT, SQL_C_CHAR, SQL_VARCHAR, 64, 0, bufs[i].data(), (SQLLEN)bufs[i].size(), &lens[i]);
                    }
                }
                if (SQL_SUCCEEDED(rc)) rc = SQLExecDirectW(st, (SQLWCHAR*)sql, SQL_NTS);
                bool ok = false;
                if (SQL_SUCCEEDED(rc))
                {
                    rc = SQLFetch(st);
                    if (SQL_SUCCEEDED(rc))
                    {
                        ok = row(st);
                        if (!ok) LOGE("sql", "%s: негодная строка ответа", what);
                    }
                    else LOGE("sql", "%s: нет строки ответа: %s", what, OdbcDiag(SQL_HANDLE_STMT, st).c_str());
                }
                else
                {
                    std::string d = OdbcDiag(SQL_HANDLE_STMT, st);
                    LOGE("sql", "%s: ошибка вызова: %s", what, d.c_str());
                    // SQLSTATE 08xxx — связь потеряна; HYT00/HYT01 — таймаут (соединение тоже пересоздаём).
                    connLost = d.rfind("08", 0) == 0 || d.find("HYT00") != std::string::npos || d.find("HYT01") != std::string::npos;
                }
                for (auto& b : bufs) if (!b.empty()) SecureZeroMemory(b.data(), b.size());
                SQLFreeHandle(SQL_HANDLE_STMT, st);
                return ok;
            }
        };

#ifdef ASDA_EAC_STAND
        // Фальшивый источник стенда.
        class FakeAuth : public IAuthBackend
        {
        public:
            AuthResult Check(const std::string& login, const std::string& pwmd5) override
            {
                // md5("stand-pass") строчным hex
                static const char* kPw = "7787e2c49efec303a6d311a19d31b8b5";
                AuthResult r; r.verdict = AuthVerdict::Denied; r.status = 2;
                std::string l = Lower(login);
                if (l == "stand_ok" || l == "stand_op" || l == "stand_blocked")
                {
                    r.status = 3;
                    if (pwmd5 == kPw)
                    {
                        if (l == "stand_blocked") { r.status = 5; return r; }
                        r.verdict = AuthVerdict::Ok; r.status = 0; r.userIndex = l == "stand_ok" ? 777u : 778u;
                    }
                }
                else if (l == "stand_dberror") { r.verdict = AuthVerdict::Error; r.status = -1; }
                else if (l.size() > 7 && l.compare(0, 7, "stand_u") == 0 && pwmd5 == kPw)   // ★ Д3 (стенд): stand_uNNN → учётка NNN
                {
                    uint32_t v = 0;
                    if (ParseUserIndex(l.substr(7), v)) { r.verdict = AuthVerdict::Ok; r.status = 0; r.userIndex = v; }
                }
                return r;
            }

            StatusResult CheckStatus(uint32_t userIndex) override
            {
                StatusResult r;
                // ★ 22.11 (стенд): учётки stand_uNNN 800…999 — без блока
                if (userIndex >= 800 && userIndex < 1000) { r.verdict = AuthVerdict::Ok; r.status = 0; r.pwTag = "00000000000000bb"; return r; }
                if (userIndex != 777 && userIndex != 778) { r.verdict = AuthVerdict::Denied; r.status = 2; return r; }
                std::wstring b = L"fake_block_" + std::to_wstring(userIndex), t = L"fake_pwtag_" + std::to_wstring(userIndex), e = L"fake_dberror";
                if (GetFileAttributesW(e.c_str()) != INVALID_FILE_ATTRIBUTES) { r.verdict = AuthVerdict::Error; return r; }
                r.status = GetFileAttributesW(b.c_str()) != INVALID_FILE_ATTRIBUTES ? 5 : 0;
                r.verdict = r.status == 0 ? AuthVerdict::Ok : AuthVerdict::Denied;
                r.pwTag = "00000000000000aa";
                FILE* f = _wfopen(t.c_str(), L"rb");
                if (f) { char buf[64] = {}; size_t n = fread(buf, 1, 32, f); fclose(f); r.pwTag.assign(buf, n); while (!r.pwTag.empty() && (r.pwTag.back() == '\n' || r.pwTag.back() == '\r')) r.pwTag.pop_back(); }
                return r;
            }

            bool RecordFail(const std::string& login, int& status) override
            {
                std::lock_guard<std::mutex> lk(s_mu);
                std::string l = Lower(login);
                if (l != "stand_ok" && l != "stand_op" && l != "stand_blocked") { status = 2; return true; }
                status = 0;
                ++s_fails[l];
                return true;
            }

        private:
            static std::mutex s_mu;                          // счётчики общие для всех нитей стенда
            static std::map<std::string, int> s_fails;       // логин → засчитано неудач
        };
        std::mutex FakeAuth::s_mu;
        std::map<std::string, int> FakeAuth::s_fails;
#endif
    }

    std::unique_ptr<IAuthBackend> MakeOdbcAuth(const std::string& connString, const std::string& password, int timeoutSec)
    {
        return std::unique_ptr<IAuthBackend>(new OdbcAuth(connString, password, timeoutSec));
    }

#ifdef ASDA_EAC_STAND
    std::unique_ptr<IAuthBackend> MakeFakeAuth() { return std::unique_ptr<IAuthBackend>(new FakeAuth()); }
#endif
}
