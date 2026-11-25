// Copyright (c) 2026 @sitxovski (Discord)
// Json.cpp — строгий разборщик/экранирование JSON (см. Json.h).
#include "Json.h"
#include <cstdlib>
#include <cstring>

namespace Eac { namespace Json
{
    namespace
    {
        constexpr int    kMaxDepth  = 16;          // предел вложенности
        constexpr size_t kMaxString = 64 * 1024;   // предел длины строки

        // Разборщик с курсором.
        struct Parser
        {
            const char* p;        // текущая позиция
            const char* e;        // конец
            std::string err;      // причина отказа

            bool Fail(const char* why) { if (err.empty()) err = why; return false; }

            void Ws() { while (p < e && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) ++p; }

            // Дописать кодовую точку в UTF-8.
            static void PutUtf8(std::string& s, unsigned cp)
            {
                if (cp < 0x80) s += (char)cp;
                else if (cp < 0x800) { s += (char)(0xC0 | (cp >> 6)); s += (char)(0x80 | (cp & 0x3F)); }
                else if (cp < 0x10000) { s += (char)(0xE0 | (cp >> 12)); s += (char)(0x80 | ((cp >> 6) & 0x3F)); s += (char)(0x80 | (cp & 0x3F)); }
                else { s += (char)(0xF0 | (cp >> 18)); s += (char)(0x80 | ((cp >> 12) & 0x3F)); s += (char)(0x80 | ((cp >> 6) & 0x3F)); s += (char)(0x80 | (cp & 0x3F)); }
            }

            bool Hex4(unsigned& v)
            {
                if (e - p < 4) return Fail("короткий \\u");
                v = 0;
                for (int i = 0; i < 4; ++i)
                {
                    char c = *p++; v <<= 4;
                    if (c >= '0' && c <= '9') v |= (unsigned)(c - '0');
                    else if (c >= 'a' && c <= 'f') v |= (unsigned)(c - 'a' + 10);
                    else if (c >= 'A' && c <= 'F') v |= (unsigned)(c - 'A' + 10);
                    else return Fail("негодный \\u");
                }
                return true;
            }

            // Проверить, что [s, s+n) — корректная последовательность UTF-8 (без суррогатов и overlong).
            static bool ValidUtf8Seq(const unsigned char* s, size_t n, size_t& used)
            {
                unsigned char c = s[0];
                if (c < 0x80) { used = 1; return true; }
                size_t len; unsigned cp;
                if ((c & 0xE0) == 0xC0) { len = 2; cp = c & 0x1F; }
                else if ((c & 0xF0) == 0xE0) { len = 3; cp = c & 0x0F; }
                else if ((c & 0xF8) == 0xF0) { len = 4; cp = c & 0x07; }
                else return false;
                if (n < len) return false;
                for (size_t i = 1; i < len; ++i) { if ((s[i] & 0xC0) != 0x80) return false; cp = (cp << 6) | (s[i] & 0x3F); }
                if ((len == 2 && cp < 0x80) || (len == 3 && cp < 0x800) || (len == 4 && cp < 0x10000)) return false;
                if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return false;
                used = len; return true;
            }

            bool String(std::string& out)
            {
                if (p >= e || *p != '"') return Fail("ожидалась строка");
                ++p;
                out.clear();
                while (true)
                {
                    if (p >= e) return Fail("строка не закрыта");
                    unsigned char c = (unsigned char)*p;
                    if (c == '"') { ++p; break; }
                    if (c < 0x20) return Fail("управляющий символ в строке");
                    if (c == '\\')
                    {
                        ++p; if (p >= e) return Fail("обрыв escape");
                        char x = *p++;
                        switch (x)
                        {
                        case '"': out += '"'; break;  case '\\': out += '\\'; break; case '/': out += '/'; break;
                        case 'b': out += '\b'; break; case 'f': out += '\f'; break;  case 'n': out += '\n'; break;
                        case 'r': out += '\r'; break; case 't': out += '\t'; break;
                        case 'u':
                        {
                            unsigned cp; if (!Hex4(cp)) return false;
                            if (cp >= 0xD800 && cp <= 0xDBFF)
                            {
                                if (e - p < 6 || p[0] != '\\' || p[1] != 'u') return Fail("одиночный суррогат");
                                p += 2; unsigned lo; if (!Hex4(lo)) return false;
                                if (lo < 0xDC00 || lo > 0xDFFF) return Fail("негодный суррогат");
                                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                            }
                            else if (cp >= 0xDC00 && cp <= 0xDFFF) return Fail("одиночный суррогат");
                            if (cp == 0) return Fail("NUL в строке");
                            PutUtf8(out, cp);
                            break;
                        }
                        default: return Fail("негодный escape");
                        }
                    }
                    else
                    {
                        size_t used = 0;
                        if (!ValidUtf8Seq((const unsigned char*)p, (size_t)(e - p), used)) return Fail("негодный UTF-8");
                        out.append(p, used); p += used;
                    }
                    if (out.size() > kMaxString) return Fail("строка слишком длинная");
                }
                return true;
            }

            bool Number(Value& v)
            {
                const char* s = p;
                if (p < e && *p == '-') ++p;
                if (p >= e) return Fail("число");
                if (*p == '0') ++p;
                else if (*p >= '1' && *p <= '9') { while (p < e && *p >= '0' && *p <= '9') ++p; }
                else return Fail("число");
                if (p < e && *p == '.') { ++p; if (p >= e || *p < '0' || *p > '9') return Fail("число"); while (p < e && *p >= '0' && *p <= '9') ++p; }
                if (p < e && (*p == 'e' || *p == 'E'))
                {
                    ++p; if (p < e && (*p == '+' || *p == '-')) ++p;
                    if (p >= e || *p < '0' || *p > '9') return Fail("число");
                    while (p < e && *p >= '0' && *p <= '9') ++p;
                }
                v.type = Type::Number; v.raw.assign(s, p);
                v.num = strtod(v.raw.c_str(), nullptr);
                return true;
            }

            bool Lit(const char* w) { size_t n = strlen(w); if ((size_t)(e - p) < n || memcmp(p, w, n) != 0) return Fail("литерал"); p += n; return true; }

            bool Val(Value& v, int depth)
            {
                if (depth > kMaxDepth) return Fail("слишком глубоко");
                Ws(); if (p >= e) return Fail("ожидалось значение");
                char c = *p;
                if (c == '{')
                {
                    ++p; v.type = Type::Object; Ws();
                    if (p < e && *p == '}') { ++p; return true; }
                    while (true)
                    {
                        Ws(); std::string key; if (!String(key)) return false;
                        for (auto& kv : v.obj) if (kv.first == key) return Fail("повтор ключа");
                        Ws(); if (p >= e || *p != ':') return Fail("ожидалось ':'"); ++p;
                        Value child; if (!Val(child, depth + 1)) return false;
                        v.obj.emplace_back(std::move(key), std::move(child));
                        Ws(); if (p >= e) return Fail("объект не закрыт");
                        if (*p == ',') { ++p; continue; }
                        if (*p == '}') { ++p; return true; }
                        return Fail("ожидалось ',' или '}'");
                    }
                }
                if (c == '[')
                {
                    ++p; v.type = Type::Array; Ws();
                    if (p < e && *p == ']') { ++p; return true; }
                    while (true)
                    {
                        Value child; if (!Val(child, depth + 1)) return false;
                        v.arr.push_back(std::move(child));
                        Ws(); if (p >= e) return Fail("массив не закрыт");
                        if (*p == ',') { ++p; continue; }
                        if (*p == ']') { ++p; return true; }
                        return Fail("ожидалось ',' или ']'");
                    }
                }
                if (c == '"') { v.type = Type::String; return String(v.raw); }
                if (c == 't') { v.type = Type::Bool; v.b = true;  return Lit("true"); }
                if (c == 'f') { v.type = Type::Bool; v.b = false; return Lit("false"); }
                if (c == 'n') { v.type = Type::Null; return Lit("null"); }
                return Number(v);
            }
        };
    }

    const Value* Value::Get(const char* key) const
    {
        if (type != Type::Object) return nullptr;
        for (auto& kv : obj) if (kv.first == key) return &kv.second;
        return nullptr;
    }

    bool Value::GetString(const char* key, std::string& out) const
    {
        const Value* v = Get(key);
        if (!v || v->type != Type::String) return false;
        out = v->raw; return true;
    }

    bool Parse(const std::string& text, Value& out, std::string* err)
    {
        Parser ps{ text.data(), text.data() + text.size(), {} };
        // UTF-8 BOM допускается только у файлов (eos.json мог быть сохранён Блокнотом).
        if (text.size() >= 3 && (unsigned char)text[0] == 0xEF && (unsigned char)text[1] == 0xBB && (unsigned char)text[2] == 0xBF) ps.p += 3;
        out = Value();
        bool ok = ps.Val(out, 0);
        if (ok) { ps.Ws(); if (ps.p != ps.e) ok = ps.Fail("мусор после значения"); }
        if (!ok && err) *err = ps.err;
        return ok;
    }

    std::string Quote(const std::string& s)
    {
        std::string o; o.reserve(s.size() + 2);
        o += '"';
        for (unsigned char c : s)
        {
            switch (c)
            {
            case '"': o += "\\\""; break; case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break; case '\r': o += "\\r"; break; case '\t': o += "\\t"; break;
            default:
                if (c < 0x20) { char t[8]; snprintf(t, sizeof(t), "\\u%04x", c); o += t; }
                else o += (char)c;
            }
        }
        o += '"';
        return o;
    }
}}
