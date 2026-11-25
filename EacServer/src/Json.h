// Copyright (c) 2026 @sitxovski (Discord)
// Json.h — строгий минимальный JSON (RFC 8259) для AsdaId и eos.json.
// Разбор: объекты, массивы, строки (с \uXXXX и суррогатами → UTF-8), числа, true/false/null.
// Строгость: без хвостовых запятых, без комментариев, без мусора после значения, без повторных ключей
// в объекте (повтор — ошибка: «строго по схеме» контракта), глубина ≤ 16, строка ≤ 64 КиБ.
#pragma once
#include <string>
#include <vector>
#include <utility>

namespace Eac { namespace Json
{
    // Тип значения.
    enum class Type { Null, Bool, Number, String, Array, Object };

    // Значение JSON (дерево).
    struct Value
    {
        Type type = Type::Null;                                // тип
        bool b = false;                                        // Bool
        double num = 0;                                        // Number
        std::string raw;                                       // Number — исходный текст; String — значение (UTF-8)
        std::vector<Value> arr;                                // Array
        std::vector<std::pair<std::string, Value>> obj;        // Object (порядок сохранён, ключи уникальны)

        // Найти поле объекта (nullptr — нет или не объект).
        const Value* Get(const char* key) const;
        // Строковое поле объекта: true и out — если поле есть и это строка.
        bool GetString(const char* key, std::string& out) const;
    };

    // Разобрать текст целиком. false — синтаксис/лимиты/повтор ключа; err — краткая причина.
    bool Parse(const std::string& text, Value& out, std::string* err = nullptr);

    // Экранировать строку для вывода в JSON (с кавычками).
    std::string Quote(const std::string& s);
}}
