// Copyright (c) 2026 @sitxovski (Discord)
// ★ 22.11.2026 (ревизия 53 М-2) Стенд шлюза gp7: детерминированный crypto.randomInt для сравнения двух server.js на одних входах.
//   Подключается ключом node -r <этот файл> server.js. Шлюз зовёт crypto.randomInt только в selectLuckyBoxReward (выбор награды
//   лаки-бокса), поэтому у двух экземпляров с одним зерном (GP7_STAND_SEED) на одной последовательности запросов награды совпадают.
//   Поведение server.js не меняется: подменён только источник случайности, распределение — равномерное по [min, max).
"use strict";
const crypto = require("crypto");
let state = (Number(process.env.GP7_STAND_SEED || 20261122) >>> 0) || 1;   // зерно генератора
function next() {                                                            // xorshift32
  state ^= state << 13; state >>>= 0;
  state ^= state >>> 17;
  state ^= state << 5; state >>>= 0;
  return state;
}
crypto.randomInt = function (min, max, cb) {
  if (max === undefined || typeof max === "function") { cb = max; max = min; min = 0; }
  const v = min + (next() % (max - min));
  if (typeof cb === "function") { process.nextTick(cb, null, v); return undefined; }
  return v;
};
