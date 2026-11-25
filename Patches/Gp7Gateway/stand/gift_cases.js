// Copyright (c) 2026 @sitxovski (Discord)
// Стенд шлюза gp7 — подарок P101_CashGift (01.11.2026): запросы 0x52 (HOLD/COMMIT/REFUND) → ответы 0x53 на НАСТОЯЩЕМ SQL
//   (свой LocalDB «gp7gift», готовит gift_stand.py), проверка денег/журналов в базе после каждого шага и кадра ответа побайтно.
//   Контракт — Reports/cash_gift/p101/PROTOCOL_GP7_GIFT.md. Живой сервер и живые БД не трогает.
// argv: <каталог стенда gp7-server> <порт> <sql-сервер> <режим normal|test|slow>
//   задержку ДО или ПОСЛЕ настоящего sqlcmd — имитация тайм-аута до и после коммита.
"use strict";
const fs = require("fs");
const path = require("path");
const net = require("net");
const { spawn, execFileSync, execFile } = require("child_process");

const standDir = process.argv[2];                 // каталог копии gp7-server
const port = Number(process.argv[3]);             // порт стенда
const sqlServer = process.argv[4];                // (localdb)\gp7gift
const mode = process.argv[5] || "normal";         // normal — без тестового режима, test — testFixedBalance 999999, slow — тайм-ауты
const SLOW_FLAG = process.env.SLOW_SQL_FLAG || ""; // файл-команда обёртки slow_sqlcmd.exe
const SQLCMD = "sqlcmd";                          // клиент sqlcmd из PATH
const KIND = 0x0003;                              // kind кадра GameServer → GP7 (как в tpl_75702.hex)
const ROUTE = 0x005d;                             // route 93 (sub_5646C0(mgr, 82, N, 93, …))

let ok = 0;                                       // пройдено проверок
let bad = 0;                                      // провалено проверок
// Одна проверка: печать [OK]/[!!] и счёт.
function check(cond, msg) { console.log(`  [${cond ? "OK" : "!!"}] ${msg}`); if (cond) { ++ok; } else { ++bad; } }

// SELECT на стенде → массив строк (поля через |).
function q(sql) {
  const out = execFileSync(SQLCMD, ["-S", sqlServer, "-E", "-d", "AsdaStoryLogin", "-b", "-h", "-1", "-W", "-s", "|", "-Q", `SET NOCOUNT ON; ${sql}`],
    { encoding: "utf8" });
  return out.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
}
// Баланс учётки на стенде.
function bal(account) { return Number(q(`SELECT b.balance FROM dbo.GP7Balance b JOIN dbo.[user] u ON u.id=b.user_id WHERE u.username='${account}'`)[0]); }
// Число строк GP7PurchaseLog.
function purchaseRows() { return Number(q("SELECT COUNT(*) FROM dbo.GP7PurchaseLog")[0]); }
// Строка GP7GiftLog по заказу → объект или null.
function giftRow(order) {
  const r = q(`SELECT state, amount, test_mode, ISNULL(CAST(settle_result AS VARCHAR),'-'), ISNULL(CAST(refund_log_id AS VARCHAR),'-'), ` +
    `CONVERT(VARCHAR(40), CAST(recipient_name AS VARBINARY(20)), 2), CONVERT(VARCHAR(40), gs_key, 2) FROM dbo.GP7GiftLog WHERE order_id=${order}`)[0];
  if (!r) { return null; }
  const f = r.split("|");
  return { state: f[0], amount: Number(f[1]), test: Number(f[2]), result: f[3], refund: f[4], recipientHex: f[5], key: f[6] };
}

// Кадр 0x52 по PROTOCOL_GP7_GIFT.md §2.
function giftFrame(o) {
  const p = Buffer.alloc(157, 0);
  p[0] = o.action;
  p.writeUInt32LE(o.userIndex >>> 0, 1);
  p.write(o.account, 5, 61, "latin1");
  p.writeUInt32LE(o.charIdx >>> 0, 66);
  p.writeUInt16LE(o.userNum, 70);
  (Buffer.isBuffer(o.sender) ? o.sender : Buffer.from(o.sender || "Sender", "latin1")).copy(p, 72, 0, 20);
  (Buffer.isBuffer(o.recipient) ? o.recipient : Buffer.from(o.recipient, "latin1")).copy(p, 92, 0, 20);
  for (let i = 0; i < 7; ++i) { p.writeUInt32LE((o.codes[i] || 0) >>> 0, 112 + 4 * i); }
  p.writeUInt32LE(o.amount >>> 0, 140);
  p.writeUInt32LE((o.order || 0) >>> 0, 144);
  Buffer.from(o.key, "hex").copy(p, 148);
  p[156] = o.result || 0;
  const f = Buffer.alloc(9 + p.length + 1, 0);
  f[0] = 0xfb; f.writeUInt16LE(f.length, 1); f.writeUInt16LE(KIND, 3); f.writeUInt16LE(ROUTE, 5); f.writeUInt16LE(0x52, 7);
  p.copy(f, 9); f[f.length - 1] = 0xfe;
  return f;
}

// Ожидаемый кадр 0x53 (PROTOCOL_GP7_GIFT.md §3) — собран здесь независимо от server.js.
function expectFrame(status, action, userIndex, userNum, order, balance, present, keyHex) {
  const p = Buffer.alloc(28, 0);
  p[0] = status; p[1] = action; p.writeUInt32LE(userIndex >>> 0, 2); p.writeUInt16LE(userNum, 6);
  p.writeUInt32LE(order >>> 0, 8); p.writeUInt32LE(balance >>> 0, 12); p.writeUInt32LE(present >>> 0, 16);
  Buffer.from(keyHex, "hex").copy(p, 20);
  const f = Buffer.alloc(38, 0);
  f[0] = 0xfb; f.writeUInt16LE(38, 1); f.writeUInt16LE(KIND, 3); f.writeUInt16LE(ROUTE, 5); f.writeUInt16LE(0x53, 7);
  p.copy(f, 9); f[37] = 0xfe;
  return f;
}

// Разбор ответа 0x53.
function parse(resp) {
  const p = resp.subarray(9, resp.length - 1);
  return { len: resp.length, cmd: resp.readUInt16LE(7), status: p[0], action: p[1], userIndex: p.readUInt32LE(2), userNum: p.readUInt16LE(6),
    order: p.readUInt32LE(8), balance: p.readUInt32LE(12), present: p.readUInt32LE(16), key: p.subarray(20, 28).toString("hex").toUpperCase(), raw: resp };
}

// Последняя строка журнала шлюза с меткой GIFT_*.
function lastGiftLog() {
  const dir = path.join(standDir, "logs");
  const all = fs.readdirSync(dir).sort().map((f) => fs.readFileSync(path.join(dir, f), "utf8")).join("\n").split(/\r?\n/);
  return all.filter((l) => / GIFT_(HOLD|COMMIT|REFUND|BAD_ACTION) /.test(l)).pop() || "";
}
// Поле key=value строки журнала.
function field(line, name) { const m = line.match(new RegExp(` ${name}=("[^"]*"|\\S+)`)); return m ? m[1].replace(/"/g, "") : null; }

let sock;                                         // соединение со стендом
let pending = Buffer.alloc(0);                    // недочитанные байты
let waiter = null;                                // ожидающий ответа промис
// Отправить кадр и дождаться одного ответа.
function send(frame) {
  return new Promise((resolve) => { waiter = resolve; sock.write(frame); });
}
// Пауза (журнал шлюза пишется синхронно, но даём сокету отдать данные).
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

const A = { account: "giftA", userIndex: 1001, charIdx: 1, userNum: 11, sender: "AliceGift" };   // отправитель с деньгами
const B = { account: "giftB", userIndex: 1002, charIdx: 0, userNum: 12, sender: "BobGift" };     // мало денег
const C = { account: "giftC", userIndex: 1003, charIdx: 0, userNum: 13, sender: "CarlGift" };    // только в Us_member (автосоздание)
const D = { account: "giftD", userIndex: 1004, charIdx: 2, userNum: 14, sender: "DanGift" };     // тестовый режим, реальный баланс 0
const ARABIC = Buffer.from([0xc7, 0xe1, 0xd3, 0xe1, 0xc7, 0xe3]);   // имя получателя в cp1256 (السلام) — байты должны дойти без перекодировки
let seq = 0;                                      // счётчик ключей
// Новый ключ запроса GS (8 б hex): группа, канал, UserNum, «тик».
// Ключ GS как в DLL P101 (ред. 02.11, ревизия DLL М8): [0] группа, [1] канал ^ (система << 4), [2..3] UserNum, [4..7] время UNIX (с) + seq.
function newKey(who) { ++seq; const b = Buffer.alloc(8); b[0] = 1; b[1] = 0 ^ (4 << 4); b.writeUInt16LE(who.userNum, 2); b.writeUInt32LE((Math.floor(Date.now() / 1000) + seq + ({ test: 0x500000, slow: 0x900000 }[mode] || 0)) >>> 0, 4); return b.toString("hex").toUpperCase(); }

// Один шаг: запрос → ответ → проверки.
async function step(name, who, o, want) {
  console.log(`— ${name}`);
  const rowsBefore = purchaseRows();
  const balBefore = want.balAccount ? bal(want.balAccount) : null;
  const r = parse(await send(giftFrame({ ...who, ...o })));
  await sleep(30);
  const line = lastGiftLog();
  check(r.cmd === 0x53 && r.len === 38, `ответ 0x53, кадр ${r.len} б`);
  check(r.status === want.status, `status ${r.status} (ждали ${want.status})`);
  if (want.source) { check(field(line, "source") === want.source, `журнал: ${field(line, "source")} (ждали ${want.source})`); }
  check(r.action === o.action && r.userIndex === who.userIndex && r.userNum === who.userNum && r.key === o.key,
    `эхо action/UserIndex/UserNum/ключа`);
  if (want.rows !== undefined) { const d = purchaseRows() - rowsBefore; check(d === want.rows, `строк GP7PurchaseLog +${d} (ждали +${want.rows})`); }
  if (want.balDelta !== undefined) { const d = bal(want.balAccount) - balBefore; check(d === want.balDelta, `баланс в базе ${d >= 0 ? "+" : ""}${d} (ждали ${want.balDelta >= 0 ? "+" : ""}${want.balDelta})`); }
  if (want.respBalance !== undefined) { check(r.balance === want.respBalance, `баланс в ответе ${r.balance} (ждали ${want.respBalance})`); }
  if (want.order !== undefined) { check(r.order === want.order, `Orderidx ${r.order} (ждали ${want.order})`); }
  if (want.state) { const g = giftRow(r.order || o.order); check(g && g.state === want.state, `GP7GiftLog.state = ${g ? g.state : "нет строки"} (ждали ${want.state})`); }
  const tag = { 1: "GIFT_HOLD", 2: "GIFT_COMMIT", 3: "GIFT_REFUND" }[o.action] || "GIFT_BAD_ACTION";
  check(line.includes(` ${tag} `), `строка журнала ${tag}`);
  return r;
}

async function runNormal() {
  console.log("== РЕЖИМ normal (testFixedBalance нет)");
  // 1. HOLD ок + кадр побайтно
  const k1 = newKey(A);
  const b0 = bal("giftA");
  const h1 = await step("1 HOLD ок: 62728 (390) + 30 (коробка по карте, 990) = 1380", A,
    { action: 1, recipient: "Recip", codes: [62728, 30], amount: 1380, key: k1 },
    { status: 1, source: "gift-ok", rows: 1, balAccount: "giftA", balDelta: -1380, respBalance: b0 - 1380, state: "H" });
  const exp1 = expectFrame(1, 1, A.userIndex, A.userNum, h1.order, b0 - 1380, 0, k1);
  check(h1.raw.equals(exp1), `кадр ответа побайтно: ${h1.raw.toString("hex").toUpperCase()}`);
  if (!h1.raw.equals(exp1)) { console.log(`      ждали ${exp1.toString("hex").toUpperCase()}`); }
  const g1 = giftRow(h1.order);
  check(g1 && g1.amount === 1380 && g1.test === 0 && g1.key === k1, `GP7GiftLog: сумма 1380, test_mode 0, ключ ${g1 && g1.key}`);
  const pl = q(`SELECT amount, success, item_code FROM dbo.GP7PurchaseLog WHERE id=${h1.order}`)[0];
  check(pl === "1380|1|62728", `GP7PurchaseLog id=Orderidx: ${pl}`);

  // 2. Повтор ключа
  await step("2 повтор того же ключа — прежний Orderidx, без списания", A,
    { action: 1, recipient: "Recip", codes: [62728, 30], amount: 1380, key: k1 },
    { status: 1, source: "gift-repeat", rows: 0, balAccount: "giftA", balDelta: 0, order: h1.order });
  // 3. Тот же ключ, другой подарок
  await step("3 тот же ключ, другой состав — отказ key-conflict", A,
    { action: 1, recipient: "Recip", codes: [62728], amount: 390, key: k1 },
    { status: 0, source: "gift-key-conflict", rows: 0, balAccount: "giftA", balDelta: 0, order: 0 });
  // 4. Мало денег
  const bB = bal("giftB");
  await step("4 мало денег: giftB (100) дарит 62728 (390)", B,
    { action: 1, recipient: "Recip", codes: [62728], amount: 390, key: newKey(B) },
    { status: 2, source: "gift-insufficient", rows: 1, balAccount: "giftB", balDelta: 0, respBalance: bB, order: 0 });
  const plB = q("SELECT TOP (1) amount, success FROM dbo.GP7PurchaseLog ORDER BY id DESC")[0];
  check(plB === "390|0", `строка отказа GP7PurchaseLog success=0: ${plB}`);
  // 5. Неверная цена
  await step("5 сумма не равна ценам витрины (400 вместо 390) — gift-price-mismatch", A,
    { action: 1, recipient: "Recip", codes: [62728], amount: 400, key: newKey(A) },
    { status: 0, source: "gift-price-mismatch", rows: 0, balAccount: "giftA", balDelta: 0, order: 0 });
  await step("5b 298 (Function_Table 100000, без строки карты) по цене клиента 500 — gift-price-mismatch", A,
    { action: 1, recipient: "Recip", codes: [298], amount: 500, key: newKey(A) },
    { status: 0, source: "gift-price-mismatch", rows: 0, balAccount: "giftA", balDelta: 0 });
  // 6. Неизвестный код / не на витрине / нет цены
  await step("6 неизвестный код 99999999 — gift-code-not-on-sale", A,
    { action: 1, recipient: "Recip", codes: [99999999], amount: 100, key: newKey(A) },
    { status: 0, source: "gift-code-not-on-sale", rows: 0, balAccount: "giftA", balDelta: 0 });
  await step("6b 205 (есть в карте, но НЕ в SellItemTable) — gift-code-not-on-sale", A,
    { action: 1, recipient: "Recip", codes: [205], amount: 550, key: newKey(A) },
    { status: 0, source: "gift-code-not-on-sale", rows: 0, balAccount: "giftA", balDelta: 0 });
  await step("6c 99999998 (добавлен в SellItemTable стенда, цены нет) — gift-unknown-item-price", A,
    { action: 1, recipient: "Recip", codes: [99999998], amount: 100, key: newKey(A) },
    { status: 0, source: "gift-unknown-item-price", rows: 0, balAccount: "giftA", balDelta: 0 });
  await step("6d дырка в позициях (62728, 0, 30) — gift-bad-request", A,
    { action: 1, recipient: "Recip", codes: [62728, 0, 30], amount: 1380, key: newKey(A) },
    { status: 0, source: "gift-bad-request", rows: 0, balAccount: "giftA", balDelta: 0 });
  await step("6e получатель = отправитель — gift-self-recipient", A,
    { action: 1, recipient: "aliceGIFT", codes: [62728], amount: 390, key: newKey(A) },
    { status: 0, source: "gift-self-recipient", rows: 0, balAccount: "giftA", balDelta: 0 });
  // 02.11 (ревизия М2): «себе» — как у процедур Joy1 (fn_AsdaNameEq): ASCII без регистра, прочее — байт в байт / маркер 0x98
  const RU_UP = Buffer.from([0xd7, 0xe0, 0xe9]);   // «Чай» в cp1251
  const RU_LO = Buffer.from([0xf7, 0xe0, 0xe9]);   // «чай» в cp1251
  await step("6e2 «себе» кириллицей cp1251 байт в байт — gift-self-recipient", { ...A, sender: RU_UP },
    { action: 1, recipient: RU_UP, codes: [62728], amount: 390, key: newKey(A) },
    { status: 0, source: "gift-self-recipient", rows: 0, balAccount: "giftA", balDelta: 0 });
  await step("6e3 «Чай» → «чай» (cp1251, разные байты) — НЕ «себе», как в Joy1 (не-ASCII сравнивается байт в байт)", { ...A, sender: RU_UP },
    { action: 1, recipient: RU_LO, codes: [62728], amount: 390, key: newKey(A) },
    { status: 1, source: "gift-ok", rows: 1, balAccount: "giftA", balDelta: -390, state: "H" });
  const AR1 = Buffer.from([0x98, 0xd3, 0xc7, 0xe3, 0xed]);         // маркер 0x98 + «سامي» (cp1256)
  const AR2 = Buffer.from([0x98, 0xd3, 0xdc, 0xc7, 0xe3, 0xed]);   // то же с татвилем 0xDC («سـامي»)
  await step("6e4 арабское имя с маркером 0x98 и татвилем — «себе» по Arabic_CI_AS (как fn_AsdaNameEq)", { ...A, sender: AR1 },
    { action: 1, recipient: AR2, codes: [62728], amount: 390, key: newKey(A) },
    { status: 0, source: "gift-self-recipient", rows: 0, balAccount: "giftA", balDelta: 0 });
  await step("6f действие 7 — GIFT_BAD_ACTION", A,
    { action: 7, recipient: "Recip", codes: [62728], amount: 390, key: newKey(A) },
    { status: 0, source: "gift-bad-action", rows: 0, balAccount: "giftA", balDelta: 0 });
  // 7. Commit / повтор / refund после commit
  await step("7 COMMIT заказа шага 1", A,
    { action: 2, recipient: "Recip", codes: [62728, 30], amount: 1380, key: k1, order: h1.order, result: 1 },
    { status: 1, source: "gift-ok", rows: 0, balAccount: "giftA", balDelta: 0, order: h1.order, state: "C" });
  check(giftRow(h1.order).result === "1", "settle_result = 1 (байт 5077)");
  await step("8 повтор COMMIT — repeat, без изменений", A,
    { action: 2, recipient: "Recip", codes: [62728, 30], amount: 1380, key: k1, order: h1.order, result: 1 },
    { status: 1, source: "gift-repeat", rows: 0, balAccount: "giftA", balDelta: 0, state: "C" });
  await step("9 REFUND после COMMIT — отказ wrong-state, денег не вернули", A,
    { action: 3, recipient: "Recip", codes: [62728, 30], amount: 1380, key: k1, order: h1.order, result: 0 },
    { status: 3, source: "gift-wrong-state", rows: 0, balAccount: "giftA", balDelta: 0, state: "C" });
  await step("9b (ревизия В1) повтор HOLD тем же ключом после COMMIT — status 3 wrong-state, прежний Orderidx, без денег", A,
    { action: 1, recipient: "Recip", codes: [62728, 30], amount: 1380, key: k1 },
    { status: 3, source: "gift-wrong-state", rows: 0, balAccount: "giftA", balDelta: 0, order: h1.order, state: "C" });
  // 10. Hold → refund → повтор → commit после refund
  const k2 = newKey(A);
  const h2 = await step("10 HOLD 7 позиций: 63103×2 + 62728×5 = 3530, получатель арабскими байтами", A,
    { action: 1, recipient: ARABIC, codes: [63103, 63103, 62728, 62728, 62728, 62728, 62728], amount: 3530, key: k2 },
    { status: 1, source: "gift-ok", rows: 1, balAccount: "giftA", balDelta: -3530, state: "H" });
  check(giftRow(h2.order).recipientHex === ARABIC.toString("hex").toUpperCase(), `имя получателя в базе байт в байт: ${giftRow(h2.order).recipientHex}`);
  await step("10b REFUND с чужой суммой — order-mismatch", A,
    { action: 3, recipient: ARABIC, codes: [63103], amount: 3529, key: k2, order: h2.order, result: 2 },
    { status: 4, source: "gift-order-mismatch", rows: 0, balAccount: "giftA", balDelta: 0, state: "H" });
  await step("10c REFUND с чужим ключом — order-mismatch", A,
    { action: 3, recipient: ARABIC, codes: [63103], amount: 3530, key: newKey(A), order: h2.order, result: 2 },
    { status: 4, source: "gift-order-mismatch", rows: 0, balAccount: "giftA", balDelta: 0, state: "H" });
  await step("10d REFUND от другой учётки — order-mismatch", B,
    { action: 3, recipient: ARABIC, codes: [63103], amount: 3530, key: k2, order: h2.order, result: 2 },
    { status: 4, source: "gift-order-mismatch", rows: 0, balAccount: "giftA", balDelta: 0, state: "H" });
  await step("10e REFUND несуществующего заказа — order-not-found", A,
    { action: 3, recipient: ARABIC, codes: [63103], amount: 3530, key: k2, order: 987654, result: 2 },
    { status: 4, source: "gift-order-not-found", rows: 0, balAccount: "giftA", balDelta: 0, order: 0 });
  const r11 = await step("11 REFUND (5077 [0]=2, нет места) — деньги назад + строка возврата", A,
    { action: 3, recipient: ARABIC, codes: [63103], amount: 3530, key: k2, order: h2.order, result: 2 },
    { status: 1, source: "gift-ok", rows: 1, balAccount: "giftA", balDelta: 3530, state: "R" });
  const g2 = giftRow(h2.order);
  const back = q(`SELECT amount, success, item_code FROM dbo.GP7PurchaseLog WHERE id=${g2.refund}`)[0];
  check(back === "-3530|1|63103" && g2.result === "2", `строка возврата id=${g2.refund}: ${back}; settle_result=${g2.result}`);
  check(r11.balance === bal("giftA"), `баланс в ответе = баланс в базе (${r11.balance})`);
  await step("12 повтор REFUND — repeat, второй раз не вернули", A,
    { action: 3, recipient: ARABIC, codes: [63103], amount: 3530, key: k2, order: h2.order, result: 2 },
    { status: 1, source: "gift-repeat", rows: 0, balAccount: "giftA", balDelta: 0, state: "R" });
  await step("13 COMMIT после REFUND — wrong-state", A,
    { action: 2, recipient: ARABIC, codes: [63103], amount: 3530, key: k2, order: h2.order, result: 1 },
    { status: 3, source: "gift-wrong-state", rows: 0, balAccount: "giftA", balDelta: 0, state: "R" });
  await step("13b (ревизия В1) повтор HOLD тем же ключом после REFUND — status 3 wrong-state, без денег и без 5076", A,
    { action: 1, recipient: ARABIC, codes: [63103, 63103, 62728, 62728, 62728, 62728, 62728], amount: 3530, key: k2 },
    { status: 3, source: "gift-wrong-state", rows: 0, balAccount: "giftA", balDelta: 0, order: h2.order, state: "R" });
  // 14. Автосоздание учётки сайта (как у покупки) → баланс 0 → мало денег
  await step("14 giftC есть только в Us_member — заведена в dbo.[user], баланс 0 → мало денег", C,
    { action: 1, recipient: "Recip", codes: [62728], amount: 390, key: newKey(C) },
    { status: 2, source: "gift-insufficient", rows: 1 });
  check(q("SELECT COUNT(*) FROM dbo.[user] WHERE username='giftC'")[0] === "1", "строка dbo.[user] giftC создана");
  // 15. Нет учётки нигде
  await step("15 учётки нет ни на сайте, ни в игре — gift-no-account", { ...C, account: "nobody_x" },
    { action: 1, recipient: "Recip", codes: [62728], amount: 390, key: newKey(C) },
    { status: 0, source: "gift-no-account", rows: 0 });
  // 16. Заказ для проверки «реальный hold → возврат в тестовом режиме» (шаг T4)
  const k3 = newKey(A);
  const h3 = await step("16 HOLD 63103 (790) — останется 'H' для прогона test и сверки", A,
    { action: 1, recipient: "Recip", codes: [63103], amount: 790, key: k3 },
    { status: 1, source: "gift-ok", rows: 1, balAccount: "giftA", balDelta: -790, state: "H" });
  fs.writeFileSync(path.join(standDir, "..", "pending_real_hold.json"), JSON.stringify({ order: h3.order, key: k3, amount: 790 }));
  // 17. Гонка: два параллельных HOLD с одним новым ключом прямо в процедуру — одно списание
  const k4 = newKey(A);
  const b4 = bal("giftA");
  const rows4 = purchaseRows();
  const exec = () => new Promise((res) => execFile(SQLCMD, ["-S", sqlServer, "-E", "-d", "AsdaStoryLogin", "-b", "-h", "-1", "-W", "-s", "|", "-Q",
    `SET NOCOUNT ON; EXEC dbo.GP7_GiftHold @username='giftA', @gs_key=0x${k4}, @userindex=1001, @charidx=1, @usernum=11, @sender_name=0x41, ` +
    `@recipient_name=0x52, @code1=62728, @code2=0, @code3=0, @code4=0, @code5=0, @code6=0, @code7=0, @amount=390;`], { encoding: "utf8" },
  (e, out) => res((out || String(e)).trim())));
  const both = await Promise.all([exec(), exec()]);
  const reasons = both.map((s) => s.split("|")[4]).sort().join(",");
  check(reasons === "ok,repeat" && bal("giftA") === b4 - 390 && purchaseRows() - rows4 === 1,
    `17 гонка двух HOLD одного ключа: ${reasons}; списано ${b4 - bal("giftA")}, строк +${purchaseRows() - rows4}`);
  // 18. Ручная сверка: EXEC без учётки/ключа (как печатает gift_reconcile.py --emit-sql)
  const o4 = Number(both[0].split("|")[3]);
  const man = q(`EXEC dbo.GP7_GiftSettle @order_id=${o4}, @action=2;`)[0];
  check(/^1\|\d+\|\d+\|\d+\|ok\|C$/.test(man), `18 ручной COMMIT только по @order_id/@action: ${man}`);
}

async function runTest() {
  console.log("== РЕЖИМ test (testFixedBalance 999999)");
  const k = newKey(D);
  const h = await step("T1 HOLD в тестовом режиме: пополнение + списание, база без изменений", D,
    { action: 1, recipient: "Recip", codes: [62728, 30], amount: 1380, key: k },
    { status: 1, source: "gift-ok", rows: 1, balAccount: "giftD", balDelta: 0, respBalance: 999999, state: "H" });
  check(giftRow(h.order).test === 1, "GP7GiftLog.test_mode = 1");
  await step("T2 повтор ключа — без второго пополнения", D,
    { action: 1, recipient: "Recip", codes: [62728, 30], amount: 1380, key: k },
    { status: 1, source: "gift-repeat", rows: 0, balAccount: "giftD", balDelta: 0, order: h.order, respBalance: 999999 });
  await step("T3 REFUND тестового заказа — меняет ТОЛЬКО state", D,
    { action: 3, recipient: "Recip", codes: [62728, 30], amount: 1380, key: k, order: h.order, result: 0 },
    { status: 1, source: "gift-ok", rows: 0, balAccount: "giftD", balDelta: 0, respBalance: 999999, state: "R" });
  check(giftRow(h.order).refund === "-", "строки возврата нет (refund_log_id NULL)");
  const pend = JSON.parse(fs.readFileSync(path.join(standDir, "..", "pending_real_hold.json"), "utf8"));
  await step("T4 REFUND заказа, замороженного БЕЗ тестового режима — деньги возвращены", A,
    { action: 3, recipient: "Recip", codes: [63103], amount: pend.amount, key: pend.key, order: pend.order, result: 2 },
    { status: 1, source: "gift-ok", rows: 1, balAccount: "giftA", balDelta: pend.amount, respBalance: 999999, state: "R" });
  await step("T5 мало денег в тестовом режиме не бывает: giftB 62728 → ок", B,
    { action: 1, recipient: "Recip", codes: [62728], amount: 390, key: newKey(B) },
    { status: 1, source: "gift-ok", rows: 1, balAccount: "giftB", balDelta: 0, respBalance: 999999, state: "H" });
  // 02.11 (ревизия М4): пополнение тестового режима сверх потолка 4294967295 — явный отказ balance-overflow
  q("UPDATE b SET balance = 4294967000 FROM dbo.GP7Balance b JOIN dbo.[user] u ON u.id=b.user_id WHERE u.username='giftD'");
  await step("T6 (ревизия М4) пополнение сверх потолка баланса — status 0 balance-overflow, без денег", D,
    { action: 1, recipient: "Recip", codes: [62728], amount: 390, key: newKey(D) },
    { status: 0, source: "gift-balance-overflow", rows: 0, balAccount: "giftD", balDelta: 0 });
  q("UPDATE b SET balance = 0 FROM dbo.GP7Balance b JOIN dbo.[user] u ON u.id=b.user_id WHERE u.username='giftD'");
}

// Задать одноразовую задержку обёртки: when = after|before, pattern — подстрока запроса.
function arm(when, ms, pattern) { fs.writeFileSync(SLOW_FLAG, `${when} ${ms} ${pattern}`); }

async function runSlow() {
  console.log("== РЕЖИМ slow (ревизия В2: тайм-аут sqlcmd 4 с, обёртка slow_sqlcmd.exe)");
  // S1: тайм-аут ПОСЛЕ коммита HOLD — шлюз перечитывает заказ по ключу и отвечает фактом
  const k = newKey(A);
  arm("after", 9000, "GP7_GiftHold");
  const s1 = await step("S1 HOLD: sqlcmd убит по тайм-ауту ПОСЛЕ коммита — status 1 recovered (деньги заморожены)", A,
    { action: 1, recipient: "Recip", codes: [62728], amount: 390, key: k },
    { status: 1, source: "gift-recovered", rows: 1, balAccount: "giftA", balDelta: -390, state: "H" });
  check(!fs.existsSync(SLOW_FLAG), "задержка сработала (флаг израсходован)");
  check(/SQL_GIFT_ERROR op=hold/.test(fs.readdirSync(path.join(standDir, "logs")).map((f) => fs.readFileSync(path.join(standDir, "logs", f), "utf8")).join("")),
    "в журнале шлюза SQL_GIFT_ERROR op=hold (тайм-аут)");
  await step("S2 повтор HOLD тем же ключом — repeat, второго списания нет", A,
    { action: 1, recipient: "Recip", codes: [62728], amount: 390, key: k },
    { status: 1, source: "gift-repeat", rows: 0, balAccount: "giftA", balDelta: 0, order: s1.order, state: "H" });
  // S3: тайм-аут ДО выполнения — заказа нет → status 5 «неизвестно, повтори тем же ключом»
  const k3 = newKey(A);
  arm("before", 9000, "GP7_GiftHold");
  await step("S3 HOLD: sqlcmd убит ДО выполнения — status 5 unknown, денег нет", A,
    { action: 1, recipient: "Recip", codes: [63103], amount: 790, key: k3 },
    { status: 5, source: "gift-unknown", rows: 0, balAccount: "giftA", balDelta: 0, order: 0 });
  const s4 = await step("S4 DLL повторяет HOLD тем же ключом — status 1 ok, одно списание", A,
    { action: 1, recipient: "Recip", codes: [63103], amount: 790, key: k3 },
    { status: 1, source: "gift-ok", rows: 1, balAccount: "giftA", balDelta: -790, state: "H" });
  // S5: тайм-аут ПОСЛЕ коммита REFUND — recovered, деньги вернулись один раз
  arm("after", 9000, "GP7_GiftSettle");
  await step("S5 REFUND: sqlcmd убит ПОСЛЕ коммита — status 1 recovered, +790 один раз", A,
    { action: 3, recipient: "Recip", codes: [63103], amount: 790, key: k3, order: s4.order, result: 2 },
    { status: 1, source: "gift-recovered", rows: 1, balAccount: "giftA", balDelta: 790, state: "R" });
  await step("S6 повтор REFUND — repeat, второй раз не вернули", A,
    { action: 3, recipient: "Recip", codes: [63103], amount: 790, key: k3, order: s4.order, result: 2 },
    { status: 1, source: "gift-repeat", rows: 0, balAccount: "giftA", balDelta: 0, state: "R" });
  // S7: тайм-аут ДО COMMIT — заказ ещё 'H' → status 5; повтор → ok
  arm("before", 9000, "GP7_GiftSettle");
  await step("S7 COMMIT: sqlcmd убит ДО выполнения — status 5 unknown, заказ остаётся H", A,
    { action: 2, recipient: "Recip", codes: [62728], amount: 390, key: k, order: s1.order, result: 1 },
    { status: 5, source: "gift-unknown", rows: 0, balAccount: "giftA", balDelta: 0, state: "H" });
  await step("S8 повтор COMMIT — ok, C", A,
    { action: 2, recipient: "Recip", codes: [62728], amount: 390, key: k, order: s1.order, result: 1 },
    { status: 1, source: "gift-ok", rows: 0, balAccount: "giftA", balDelta: 0, state: "C" });
}

const child = spawn(process.execPath, [path.join(standDir, "server.js")], { cwd: standDir, stdio: ["ignore", "pipe", "pipe"] });
child.stderr.on("data", (d) => process.stderr.write(d));
let started = false;                              // стенд поднялся
child.stdout.on("data", (d) => {
  if (started || !/listening/.test(String(d))) { return; }
  started = true;
  sock = net.connect(port, "127.0.0.1");
  sock.on("error", (err) => { if (waiter) { check(false, `сокет: ${err.message}`); } });   // сброс при остановке стенда — не провал
  sock.on("close", () => { child.kill(); });
  sock.on("data", (d2) => {
    pending = Buffer.concat([pending, d2]);
    while (pending.length >= 3 && pending.length >= pending.readUInt16LE(1)) {
      const len = pending.readUInt16LE(1);
      const resp = Buffer.from(pending.subarray(0, len));
      pending = pending.subarray(len);
      const w = waiter; waiter = null; if (w) { w(resp); }
    }
  });
  sock.on("connect", async () => {
    try {
      if (mode === "test") { await runTest(); } else if (mode === "slow") { await runSlow(); } else { await runNormal(); }
    } catch (err) {
      check(false, `исключение: ${err.stack || err}`);
    }
    console.log(`ИТОГ gift_cases ${mode} ok=${ok} bad=${bad}`);
    process.exitCode = bad ? 1 : 0;
    sock.end();
  });
});
child.on("exit", (code) => { if (!started) { console.log(`стенд не поднялся, код ${code}`); process.exitCode = 1; } });
