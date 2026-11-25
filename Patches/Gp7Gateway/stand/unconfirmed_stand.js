// Copyright (c) 2026 @sitxovski (Discord)
// ★ 22.11.2026 Стенд шлюза gp7 «оплачено, но не выдано» (Reports/admin_center/research_gp7_orphan_orders_20261121.md).
//   Что проверяет (свои копии ../server.js в %TEMP%\gp7unconf_stand\<режим>, фальшивый sqlcmd ../stand/fake_sqlcmd.exe —
//   GP7_Purchase всегда status 1, номер 424242; живой сервер и живые БД не трогаются):
//     O1 строка журнала SEND 0x0051 несёт order=<номер заказа> (= смещение 174 ответа), у отказа order=0;
//     U1 GameServer закрыл сокет сразу после ответа status 1 → PURCHASE_UNCONFIRMED order=424242 reason=close;
//     U2 обрыв RST сразу после ответа → PURCHASE_UNCONFIRMED reason=socket-error:ECONNRESET (или close — что раньше дошло);
//     U3 сокет закрыт позже окна purchaseUnconfirmedMs → отметки нет;
//     U4 отказ без списания (status 0) и сразу закрытие → отметки нет;
//     U5 purchaseUnconfirmedMs = 0 → отметки нет (прежнее поведение);
//     L1 лаки-бокс с наградой, которой нет ни в item_table, ни в Function_Table → status 0 unknown-reward-code, GP7_Purchase
//        НЕ вызывался (журнал фальшивого sqlcmd), байт статуса ответа 0;
//     L2 награда — функциональный код из Function_Table (< 20551) → status 1, списание (как сейчас на живой, box type 0);
//     L3 награда — код item_table (>= 20551, не больше конца таблицы) → status 1;
//     L4 награда — код > конца item_table → status 0 unknown-reward-code;
//     L5 config.rejectUnknownRewardCode = false → награда L1 проходит (прежнее поведение);
//     L6 (ревизия 53 М-1) config.rejectUndeliverable = false (ключ подтипа 1) проверку награды не снимает;
//     LV (если передан каталог живых таблиц) — КАЖДАЯ из строк живой PrimiumGaChaTable проходит проверку (0 отказов):
//        таблица режется по 255 строк, каждая строка — свой тип ящика, по запросу на тип.
//   argv: [порт] [каталог живых таблиц: PrimiumGaChaTable.txt, Function_Table.txt, item_table.txt]
//   Итог: «GP7-UNCONF ИТОГ: ok=N fail=M», код возврата 0/1.
"use strict";
const fs = require("fs");
const os = require("os");
const path = require("path");
const net = require("net");
const { spawn } = require("child_process");

const basePort = Number(process.argv[2] || 25071);          // первый порт стенда (каждый экземпляр — свой)
const liveDir = process.argv[3] || "";                       // снимок живых таблиц (только чтение), пусто — без LV
const work = path.join(os.tmpdir(), "gp7unconf_stand");     // рабочий каталог стенда
const tpl = Buffer.from(fs.readFileSync(path.join(__dirname, "tpl_75702.hex"), "utf8").trim(), "hex");   // настоящий кадр 0x50
const fakeSql = path.join(__dirname, "fake_sqlcmd.exe");    // фальшивый sqlcmd (status 1, id 424242)
let ok = 0;                                                  // пройдено
let fail = 0;                                                // провалено
let nextPort = basePort;                                     // следующий свободный порт стенда

function expect(cond, what, detail) {
  if (cond) { ++ok; console.log(`GP7-UNCONF ok   ${what}`); } else { ++fail; console.log(`GP7-UNCONF FAIL ${what}${detail ? " :: " + detail : ""}`); }
}

// Запрос покупки 0x50 по шаблону: подтип 1 (предмет, код @66, цена @104) или 2 (лаки-бокс, тип @71).
function buyFrame(subtype, opts) {
  const f = Buffer.from(tpl);
  const p = f.subarray(9, f.length - 1);
  p[0] = subtype;
  if (subtype === 2) {
    p[71] = opts.boxType;
    p.writeUInt32LE(opts.price || 690, 104);
  } else {
    p.writeUInt32LE(opts.code, 66);
    p.writeUInt32LE(opts.price, 104);
  }
  p.fill(0, 128, 161);    // без расширения корзины
  return f;
}

// Таблицы стенда: item_table (только шапка — число строк 100 → коды 20551…20650), Function_Table (коды 30, 476 — 21 колонка).
function writeTables(dir, luckyRows, live) {
  const tab = path.join(dir, "..", "GameServer", "ItemTable_Info");
  fs.mkdirSync(tab, { recursive: true });
  if (live) {
    for (const n of ["Function_Table.txt", "item_table.txt"]) fs.copyFileSync(path.join(live, n), path.join(tab, n));
  } else {
    fs.writeFileSync(path.join(tab, "item_table.txt"), "100\r\n");
    const row = (code, price) => [code].concat(Array(19).fill(0)).concat([price]).join("\t");
    fs.writeFileSync(path.join(tab, "Function_Table.txt"), [row(30, 500), row(476, 690)].join("\r\n") + "\r\n");
  }
  fs.writeFileSync(path.join(tab, "PrimiumGaChaTable.txt"), [String(luckyRows.length)].concat(luckyRows.map((r) => r.join("\t"))).join("\r\n") + "\r\n");
}

// Поднять экземпляр шлюза с данным конфигом и таблицей лаки-бокса → { proc, port, dir, sqlLog }.
async function startGateway(name, extra, luckyRows, live) {
  const root = path.join(work, name);
  const dir = path.join(root, "gp7-server");
  fs.rmSync(root, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  fs.copyFileSync(path.join(__dirname, "..", "server.js"), path.join(dir, "server.js"));
  writeTables(dir, luckyRows, live);
  const port = nextPort++;
  const cfg = Object.assign({
    host: "127.0.0.1", port, logBytes: 32, mode: "echo", balanceSource: "json", balancesFile: "balances.json",
    defaultPremiumBalance: 0, defaultPremiumPresent: 0, quietHeartbeat: true, heartbeatHex: "FB0A0000005D001400FE",
    sql: { command: fakeSql, server: "none", database: "none", timeoutMs: 3000 },
  }, extra);
  fs.writeFileSync(path.join(dir, "config.json"), JSON.stringify(cfg, null, 2));
  const sqlLog = path.join(root, "sql.log");
  const proc = spawn(process.execPath, [path.join(dir, "server.js")], { cwd: dir, env: Object.assign({}, process.env, { FAKE_SQL_LOG: sqlLog }), stdio: "ignore" });
  for (let i = 0; i < 50; ++i) {
    await new Promise((r) => setTimeout(r, 100));
    if (await new Promise((r) => { const s = net.connect(port, "127.0.0.1", () => { s.destroy(); r(true); }); s.on("error", () => r(false)); })) break;
  }
  return { proc, port, dir, sqlLog };
}

function logText(g) {
  const d = path.join(g.dir, "logs");
  return fs.existsSync(d) ? fs.readdirSync(d).map((n) => fs.readFileSync(path.join(d, n), "utf8")).join("") : "";
}

function sqlText(g) {
  return fs.existsSync(g.sqlLog) ? fs.readFileSync(g.sqlLog, "utf8") : "";
}

// Один запрос → ответ; after: "keep" (закрыть через closeMs), "close" (закрыть сразу), "reset" (RST сразу). → { status, order, cmd }.
function ask(port, frame, after, closeMs) {
  return new Promise((resolve) => {
    const s = net.connect(port, "127.0.0.1", () => s.write(frame));
    let buf = Buffer.alloc(0);
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    s.on("data", (d) => {
      buf = Buffer.concat([buf, d]);
      if (buf.length >= 3 && buf.length >= buf.readUInt16LE(1)) {
        const p = buf.subarray(9, buf.readUInt16LE(1) - 1);
        const v = { cmd: buf.readUInt16LE(7), status: p[0], order: p.length >= 178 ? p.readUInt32LE(174) : -1, code: p.length >= 71 ? p.readUInt32LE(67) : -1 };
        if (after === "reset" && typeof s.resetAndDestroy === "function") { s.resetAndDestroy(); finish(v); }
        else if (after === "close") { s.destroy(); finish(v); }
        else { setTimeout(() => { s.destroy(); finish(v); }, closeMs || 0); }
      }
    });
    s.on("error", () => finish({ cmd: -1, status: -1, order: -1, code: -1 }));
    setTimeout(() => { s.destroy(); finish({ cmd: -2, status: -2, order: -2, code: -2 }); }, 5000);
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const count = (text, rx) => (text.match(rx) || []).length;

async function main() {
  fs.rmSync(work, { recursive: true, force: true });
  // типы ящиков стенда: 7 — неизвестный код 15000 (нет ни там, ни там), 8 — 476 (Function_Table), 9 — 20600 (item_table),
  //   10 — 30000 (> конца item_table 20650)
  const lucky = [[1, 7, 15000, 1], [2, 8, 476, 1], [3, 9, 20600, 1], [4, 10, 30000, 1]];
  const g = await startGateway("on", { purchaseUnconfirmedMs: 400 }, lucky);
  try {
    const okBuy = buyFrame(1, { code: 20600, price: 30000 });
    const r1 = await ask(g.port, okBuy, "close");
    await sleep(300);
    let log = logText(g);
    expect(r1.status === 1 && r1.order === 424242, "O1 ответ status 1, номер заказа 424242 в смещении 174", JSON.stringify(r1));
    expect(/SEND \S+ bytes=188 command=0x0051 account="Player17" source=sql status=1 order=424242 /.test(log), "O1 строка SEND 0x0051 несёт order=424242");
    expect(count(log, /PURCHASE_UNCONFIRMED \S+ order=424242 account="Player17" subtype=1 itemCode=20600 price=30000 afterMs=\d+ reason=close/g) === 1,
      "U1 закрыт сразу после ответа — одна строка PURCHASE_UNCONFIRMED order=424242 reason=close", log.split("\n").filter((x) => /UNCONF|CLOSE|SOCKET/.test(x)).join(" | "));
    const before2 = count(log, /PURCHASE_UNCONFIRMED/g);
    const r2 = await ask(g.port, okBuy, "reset");
    await sleep(300);
    log = logText(g);
    expect(r2.status === 1 && count(log, /PURCHASE_UNCONFIRMED/g) === before2 + 1 && /PURCHASE_UNCONFIRMED .*reason=(socket-error:ECONNRESET|close)\n[^]*$/.test(log),
      "U2 обрыв RST после ответа — одна строка PURCHASE_UNCONFIRMED (socket-error:ECONNRESET или close)");
    const before3 = count(log, /PURCHASE_UNCONFIRMED/g);
    const r3 = await ask(g.port, okBuy, "keep", 900);
    await sleep(300);
    log = logText(g);
    expect(r3.status === 1 && count(log, /PURCHASE_UNCONFIRMED/g) === before3, "U3 сокет закрыт позже окна 400 мс — отметки нет");
    const sqlBefore = count(sqlText(g), /GP7_Purchase/g);
    const r4 = await ask(g.port, buyFrame(2, { boxType: 7 }), "close");
    await sleep(300);
    log = logText(g);
    expect(r4.status === 0 && r4.order === 0 && count(sqlText(g), /GP7_Purchase/g) === sqlBefore, "L1 награда 15000 (нет ни в item_table, ни в Function_Table) — status 0, номер 0, GP7_Purchase не вызывался",
      JSON.stringify(r4));
    expect(/SEND \S+ bytes=188 command=0x0051 account="Player17" source=unknown-reward-code status=0 order=0 subtype=2 /.test(log), "L1 строка журнала: source=unknown-reward-code status=0 order=0");
    expect(count(log, /PURCHASE_UNCONFIRMED/g) === before3, "U4 отказ без списания и сразу закрытие — отметки нет");
    const r5 = await ask(g.port, buyFrame(2, { boxType: 8 }), "keep", 0);
    const r6 = await ask(g.port, buyFrame(2, { boxType: 9 }), "keep", 0);
    const r7 = await ask(g.port, buyFrame(2, { boxType: 10 }), "keep", 0);
    await sleep(200);
    expect(r5.status === 1 && r5.code === 476 && r5.order === 424242, "L2 награда 476 из Function_Table (< 20551) — status 1, код 476 (как живой box type 0)", JSON.stringify(r5));
    expect(r6.status === 1 && r6.code === 20600, "L3 награда 20600 из item_table — status 1", JSON.stringify(r6));
    expect(r7.status === 0 && r7.order === 0, "L4 награда 30000 > конца item_table (20650) — status 0", JSON.stringify(r7));
    expect(count(sqlText(g), /GP7_Purchase/g) === sqlBefore + 2, "L1–L4 GP7_Purchase вызван ровно 2 раза (L2, L3)", String(count(sqlText(g), /GP7_Purchase/g) - sqlBefore));
    const hb = await ask(g.port, Buffer.from("FB0A0000005D001400FE", "hex"), "keep", 0);
    expect(hb.cmd === 0x15, "пинг 0x14 → 0x15 (ответ на пинг не задет)", JSON.stringify(hb));
  } finally {
    g.proc.kill();
  }
  const off = await startGateway("off", { purchaseUnconfirmedMs: 0, rejectUnknownRewardCode: false }, lucky);
  try {
    const r = await ask(off.port, buyFrame(1, { code: 20600, price: 30000 }), "close");
    const rl = await ask(off.port, buyFrame(2, { boxType: 7 }), "close");
    await sleep(300);
    const log = logText(off);
    expect(r.status === 1 && count(log, /PURCHASE_UNCONFIRMED/g) === 0, "U5 purchaseUnconfirmedMs = 0 — отметки нет (прежнее поведение)");
    expect(rl.status === 1 && rl.code === 15000, "L5 rejectUnknownRewardCode = false — награда 15000 проходит без проверки (прежнее поведение)", JSON.stringify(rl));
  } finally {
    off.proc.kill();
  }
  // ★ ревизия 53 М-1: выключение ключа подтипа 1 (rejectUndeliverable) проверку награды НЕ снимает
  const sub = await startGateway("subkey", { rejectUndeliverable: false }, lucky);
  try {
    const r10 = await ask(sub.port, buyFrame(2, { boxType: 10 }), "keep", 0);
    const r7 = await ask(sub.port, buyFrame(2, { boxType: 7 }), "keep", 0);
    expect(r10.status === 0 && r7.status === 0, "L6 rejectUndeliverable = false — награды 30000 (за концом item_table) и 15000 по-прежнему отклоняются",
      JSON.stringify([r10, r7]));
  } finally {
    sub.proc.kill();
  }
  const dflt = await startGateway("default", {}, lucky);
  try {
    const r = await ask(dflt.port, buyFrame(1, { code: 20600, price: 30000 }), "close");
    await sleep(300);
    expect(r.status === 1 && /PURCHASE_UNCONFIRMED .*order=424242 .*reason=close/.test(logText(dflt)), "U6 без ключа в config.json — окно по умолчанию 2000 мс, отметка есть");
  } finally {
    dflt.proc.kill();
  }
  if (liveDir) {
    const lines = fs.readFileSync(path.join(liveDir, "PrimiumGaChaTable.txt"), "utf8").replace(/^﻿/, "").split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
    const rows = lines.slice(1).map((x) => x.split(/\s+/).map(Number)).filter((f) => f.length >= 4 && f[2] > 0 && f[3] > 0);
    let refused = [];
    let asked = 0;
    for (let i = 0; i < rows.length; i += 255) {
      const part = rows.slice(i, i + 255).map((f, k) => [f[0], k + 1, f[2], f[3]]);
      const gl = await startGateway("live" + i, { purchaseUnconfirmedMs: 0 }, part, liveDir);
      try {
        for (const r of part) {
          const a = await ask(gl.port, buyFrame(2, { boxType: r[1] }), "keep", 0);
          ++asked;
          if (a.status !== 1 || a.code !== r[2]) refused.push(`${r[0]}:${r[2]}:${a.status}`);
        }
      } finally {
        gl.proc.kill();
      }
    }
    expect(asked === rows.length && refused.length === 0, `LV все ${rows.length} наград живой PrimiumGaChaTable проходят проверку (отказов 0)`, refused.slice(0, 10).join(","));
  }
  console.log(`GP7-UNCONF ИТОГ: ok=${ok} fail=${fail}`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => { console.log(`GP7-UNCONF FAIL исключение ${e.stack}`); process.exit(1); });
