// Copyright (c) 2026 @sitxovski (Discord)
// Стенд шлюза gp7 для премиум-коробок «предмет ×N» (26.10.2026; генератор AstoryClient/Tools/asda_premium_box_add.py,
//   рецепт Docs/Port/systems/PREMIUM_ITEM_ADD_FLOW.md). Поднимает server.js стенда (item_table из srv_out, фальшивый
//   sqlcmd) и шлёт синтетические запросы 0x50 поверх настоящего исторического кадра (tpl_75702.hex):
//     S  одиночная покупка каждой коробки по цене спецификации — status 1, код ответа @67 = коробка, списание = цене;
//     X  та же коробка с ценой +1 (клиент/сервер разошлись) — отказ cart-total-mismatch без списания;
//     C  корзина из всех коробок (CRT8, таблица 1, принято N, BuyCash = сумма) — status 1, одна транзакция, позиции в
//        ItemPostBoxCart = коды коробок, списание = сумме.
// argv: <stand gp7-server dir> <template hex> <port> <fake sql log> <premium_box_sets.json>
"use strict";
const fs = require("fs");
const path = require("path");
const net = require("net");
const { spawn } = require("child_process");

const standDir = process.argv[2];
const tplHex = fs.readFileSync(process.argv[3], "utf8").trim();
const port = Number(process.argv[4]);
const sqlLog = process.argv[5];
const boxes = JSON.parse(fs.readFileSync(process.argv[6], "utf8")).boxes;

// Кадр запроса 0x50: коды позиций, цена (BuyCash), расширение корзины CRT8 (P85 r2).
function frameWith(codes, price, v8) {
  const f = Buffer.from(tplHex, "hex");
  const p = f.subarray(9, f.length - 1);   // payload 173
  p.writeUInt32LE(codes[0] || 0, 66);
  p.writeUInt32LE(price, 104);
  p.fill(0, 128, 161);
  if (v8) {
    p.write("CRT8", 128, "latin1");
    for (let i = 0; i < 7; ++i) { p.writeInt32LE(i < codes.length ? codes[i] : 0, 132 + 4 * i); }
    p[160] = codes.length;
    p[161] = v8.table;
    p[162] = v8.accepted;
  }
  return f;
}

// ★ 02.11.2026: коробку под прежней позицией витрины (b.catalog — функциональный код, напр. 558 «Зелье повышения
//   уровня») клиент покупает по коду позиции, шлюз отвечает кодом коробки по карте (Reports/levelup_potion).
const req = (b) => b.catalog || b.code;
const cases = [];
for (const b of boxes) {
  cases.push({ name: `S ${req(b)}→${b.code} «${b.name_ru}» по одной за ${b.price}`, codes: [req(b)], price: b.price,
    want: { status: 1, item: b.code, sql: true, bill: b.price } });
  cases.push({ name: `X ${req(b)}→${b.code} с чужой ценой ${b.price + 1}`, codes: [req(b)], price: b.price + 1,
    // позиция из карты сверяется с ценой карты раньше суммы корзины (server.js: premium-price-mismatch)
    want: { status: 0, source: b.catalog ? "premium-price-mismatch" : "cart-total-mismatch", sql: false } });
}
const cart = boxes.filter((b) => !b.catalog).slice(0, 7);   // корзина таблицы 1 (item_list) — без функциональных позиций
const sum = cart.reduce((a, b) => a + b.price, 0);
cases.push({ name: `C корзина ${cart.map(req).join("+")} = ${sum}`, codes: cart.map(req), price: sum,
  v8: { table: 1, accepted: cart.length },
  want: { status: 1, item: cart[0].code, sql: true, bill: sum, cart: cart.map((b) => b.code).join(",") } });

const child = spawn(process.execPath, [path.join(standDir, "server.js")], {
  cwd: standDir, stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, FAKE_SQL_LOG: sqlLog } });
child.stderr.on("data", (d) => process.stderr.write(d));
let ok = 0, bad = 0;
function check(c, msg) { console.log(`  [${c ? "OK" : "!!"}] ${msg}`); if (c) { ++ok; } else { ++bad; } }
function field(line, name) { const m = line && line.match(new RegExp(` ${name}=("[^"]*"|\\S+)`)); return m ? m[1].replace(/"/g, "") : null; }

function run() {
  const sock = net.connect(port, "127.0.0.1");
  let idx = 0, pending = Buffer.alloc(0);
  const sqlBefore = [];
  const next = () => {
    if (idx >= cases.length) { sock.end(); return; }
    sqlBefore[idx] = fs.existsSync(sqlLog) ? fs.readFileSync(sqlLog, "utf8").split("\n").filter(Boolean).length : 0;
    const c = cases[idx];
    sock.write(frameWith(c.codes, c.price, c.v8));
  };
  sock.on("data", (d) => {
    pending = Buffer.concat([pending, d]);
    while (pending.length >= 3 && pending.length >= pending.readUInt16LE(1)) {
      const len = pending.readUInt16LE(1);
      const resp = pending.subarray(0, len);
      pending = pending.subarray(len);
      const c = cases[idx];
      const status = resp[9];
      const item = resp.readUInt32LE(9 + 67);
      setTimeout(() => {
        const logs = fs.readdirSync(path.join(standDir, "logs")).map((f) => fs.readFileSync(path.join(standDir, "logs", f), "utf8")).join("\n");
        const sends = logs.split(/\r?\n/).filter((l) => / command=0x0051 /.test(l));
        const line = sends[sends.length - 1];
        const sqls = fs.existsSync(sqlLog) ? fs.readFileSync(sqlLog, "utf8").split("\n").filter(Boolean) : [];
        const newSql = sqls.slice(sqlBefore[idx]).filter((q) => /GP7_Purchase/.test(q));
        check(status === c.want.status, `${c.name}: status ${status} (ждали ${c.want.status})`);
        if (c.want.source) { check(field(line, "source") === c.want.source, `${c.name}: source=${field(line, "source")}`); }
        if (c.want.status === 1) { check(item === c.want.item, `${c.name}: код ответа @67 = ${item}`); }
        check((newSql.length === 1) === c.want.sql, `${c.name}: списание ${newSql.length ? "было" : "не было"} (${c.want.sql ? "ждали" : "не ждали"})`);
        if (newSql.length === 1) {
          const q = newSql[0];
          check(q.includes(`@amount=${c.want.bill}`), `${c.name}: сумма списания ${c.want.bill}`);
          if (c.want.cart) {
            const rows = (q.match(/\(\(\(@pid - 1\) % 2147483647\) \+ 1, \d+, \d+, \d+\)/g) || []).map((r) => r.split(",")[2].trim());
            check(/INSERT Joy1\.dbo\.ItemPostBoxCart/.test(q) && rows.join(",") === c.want.cart,
              `${c.name}: позиции ItemPostBoxCart ${rows.join(",")}`);
          }
        }
        ++idx; next();
      }, 150);
    }
  });
  sock.on("end", () => { console.log(`ИТОГ premium_box_cases ok=${ok} bad=${bad}`); child.kill(); process.exitCode = bad ? 1 : 0; });
  sock.on("connect", next);
}
let started = false;
child.stdout.on("data", (d) => { if (!started && /listening/.test(String(d))) { started = true; run(); } });
