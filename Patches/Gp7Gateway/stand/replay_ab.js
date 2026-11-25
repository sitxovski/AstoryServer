// Copyright (c) 2026 @sitxovski (Discord)
// ★ 22.11.2026 (ревизия 53 М-2) Стенд шлюза gp7: СТАРЫЙ и НОВЫЙ server.js на ОДНИХ входах — все исторические запросы 0x0050
//   из журналов gp7 (как replay.js), одним потоком в каждый экземпляр. Экземпляры — свои каталоги с одинаковыми таблицами, картой
//   и config.json (фальшивый sqlcmd stand/fake_sqlcmd.exe → путь списания проходит), случайность награды лаки-бокса — одним зерном
//   (stand/seeded_random.js, node -r). Сравнивается каждый ответ ПОБАЙТНО и решение (source, status) из строки SEND 0x0051.
//   Живой сервер и живые БД не трогаются.
// argv: <каталог старого gp7-server> <каталог нового gp7-server> <каталог журналов> <порт старого> <порт нового>
//   (порты должны совпадать с config.json каталогов). Итог: «REPLAY-AB ИТОГ: …», код 0 — всё совпало.
"use strict";
const fs = require("fs");
const path = require("path");
const net = require("net");
const { spawn } = require("child_process");

const [oldDir, newDir, logsDir] = process.argv.slice(2, 5);           // каталоги экземпляров и журналов
const ports = [Number(process.argv[5]), Number(process.argv[6])];     // порты экземпляров
const seedFile = path.join(__dirname, "seeded_random.js");            // детерминированный crypto.randomInt

// 1) Кадры запросов 0x0050 из журналов (полный hex-дамп строки RECV).
const cases = [];
for (const f of fs.readdirSync(logsDir).filter((n) => /^gp7-\d+\.log$/.test(n)).sort()) {
  const lines = fs.readFileSync(path.join(logsDir, f), "utf8").split(/\r?\n/);
  for (let i = 0; i < lines.length; ++i) {
    if (!/ RECV .* command=0x0050$/.test(lines[i])) continue;
    const bytes = [];
    let j = i + 1;
    while (j < lines.length && /^[0-9a-f]{4}  /.test(lines[j])) {
      for (const h of lines[j].slice(6, 6 + 47).trim().split(/\s+/)) if (h) bytes.push(parseInt(h, 16));
      ++j;
    }
    const buf = Buffer.from(bytes);
    if (buf.length >= 3 && buf.length === buf.readUInt16LE(1)) cases.push(buf);
  }
}
console.log(`cases=${cases.length} subtype2=${cases.filter((b) => b[9] === 2).length}`);

// 2) Поднять экземпляр и прогнать все кадры по порядку → массив ответов.
function runOne(dir, port) {
  return new Promise((resolve) => {
    fs.rmSync(path.join(dir, "logs"), { recursive: true, force: true });
    const child = spawn(process.execPath, ["-r", seedFile, path.join(dir, "server.js")], {
      cwd: dir, stdio: ["ignore", "pipe", "pipe"], env: Object.assign({}, process.env, { FAKE_SQL_LOG: path.join(dir, "..", "sql_ab.log") }) });
    let started = false;
    child.stderr.on("data", (d) => process.stderr.write(d));
    child.stdout.on("data", (d) => {
      if (started || !/listening/.test(String(d))) return;
      started = true;
      const sock = net.connect(port, "127.0.0.1");
      let pending = Buffer.alloc(0);
      const out = [];
      sock.on("data", (d2) => {
        pending = Buffer.concat([pending, d2]);
        while (pending.length >= 3 && pending.length >= pending.readUInt16LE(1)) {
          const n = pending.readUInt16LE(1);
          out.push(Buffer.from(pending.subarray(0, n)));
          pending = pending.subarray(n);
          if (out.length < cases.length) sock.write(cases[out.length]); else sock.end();
        }
      });
      sock.on("end", () => { setTimeout(() => { child.kill(); resolve(out); }, 300); });
      sock.on("connect", () => sock.write(cases[0]));
    });
  });
}

function decisions(dir) {
  const d = path.join(dir, "logs");
  const out = [];
  for (const f of fs.readdirSync(d).sort()) {
    for (const l of fs.readFileSync(path.join(d, f), "utf8").split(/\r?\n/)) {
      const m = l.match(/command=0x0051 .*? source=(\S+) status=(\d+)/);
      if (m) out.push(`${m[1]}/${m[2]}`);
    }
  }
  return out;
}

(async () => {
  const a = await runOne(oldDir, ports[0]);
  const b = await runOne(newDir, ports[1]);
  const da = decisions(oldDir), db = decisions(newDir);
  let sameBytes = 0, sameDecision = 0;
  const diff = [];
  const tally = {};
  for (let i = 0; i < cases.length; ++i) {
    if (a[i] && b[i] && a[i].equals(b[i])) ++sameBytes; else if (diff.length < 10) diff.push(`#${i} bytes`);
    if (da[i] === db[i]) ++sameDecision; else if (diff.length < 10) diff.push(`#${i} ${da[i]} -> ${db[i]}`);
    const k = `${cases[i][9] === 2 ? "лаки-бокс" : "предмет"} ${db[i]}`;
    tally[k] = (tally[k] || 0) + 1;
  }
  console.log("TALLY", JSON.stringify(tally));
  console.log(`REPLAY-AB ИТОГ: cases=${cases.length} ответы побайтно ${sameBytes}/${cases.length} решения ${sameDecision}/${cases.length} ` +
    `ответов old=${a.length} new=${b.length}${diff.length ? " РАЗЛИЧИЯ " + diff.join("; ") : ""}`);
  process.exit(sameBytes === cases.length && sameDecision === cases.length && a.length === cases.length && b.length === cases.length ? 0 : 1);
})();
