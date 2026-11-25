<div align="center">

[English](README.md) · [Русский](README.ru.md) · **العربية**

### ❤️ هل أعجبك المشروع؟ ادعم هذا العمل الشاق على [**Boosty**](https://boosty.to/sitxovski_yurii)

# Astory Server

**التصحيحات والخدمات التي تشغّل خادم لعبة Astory**

[Astory Client](https://github.com/sitxovski/AstoryClient) · [Astory Server](https://github.com/sitxovski/AstoryServer) · [Astory Admin Center](https://github.com/sitxovski/AstoryAdminCenter)

</div>

---

<div dir="rtl">

> ⚠️ تنبيه. هذه الحزمة وحدها (وليس المشروع بأكمله) أُعدّت باستخدام Claude Code، وقد تحتوي على بعض الأخطاء. أما المشروع نفسه فقد طُوِّر يدويًا بالكامل. للحصول على المساعدة، راسلني على Discord ‏(@sitxovski).

## محتويات المستودع

| المجلد | الوصف |
|---|---|
| `Patches` | تصحيحات DLL لبرامج الخادم: إصلاحات، وميزات جديدة، ومكافحة الغش، وجسر للوحة الإدارة |
| `EacServer` | خادم Easy Anti-Cheat |
| `LogDrop` | مستقبِل سجلّات الأعطال والتشخيص الواردة من العميل |
| `Patches\Gp7Gateway` | بوابة المتجر والرصيد (Node.js) |
| `Tools` | تقارير مكافحة الغش ومؤشراتها |
| `Docs` | شرح عمل كل تصحيح — ابدأ من [`Docs/INDEX.md`](Docs/INDEX.md) |
| `Prerequisites` | ما يجب تثبيته، وكيفية البناء والتشغيل |

> 📦 **ملفات خادم اللعبة وقواعد بياناته النظيفة تُنزَّل بشكل منفصل** — [*AstoryServer Files* و*AstoryServer Database* ‏(Google Drive)](https://drive.google.com/drive/folders/1GWlBoy64nsW05HBMXS-slBLDQinwxh4h?usp=sharing). التثبيت، وSQL Server، وربط العميل بالخادم، والمنافذ التي يجب فتحها في الموجّه: [Prerequisites/README.md](Prerequisites/README.md).

## البدء السريع

1. **التثبيت** — شغّل `Prerequisites\install_prerequisites.bat` على حاسوبك، و`... -Server` على الخادم ([التفاصيل](Prerequisites/README.md)).
2. **الإعداد** — شغّل `_setup\configure.bat` (عنوان الخادم، والمجلدات، ومفتاح SSH — [من أين تحصل عليها](_setup/SETUP.md)).
   شغّله في النسخ الثلاث كلها؛ تُحفظ إجاباتك، فلا تسألك النسخ الأخرى إلا عن الجديد.
3. **الخادم** — فك ضغط *AstoryServer Files* و*AstoryServer Database* على الخادم، ثم شغّل
   `Prerequisites\setup_server.ps1 -Firewall`: ينسخ ملفات الخادم، ويستعيد قواعد البيانات، وينشئ حسابات SQL ومصادر ODBC والمفاتيح، ويثبّت خدمات EAC وCaddy وLogDrop؛
   ثم انسخ الملف `keys\server_public.h` الذي يطبعه إلى Astory Client وأعد بناء العميل ([خطوة بخطوة](Prerequisites/README.md#2-set-up-the-server--step-by-step)).
4. **البناء** — `Patches\<الاسم>\build.bat` و`EacServer\build.bat` و`LogDrop\build.bat`.
5. **النشر** — سكربت `deploy_*.py` الموجود بجوار كل جزء (يعمل افتراضيًا في وضع التجربة دون تغيير أي شيء).

يتصل اللاعبون عبر [Astory Client](https://github.com/sitxovski/AstoryClient).
ويمكنك إدارة الخادم من المتصفح باستخدام [Astory Admin Center](https://github.com/sitxovski/AstoryAdminCenter).

## المؤلف

صاحب المشروع: **@sitxovski** ‏(Discord).

يمكنك استخدامه بحرية لأي غرض ودون أي قيود — [رخصة MIT](LICENSE). **فقط اذكر المؤلف الأصلي — @sitxovski ‏(Discord) —
وضع رابطًا لهذا المستودع عند نسخ أي جزء منه أو تفريعه (fork) أو إعادة استخدامه.**

</div>

---

<div align="center">

### ❤️ ادعم هذا العمل الشاق على [**Boosty**](https://boosty.to/sitxovski_yurii)

</div>
