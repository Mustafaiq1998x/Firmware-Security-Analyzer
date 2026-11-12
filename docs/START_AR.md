# ابدأ باستخدام Firmware Security Analyzer

افتح البرنامج لتفحص صورة فيرموير على جهازك. للتعرّف على شكل النتائج قبل التثبيت، افتح [تقرير العينة](SAMPLE_REPORT.md). وللاطلاع على تجربة ملفات أجهزة فعلية، راجع [نتائج OpenWrt](FIRMWARE_VALIDATION.md).

## على كالي أو لينكس

```sh
git clone https://github.com/Mustafaiq1998x/Firmware-Security-Analyzer.git
cd Firmware-Security-Analyzer
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/fsa-gui
```

على Windows، اتبع عمود PowerShell في [جدول التثبيت](../README.md#run-your-first-inspection).

1. افتح **Open firmware…** واختر ملف BIN أو DAV أو أرشيفاً. على كالي قد تحتاج إلى تثبيت `python3-tk`.
2. راجع الجهاز والنظام وأدلة التشفير في **Overview**. يعرض **Components** نوع الضغط وإزاحات الأجزاء.
3. راجع **Files** ثم اختر **Save extracted files…** لحفظ الملفات أو أجزاء الصورة المدعومة.
4. اختر **CVE feed…** قبل الفحص إذا كانت لديك قاعدة تنبيهات محلية. يمكنك حفظ النتائج بصيغة HTML أو JSON.
5. لواجهة المتصفح بالعربية ثبّت `.[web]` ثم شغّل `fsa-web`.

بصمة SHA-256 في التقرير تخص الفيرموير الذي اخترته. بصمة حزمة **البرنامج** وتقرير VirusTotal الخاص بها يُنشران في ملاحظات إصدار GitHub عند اكتمال فحص الحزمة.
