# 🚀 RexFuzz - Powerful Web Fuzzer with GUI

RexFuzz هي أداة Fuzzing احترافية لاكتشاف المسارات المخفية والصفحات الحساسة في مواقع الويب، تأتي بواجهة رسومية جميلة وسهلة الاستخدام. تعتمد على مكتبة `rich` لعرض النتائج الملونة، وتركز على إظهار الصفحات الحقيقية فقط، مع تجاهل استجابات 404 المزعجة.

---

## ✅ الميزات

- واجهة رسومية احترافية وسهلة الاستخدام.
- دعم روابط بصيغ مختلفة مثل:  
  `/FUZZ`, `/admin/FUZZ/config`, `/wp-content/FUZZ/backup`, إلخ.
- عرض النتائج الناجحة فقط بألوان جذابة عبر rich.
- تجاهل الاستجابات الفارغة أو 404 تلقائيًا.
- دعم Fuzz لمسارات الإدارات ولوحات التحكم والملفات الحساسة مثل:
  - `.env`, `wp-config.php`, `dashboard`, `config.json`, إلخ.
- دعم متعدد الخيوط لسرعة فائقة.

---

## 📦 التثبيت (Install)

```bash
git clone https://github.com/SHARSHABIL-PS/FuzzerGUI.git
cd FuzzerGUI

pip install -r requirements.txt
```

**أو تثبيت المكاتب يدويًا:**

```bash
pip install requests rich tkinter
```

---

## ⚙️ الاستخدام (Usage)

```bash
python RexFuzzerGUI.py
```

- أدخل عنوان URL يحتوي على الكلمة FUZZ مثل:
  ```
  https://example.com/FUZZ
  ```
- اختر ملف wordlist مناسب (مثل: SecLists).
- ستُعرض النتائج الناجحة فقط، مع تجاهل الأخطاء.
- كل نتيجة ملونة حسب حالة الاستجابة.

---

## 🛠 المتطلبات (Requirements)

- Python 3.8+
- المكتبات:
  - `requests`
  - `rich`
  - `tkinter`

---

## 💡 ملاحظات

- FUZZ يجب أن تكون موجودة في الرابط لكي تبدأ الأداة بالعمل.
- الأداة تتجنب استجابات 404 بشكل تلقائي.
- يمكن استخدامها للعثور على:
  - لوحات الإدارة مثل `/admin`, `/dashboard`
  - ملفات التكوين مثل `.env`, `config.php`
  - صفحات الدخول والنسخ الاحتياطية.

---

## 👨‍💻 صممت بواسطة
**SHARSHABIL-PS & REX** – لمجتمع Bug Bounty العربي
```
