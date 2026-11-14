# -*- coding: utf-8 -*-
"""
فاحص التسريبات - Breach Checker
================================
برنامج بواجهة رسومية (Tkinter) للتحقق مما إذا كان بريد إلكتروني أو اسم مستخدم
قد ظهر في تسريبات بيانات معروفة، وعرض أسماء المواقع المسرَّبة وتواريخها.

المصادر المستخدمة (واجهات برمجية عامة):
  1. LeakCheck (public)     : إيميل + يوزرنيم  - مجاني بدون مفتاح
  2. XposedOrNot            : إيميل فقط        - مجاني بدون مفتاح
  3. Have I Been Pwned (v3) : إيميل فقط        - يحتاج مفتاح API (اختياري)

تشغيل:  python breach_checker.py

يعمل على الكمبيوتر وعلى الهاتف (Pydroid 3).
لا يحتاج أي مكتبات خارجية.

ملاحظة: استخدم البرنامج لفحص حساباتك أنت أو حسابات لديك إذن بفحصها.
"""

import csv
import json
import os
import re
import sys
import threading
import tkinter as tk
import urllib.error
import urllib.parse
import urllib.request
from tkinter import filedialog, messagebox, ttk
from tkinter import font as tkfont

USER_AGENT = "BreachChecker-Desktop/1.0"
TIMEOUT = 20
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# --------------------------------------------------------------------------- #
#                               طبقة الشبكة                                   #
# --------------------------------------------------------------------------- #
class ApiError(Exception):
    pass


def http_get_json(url, headers=None):
    """طلب GET يرجع (status_code, json_or_None)."""
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read().decode("utf-8", "replace")
            return resp.status, (json.loads(body) if body.strip() else None)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        try:
            data = json.loads(body) if body.strip() else None
        except ValueError:
            data = None
        return e.code, data
    except urllib.error.URLError as e:
        raise ApiError(f"تعذر الاتصال: {e.reason}") from e
    except ValueError as e:
        raise ApiError("رد غير صالح من الخادم") from e


# كل دالة فحص ترجع قائمة نتائج: dict(source, site, date, data)
def check_leakcheck(query, kind):
    url = "https://leakcheck.io/api/public?check=" + urllib.parse.quote(query)
    status, data = http_get_json(url)
    if status == 429:
        raise ApiError("تجاوزت حد الطلبات، انتظر قليلاً")
    if not isinstance(data, dict):
        raise ApiError(f"رد غير متوقع (HTTP {status})")
    if not data.get("success"):
        msg = str(data.get("error") or data.get("message") or "")
        if "not found" in msg.lower():
            return []
        raise ApiError(msg or f"HTTP {status}")
    # ملاحظة: LeakCheck يعطي قائمة حقول واحدة لكل التسريبات مجتمعة
    # (وليس لكل موقع على حدة)، لذلك نحفظها منفصلة.
    fields = list(data.get("fields") or [])
    results = []
    for src in data.get("sources") or []:
        if isinstance(src, dict):
            name, date = src.get("name", "?"), src.get("date", "")
        else:
            name, date = str(src), ""
        results.append({"source": "LeakCheck", "site": name,
                        "date": date or "غير معروف", "data": "",
                        "account_fields": fields})
    return results


def check_xposedornot(query, kind):
    if kind != "email":
        return None  # لا يدعم اليوزرنيم
    url = ("https://api.xposedornot.com/v1/check-email/"
           + urllib.parse.quote(query))
    status, data = http_get_json(url)
    if status == 404:
        return []
    if status == 429:
        raise ApiError("تجاوزت حد الطلبات، انتظر قليلاً")
    if status != 200 or not isinstance(data, dict):
        raise ApiError(f"HTTP {status}")
    breaches = data.get("breaches") or []
    # الشكل المعتاد: [["Adobe", "LinkedIn", ...]]
    names = []
    for item in breaches:
        if isinstance(item, list):
            names.extend(item)
        else:
            names.append(item)
    return [{"source": "XposedOrNot", "site": str(n),
             "date": "-", "data": "-"} for n in names if n]


def check_hibp(query, kind, api_key):
    if kind != "email" or not api_key:
        return None
    url = ("https://haveibeenpwned.com/api/v3/breachedaccount/"
           + urllib.parse.quote(query) + "?truncateResponse=false")
    status, data = http_get_json(url, {"hibp-api-key": api_key})
    if status == 404:
        return []
    if status == 401:
        raise ApiError("مفتاح API غير صالح")
    if status == 429:
        raise ApiError("تجاوزت حد الطلبات، انتظر قليلاً")
    if status != 200 or not isinstance(data, list):
        raise ApiError(f"HTTP {status}")
    return [{"source": "HIBP",
             "site": f"{b.get('Title', b.get('Name'))} ({b.get('Domain') or '-'})",
             "date": b.get("BreachDate", "-"),
             "data": ", ".join(b.get("DataClasses", []))} for b in data]


# --------------------------------------------------------------------------- #
#                  عرض العربي بشكل صحيح (خصوصاً على أندرويد)                  #
# --------------------------------------------------------------------------- #
# Tkinter (حتى على Pydroid 3) يعرض العربي بشكل صحيح بنفسه، لذلك المعالجة
# معطلة افتراضياً. إذا ظهر العربي مقلوباً على جهاز معين شغّلها بـ:
#     BREACH_FIX_ARABIC=1   مع   pip install arabic-reshaper
IS_ANDROID = ("ANDROID_ROOT" in os.environ or "ANDROID_DATA" in os.environ
              or hasattr(sys, "getandroidapilevel"))
# يمكن فرض التشغيل/الإيقاف يدوياً: BREACH_FIX_ARABIC=1 أو 0
_force = os.environ.get("BREACH_FIX_ARABIC")
FIX_ARABIC = _force == "1"

_MIRROR = str.maketrans("()[]{}<>", ")(][}{><")
_LTR_RUN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9@._\-/:+%,' ]*[A-Za-z0-9)\]])?")


def _simple_bidi(line):
    """ترتيب بصري مبسّط لسطر عربي (بديل python-bidi):
    يعكس ترتيب المقاطع، ويعكس حروف المقاطع العربية، ويترك الإنجليزي والأرقام كما هي."""
    runs, pos = [], 0
    for m in _LTR_RUN.finditer(line):
        if m.start() > pos:
            runs.append((False, line[pos:m.start()]))
        runs.append((True, m.group()))
        pos = m.end()
    if pos < len(line):
        runs.append((False, line[pos:]))
    out = []
    for is_ltr, txt in reversed(runs):
        out.append(txt if is_ltr else txt[::-1].translate(_MIRROR))
    return "".join(out)


_reshape = None
_get_display = _simple_bidi
if FIX_ARABIC:
    try:
        import arabic_reshaper
        _reshape = arabic_reshaper.reshape
    except ImportError:
        _reshape = None
    try:  # اختياري: إن وُجدت python-bidi نستخدمها، وإلا البديل المبسّط
        try:
            from bidi import get_display as _get_display
        except ImportError:
            from bidi.algorithm import get_display as _get_display
    except ImportError:
        _get_display = _simple_bidi

ARABIC_LIBS_MISSING = FIX_ARABIC and _reshape is None
_AR_RE = re.compile(r"[\u0600-\u06FF]")


def t(text):
    """يجهّز النص العربي للعرض (سطراً سطراً)."""
    text = str(text)
    if not FIX_ARABIC or _reshape is None or not _AR_RE.search(text):
        return text
    return "\n".join(_get_display(_reshape(line)) for line in text.split("\n"))


FIELD_NAMES_AR = {
    # LeakCheck
    "username": "اسم المستخدم", "email": "الإيميل", "password": "كلمة المرور",
    "first_name": "الاسم الأول", "last_name": "اسم العائلة", "name": "الاسم",
    "profile_name": "اسم الملف الشخصي", "dob": "تاريخ الميلاد",
    "phone": "رقم الهاتف", "address": "العنوان", "zip": "الرمز البريدي",
    "city": "المدينة", "country": "الدولة", "state": "المنطقة",
    "gender": "الجنس", "ip": "عنوان IP", "id": "رقم الحساب (ID)",
    "origin": "رابط صفحة تسجيل الدخول", "url": "الرابط",
    "hash": "كلمة مرور مشفّرة", "company": "الشركة", "website": "الموقع الشخصي",
    "line": "سطر بيانات كامل",
    # HIBP
    "email addresses": "الإيميل", "passwords": "كلمة المرور",
    "usernames": "اسم المستخدم", "names": "الاسم",
    "phone numbers": "رقم الهاتف", "ip addresses": "عنوان IP",
    "dates of birth": "تاريخ الميلاد", "genders": "الجنس",
    "physical addresses": "العنوان", "geographic locations": "الموقع الجغرافي",
    "employers": "جهة العمل", "job titles": "المسمى الوظيفي",
    "social media profiles": "حسابات التواصل الاجتماعي",
    "password hints": "تلميح كلمة المرور",
    "security questions and answers": "أسئلة الأمان وإجاباتها",
    "credit cards": "بطاقات ائتمان", "partial credit card data": "جزء من بيانات البطاقة",
    "device information": "معلومات الجهاز", "browser user agent details": "معلومات المتصفح",
    "website activity": "نشاط الموقع", "auth tokens": "رموز تسجيل الدخول",
}


def field_ar(name):
    """يترجم اسم الحقل للعربي، مع إبقاء الاسم الأصلي بين قوسين."""
    name = str(name).strip()
    ar = FIELD_NAMES_AR.get(name.lower())
    return f"{ar} ({name})" if ar else name


def split_fields(data):
    if isinstance(data, (list, tuple)):
        return [str(x) for x in data if str(x).strip()]
    return [x.strip() for x in str(data).split(",") if x.strip()]


def site_key(name):
    """مفتاح لدمج نفس الموقع من مصادر مختلفة (CoinMarketCap.com = Coinmarketcap)."""
    n = re.sub(r"\(.*?\)", "", name.lower())
    n = re.sub(r"\.(com|net|org|io|co)$", "", n.strip())
    return re.sub(r"[^a-z0-9؀-ۿ]", "", n) or name.lower()


def merge_results(results):
    merged = {}
    for r in results:
        k = site_key(r["site"])
        m = merged.setdefault(k, {"site": r["site"], "date": "", "sources": [],
                                  "data": ""})
        if r["source"] not in m["sources"]:
            m["sources"].append(r["source"])
        if r["date"] not in ("", "-", "غير معروف") and not m["date"]:
            m["date"] = r["date"]
        if r["data"] not in ("", "-") and len(r["data"]) > len(m["data"]):
            m["data"] = r["data"]
        if len(r["site"]) > len(m["site"]):
            m["site"] = r["site"]
    out = list(merged.values())
    out.sort(key=lambda m: m["date"] or "0000", reverse=True)
    return out


# --------------------------------------------------------------------------- #
#                               الواجهة الرسومية                              #
# --------------------------------------------------------------------------- #
class BreachCheckerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(t("فاحص التسريبات") if not IS_ANDROID else "Breach Checker")
        if not IS_ANDROID:
            self.geometry("560x680")
            self.minsize(420, 500)
        self.results = []
        self._build_ui()
        if ARABIC_LIBS_MISSING:
            self.after(300, lambda: messagebox.showwarning(
                "Arabic",
                "To display Arabic correctly install:\n"
                "pip install arabic-reshaper\n\n"
                + t("لعرض العربي بشكل صحيح ثبّت المكتبة أعلاه")))

    def _build_ui(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        base = tkfont.nametofont("TkDefaultFont")
        size = base.cget("size")
        style.configure("Title.TLabel",
                        font=(base.cget("family"), size + 2, "bold"))

        pad = 8
        # العنوان
        ttk.Label(self, text=t("فحص تسريبات الإيميل واليوزرنيم"),
                  style="Title.TLabel", anchor="e").pack(fill="x", padx=pad,
                                                         pady=(pad, 4))

        # --- الإدخال: كل عنصر في سطر مستقل ليناسب شاشة الهاتف ---
        form = ttk.Frame(self, padding=(pad, 0))
        form.pack(fill="x")

        self.query_var = tk.StringVar()
        self.kind_var = tk.StringVar(value="auto")
        self.key_var = tk.StringVar()

        ttk.Label(form, text=t("الإيميل أو اليوزرنيم:"), anchor="e").pack(fill="x")
        entry = ttk.Entry(form, textvariable=self.query_var)
        entry.pack(fill="x", pady=(2, 6))
        entry.bind("<Return>", lambda e: self.start_check())

        kinds = ttk.Frame(form)
        kinds.pack(fill="x")
        for text, val in (("تلقائي", "auto"), ("إيميل", "email"),
                          ("يوزرنيم", "username")):
            ttk.Radiobutton(kinds, text=t(text), value=val,
                            variable=self.kind_var).pack(side="right", padx=4)

        ttk.Label(form, text=t("مفتاح HIBP (اختياري):"), anchor="e").pack(
            fill="x", pady=(6, 0))
        ttk.Entry(form, textvariable=self.key_var, show="*").pack(fill="x",
                                                                  pady=(2, 6))

        btns = ttk.Frame(form)
        btns.pack(fill="x")
        self.check_btn = ttk.Button(btns, text=t("فحص"), command=self.start_check)
        self.check_btn.pack(side="right", fill="x", expand=True)
        ttk.Button(btns, text=t("مسح"), command=self.clear).pack(
            side="right", fill="x", expand=True, padx=4)
        self.export_btn = ttk.Button(btns, text=t("تصدير CSV"),
                                     command=self.export_csv, state="disabled")
        self.export_btn.pack(side="right", fill="x", expand=True)

        self.progress = ttk.Progressbar(self, mode="indeterminate")
        self.progress.pack(fill="x", padx=pad, pady=(6, 0))
        self.status_var = tk.StringVar(value=t("جاهز"))
        ttk.Label(self, textvariable=self.status_var, anchor="e",
                  wraplength=300).pack(fill="x", padx=pad, pady=4)
        self.status_label = self.winfo_children()[-1]
        self.bind("<Configure>", self._on_resize)

        # --- النتائج: بطاقات نصية تناسب الشاشات الضيقة ---
        res = ttk.Frame(self, padding=(pad, 0, pad, pad))
        res.pack(fill="both", expand=True)
        self.text = tk.Text(res, wrap="word", state="disabled", relief="flat",
                            padx=6, pady=6, background="white")
        vsb = ttk.Scrollbar(res, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=vsb.set)
        vsb.pack(side="left", fill="y")
        self.text.pack(side="left", fill="both", expand=True)
        self.text.tag_configure("right", justify="right")
        self.text.tag_configure("site", justify="right",
                                font=(base.cget("family"), size + 1, "bold"),
                                foreground="#b00020", spacing1=8)
        self.text.tag_configure("data", justify="right", foreground="#444444")
        self.text.tag_configure("ok", justify="right", foreground="#1b7f3a",
                                font=(base.cget("family"), size + 1, "bold"))

    def _on_resize(self, event):
        if event.widget is self:
            self.status_label.configure(wraplength=max(event.width - 20, 100))

    def _write(self, lines):
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        for line, tag in lines:
            self.text.insert("end", line + "\n", tag)
        self.text.configure(state="disabled")
        self.text.yview_moveto(0)

    # ----------------------------------------------------------------- #
    def clear(self):
        self._write([])
        self.results = []
        self.export_btn.config(state="disabled")
        self.status_var.set(t("جاهز"))

    def start_check(self):
        query = self.query_var.get().strip()
        if not query:
            messagebox.showwarning(t("تنبيه"), t("اكتب إيميل أو يوزرنيم أولاً"))
            return
        kind = self.kind_var.get()
        if kind == "auto":
            kind = "email" if EMAIL_RE.match(query) else "username"
        elif kind == "email" and not EMAIL_RE.match(query):
            messagebox.showwarning(t("تنبيه"), t("صيغة الإيميل غير صحيحة"))
            return

        self.clear()
        self.check_btn.config(state="disabled")
        self.progress.start(12)
        self.status_var.set(t("جاري الفحص..."))
        threading.Thread(target=self._worker,
                         args=(query, kind, self.key_var.get().strip()),
                         daemon=True).start()

    def _worker(self, query, kind, api_key):
        checks = [
            ("LeakCheck", lambda: check_leakcheck(query, kind)),
            ("XposedOrNot", lambda: check_xposedornot(query, kind)),
            ("HIBP", lambda: check_hibp(query, kind, api_key)),
        ]
        results, errors, used = [], [], 0
        for name, fn in checks:
            try:
                r = fn()
                if r is None:  # المصدر لا يدعم هذا النوع أو لا يوجد مفتاح
                    continue
                used += 1
                results.extend(r)
            except Exception as e:  # noqa: BLE001
                errors.append(f"{name}: {e}")
        account_fields = []
        for r in results:
            for f in r.get("account_fields", []):
                if f not in account_fields:
                    account_fields.append(f)
        self.after(0, self._done, kind, merge_results(results), errors, used,
                   account_fields)

    def _done(self, kind, merged, errors, used, account_fields=()):
        self.progress.stop()
        self.check_btn.config(state="normal")
        self.results = merged
        kind_ar = "الإيميل" if kind == "email" else "اليوزرنيم"

        lines = []
        if account_fields:
            lines.append((t("البيانات التي تسربت عنك:"), "site"))
            lines += [(t("• " + field_ar(f)), "right") for f in account_fields]
            lines.append(("", "right"))
        if merged:
            lines.append((t("المواقع التي تسربت منها:"), "site"))
        for i, m in enumerate(merged, 1):
            lines.append((f"{i}. {m['site']}", "site"))
            lines.append((t("التاريخ: " + (m["date"] or "غير معروف")), "right"))
            lines.append((t("المصدر:"), "right"))
            lines += [(src, "right") for src in m["sources"]]
            if m["data"]:
                lines.append((t("البيانات المسربة:"), "right"))
                lines += [(t("• " + field_ar(f)), "data")
                          for f in split_fields(m["data"])]

        if merged:
            self.export_btn.config(state="normal")
            self.status_var.set(t(f"تحذير: {kind_ar} ظهر في {len(merged)} تسريب "
                                  f"(من {used} مصدر)"))
            lines += [("", "right"),
                      (t("نصائح:"), "site"),
                      (t("- غيّر كلمة المرور في هذه المواقع"), "right"),
                      (t("- لا تستخدم نفس كلمة المرور في أكثر من موقع"), "right"),
                      (t("- فعّل المصادقة الثنائية (2FA)"), "right"),
                      (t("- استخدم مدير كلمات مرور"), "right")]
        elif used:
            self.status_var.set(t(f"لم يتم العثور على {kind_ar} في أي تسريب "
                                  f"(من {used} مصدر)"))
            lines.append((t("لا توجد تسريبات معروفة"), "ok"))
        else:
            self.status_var.set(t("فشل الفحص"))

        if errors:
            lines += [("", "right"), (t("مصادر فشلت:"), "site")]
            lines += [(e, "data") for e in errors]
        self._write(lines)

    def export_csv(self):
        if not self.results:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV", "*.csv")],
            initialfile="breach_results.csv")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(["site", "date", "sources", "data"])
            for m in self.results:
                w.writerow([m["site"], m["date"], " | ".join(m["sources"]),
                            m["data"]])
        messagebox.showinfo(t("تم"), t("تم الحفظ في:") + "\n" + path)


if __name__ == "__main__":
    BreachCheckerApp().mainloop()
