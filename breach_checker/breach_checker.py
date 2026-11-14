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
# Tkinter على أندرويد (Pydroid 3) يرسم النص من اليسار لليمين دائماً، فتظهر
# الكلمات العربية مقلوبة ("مسح" تظهر "حسم"). الحل المدمج هنا بدون أي مكتبات:
#   1) تحويل الحروف لأشكالها المتصلة (أول/وسط/آخر الكلمة) - Arabic shaping
#   2) عكس ترتيب النص للعرض من اليمين لليسار مع إبقاء الإنجليزي والأرقام كما هي
# على ويندوز/لينكس سطح المكتب النظام يعرض العربي صحيحاً فلا نحتاج ذلك.
# للفرض يدوياً: BREACH_FIX_ARABIC=1 (تشغيل) أو 0 (إيقاف)
IS_ANDROID = ("ANDROID_ROOT" in os.environ or "ANDROID_DATA" in os.environ
              or hasattr(sys, "getandroidapilevel"))
_force = os.environ.get("BREACH_FIX_ARABIC")
FIX_ARABIC = IS_ANDROID if _force is None else _force == "1"

# الأشكال: (منفصل، آخر، أول، وسط) - الحروف التي لا تتصل بما بعدها لها شكلان فقط
_FORMS = {
    "ء": (0xFE80,), "آ": (0xFE81, 0xFE82), "أ": (0xFE83, 0xFE84),
    "ؤ": (0xFE85, 0xFE86), "إ": (0xFE87, 0xFE88), "ئ": (0xFE89, 0xFE8A, 0xFE8B, 0xFE8C),
    "ا": (0xFE8D, 0xFE8E), "ب": (0xFE8F, 0xFE90, 0xFE91, 0xFE92),
    "ة": (0xFE93, 0xFE94), "ت": (0xFE95, 0xFE96, 0xFE97, 0xFE98),
    "ث": (0xFE99, 0xFE9A, 0xFE9B, 0xFE9C), "ج": (0xFE9D, 0xFE9E, 0xFE9F, 0xFEA0),
    "ح": (0xFEA1, 0xFEA2, 0xFEA3, 0xFEA4), "خ": (0xFEA5, 0xFEA6, 0xFEA7, 0xFEA8),
    "د": (0xFEA9, 0xFEAA), "ذ": (0xFEAB, 0xFEAC), "ر": (0xFEAD, 0xFEAE),
    "ز": (0xFEAF, 0xFEB0), "س": (0xFEB1, 0xFEB2, 0xFEB3, 0xFEB4),
    "ش": (0xFEB5, 0xFEB6, 0xFEB7, 0xFEB8), "ص": (0xFEB9, 0xFEBA, 0xFEBB, 0xFEBC),
    "ض": (0xFEBD, 0xFEBE, 0xFEBF, 0xFEC0), "ط": (0xFEC1, 0xFEC2, 0xFEC3, 0xFEC4),
    "ظ": (0xFEC5, 0xFEC6, 0xFEC7, 0xFEC8), "ع": (0xFEC9, 0xFECA, 0xFECB, 0xFECC),
    "غ": (0xFECD, 0xFECE, 0xFECF, 0xFED0), "ف": (0xFED1, 0xFED2, 0xFED3, 0xFED4),
    "ق": (0xFED5, 0xFED6, 0xFED7, 0xFED8), "ك": (0xFED9, 0xFEDA, 0xFEDB, 0xFEDC),
    "ل": (0xFEDD, 0xFEDE, 0xFEDF, 0xFEE0), "م": (0xFEE1, 0xFEE2, 0xFEE3, 0xFEE4),
    "ن": (0xFEE5, 0xFEE6, 0xFEE7, 0xFEE8), "ه": (0xFEE9, 0xFEEA, 0xFEEB, 0xFEEC),
    "و": (0xFEED, 0xFEEE), "ى": (0xFEEF, 0xFEF0), "ي": (0xFEF1, 0xFEF2, 0xFEF3, 0xFEF4),
    "ـ": (0x0640, 0x0640, 0x0640, 0x0640),
}
_LAM_ALEF = {"آ": (0xFEF5, 0xFEF6), "أ": (0xFEF7, 0xFEF8),
             "إ": (0xFEF9, 0xFEFA), "ا": (0xFEFB, 0xFEFC)}
_HARAKAT = re.compile("[\u064B-\u0652\u0670]")


def _joins_next(ch):
    f = _FORMS.get(ch)
    return f is not None and len(f) == 4


def _builtin_reshape(text):
    """يحوّل الحروف العربية لأشكالها المتصلة (بديل مكتبة arabic-reshaper)."""
    text = _HARAKAT.sub("", text)
    out, i, n = [], 0, len(text)
    prev_joins = False
    while i < n:
        ch = text[i]
        if ch == "ل" and i + 1 < n and text[i + 1] in _LAM_ALEF:
            iso, fin = _LAM_ALEF[text[i + 1]]
            out.append(chr(fin if prev_joins else iso))
            prev_joins = False
            i += 2
            continue
        forms = _FORMS.get(ch)
        if not forms:
            out.append(ch)
            prev_joins = False
            i += 1
            continue
        nxt = text[i + 1] if i + 1 < n else ""
        next_joins = len(forms) == 4 and nxt in _FORMS
        if len(forms) == 1:
            out.append(chr(forms[0]))
        elif prev_joins and next_joins:
            out.append(chr(forms[3]))
        elif prev_joins:
            out.append(chr(forms[1]))
        elif next_joins:
            out.append(chr(forms[2]))
        else:
            out.append(chr(forms[0]))
        prev_joins = _joins_next(ch)
        i += 1
    return "".join(out)


_MIRROR = str.maketrans("()[]{}<>", ")(][}{><")
_LTR_RUN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9@._\-/:+%,' ]*[A-Za-z0-9])?")


def _simple_bidi(line):
    """ترتيب بصري لسطر عربي: يعكس ترتيب المقاطع وحروف المقاطع العربية،
    ويترك الإنجليزي والأرقام كما هي."""
    runs, pos = [], 0
    for m in _LTR_RUN.finditer(line):
        if m.start() > pos:
            runs.append((False, line[pos:m.start()]))
        runs.append((True, m.group()))
        pos = m.end()
    if pos < len(line):
        runs.append((False, line[pos:]))
    return "".join(txt if ltr else txt[::-1].translate(_MIRROR)
                   for ltr, txt in reversed(runs))


_AR_RE = re.compile("[\u0600-\u06FF]")


def t(text):
    """يجهّز النص العربي للعرض (سطراً سطراً)."""
    text = str(text)
    if not FIX_ARABIC or not _AR_RE.search(text):
        return text
    return "\n".join(_simple_bidi(_builtin_reshape(line))
                     for line in text.split("\n"))


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
SETTINGS_FILE = os.path.join(os.path.expanduser("~"), ".breach_checker.json")


def load_settings():
    try:
        with open(SETTINGS_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_settings(data):
    try:
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except OSError:
        pass


class BreachCheckerApp(tk.Tk):
    MIN_FONT, MAX_FONT = 8, 40

    def __init__(self):
        super().__init__()
        self.title(t("فاحص التسريبات") if not IS_ANDROID else "Breach Checker")
        if not IS_ANDROID:
            self.geometry("600x760")
            self.minsize(420, 500)
        self.results = []
        self.settings = load_settings()
        self._setup_fonts()
        self._build_ui()

    # ------------------------------ الخطوط ------------------------------ #
    def _setup_fonts(self):
        base = tkfont.nametofont("TkDefaultFont")
        self.family = base.cget("family")
        default_size = abs(int(base.cget("size"))) or 10
        # خط أكبر من الافتراضي (أوضح على الهاتف)
        self.font_size = int(self.settings.get("font_size",
                                               round(default_size * 1.4)))
        self.f_body = tkfont.Font(family=self.family)
        self.f_bold = tkfont.Font(family=self.family, weight="bold")
        self.f_title = tkfont.Font(family=self.family, weight="bold")
        self._apply_font_size()

    def _apply_font_size(self):
        s = self.font_size
        self.f_body.configure(size=s)
        self.f_bold.configure(size=s + 2)
        self.f_title.configure(size=s + 3)
        # تكبير خطوط كل عناصر الواجهة (الأزرار، الحقول، العناوين)
        for name in ("TkDefaultFont", "TkTextFont", "TkFixedFont",
                     "TkMenuFont", "TkHeadingFont", "TkCaptionFont"):
            try:
                tkfont.nametofont(name).configure(size=s)
            except tk.TclError:
                pass

    def change_font(self, delta):
        self.font_size = max(self.MIN_FONT,
                             min(self.MAX_FONT, self.font_size + delta))
        self._apply_font_size()
        self.settings["font_size"] = self.font_size
        save_settings(self.settings)

    # ------------------------------ الواجهة ----------------------------- #
    def _build_ui(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Title.TLabel", font=self.f_title)
        pad = 8

        # العنوان + أزرار حجم الخط
        head = ttk.Frame(self, padding=(pad, pad, pad, 4))
        head.pack(fill="x")
        ttk.Label(head, text=t("فحص التسريبات"), style="Title.TLabel",
                  anchor="e").pack(side="right", fill="x", expand=True)
        ttk.Button(head, text="A+", width=3,
                   command=lambda: self.change_font(+2)).pack(side="left")
        ttk.Button(head, text="A-", width=3,
                   command=lambda: self.change_font(-2)).pack(side="left", padx=4)

        form = ttk.Frame(self, padding=(pad, 0))
        form.pack(fill="x")
        self.email_var = tk.StringVar()
        self.user_var = tk.StringVar()
        self.key_var = tk.StringVar(value=self.settings.get("hibp_key", ""))

        ttk.Label(form, text=t("الإيميل:"), anchor="e").pack(fill="x")
        e1 = ttk.Entry(form, textvariable=self.email_var, font=self.f_body)
        e1.pack(fill="x", pady=(2, 4))
        ttk.Label(form, text=t("اليوزرنيم:"), anchor="e").pack(fill="x")
        e2 = ttk.Entry(form, textvariable=self.user_var, font=self.f_body)
        e2.pack(fill="x", pady=(2, 4))
        for e in (e1, e2):
            e.bind("<Return>", lambda ev: self.start_check())

        # مفتاح HIBP مخفي افتراضياً لتوفير مساحة للنتائج
        self.show_key = tk.BooleanVar(value=bool(self.key_var.get()))
        ttk.Checkbutton(form, text=t("مفتاح HIBP (اختياري)"),
                        variable=self.show_key,
                        command=self._toggle_key).pack(anchor="e")
        self.key_entry = ttk.Entry(form, textvariable=self.key_var, show="*",
                                   font=self.f_body)
        self.key_anchor = ttk.Frame(form)
        self.key_anchor.pack(fill="x")
        self._toggle_key()

        btns = ttk.Frame(form)
        btns.pack(fill="x", pady=(4, 0))
        self.check_btn = ttk.Button(btns, text=t("فحص"), command=self.start_check)
        self.check_btn.pack(side="right", fill="x", expand=True)
        ttk.Button(btns, text=t("مسح"), command=self.clear).pack(
            side="right", fill="x", expand=True, padx=4)
        self.export_btn = ttk.Button(btns, text="CSV",
                                     command=self.export_csv, state="disabled")
        self.export_btn.pack(side="right", fill="x", expand=True)

        self.progress = ttk.Progressbar(self, mode="indeterminate")
        self.status_var = tk.StringVar(value=t("جاهز"))
        self.status_label = ttk.Label(self, textvariable=self.status_var,
                                      anchor="e", wraplength=300)
        self.status_label.pack(fill="x", padx=pad, pady=4)
        self.bind("<Configure>", self._on_resize)

        # --- النتائج: تأخذ كل المساحة المتبقية ---
        res = ttk.Frame(self, padding=(pad, 0, pad, pad))
        res.pack(fill="both", expand=True)
        self.text = tk.Text(res, wrap="word", state="disabled", relief="flat",
                            padx=6, pady=6, background="white",
                            font=self.f_body, height=1)
        vsb = ttk.Scrollbar(res, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=vsb.set)
        vsb.pack(side="left", fill="y")
        self.text.pack(side="left", fill="both", expand=True)
        self.text.tag_configure("right", justify="right")
        self.text.tag_configure("query", justify="right", font=self.f_title,
                                foreground="white", background="#37474f",
                                spacing1=10, spacing3=6)
        self.text.tag_configure("site", justify="right", font=self.f_bold,
                                foreground="#b00020", spacing1=10)
        self.text.tag_configure("data", justify="right", foreground="#444444")
        self.text.tag_configure("ok", justify="right", font=self.f_bold,
                                foreground="#1b7f3a")

    def _toggle_key(self):
        if self.show_key.get():
            self.key_entry.pack(in_=self.key_anchor, fill="x", pady=(2, 4))
        else:
            self.key_entry.pack_forget()

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

    # ------------------------------ الفحص ------------------------------- #
    def clear(self):
        self._write([])
        self.results = []
        self.export_btn.config(state="disabled")
        self.status_var.set(t("جاهز"))

    def start_check(self):
        email = self.email_var.get().strip()
        user = self.user_var.get().strip()
        if not email and not user:
            messagebox.showwarning(t("تنبيه"), t("اكتب إيميل أو يوزرنيم أولاً"))
            return
        if email and not EMAIL_RE.match(email):
            messagebox.showwarning(t("تنبيه"), t("صيغة الإيميل غير صحيحة"))
            return
        jobs = []
        if email:
            jobs.append((email, "email"))
        if user:
            jobs.append((user, "username"))

        key = self.key_var.get().strip()
        if key != self.settings.get("hibp_key", ""):
            self.settings["hibp_key"] = key
            save_settings(self.settings)

        self.clear()
        self.check_btn.config(state="disabled")
        self.progress.pack(fill="x", padx=8, before=self.status_label)
        self.progress.start(12)
        self.status_var.set(t("جاري الفحص..."))
        threading.Thread(target=self._worker, args=(jobs, key),
                         daemon=True).start()

    @staticmethod
    def _check_one(query, kind, api_key):
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
        fields = []
        for r in results:
            for f in r.get("account_fields", []):
                if f not in fields:
                    fields.append(f)
        return {"query": query, "kind": kind, "merged": merge_results(results),
                "errors": errors, "used": used, "fields": fields}

    def _worker(self, jobs, api_key):
        reports = [self._check_one(q, k, api_key) for q, k in jobs]
        self.after(0, self._done, reports)

    def _done(self, reports):
        self.progress.stop()
        self.progress.pack_forget()
        self.check_btn.config(state="normal")
        self.results = []
        lines, status, any_found = [], [], False

        for rep in reports:
            kind_ar = "الإيميل" if rep["kind"] == "email" else "اليوزرنيم"
            merged = rep["merged"]
            for m in merged:
                self.results.append(dict(m, query=rep["query"]))

            # عنوان القسم: يعرض الإيميل/اليوزرنيم الذي تم فحصه
            lines.append((t(kind_ar + ":"), "query"))
            lines.append((rep["query"], "query"))

            if merged:
                any_found = True
                status.append(t(f"{kind_ar}: {len(merged)} تسريب"))
                lines.append((t(f"ظهر في {len(merged)} تسريب "
                                f"(من {rep['used']} مصدر)"), "site"))
            elif rep["used"]:
                status.append(t(f"{kind_ar}: سليم"))
                lines.append((t("لا توجد تسريبات معروفة"), "ok"))
            else:
                status.append(t(f"{kind_ar}: فشل الفحص"))

            if rep["fields"]:
                lines.append((t("البيانات التي تسربت:"), "site"))
                lines += [(t("• " + field_ar(f)), "right") for f in rep["fields"]]
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
            if rep["errors"]:
                lines.append((t("مصادر فشلت:"), "site"))
                lines += [(t(e), "data") for e in rep["errors"]]
            lines.append(("", "right"))

        if any_found:
            self.export_btn.config(state="normal")
            lines += [(t("نصائح:"), "site"),
                      (t("- غيّر كلمة المرور في هذه المواقع"), "right"),
                      (t("- لا تستخدم نفس كلمة المرور في أكثر من موقع"), "right"),
                      (t("- فعّل المصادقة الثنائية (2FA)"), "right"),
                      (t("- استخدم مدير كلمات مرور"), "right")]
        self.status_var.set(" | ".join(status))
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
            w.writerow(["query", "site", "date", "sources", "data"])
            for m in self.results:
                w.writerow([m["query"], m["site"], m["date"],
                            " | ".join(m["sources"]), m["data"]])
        messagebox.showinfo(t("تم"), t("تم الحفظ في:") + "\n" + path)


if __name__ == "__main__":
    BreachCheckerApp().mainloop()
