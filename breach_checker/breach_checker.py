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

لا يحتاج أي مكتبات خارجية (يستخدم مكتبة بايثون القياسية فقط).
تشغيل:  python breach_checker.py

ملاحظة: استخدم البرنامج لفحص حساباتك أنت أو حسابات لديك إذن بفحصها.
"""

import csv
import json
import re
import threading
import tkinter as tk
import urllib.error
import urllib.parse
import urllib.request
from tkinter import filedialog, messagebox, ttk

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
    fields = ", ".join(data.get("fields") or [])
    results = []
    for src in data.get("sources") or []:
        if isinstance(src, dict):
            name, date = src.get("name", "?"), src.get("date", "")
        else:
            name, date = str(src), ""
        results.append({"source": "LeakCheck", "site": name,
                        "date": date or "غير معروف", "data": fields})
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
#                               الواجهة الرسومية                              #
# --------------------------------------------------------------------------- #
class BreachCheckerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("فاحص التسريبات - Breach Checker")
        self.geometry("900x600")
        self.minsize(700, 450)
        self.results = []
        self._build_ui()

    def _build_ui(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Title.TLabel", font=("Segoe UI", 16, "bold"))

        top = ttk.Frame(self, padding=12)
        top.pack(fill="x")
        ttk.Label(top, text="🔍 فحص تسريبات الإيميل واليوزرنيم",
                  style="Title.TLabel").pack(anchor="e")

        # --- إدخال ---
        form = ttk.LabelFrame(self, text="البحث", padding=10)
        form.pack(fill="x", padx=12)

        self.query_var = tk.StringVar()
        self.kind_var = tk.StringVar(value="auto")
        self.key_var = tk.StringVar()

        row1 = ttk.Frame(form)
        row1.pack(fill="x", pady=3)
        self.check_btn = ttk.Button(row1, text="فحص", command=self.start_check)
        self.check_btn.pack(side="left", padx=(0, 8))
        entry = ttk.Entry(row1, textvariable=self.query_var, font=("Segoe UI", 11),
                          justify="left")
        entry.pack(side="left", fill="x", expand=True)
        entry.bind("<Return>", lambda e: self.start_check())
        entry.focus_set()
        ttk.Label(row1, text=": الإيميل أو اليوزرنيم").pack(side="left", padx=6)

        row2 = ttk.Frame(form)
        row2.pack(fill="x", pady=3)
        for text, val in (("يوزرنيم", "username"), ("إيميل", "email"),
                          ("تلقائي", "auto")):
            ttk.Radiobutton(row2, text=text, value=val,
                            variable=self.kind_var).pack(side="right", padx=6)
        ttk.Label(row2, text=": النوع").pack(side="right")

        row3 = ttk.Frame(form)
        row3.pack(fill="x", pady=3)
        ttk.Entry(row3, textvariable=self.key_var, show="•").pack(
            side="left", fill="x", expand=True)
        ttk.Label(row3, text=": مفتاح HIBP (اختياري)").pack(side="left", padx=6)

        # --- النتائج ---
        res = ttk.LabelFrame(self, text="النتائج", padding=8)
        res.pack(fill="both", expand=True, padx=12, pady=10)

        cols = ("source", "site", "date", "data")
        heads = ("المصدر", "الموقع المسرَّب", "التاريخ", "البيانات المسرَّبة")
        widths = (110, 260, 100, 360)
        self.tree = ttk.Treeview(res, columns=cols, show="headings")
        for c, h, w in zip(cols, heads, widths):
            self.tree.heading(c, text=h)
            self.tree.column(c, width=w, anchor="w")
        vsb = ttk.Scrollbar(res, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        # --- شريط سفلي ---
        bottom = ttk.Frame(self, padding=(12, 0, 12, 10))
        bottom.pack(fill="x")
        self.export_btn = ttk.Button(bottom, text="تصدير CSV",
                                     command=self.export_csv, state="disabled")
        self.export_btn.pack(side="left")
        ttk.Button(bottom, text="مسح", command=self.clear).pack(side="left", padx=6)
        self.progress = ttk.Progressbar(bottom, mode="indeterminate", length=140)
        self.progress.pack(side="left", padx=6)
        self.status_var = tk.StringVar(value="جاهز")
        ttk.Label(bottom, textvariable=self.status_var).pack(side="right")

    # ----------------------------------------------------------------- #
    def clear(self):
        self.tree.delete(*self.tree.get_children())
        self.results = []
        self.export_btn.config(state="disabled")
        self.status_var.set("جاهز")

    def start_check(self):
        query = self.query_var.get().strip()
        if not query:
            messagebox.showwarning("تنبيه", "اكتب إيميل أو يوزرنيم أولاً")
            return
        kind = self.kind_var.get()
        if kind == "auto":
            kind = "email" if EMAIL_RE.match(query) else "username"
        elif kind == "email" and not EMAIL_RE.match(query):
            messagebox.showwarning("تنبيه", "صيغة الإيميل غير صحيحة")
            return

        self.clear()
        self.check_btn.config(state="disabled")
        self.progress.start(12)
        self.status_var.set("جاري الفحص...")
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
            except ApiError as e:
                errors.append(f"{name}: {e}")
            except Exception as e:  # noqa: BLE001
                errors.append(f"{name}: {e}")
        self.after(0, self._done, query, kind, results, errors, used)

    def _done(self, query, kind, results, errors, used):
        self.progress.stop()
        self.check_btn.config(state="normal")
        self.results = results
        for r in results:
            self.tree.insert("", "end",
                             values=(r["source"], r["site"], r["date"], r["data"]))

        sites = {r["site"].split(" (")[0].lower() for r in results}
        kind_ar = "الإيميل" if kind == "email" else "اليوزرنيم"
        if results:
            self.export_btn.config(state="normal")
            self.status_var.set(f"⚠️ {kind_ar} ظهر في {len(sites)} تسريب "
                                f"(من {used} مصدر)")
        elif used:
            self.status_var.set(f"✅ لم يتم العثور على {kind_ar} في أي تسريب "
                                f"(من {used} مصدر)")
        else:
            self.status_var.set("❌ فشل الفحص")

        if errors:
            messagebox.showwarning("بعض المصادر فشلت", "\n".join(errors))
        if results:
            messagebox.showinfo(
                "نصيحة",
                "تم العثور على تسريبات!\n\n"
                "• غيّر كلمة المرور في المواقع المذكورة وأي موقع يستخدم نفس الكلمة\n"
                "• فعّل المصادقة الثنائية (2FA)\n"
                "• استخدم مدير كلمات مرور وكلمة مختلفة لكل موقع")

    def export_csv(self):
        if not self.results:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV", "*.csv")],
            initialfile="breach_results.csv")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=["source", "site", "date", "data"])
            w.writeheader()
            w.writerows(self.results)
        messagebox.showinfo("تم", f"تم الحفظ في:\n{path}")


if __name__ == "__main__":
    BreachCheckerApp().mainloop()
