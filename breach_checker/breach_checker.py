# -*- coding: utf-8 -*-
"""
فاحص التسريبات - Breach Checker
================================
برنامج بواجهة رسومية (Tkinter) للتحقق مما إذا كان بريد إلكتروني أو اسم مستخدم
قد ظهر في تسريبات بيانات معروفة، وعرض أسماء المواقع المسرَّبة وتواريخها.

المصادر المستخدمة (واجهات برمجية عامة):
  1. LeakCheck (public)       : إيميل + يوزرنيم  - مجاني بدون مفتاح
  2. XposedOrNot (analytics)  : إيميل + تفاصيل كل تسريب - مجاني
  3. كتالوج HIBP العام         : تفاصيل المواقع (عدد الحسابات، نوع البيانات) - مجاني
  4. Pwned Passwords          : فحص كلمة مرور بأمان (لا تُرسل كلمة المرور) - مجاني
  5. Have I Been Pwned (v3)   : إيميل - يحتاج مفتاح API (اختياري)

الفحص المعمّق يضيف:
  - فحص الجزء قبل @ من الإيميل كيوزرنيم
  - تحليل مستوى الخطر (Stealer Logs، كلمات مرور مكشوفة، تسريبات حديثة...)
  - نصائح مخصصة حسب نتيجة الفحص

تشغيل:  python breach_checker.py

يعمل على الكمبيوتر وعلى الهاتف (Pydroid 3).
لا يحتاج أي مكتبات خارجية.

ملاحظة: استخدم البرنامج لفحص حساباتك أنت أو حسابات لديك إذن بفحصها.
"""

import csv
import hashlib
import json
import os
import re
import sys
import threading
import time
import tkinter as tk
import urllib.error
import urllib.parse
import urllib.request
from tkinter import filedialog, messagebox, ttk
from tkinter import font as tkfont
from concurrent.futures import ThreadPoolExecutor

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
                                  "data": "", "records": None, "pw_risk": "",
                                  "industry": "", "verified": None, "domain": ""})
        if r["source"] not in m["sources"]:
            m["sources"].append(r["source"])
        if r.get("date") and (not m["date"] or len(r["date"]) > len(m["date"])):
            m["date"] = r["date"]
        if r.get("data") and len(r["data"]) > len(m["data"]):
            m["data"] = r["data"]
        if len(r["site"]) > len(m["site"]):
            m["site"] = r["site"]
        for key in ("records", "pw_risk", "industry", "verified", "domain",
                    "xon_risk", "pastes"):
            if r.get(key) not in (None, "") and m.get(key) in (None, ""):
                m[key] = r[key]
    out = list(merged.values())
    out.sort(key=lambda m: m["date"] or "0000", reverse=True)
    return out


def http_get_text(url, headers=None):
    hdrs = {"User-Agent": USER_AGENT}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except urllib.error.URLError as e:
        raise ApiError(f"تعذر الاتصال: {e.reason}") from e


# LeakCheck المجاني يرفض الطلبات المتتالية بسرعة، فنباعد بينها
_LEAKCHECK_LOCK = threading.Lock()
_LEAKCHECK_LAST = [0.0]
LEAKCHECK_GAP = 1.5  # ثانية


# كل دالة فحص ترجع قائمة نتائج، كل نتيجة dict فيها:
#   source, site, date, data  + حقول إضافية اختيارية:
#   records (عدد الحسابات المسربة), pw_risk, industry, verified, domain
def check_leakcheck(query, kind):
    url = "https://leakcheck.io/api/public?check=" + urllib.parse.quote(query)
    with _LEAKCHECK_LOCK:
        wait = LEAKCHECK_GAP - (time.time() - _LEAKCHECK_LAST[0])
        if wait > 0:
            time.sleep(wait)
        try:
            status, data = http_get_json(url)
        finally:
            _LEAKCHECK_LAST[0] = time.time()
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
                        "date": date or "", "data": "",
                        "account_fields": fields})
    return results


PW_RISK_AR = {
    "plaintext": "مخزنة كنص واضح (خطير جداً)",
    "easytocrack": "مشفرة تشفيراً ضعيفاً (سهلة الكسر)",
    "hardtocrack": "مشفرة تشفيراً قوياً",
    "unknown": "غير معروف",
}


def check_xposedornot(query, kind):
    """فحص معمّق: تفاصيل كل تسريب (عدد الحسابات، نوع الموقع، حالة كلمات المرور)."""
    if kind != "email":
        return None  # لا يدعم اليوزرنيم
    url = ("https://api.xposedornot.com/v1/breach-analytics?email="
           + urllib.parse.quote(query))
    status, data = http_get_json(url)
    if status == 404:
        return []
    if status == 429:
        raise ApiError("تجاوزت حد الطلبات، انتظر قليلاً")
    if status != 200 or not isinstance(data, dict):
        return _xposedornot_simple(query)

    exposed = data.get("ExposedBreaches") or {}
    details = exposed.get("breaches_details") or [] if isinstance(exposed, dict) else []
    results = []
    for b in details:
        if not isinstance(b, dict) or not b.get("breach"):
            continue
        records = b.get("xposed_records")
        try:
            records = int(records)
        except (TypeError, ValueError):
            records = None
        results.append({
            "source": "XposedOrNot",
            "site": str(b.get("breach")),
            "date": str(b.get("xposed_date") or ""),
            "data": ", ".join(x.strip() for x in
                              str(b.get("xposed_data") or "").split(";") if x.strip()),
            "records": records,
            "pw_risk": str(b.get("password_risk") or "").lower(),
            "industry": str(b.get("industry") or ""),
            "verified": str(b.get("verified") or "").lower() == "yes",
            "domain": str(b.get("domain") or ""),
        })
    # تقييم الخطر من XposedOrNot (إن وجد)
    try:
        risk = (data.get("BreachMetrics") or {}).get("risk") or []
        if risk and results:
            results[0]["xon_risk"] = (risk[0].get("risk_label"),
                                      risk[0].get("risk_score"))
    except (AttributeError, IndexError, TypeError):
        pass
    try:
        pastes = int((data.get("PastesSummary") or {}).get("cnt") or 0)
        if pastes and results:
            results[0]["pastes"] = pastes
    except (TypeError, ValueError, AttributeError):
        pass
    if not results:  # بعض الردود لا تحتوي التفاصيل؛ نجرب الفحص البسيط
        return _xposedornot_simple(query)
    return results


def _xposedornot_simple(query):
    url = ("https://api.xposedornot.com/v1/check-email/"
           + urllib.parse.quote(query))
    status, data = http_get_json(url)
    if status == 404:
        return []
    if status == 429:
        raise ApiError("تجاوزت حد الطلبات، انتظر قليلاً")
    if status != 200 or not isinstance(data, dict):
        raise ApiError(f"HTTP {status}")
    names = []
    for item in data.get("breaches") or []:
        names.extend(item if isinstance(item, list) else [item])
    return [{"source": "XposedOrNot", "site": str(n), "date": "", "data": ""}
            for n in names if n]


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
             "site": b.get("Title") or b.get("Name"),
             "date": b.get("BreachDate", ""),
             "data": ", ".join(b.get("DataClasses", [])),
             "records": b.get("PwnCount"),
             "verified": bool(b.get("IsVerified")),
             "domain": b.get("Domain") or ""} for b in data]


# ---------- كتالوج HIBP العام (مجاني بدون مفتاح) لإكمال تفاصيل المواقع ---------- #
HIBP_CACHE = os.path.join(os.path.expanduser("~"), ".breach_checker_catalog.json")
_catalog = {"index": None}


def load_hibp_catalog():
    """يحمّل قائمة كل التسريبات المعروفة من HIBP (مع حفظ نسخة لمدة 7 أيام)."""
    if _catalog["index"] is not None:
        return _catalog["index"]
    items = None
    try:
        if time.time() - os.path.getmtime(HIBP_CACHE) < 7 * 86400:
            with open(HIBP_CACHE, encoding="utf-8") as f:
                items = json.load(f)
    except (OSError, ValueError):
        items = None
    if items is None:
        status, items = http_get_json("https://haveibeenpwned.com/api/v3/breaches")
        if status != 200 or not isinstance(items, list):
            raise ApiError(f"تعذر تحميل كتالوج HIBP (HTTP {status})")
        try:
            with open(HIBP_CACHE, "w", encoding="utf-8") as f:
                json.dump(items, f)
        except OSError:
            pass
    index = {}
    for b in items:
        for key in (b.get("Name"), b.get("Title"), b.get("Domain")):
            if key:
                index.setdefault(site_key(key), b)
    _catalog["index"] = index
    return index


def enrich_with_catalog(merged):
    """يضيف عدد الحسابات وأنواع البيانات والتاريخ للمواقع الناقصة."""
    index = load_hibp_catalog()
    for m in merged:
        b = index.get(site_key(m["site"]))
        if not b and m.get("domain"):
            b = index.get(site_key(m["domain"]))
        if not b:
            continue
        if not m.get("records"):
            m["records"] = b.get("PwnCount")
        if not m.get("data"):
            m["data"] = ", ".join(b.get("DataClasses", []))
        if not m.get("date"):
            m["date"] = b.get("BreachDate", "")
        if not m.get("domain"):
            m["domain"] = b.get("Domain") or ""
        if m.get("verified") is None:
            m["verified"] = bool(b.get("IsVerified"))
        if b.get("IsSensitive"):
            m["sensitive"] = True
        if "HIBP" not in m["sources"]:
            m["sources"].append("HIBP")


# ---------- فحص كلمة المرور بأمان (k-anonymity) ---------- #
def check_password(password):
    """يرجع عدد مرات ظهور كلمة المرور في التسريبات.
    كلمة المرور لا تُرسل: نرسل أول 5 أحرف فقط من بصمة SHA-1 الخاصة بها."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    status, body = http_get_text("https://api.pwnedpasswords.com/range/" + prefix,
                                 {"Add-Padding": "true"})
    if status != 200:
        raise ApiError(f"HTTP {status}")
    for line in body.splitlines():
        h, _, count = line.partition(":")
        if h.strip() == suffix:
            try:
                return int(count.strip())
            except ValueError:
                return 1
    return 0


# ---------- تحليل مستوى الخطر ---------- #
STEALER_RE = re.compile(r"stealer|infostealer|\blogs?\b|redline|raccoon|vidar", re.I)
COMBO_RE = re.compile(r"collection|combo|exploit\.?in|anti.?public|cit0day|"
                      r"billion|compilation|naz\.api|synthient", re.I)
SENSITIVE_FIELDS = re.compile(r"dob|birth|phone|address|credit|card|ssn|"
                              r"passport|security question", re.I)


def _year(date):
    m = re.search(r"(19|20)\d{2}", str(date or ""))
    return int(m.group()) if m else None


def analyze(merged, fields):
    """يرجع (المستوى، النقاط، قائمة الأسباب)."""
    if not merged:
        return "none", 0, []
    score, reasons = 0, []
    n = len(merged)
    score += min(n, 10) * 3
    reasons.append(f"ظهر في {n} تسريب")

    all_data = " ".join([m.get("data", "") for m in merged] + list(fields)).lower()
    if "password" in all_data:
        score += 20
        reasons.append("كلمة المرور من ضمن البيانات المسربة")
    plain = [m["site"] for m in merged if m.get("pw_risk") in ("plaintext", "easytocrack")]
    if plain:
        score += 15
        reasons.append("كلمات مرور مكشوفة أو سهلة الكسر في: " + ", ".join(plain[:4]))
    stealer = [m["site"] for m in merged if STEALER_RE.search(m["site"])]
    if stealer:
        score += 30
        reasons.append("ظهر في سجلات برامج سرقة البيانات (Stealer Logs): جهاز "
                       "سجّلت منه الدخول كان مصاباً ببرنامج خبيث")
    combo = [m["site"] for m in merged if COMBO_RE.search(m["site"])]
    if combo:
        score += 10
        reasons.append("ضمن قوائم مجمّعة تُستخدم في هجمات تجربة كلمات المرور: "
                       + ", ".join(combo[:4]))
    this_year = time.localtime().tm_year
    recent = [m["site"] for m in merged
              if (_year(m.get("date")) or 0) >= this_year - 2]
    if recent:
        score += 10
        reasons.append("تسريبات حديثة (آخر سنتين): " + ", ".join(recent[:4]))
    if SENSITIVE_FIELDS.search(all_data):
        score += 10
        reasons.append("تسربت بيانات شخصية حساسة (تاريخ ميلاد، هاتف، عنوان...)")
    if any(m.get("sensitive") for m in merged):
        score += 5
        reasons.append("ظهر في موقع حساس")
    pastes = sum(m.get("pastes", 0) for m in merged)
    if pastes:
        score += 10
        reasons.append(f"ظهر في {pastes} منشور مسرّب (Paste)")

    score = min(score, 100)
    level = "high" if score >= 50 else "medium" if score >= 20 else "low"
    return level, score, reasons


def recommendations(reasons_text):
    recs = ["غيّر كلمة المرور في المواقع المسربة وأي موقع يستخدم نفس الكلمة",
            "فعّل المصادقة الثنائية (2FA) خصوصاً للإيميل",
            "استخدم مدير كلمات مرور وكلمة مختلفة لكل موقع"]
    if "Stealer" in reasons_text:
        recs.insert(0, "افحص أجهزتك ببرنامج مكافحة فيروسات، ثم غيّر كل كلمات "
                       "المرور المحفوظة في المتصفح من جهاز نظيف")
        recs.append("سجّل الخروج من كل الجلسات المفتوحة في حساباتك المهمة")
    if "حساسة" in reasons_text:
        recs.append("احذر من رسائل الاحتيال التي تستخدم بياناتك الشخصية")
    return recs


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

        # خيارات إضافية مخفية افتراضياً لتوفير مساحة للنتائج
        self.deep_var = tk.BooleanVar(value=self.settings.get("deep", True))
        self.pass_var = tk.StringVar()
        self.show_opts = tk.BooleanVar(value=False)
        ttk.Checkbutton(form, text=t("خيارات إضافية"), variable=self.show_opts,
                        command=self._toggle_opts).pack(anchor="e")
        self.opts = ttk.Frame(form)
        ttk.Checkbutton(self.opts, text=t("فحص معمّق (يفحص ما قبل @ كيوزرنيم)"),
                        variable=self.deep_var).pack(anchor="e")
        ttk.Label(self.opts, text=t("كلمة مرور للفحص (لا تُرسل، يُرسل جزء من بصمتها فقط):"),
                  anchor="e", wraplength=600).pack(fill="x")
        ttk.Entry(self.opts, textvariable=self.pass_var, show="*",
                  font=self.f_body).pack(fill="x", pady=(2, 4))
        ttk.Label(self.opts, text=t("مفتاح HIBP (اختياري):"), anchor="e").pack(fill="x")
        ttk.Entry(self.opts, textvariable=self.key_var, show="*",
                  font=self.f_body).pack(fill="x", pady=(2, 4))
        self.opts_anchor = ttk.Frame(form)
        self.opts_anchor.pack(fill="x")

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
        for name, color in (("high", "#c62828"), ("medium", "#ef6c00"),
                            ("low", "#2e7d32")):
            self.text.tag_configure(name, justify="right", font=self.f_bold,
                                    foreground="white", background=color,
                                    spacing1=6, spacing3=4)

    def _toggle_opts(self):
        if self.show_opts.get():
            self.opts.pack(in_=self.opts_anchor, fill="x")
        else:
            self.opts.pack_forget()

    def _on_resize(self, event):
        if event.widget is self:
            self.status_label.configure(wraplength=max(event.width - 20, 100))

    def _w(self, text):
        """على أندرويد: نقسّم السطر الطويل يدوياً قبل قلبه، لأن Tk يقسّم بعد
        القلب فيظهر آخر الجملة في أول سطر."""
        if not FIX_ARABIC:
            return t(text)
        width = self.text.winfo_width()
        char_w = max(self.f_body.measure("ابتثج سشص") / 9, 1)
        n = int(width / char_w) - 2 if width > 50 else 28
        n = max(n, 12)
        out = []
        for para in str(text).split("\n"):
            cur = ""
            for word in para.split(" "):
                if cur and len(cur) + 1 + len(word) > n:
                    out.append(cur)
                    cur = word
                else:
                    cur = f"{cur} {word}" if cur else word
            out.append(cur)
        return t("\n".join(out))

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
        password = self.pass_var.get()
        if not email and not user and not password:
            messagebox.showwarning(t("تنبيه"), t("اكتب إيميل أو يوزرنيم أولاً"))
            return
        if email and not EMAIL_RE.match(email):
            messagebox.showwarning(t("تنبيه"), t("صيغة الإيميل غير صحيحة"))
            return
        deep = self.deep_var.get()
        jobs = []
        if email:
            jobs.append((email, "email"))
        if user:
            jobs.append((user, "username"))
        if deep and email:
            local = email.split("@")[0]
            if len(local) >= 4 and local.lower() != user.lower():
                jobs.append((local, "username"))

        key = self.key_var.get().strip()
        changed = False
        if key != self.settings.get("hibp_key", ""):
            self.settings["hibp_key"] = key
            changed = True
        if deep != self.settings.get("deep", True):
            self.settings["deep"] = deep
            changed = True
        if changed:
            save_settings(self.settings)

        self.clear()
        self.check_btn.config(state="disabled")
        self.progress.pack(fill="x", padx=8, before=self.status_label)
        self.progress.start(12)
        self.status_var.set(t("جاري الفحص..."))
        threading.Thread(target=self._worker,
                         args=(jobs, key, password, deep),
                         daemon=True).start()

    @staticmethod
    def _check_one(query, kind, api_key, deep):
        checks = [
            ("LeakCheck", lambda: check_leakcheck(query, kind)),
            ("XposedOrNot", lambda: check_xposedornot(query, kind)),
            ("HIBP", lambda: check_hibp(query, kind, api_key)),
        ]
        results, errors, used = [], [], 0
        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = [(name, pool.submit(fn)) for name, fn in checks]
            for name, fut in futures:
                try:
                    r = fut.result()
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
        merged = merge_results(results)
        if deep and merged:
            try:
                enrich_with_catalog(merged)
            except Exception as e:  # noqa: BLE001
                errors.append(f"HIBP catalog: {e}")
        level, score, reasons = analyze(merged, fields)
        return {"query": query, "kind": kind, "merged": merged,
                "errors": errors, "used": used, "fields": fields,
                "level": level, "score": score, "reasons": reasons}

    def _worker(self, jobs, api_key, password, deep):
        reports = [self._check_one(q, k, api_key, deep) for q, k in jobs]
        pw = None
        if password:
            try:
                pw = check_password(password)
            except Exception as e:  # noqa: BLE001
                pw = e
        self.after(0, self._done, reports, pw)

    LEVEL_AR = {"high": "عالي", "medium": "متوسط", "low": "منخفض"}

    def _done(self, reports, pw=None):
        self.progress.stop()
        self.progress.pack_forget()
        self.check_btn.config(state="normal")
        self.results = []
        lines, status, all_reasons = [], [], []

        # --- نتيجة كلمة المرور ---
        if pw is not None:
            lines.append((self._w("كلمة المرور:"), "query"))
            if isinstance(pw, Exception):
                lines.append((self._w("فشل الفحص: ") + str(pw), "data"))
                status.append(self._w("كلمة المرور: فشل الفحص"))
            elif pw:
                lines.append((self._w(f"مكشوفة! ظهرت {pw:,} مرة في التسريبات"), "high"))
                lines.append((self._w("لا تستخدمها أبداً وغيّرها في كل مكان"), "right"))
                status.append(self._w("كلمة المرور: مكشوفة"))
            else:
                lines.append((self._w("لم تظهر في أي تسريب معروف"), "ok"))
                status.append(self._w("كلمة المرور: سليمة"))
            lines.append(("", "right"))

        for rep in reports:
            kind_ar = "الإيميل" if rep["kind"] == "email" else "اليوزرنيم"
            merged = rep["merged"]
            for m in merged:
                self.results.append(dict(m, query=rep["query"]))

            # عنوان القسم: يعرض الإيميل/اليوزرنيم الذي تم فحصه
            lines.append((self._w(kind_ar + ":"), "query"))
            lines.append((rep["query"], "query"))

            if merged:
                status.append(self._w(f"{rep['query']}: {len(merged)} تسريب"))
                level = rep["level"]
                lines.append((self._w(f"مستوى الخطر: {self.LEVEL_AR[level]} "
                                f"({rep['score']}/100)"), level))
                lines.append((self._w("الأسباب:"), "site"))
                lines += [(self._w("• " + r), "right") for r in rep["reasons"]]
                all_reasons += rep["reasons"]
                xon = next((m.get("xon_risk") for m in merged if m.get("xon_risk")),
                           None)
                if xon and xon[0]:
                    lines.append((self._w(f"تقييم XposedOrNot: {xon[0]} ({xon[1]})"),
                                  "right"))
            elif rep["used"]:
                status.append(self._w(f"{rep['query']}: سليم"))
                lines.append((self._w("لا توجد تسريبات معروفة"), "ok"))
            else:
                status.append(self._w(f"{rep['query']}: فشل الفحص"))

            if rep["fields"]:
                lines.append((self._w("البيانات التي تسربت:"), "site"))
                lines += [(self._w("• " + field_ar(f)), "right") for f in rep["fields"]]
            if merged:
                lines.append((self._w(f"المواقع التي تسربت منها ({len(merged)}):"), "site"))
            for i, m in enumerate(merged, 1):
                lines.append((f"{i}. {m['site']}", "site"))
                if m.get("domain") and site_key(m["domain"]) != site_key(m["site"]):
                    lines.append((m["domain"], "right"))
                lines.append((self._w("التاريخ: " + (m["date"] or "غير معروف")), "right"))
                if m.get("records"):
                    lines.append((self._w(f"عدد الحسابات المسربة: {int(m['records']):,}"),
                                  "right"))
                if m.get("industry"):
                    lines.append((self._w("نوع الموقع: ") + m["industry"], "right"))
                if m.get("pw_risk") and m["pw_risk"] != "unknown":
                    lines.append((self._w("كلمات المرور: " + PW_RISK_AR.get(
                        m["pw_risk"], m["pw_risk"])), "right"))
                if m.get("verified") is not None:
                    lines.append((self._w("تسريب موثّق: " + ("نعم" if m["verified"]
                                                     else "لا")), "right"))
                if STEALER_RE.search(m["site"]):
                    lines.append((self._w("تنبيه: سجلات برامج سرقة من أجهزة مصابة"),
                                  "medium"))
                lines.append((self._w("المصدر: ") + ", ".join(m["sources"]), "right"))
                if m["data"]:
                    lines.append((self._w("البيانات المسربة:"), "right"))
                    lines += [(self._w("• " + field_ar(f)), "data")
                              for f in split_fields(m["data"])]
            if rep["errors"]:
                lines.append((self._w("مصادر فشلت:"), "site"))
                lines += [(self._w(e), "data") for e in rep["errors"]]
            lines.append(("", "right"))

        found = any(r["merged"] for r in reports) or (isinstance(pw, int) and pw)
        if any(r["merged"] for r in reports):
            self.export_btn.config(state="normal")
        if found:
            lines.append((self._w("ماذا تفعل الآن:"), "site"))
            lines += [(self._w(f"{i}. {r}"), "right") for i, r in
                      enumerate(recommendations(" ".join(all_reasons)), 1)]
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
            w.writerow(["query", "site", "domain", "date", "records",
                        "password_risk", "industry", "verified", "sources", "data"])
            for m in self.results:
                w.writerow([m["query"], m["site"], m.get("domain", ""), m["date"],
                            m.get("records") or "", m.get("pw_risk", ""),
                            m.get("industry", ""), m.get("verified", ""),
                            " | ".join(m["sources"]), m["data"]])
        messagebox.showinfo(t("تم"), t("تم الحفظ في:") + "\n" + path)


if __name__ == "__main__":
    BreachCheckerApp().mainloop()
