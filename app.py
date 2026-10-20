import os, re, json, sqlite3, secrets, hashlib, threading, time, zlib, struct
from contextlib import closing
from fastapi import FastAPI, Header, HTTPException, Depends, Request
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, field_validator
import httpx

DB = os.getenv("DB_PATH", "finance.db")
BOT = os.getenv("TELEGRAM_BOT_TOKEN", "8408115596:AAEZB02uiznq7c7tnQpNqyAsIlZG7v_vU58")
app = FastAPI(title="Finance Tracker")

def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c

with closing(db()) as c:
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE, pw TEXT, salt TEXT, tg_chat INTEGER, tg_code TEXT);
    CREATE TABLE IF NOT EXISTS tokens(hash TEXT PRIMARY KEY, user_id INTEGER, kind TEXT);
    CREATE TABLE IF NOT EXISTS tx(id INTEGER PRIMARY KEY, user_id INTEGER, amount REAL, category TEXT, note TEXT, ts INTEGER);
    CREATE INDEX IF NOT EXISTS i_tx ON tx(user_id, ts);
    CREATE TABLE IF NOT EXISTS recurring(id INTEGER PRIMARY KEY, user_id INTEGER, amount REAL, category TEXT, merchant TEXT, note TEXT, day INTEGER, last_run TEXT);
    CREATE TABLE IF NOT EXISTS goals(id INTEGER PRIMARY KEY, user_id INTEGER, name TEXT, emoji TEXT, target REAL, saved REAL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS budgets(user_id INTEGER, category TEXT, limit_ REAL, PRIMARY KEY(user_id, category));""")

with closing(db()) as c:
    if "merchant" not in [r[1] for r in c.execute("PRAGMA table_info(tx)")]:
        c.execute("ALTER TABLE tx ADD COLUMN merchant TEXT DEFAULT ''"); c.commit()

with closing(db()) as c:
    tc = [r[1] for r in c.execute("PRAGMA table_info(tx)")]; uc = [r[1] for r in c.execute("PRAGMA table_info(users)")]
    if "ext_id" not in tc: c.execute("ALTER TABLE tx ADD COLUMN ext_id TEXT DEFAULT ''")
    if "hook" not in uc: c.execute("ALTER TABLE users ADD COLUMN hook TEXT")
    c.execute("CREATE TABLE IF NOT EXISTS rules(id INTEGER PRIMARY KEY, user_id INTEGER, pattern TEXT, category TEXT)"); c.commit()

with closing(db()) as c:
    if "account" not in [r[1] for r in c.execute("PRAGMA table_info(tx)")]: c.execute("ALTER TABLE tx ADD COLUMN account TEXT DEFAULT ''")
    if "digest_off" not in [r[1] for r in c.execute("PRAGMA table_info(users)")]:
        c.execute("ALTER TABLE users ADD COLUMN digest_off INTEGER DEFAULT 0"); c.execute("ALTER TABLE users ADD COLUMN digest_day TEXT DEFAULT ''")
    c.execute("CREATE TABLE IF NOT EXISTS accounts(id INTEGER PRIMARY KEY, user_id INTEGER, name TEXT, emoji TEXT)"); c.commit()

with closing(db()) as c:
    c.execute("CREATE TABLE IF NOT EXISTS categories(user_id INTEGER, name TEXT, emoji TEXT, color TEXT, PRIMARY KEY(user_id, name))"); c.commit()

sha = lambda s: hashlib.sha256(s.encode()).hexdigest()
hp = lambda p, s: hashlib.scrypt(p.encode(), salt=bytes.fromhex(s), n=2**14, r=8, p=1).hex()

def new_token(c, uid, kind):
    raw = ("fk_" if kind == "api" else "s_") + secrets.token_urlsafe(32)
    if kind == "api":
        c.execute("DELETE FROM tokens WHERE user_id=? AND kind='api'", (uid,))
    c.execute("INSERT INTO tokens VALUES(?,?,?)", (sha(raw), uid, kind)); c.commit()
    return raw

def me(authorization: str = Header("")):
    t = authorization.removeprefix("Bearer ").strip()
    with closing(db()) as c:
        r = c.execute("SELECT user_id FROM tokens WHERE hash=?", (sha(t),)).fetchone()
    if not r: raise HTTPException(401, "Unauthorized")
    return r["user_id"]

class Cred(BaseModel): email: str; password: str
NUM = r"(\d{1,3}(?:[\s\u00a0]\d{3})+|\d+)([.,]\d+)?"
def parse_amount(v):
    if isinstance(v, (int, float)): return float(v)
    m = re.search(r"([-−+]?)\s*" + NUM, str(v))
    if not m: raise ValueError("Некорректная сумма")
    return float(re.sub(r"\s", "", m[2]) + (m[3] or "").replace(",", ".")) * (-1 if m[1] and m[1] in "-−" else 1)

def parse_quick(text):
    m = re.match(r"^\s*([+\-−]?)\s*" + NUM + r"\s*(.*)$", text.strip(), re.S)
    if not m: raise HTTPException(400, "Формат: «350 кофе» или «+50000 зарплата»")
    amt = float(re.sub(r"\s", "", m[2]) + (m[3] or "").replace(",", ".")) * (1 if m[1] == "+" else -1)
    note = m[4].strip()
    return amt, (note.split()[0] if note else "Прочее"), note

def signed(a, t): return -abs(a) if t == "expense" else abs(a) if t == "income" else a

class Tx(BaseModel):
    amount: float; category: str = "Прочее"; note: str = ""; ts: int | None = None; merchant: str = ""; type: str = ""; external_id: str = ""; account: str = ""
    @field_validator("amount", mode="before")
    @classmethod
    def _amt(cls, v): return parse_amount(v)

@app.post("/api/register")
def register(b: Cred):
    e = b.email.strip().lower()
    if not re.match(r"^[^@\s]+@[^@\s]+\.\w+$", e) or len(b.password) < 8:
        raise HTTPException(400, "Нужен корректный email и пароль от 8 символов")
    salt = secrets.token_hex(16)
    with closing(db()) as c:
        try: cur = c.execute("INSERT INTO users(email,pw,salt) VALUES(?,?,?)", (e, hp(b.password, salt), salt))
        except sqlite3.IntegrityError: raise HTTPException(409, "Email уже занят")
        return {"token": new_token(c, cur.lastrowid, "session")}

_fails = {}
@app.post("/api/login")
def login(b: Cred):
    e = b.email.strip().lower()
    if _fails.get(e, (0, 0))[0] >= 5 and time.time() - _fails[e][1] < 300:
        raise HTTPException(429, "Слишком много попыток, подождите 5 минут")
    with closing(db()) as c:
        u = c.execute("SELECT * FROM users WHERE email=?", (e,)).fetchone()
        if not u or not secrets.compare_digest(hp(b.password, u["salt"]), u["pw"]):
            n = _fails.get(e, (0, 0))[0] + 1; _fails[e] = (n, time.time())
            raise HTTPException(401, "Неверный email или пароль")
        _fails.pop(e, None)
        return {"token": new_token(c, u["id"], "session")}

def add_tx(uid, amount, category="Прочее", note="", ts=None, merchant="", ext_id="", account=""):
    merchant = merchant.strip()[:80]; ext_id = (ext_id or "").strip()[:80]
    with closing(db()) as c:
        if ext_id and c.execute("SELECT 1 FROM tx WHERE user_id=? AND ext_id=?", (uid, ext_id)).fetchone(): return False
        if _cat(category) == "Прочее":  # правила по ключевым словам
            hay = (merchant + " " + note).lower()
            for r in c.execute("SELECT pattern, category FROM rules WHERE user_id=?", (uid,)).fetchall():
                if r["pattern"] in hay: category = r["category"]; break
        if merchant and _cat(category) == "Прочее":  # авто-категория по истории магазина
            r = c.execute("SELECT category FROM tx WHERE user_id=? AND merchant=? AND category!='Прочее' ORDER BY id DESC LIMIT 1", (uid, merchant)).fetchone()
            if r: category = r["category"]
        c.execute("INSERT INTO tx(user_id,amount,category,note,ts,merchant,ext_id,account) VALUES(?,?,?,?,?,?,?,?)",
                  (uid, amount, _cat(category), note[:200], ts or int(time.time()), merchant, ext_id, account.strip()[:30]))
        c.commit()
    return _cat(category)

@app.post("/api/transactions")
def create(t: Tx, uid=Depends(me)):
    ok = add_tx(uid, signed(t.amount, t.type), t.category, t.note, t.ts, t.merchant, t.external_id, t.account)
    return {"ok": True, "duplicate": not ok}

def span(month=None):
    month = month or time.strftime("%Y-%m")
    try:
        y, m = map(int, month.split("-")); assert 1 <= m <= 12
    except Exception:
        raise HTTPException(400, "month: YYYY-MM")
    return month, int(time.mktime((y, m, 1, 0, 0, 0, 0, 0, -1))), int(time.mktime((y + (m == 12), m % 12 + 1, 1, 0, 0, 0, 0, 0, -1)))

@app.get("/api/transactions")
def listing(month: str = "", q: str = "", uid=Depends(me)):
    _, a, b = span(month or None)
    with closing(db()) as c:
        rows = c.execute("SELECT id,amount,category,note,merchant,ts FROM tx WHERE user_id=? AND ts>=? AND ts<? AND (category LIKE ? OR note LIKE ? OR merchant LIKE ?) ORDER BY ts DESC LIMIT 500",
                         (uid, a, b, f"%{q}%", f"%{q}%", f"%{q}%")).fetchall()
    return [dict(r) for r in rows]

@app.delete("/api/transactions/{i}")
def remove(i: int, uid=Depends(me)):
    with closing(db()) as c:
        c.execute("DELETE FROM tx WHERE id=? AND user_id=?", (i, uid)); c.commit()
    return {"ok": True}

def summary_for(uid, month=None):
    run_recurring(uid)
    month, a, b = span(month)
    with closing(db()) as c:
        tot = c.execute("SELECT COALESCE(SUM(amount),0) s FROM tx WHERE category!='Перевод' AND user_id=?", (uid,)).fetchone()["s"]
        mo = c.execute("SELECT COALESCE(SUM(CASE WHEN amount>0 THEN amount END),0) i, COALESCE(SUM(CASE WHEN amount<0 THEN -amount END),0) e FROM tx WHERE category!='Перевод' AND user_id=? AND ts>=? AND ts<?", (uid, a, b)).fetchone()
        cats = c.execute("SELECT category, SUM(-amount) s FROM tx WHERE category!='Перевод' AND user_id=? AND amount<0 AND ts>=? AND ts<? GROUP BY category ORDER BY s DESC", (uid, a, b)).fetchall()
        bud = c.execute("SELECT category, limit_ FROM budgets WHERE user_id=? ORDER BY category", (uid,)).fetchall()
    spent = {r["category"]: r["s"] for r in cats}
    y, m = map(int, month.split("-")); _, pa, pb = span(f"{y}-{m-1:02d}" if m > 1 else f"{y-1}-12")
    with closing(db()) as c:
        prev = c.execute("SELECT COALESCE(SUM(-amount),0) s FROM tx WHERE category!='Перевод' AND user_id=? AND amount<0 AND ts>=? AND ts<?", (uid, pa, pb)).fetchone()["s"]
        pcats = c.execute("SELECT category, SUM(-amount) s FROM tx WHERE category!='Перевод' AND user_id=? AND amount<0 AND ts>=? AND ts<? GROUP BY category", (uid, pa, pb)).fetchall()
        daily = c.execute("SELECT CAST(strftime('%d',ts,'unixepoch','localtime') AS INTEGER) d, SUM(-amount) s FROM tx WHERE category!='Перевод' AND user_id=? AND amount<0 AND ts>=? AND ts<? GROUP BY d", (uid, a, b)).fetchall()
    return {"prev_by_category": {r["category"]: r["s"] for r in pcats}, "prev_expense": prev, "daily": {r["d"]: r["s"] for r in daily}, "month": month, "balance": tot, "month_income": mo["i"], "month_expense": mo["e"],
            "by_category": [dict(r) for r in cats],
            "budgets": [{"category": r["category"], "limit": r["limit_"], "spent": spent.get(r["category"], 0)} for r in bud]}

@app.get("/api/summary")
def summary(month: str = "", uid=Depends(me)): return summary_for(uid, month or None)

import csv, io
_csv = lambda s: "'" + s if s and s[0] in "=+-@" else s
def _cat(s):
    s = (s or "").strip()[:40]
    return s[:1].upper() + s[1:] if s else "Прочее"

def budget_note(uid, cat):
    for b in summary_for(uid)["budgets"]:
        if b["category"] == cat and b["spent"] >= b["limit"] * 0.8:
            return f"\n⚠️ Бюджет «{cat}»: {b['spent']:.0f} из {b['limit']:.0f}"
    return ""

@app.put("/api/transactions/{i}")
def edit(i: int, t: Tx, uid=Depends(me)):
    with closing(db()) as c:
        c.execute("UPDATE tx SET amount=?,category=?,note=?,merchant=? WHERE id=? AND user_id=?", (t.amount, _cat(t.category), t.note[:200], t.merchant.strip()[:80], i, uid)); c.commit()
    return {"ok": True}

class Bud(BaseModel): category: str; limit: float
@app.put("/api/budgets")
def set_budget(b: Bud, uid=Depends(me)):
    with closing(db()) as c:
        if b.limit <= 0: c.execute("DELETE FROM budgets WHERE user_id=? AND category=?", (uid, _cat(b.category)))
        else: c.execute("INSERT OR REPLACE INTO budgets VALUES(?,?,?)", (uid, _cat(b.category), b.limit))
        c.commit()
    return {"ok": True}

@app.get("/api/export.csv")
def export(month: str = "", uid=Depends(me)):
    _, a, b = span(month or None)
    with closing(db()) as c:
        rows = c.execute("SELECT ts,amount,category,merchant,note FROM tx WHERE user_id=? AND ts>=? AND ts<? ORDER BY ts", (uid, a, b)).fetchall()
    o = io.StringIO(); w = csv.writer(o); w.writerow(["date", "amount", "category", "merchant", "note"])
    for r in rows: w.writerow([time.strftime("%Y-%m-%d %H:%M", time.localtime(r["ts"])), r["amount"], r["category"], _csv(r["merchant"]), _csv(r["note"])])
    return Response("\ufeff" + o.getvalue(), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": "attachment; filename=finance.csv"})

class Pw(BaseModel): old: str; new: str
@app.post("/api/password")
def passwd(b: Pw, uid=Depends(me), authorization: str = Header("")):
    if len(b.new) < 8: raise HTTPException(400, "Пароль от 8 символов")
    with closing(db()) as c:
        u = c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if not secrets.compare_digest(hp(b.old, u["salt"]), u["pw"]): raise HTTPException(403, "Неверный текущий пароль")
        s = secrets.token_hex(16)
        c.execute("UPDATE users SET pw=?,salt=? WHERE id=?", (hp(b.new, s), s, uid))
        c.execute("DELETE FROM tokens WHERE user_id=? AND kind='session' AND hash!=?", (uid, sha(authorization.removeprefix("Bearer ").strip()))); c.commit()
    return {"ok": True}

@app.delete("/api/telegram")
def tg_unlink(uid=Depends(me)):
    with closing(db()) as c: c.execute("UPDATE users SET tg_chat=NULL WHERE id=?", (uid,)); c.commit()
    return {"ok": True}

@app.delete("/api/account")
def delete_account(uid=Depends(me)):
    with closing(db()) as c:
        for t in ("tx", "budgets", "tokens", "recurring", "goals", "rules", "accounts", "categories"): c.execute(f"DELETE FROM {t} WHERE user_id=?", (uid,))
        c.execute("DELETE FROM users WHERE id=?", (uid,)); c.commit()
    return {"ok": True}

def run_recurring(uid):
    now = time.localtime(); cm = time.strftime("%Y-%m", now)
    with closing(db()) as c:
        due = c.execute("SELECT * FROM recurring WHERE user_id=? AND last_run!=? AND day<=?", (uid, cm, now.tm_mday)).fetchall()
        for r in due: c.execute("UPDATE recurring SET last_run=? WHERE id=?", (cm, r["id"]))
        c.commit()
    for r in due:
        add_tx(uid, r["amount"], r["category"], r["note"], int(time.mktime((now.tm_year, now.tm_mon, r["day"], 12, 0, 0, 0, 0, -1))), r["merchant"])

class Rec(BaseModel): amount: float; category: str = "Прочее"; merchant: str = ""; note: str = ""; day: int = 1
@app.get("/api/recurring")
def rec_list(uid=Depends(me)):
    with closing(db()) as c: return [dict(r) for r in c.execute("SELECT id,amount,category,merchant,note,day FROM recurring WHERE user_id=?", (uid,))]

@app.post("/api/recurring")
def rec_add(r: Rec, uid=Depends(me)):
    with closing(db()) as c:
        c.execute("INSERT INTO recurring(user_id,amount,category,merchant,note,day,last_run) VALUES(?,?,?,?,?,?,'')", (uid, r.amount, _cat(r.category), r.merchant[:80], r.note[:200], min(max(r.day, 1), 28))); c.commit()
    return {"ok": True}

@app.delete("/api/recurring/{i}")
def rec_del(i: int, uid=Depends(me)):
    with closing(db()) as c: c.execute("DELETE FROM recurring WHERE id=? AND user_id=?", (i, uid)); c.commit()
    return {"ok": True}

class Goal(BaseModel): name: str; emoji: str = "🎯"; target: float
@app.get("/api/goals")
def goals(uid=Depends(me)):
    with closing(db()) as c: return [dict(r) for r in c.execute("SELECT id,name,emoji,target,saved FROM goals WHERE user_id=? ORDER BY id", (uid,))]

@app.post("/api/goals")
def goal_add(g: Goal, uid=Depends(me)):
    if g.target <= 0 or not g.name.strip(): raise HTTPException(400, "Нужны название и сумма цели")
    with closing(db()) as c:
        c.execute("INSERT INTO goals(user_id,name,emoji,target) VALUES(?,?,?,?)", (uid, g.name.strip()[:60], (g.emoji or "🎯")[:8], g.target)); c.commit()
    return {"ok": True}

class Amt(BaseModel): amount: float
@app.post("/api/goals/{i}/add")
def goal_fund(i: int, a: Amt, uid=Depends(me)):
    with closing(db()) as c:
        c.execute("UPDATE goals SET saved=MAX(0, saved+?) WHERE id=? AND user_id=?", (a.amount, i, uid)); c.commit()
    return {"ok": True}

@app.delete("/api/goals/{i}")
def goal_del(i: int, uid=Depends(me)):
    with closing(db()) as c: c.execute("DELETE FROM goals WHERE id=? AND user_id=?", (i, uid)); c.commit()
    return {"ok": True}

@app.api_route("/api/hook/{t}", methods=["GET", "POST"])
async def hook(t: str, request: Request):
    with closing(db()) as c: u = c.execute("SELECT id FROM users WHERE hook=?", (t,)).fetchone()
    if not u: raise HTTPException(404, "Unknown hook")
    if not rate_ok(t): raise HTTPException(429, "Too many requests")
    d = dict(request.query_params)
    if request.method == "POST":
        raw = (await request.body()).decode("utf-8", "ignore")
        try: d.update(json.loads(raw))
        except Exception:
            if raw.strip(): d.setdefault("text", raw)
    merchant, cat, note = str(d.get("merchant", "")), str(d.get("category", "")), str(d.get("note", ""))
    if d.get("text"):
        amt, c2, n2 = parse_quick(str(d["text"])); cat = cat or c2; note = note or n2
    elif "amount" in d:
        try: amt = parse_amount(d["amount"])
        except ValueError: raise HTTPException(400, "Некорректная сумма")
        if d.get("type") in ("income", "expense"): amt = signed(amt, d["type"])
        elif amt > 0 and "+" not in str(d["amount"]): amt = -amt
    else: raise HTTPException(400, "Нужен text или amount")
    ok = add_tx(u["id"], amt, cat or "Прочее", note, None, merchant, str(d.get("id", d.get("external_id", ""))), str(d.get("account", "")))
    return {"ok": True, "duplicate": not ok, "amount": amt, "text": f"{amt:+.2f}" + (f" · {merchant}" if merchant else "") + (budget_note(u["id"], ok) if ok else "")}

@app.get("/api/automation")
def automation(uid=Depends(me)):
    with closing(db()) as c:
        h = c.execute("SELECT hook FROM users WHERE id=?", (uid,)).fetchone()["hook"]
        if not h: h = "hk_" + secrets.token_urlsafe(24); c.execute("UPDATE users SET hook=? WHERE id=?", (h, uid)); c.commit()
        rules = [dict(r) for r in c.execute("SELECT id,pattern,category FROM rules WHERE user_id=? ORDER BY id", (uid,))]
    return {"hook": h, "rules": rules}

@app.post("/api/automation/hook")
def hook_regen(uid=Depends(me)):
    h = "hk_" + secrets.token_urlsafe(24)
    with closing(db()) as c: c.execute("UPDATE users SET hook=? WHERE id=?", (h, uid)); c.commit()
    return {"hook": h}

class Rule(BaseModel): pattern: str; category: str
@app.post("/api/rules")
def rule_add(r: Rule, uid=Depends(me)):
    if not r.pattern.strip(): raise HTTPException(400, "Пустое правило")
    with closing(db()) as c:
        c.execute("INSERT INTO rules(user_id,pattern,category) VALUES(?,?,?)", (uid, r.pattern.strip().lower()[:60], _cat(r.category))); c.commit()
    return {"ok": True}

@app.delete("/api/rules/{i}")
def rule_del(i: int, uid=Depends(me)):
    with closing(db()) as c: c.execute("DELETE FROM rules WHERE id=? AND user_id=?", (i, uid)); c.commit()
    return {"ok": True}

class Imp(BaseModel): csv: str
@app.post("/api/import")
def import_csv(b: Imp, uid=Depends(me)):
    head = b.csv.lstrip("\ufeff").split("\n")[0]; n = 0
    rows = list(csv.DictReader(io.StringIO(b.csv.lstrip("\ufeff"), newline=""), delimiter=";" if head.count(";") > head.count(",") else ","))[:2000]
    for row in rows:
        r = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items() if isinstance(v, str) or v is None}
        try: amt = parse_amount(r.get("amount", ""))
        except ValueError: continue
        ts = None
        for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d", "%d.%m.%Y %H:%M", "%d.%m.%Y"):
            try: ts = int(time.mktime(time.strptime(r.get("date", ""), fmt))); break
            except ValueError: pass
        key = sha(f"{r.get('date')}|{amt}|{r.get('merchant')}|{r.get('note')}")[:20]
        n += bool(add_tx(uid, amt, r.get("category") or "Прочее", r.get("note", ""), ts, r.get("merchant", ""), "imp" + key))
    return {"added": n}

class Acc(BaseModel): name: str; emoji: str = "💳"
@app.get("/api/accounts")
def accounts(uid=Depends(me)):
    with closing(db()) as c:
        bal = {(r["account"] or ""): r["s"] for r in c.execute("SELECT account, SUM(amount) s FROM tx WHERE user_id=? GROUP BY account", (uid,))}
        rows = c.execute("SELECT id,name,emoji FROM accounts WHERE user_id=? ORDER BY id", (uid,)).fetchall()
    out = [{"id": r["id"], "name": r["name"], "emoji": r["emoji"], "balance": bal.get(r["name"], 0)} for r in rows]
    return ([{"id": 0, "name": "", "emoji": "👛", "balance": bal.get("", 0)}] if rows else []) + out

@app.post("/api/accounts")
def acc_add(a: Acc, uid=Depends(me)):
    n = a.name.strip()[:30]
    if not n: raise HTTPException(400, "Нужно название")
    with closing(db()) as c:
        if c.execute("SELECT 1 FROM accounts WHERE user_id=? AND name=?", (uid, n)).fetchone(): raise HTTPException(409, "Такой счёт уже есть")
        c.execute("INSERT INTO accounts(user_id,name,emoji) VALUES(?,?,?)", (uid, n, (a.emoji or "💳")[:8])); c.commit()
    return {"ok": True}

@app.delete("/api/accounts/{i}")
def acc_del(i: int, uid=Depends(me)):
    with closing(db()) as c:
        r = c.execute("SELECT name FROM accounts WHERE id=? AND user_id=?", (i, uid)).fetchone()
        if r:
            c.execute("UPDATE tx SET account='' WHERE user_id=? AND account=?", (uid, r["name"])); c.execute("DELETE FROM accounts WHERE id=?", (i,)); c.commit()
    return {"ok": True}

class Xfer(BaseModel): src: str = ""; dst: str = ""; amount: float
@app.post("/api/transfer")
def transfer(x: Xfer, uid=Depends(me)):
    a = abs(x.amount)
    with closing(db()) as c: names = {r["name"] for r in c.execute("SELECT name FROM accounts WHERE user_id=?", (uid,))} | {""}
    if not a or x.src == x.dst or x.src not in names or x.dst not in names: raise HTTPException(400, "Некорректный перевод или счёт не найден")
    now = int(time.time())
    with closing(db()) as c:
        for acc, amt, note in ((x.src, -a, "→ " + (x.dst or "Без счёта")), (x.dst, a, "← " + (x.src or "Без счёта"))):
            c.execute("INSERT INTO tx(user_id,amount,category,note,ts,merchant,ext_id,account) VALUES(?,?,?,?,?,?,?,?)", (uid, amt, "Перевод", note, now, "", "", acc))
        c.commit()
    return {"ok": True}

@app.get("/api/yearly")
def yearly(year: int = 0, uid=Depends(me)):
    y = year or time.localtime().tm_year
    a, b = int(time.mktime((y, 1, 1, 0, 0, 0, 0, 0, -1))), int(time.mktime((y + 1, 1, 1, 0, 0, 0, 0, 0, -1)))
    inc, exp = [0.0] * 12, [0.0] * 12
    with closing(db()) as c:
        for r in c.execute("SELECT CAST(strftime('%m',ts,'unixepoch','localtime') AS INTEGER) m, SUM(CASE WHEN amount>0 THEN amount ELSE 0 END) i, SUM(CASE WHEN amount<0 THEN -amount ELSE 0 END) e FROM tx WHERE category!='Перевод' AND user_id=? AND ts>=? AND ts<? GROUP BY m", (uid, a, b)):
            inc[r["m"] - 1], exp[r["m"] - 1] = r["i"], r["e"]
    return {"year": y, "income": inc, "expense": exp}

_hits = {}
def rate_ok(key, n=60):
    now = time.time(); h = [x for x in _hits.get(key, []) if now - x < 60]
    if len(h) >= n: return False
    h.append(now); _hits[key] = h; return True

class Cat(BaseModel): name: str; emoji: str = ""; color: str = ""
@app.get("/api/categories")
def cats_get(uid=Depends(me)):
    with closing(db()) as c: return [dict(r) for r in c.execute("SELECT name,emoji,color FROM categories WHERE user_id=?", (uid,))]

@app.put("/api/categories")
def cat_put(b: Cat, uid=Depends(me)):
    n = _cat(b.name)
    with closing(db()) as c:
        if b.emoji.strip() == "-": c.execute("DELETE FROM categories WHERE user_id=? AND name=?", (uid, n))
        else: c.execute("INSERT OR REPLACE INTO categories VALUES(?,?,?,?)", (uid, n, b.emoji.strip()[:8], b.color if re.match(r"^#[0-9a-fA-F]{6}$", b.color) else ""))
        c.commit()
    return {"ok": True}

@app.post("/api/key")
def regen_key(uid=Depends(me)):
    with closing(db()) as c: return {"api_key": new_token(c, uid, "api")}

@app.get("/api/telegram/code")
def tg_code(uid=Depends(me)):
    code = secrets.token_hex(3).upper()
    with closing(db()) as c:
        c.execute("UPDATE users SET tg_code=? WHERE id=?", (code, uid)); c.commit()
    return {"code": code, "bot_enabled": bool(BOT)}

@app.get("/icon.png")
def icon(n: int = 180):
    raw = b"".join(b"\0" + bytes([22, 163, 74]) * n for _ in range(n))
    ch = lambda t, d: struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))
    png = b"\x89PNG\r\n\x1a\n" + ch(b"IHDR", struct.pack(">IIBBBBB", n, n, 8, 2, 0, 0, 0)) + ch(b"IDAT", zlib.compress(raw)) + ch(b"IEND", b"")
    return Response(png, media_type="image/png")

# ---------- Telegram bot (long polling) ----------
def tg(method, **p):
    return httpx.post(f"https://api.telegram.org/bot{BOT}/{method}", json=p, timeout=40).json()

def handle(chat, text):
    say = lambda s: tg("sendMessage", chat_id=chat, text=s)
    with closing(db()) as c:
        if text.startswith("/start"):
            code = text.split()[-1].upper() if len(text.split()) > 1 else ""
            u = c.execute("SELECT id FROM users WHERE tg_code=? AND tg_code!=''", (code,)).fetchone()
            if not u: return say("Получите код в веб-приложении (Настройки → Telegram) и отправьте: /start КОД")
            c.execute("UPDATE users SET tg_chat=?, tg_code=NULL WHERE id=?", (chat, u["id"])); c.commit()
            return say("Готово! Пишите: «350 кофе» (расход), «+50000 зарплата» (доход), /balance, /month, /undo")
        u = c.execute("SELECT id FROM users WHERE tg_chat=?", (chat,)).fetchone()
    if not u: return say("Сначала привяжите аккаунт: /start КОД")
    if text.startswith("/balance"):
        s = summary_for(u["id"])
        return say(f"Баланс: {s['balance']:.2f}\nДоход за месяц: {s['month_income']:.2f}\nРасход за месяц: {s['month_expense']:.2f}")
    if text.startswith("/digest"):
        off = 0 if "on" in text else 1
        with closing(db()) as c: c.execute("UPDATE users SET digest_off=? WHERE id=?", (off, u["id"])); c.commit()
        return say("Вечерняя сводка " + ("выключена" if off else "включена") + ". Команда: /digest on|off")
    if text.startswith("/undo"):
        with closing(db()) as c:
            r = c.execute("SELECT id,amount,category FROM tx WHERE user_id=? ORDER BY id DESC LIMIT 1", (u["id"],)).fetchone()
            if r: c.execute("DELETE FROM tx WHERE id=?", (r["id"],)); c.commit()
        return say(f"Удалено: {r['amount']:+.2f} · {r['category']}" if r else "Нечего удалять")
    if text.startswith("/help"):
        return say("«350 кофе» — расход, «+50000 зарплата» — доход\n/balance /today /month /budgets /undo /digest on|off")
    if text.startswith("/today"):
        st = int(time.mktime(time.localtime()[:3] + (0, 0, 0, 0, 0, -1)))
        with closing(db()) as c: rs = c.execute("SELECT amount, category, merchant FROM tx WHERE user_id=? AND category!='Перевод' AND ts>=? ORDER BY ts DESC LIMIT 15", (u["id"], st)).fetchall()
        return say("\n".join(f"{r['amount']:+.2f} · {r['merchant'] or r['category']}" for r in rs) or "Сегодня операций нет")
    if text.startswith("/budgets"):
        bs = summary_for(u["id"])["budgets"]
        return say("\n".join(f"{b['category']}: {b['spent']:.0f} / {b['limit']:.0f} ({b['spent']/b['limit']*100:.0f}%)" for b in bs) or "Бюджеты не заданы")
    if text.startswith("/month"):
        cs = summary_for(u["id"])["by_category"]
        return say("\n".join(f"{x['category']}: {x['s']:.2f}" for x in cs) or "Расходов за месяц нет")
    m = re.match(r"^([+-]?)\s*(\d+(?:[.,]\d+)?)\s*(.*)$", text)
    if not m: return say("Формат: «350 кофе» или «+50000 зарплата»")
    amt = float(m[2].replace(",", ".")) * (1 if m[1] == "+" else -1)
    note = m[3].strip(); cat = (note.split()[0].capitalize() if note else "Прочее")
    add_tx(u["id"], amt, cat, note); say(f"Записано: {amt:+.2f} · {cat}" + budget_note(u["id"], cat))

def bot_loop():
    off = 0
    while True:
        try:
            r = httpx.get(f"https://api.telegram.org/bot{BOT}/getUpdates", params={"timeout": 30, "offset": off}, timeout=40).json()
            for u in r.get("result", []):
                off = u["update_id"] + 1
                m = u.get("message") or {}
                if m.get("text"): handle(m["chat"]["id"], m["text"].strip())
        except Exception: time.sleep(5)

def digest_loop():
    while True:
        try:
            now = time.localtime()
            if now.tm_hour >= 21:
                today = time.strftime("%Y-%m-%d", now); start = int(time.mktime((now.tm_year, now.tm_mon, now.tm_mday, 0, 0, 0, 0, 0, -1)))
                with closing(db()) as c: us = c.execute("SELECT id, tg_chat FROM users WHERE tg_chat IS NOT NULL AND digest_off=0 AND digest_day!=?", (today,)).fetchall()
                for u in us:
                    with closing(db()) as c:
                        e = c.execute("SELECT COALESCE(SUM(-amount),0) s, COUNT(*) n FROM tx WHERE user_id=? AND amount<0 AND category!='Перевод' AND ts>=?", (u["id"], start)).fetchone()
                        c.execute("UPDATE users SET digest_day=? WHERE id=?", (today, u["id"])); c.commit()
                    if e["n"]: tg("sendMessage", chat_id=u["tg_chat"], text=f"📊 Итоги дня: {e['n']} трат на {e['s']:.2f}\nБаланс: {summary_for(u['id'])['balance']:.2f}")
        except Exception: pass
        time.sleep(1800)

if BOT:
    threading.Thread(target=bot_loop, daemon=True).start()
    threading.Thread(target=digest_loop, daemon=True).start()
app.mount("/", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static"), html=True), name="static")
