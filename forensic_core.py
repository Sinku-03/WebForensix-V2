from __future__ import annotations
import os, sys, sqlite3, hashlib, tempfile, csv, re
from pathlib import Path
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, parse_qs, unquote, urlunparse

FIELDS = ["timestamp", "browser", "artifact_type", "title", "url", "details", "source_file"]

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

def chrome_time(value):
    try:
        n = int(value or 0)
        if n <= 0: return ""
        return datetime.fromtimestamp(n / 1_000_000 - 11644473600, tz=timezone.utc).isoformat()
    except (ValueError, TypeError, OverflowError, OSError):
        return ""

def firefox_time(value):
    try:
        n = int(value or 0)
        if n <= 0: return ""
        return datetime.fromtimestamp(n / 1_000_000, tz=timezone.utc).isoformat()
    except (ValueError, TypeError, OverflowError, OSError):
        return ""

def infer_search(url):
    try:
        p = urlparse(url)
        host = (p.hostname or "").lower()
        params = parse_qs(p.query)
        engines = ("google.", "bing.com", "duckduckgo.com", "yahoo.com", "yandex.")
        if any(x in host for x in engines):
            for key in ("q", "query", "p", "text", "wd"):
                if params.get(key):
                    return unquote(params[key][0].replace("+", " "))
    except Exception:
        pass
    return ""

def add_event(out, timestamp, browser, typ, title="", url="", details="", source=""):
    if timestamp:
        out.append({
            "timestamp": str(timestamp), "browser": str(browser),
            "artifact_type": str(typ), "title": str(title or "")[:500],
            "url": str(url or "")[:2500], "details": str(details or "")[:1200],
            "source_file": str(source or "")
        })

def sqlite_snapshot(source):
    """Create a consistent read snapshot; source database is never intentionally modified."""
    fd, dest = tempfile.mkstemp(prefix="webforensix_", suffix=".sqlite")
    os.close(fd)
    src = dst = None
    try:
        uri = Path(source).resolve().as_uri() + "?mode=ro"
        src = sqlite3.connect(uri, uri=True, timeout=20)
        src.execute("PRAGMA busy_timeout=20000")
        dst = sqlite3.connect(dest, timeout=20)
        src.backup(dst, pages=256, sleep=0.05)
        dst.close(); dst = None
        src.close(); src = None
        return dest
    except Exception:
        if dst:
            dst.close()
        if src:
            src.close()
        try: os.remove(dest)
        except OSError: pass
        raise

def table_names(con):
    return {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}

def extract_chromium(db_path, browser, out, hashes, errors):
    snapshot = None
    try:
        snapshot = sqlite_snapshot(db_path)
        with sqlite3.connect(snapshot) as con:
            con.row_factory = sqlite3.Row
            tables = table_names(con)
            if "urls" in tables:
                for r in con.execute("SELECT url,title,last_visit_time,visit_count FROM urls"):
                    stamp = chrome_time(r["last_visit_time"])
                    add_event(out, stamp, browser, "History", r["title"], r["url"],
                              f"Visit count: {r['visit_count']}", db_path)
                    term = infer_search(r["url"])
                    if term:
                        add_event(out, stamp, browser, "Search", term, r["url"],
                                  "Search term inferred from visited search URL", db_path)
            if "downloads" in tables:
                cols = {r[1] for r in con.execute("PRAGMA table_info(downloads)")}
                query = "SELECT * FROM downloads"
                for r in con.execute(query):
                    keys = set(r.keys())
                    raw_time = (r["end_time"] if "end_time" in keys and r["end_time"]
                                else r["start_time"] if "start_time" in keys else 0)
                    stamp = chrome_time(raw_time)
                    filename = (r["target_path"] if "target_path" in keys and r["target_path"]
                                else r["current_path"] if "current_path" in keys else "")
                    source_url = r["tab_url"] if "tab_url" in keys and r["tab_url"] else r["url"] if "url" in keys else ""
                    state = r["state"] if "state" in keys else "Unknown"
                    add_event(out, stamp, browser, "Download", Path(str(filename)).name,
                              source_url, f"Path: {filename}; state: {state}", db_path)
            if "cookies" in tables:
                for r in con.execute("SELECT * FROM cookies"):
                    keys = set(r.keys())
                    host = r["host_key"] if "host_key" in keys else ""
                    name = r["name"] if "name" in keys else ""
                    created = chrome_time(r["creation_utc"]) if "creation_utc" in keys else ""
                    expiry = chrome_time(r["expires_utc"]) if "expires_utc" in keys else ""
                    secure = bool(r["is_secure"]) if "is_secure" in keys else False
                    http = bool(r["is_httponly"]) if "is_httponly" in keys else False
                    add_event(out, created, browser, "Cookie", name, host,
                              f"Created: {created or 'unknown'}; Expiry: {expiry or 'unknown'}; "
                              f"Secure={secure}; HttpOnly={http}; value not collected", db_path)
        try: hashes[str(db_path)] = sha256_file(db_path)
        except OSError as exc: errors.append(f"Hash failed for {db_path}: {exc}")
    except Exception as exc:
        errors.append(f"{browser} database could not be read ({db_path}): {exc}")
    finally:
        if snapshot:
            try: os.remove(snapshot)
            except OSError: pass

def extract_firefox(profile, out, hashes, errors):
    places = profile / "places.sqlite"
    if places.exists():
        snapshot = None
        try:
            snapshot = sqlite_snapshot(places)
            with sqlite3.connect(snapshot) as con:
                con.row_factory = sqlite3.Row
                tables = table_names(con)
                if "moz_places" in tables:
                    cols = {r[1] for r in con.execute("PRAGMA table_info(moz_places)")}
                    if "moz_historyvisits" in tables:
                        q = """SELECT p.url,p.title,v.visit_date FROM moz_historyvisits v
                               JOIN moz_places p ON p.id=v.place_id ORDER BY v.visit_date"""
                        for r in con.execute(q):
                            stamp = firefox_time(r["visit_date"])
                            add_event(out, stamp, "Firefox", "History", r["title"], r["url"],
                                      "Firefox history visit", str(places))
                            term = infer_search(r["url"])
                            if term:
                                add_event(out, stamp, "Firefox", "Search", term, r["url"],
                                          "Search term inferred from visited search URL", str(places))
                    elif "last_visit_date" in cols:
                        for r in con.execute("SELECT url,title,last_visit_date,visit_count FROM moz_places WHERE last_visit_date > 0"):
                            stamp = firefox_time(r["last_visit_date"])
                            add_event(out, stamp, "Firefox", "History", r["title"], r["url"],
                                      f"Visit count: {r['visit_count']}", str(places))
                if "moz_annos" in tables and "moz_anno_attributes" in tables and "moz_places" in tables:
                    q = """SELECT p.url,p.title,a.content,aa.name FROM moz_annos a
                           JOIN moz_anno_attributes aa ON aa.id=a.anno_attribute_id
                           JOIN moz_places p ON p.id=a.place_id WHERE aa.name LIKE '%download%'"""
                    for r in con.execute(q):
                        add_event(out, "", "Firefox", "Download", r["title"], r["url"],
                                  f"Annotation: {r['name']}", str(places))
            try: hashes[str(places)] = sha256_file(places)
            except OSError as exc: errors.append(f"Hash failed for {places}: {exc}")
        except Exception as exc:
            errors.append(f"Firefox places database could not be read ({places}): {exc}")
        finally:
            if snapshot:
                try: os.remove(snapshot)
                except OSError: pass

    cookies = profile / "cookies.sqlite"
    if cookies.exists():
        snapshot = None
        try:
            snapshot = sqlite_snapshot(cookies)
            with sqlite3.connect(snapshot) as con:
                con.row_factory = sqlite3.Row
                cols = {r[1] for r in con.execute("PRAGMA table_info(moz_cookies)")}
                if "moz_cookies" in table_names(con):
                    selected = ["name", "host", "expiry", "isSecure", "isHttpOnly"]
                    if "creationTime" in cols: selected.append("creationTime")
                    for r in con.execute("SELECT " + ",".join(selected) + " FROM moz_cookies"):
                        created = firefox_time(r["creationTime"]) if "creationTime" in r.keys() else ""
                        expiry = datetime.fromtimestamp(r["expiry"], tz=timezone.utc).isoformat() if r["expiry"] else "session"
                        add_event(out, created, "Firefox", "Cookie", r["name"], r["host"],
                                  f"Created: {created or 'unknown'}; Expiry: {expiry}; "
                                  f"Secure={bool(r['isSecure'])}; HttpOnly={bool(r['isHttpOnly'])}; value not collected",
                                  str(cookies))
            try: hashes[str(cookies)] = sha256_file(cookies)
            except OSError as exc: errors.append(f"Hash failed for {cookies}: {exc}")
        except Exception as exc:
            errors.append(f"Firefox cookies database could not be read ({cookies}): {exc}")
        finally:
            if snapshot:
                try: os.remove(snapshot)
                except OSError: pass

def discover_browser_profiles():
    home = Path.home()
    candidates = []
    if sys.platform == "win32":
        local = Path(os.environ.get("LOCALAPPDATA", home / "AppData/Local"))
        roaming = Path(os.environ.get("APPDATA", home / "AppData/Roaming"))
        for root in (local/"Google/Chrome/User Data", local/"Microsoft/Edge/User Data"):
            if root.exists():
                candidates += [p for p in root.iterdir() if p.is_dir() and
                               (p.name == "Default" or p.name.startswith("Profile"))]
        ff = roaming/"Mozilla/Firefox/Profiles"
        if ff.exists(): candidates += [p for p in ff.iterdir() if p.is_dir()]
    elif sys.platform == "darwin":
        for root in (home/"Library/Application Support/Google/Chrome",
                     home/"Library/Application Support/Microsoft Edge"):
            if root.exists():
                candidates += [p for p in root.iterdir() if p.is_dir() and
                               (p.name == "Default" or p.name.startswith("Profile"))]
        ff = home/"Library/Application Support/Firefox/Profiles"
        if ff.exists(): candidates += [p for p in ff.iterdir() if p.is_dir()]
    else:
        for root in (home/".config/google-chrome", home/".config/chromium",
                     home/".config/microsoft-edge"):
            if root.exists():
                candidates += [p for p in root.iterdir() if p.is_dir() and
                               (p.name == "Default" or p.name.startswith("Profile"))]
        ff = home/".mozilla/firefox"
        if ff.exists(): candidates += [p for p in ff.iterdir() if p.is_dir() and ".default" in p.name]
    return candidates

class ForensicAnalyzer:
    def __init__(self):
        self.events = []
        self.evidence_hashes = {}
        self.errors = []
    def extract_from_paths(self, paths, progress=None):
        self.events, self.evidence_hashes, self.errors = [], {}, []
        db_jobs = []
        for path in paths:
            p = Path(path).expanduser()
            if not p.exists():
                self.errors.append(f"Selected path does not exist: {p}")
                continue
            if p.is_file():
                if p.name.lower() == "history":
                    browser = "Edge" if "edge" in str(p).lower() else "Chrome"
                    db_jobs.append((p, browser))
                elif p.name.lower() == "places.sqlite":
                    extract_firefox(p.parent, self.events, self.evidence_hashes, self.errors)
                continue
            if (p/"places.sqlite").exists() or (p/"cookies.sqlite").exists():
                extract_firefox(p, self.events, self.evidence_hashes, self.errors)
            # Search recursively for Chromium History databases in selected profile/evidence folder.
            try:
                for db in p.rglob("History"):
                    if db.is_file():
                        low = str(db).lower()
                        browser = "Edge" if "microsoft/edge" in low or "microsoft\\edge" in low else "Chrome"
                        db_jobs.append((db, browser))
            except OSError as exc:
                self.errors.append(f"Could not enumerate {p}: {exc}")
            # Also locate Firefox profiles nested in a selected evidence root.
            try:
                for places in p.rglob("places.sqlite"):
                    if places.is_file() and places.parent != p:
                        extract_firefox(places.parent, self.events, self.evidence_hashes, self.errors)
            except OSError as exc:
                self.errors.append(f"Could not enumerate Firefox profiles in {p}: {exc}")
        # Deduplicate database paths in case a parent and child were both selected.
        seen = set()
        jobs = []
        for db, browser in db_jobs:
            key = str(db.resolve()).lower()
            if key not in seen:
                seen.add(key); jobs.append((db, browser))
        for i, (db, browser) in enumerate(jobs, 1):
            if progress: progress(i, len(jobs), browser, db)
            extract_chromium(db, browser, self.events, self.evidence_hashes, self.errors)
        self.events.sort(key=lambda x: x.get("timestamp", ""))
        return self.events

def normalize_url(url):
    try:
        p = urlparse(url.strip())
        if not p.scheme or not p.netloc: return url.strip().lower()
        host = (p.hostname or "").lower()
        port = f":{p.port}" if p.port and p.port not in (80,443) else ""
        path = p.path.rstrip("/") or "/"
        # Drop common tracking parameters for correlation only.
        ignored = {"utm_source","utm_medium","utm_campaign","utm_term","utm_content","gclid","fbclid"}
        params = [(k,v) for k, vals in parse_qs(p.query, keep_blank_values=True).items()
                  if k.lower() not in ignored for v in vals]
        from urllib.parse import urlencode
        query = urlencode(sorted(params))
        return urlunparse((p.scheme.lower(), host+port, path, "", query, ""))
    except Exception:
        return url.strip().lower()

def analyze_events(events):
    from collections import Counter, defaultdict
    counts = Counter(e.get("artifact_type","Unknown") for e in events)
    browsers = Counter(e.get("browser","Unknown") for e in events)
    # Duplicate records: identical browser/type/title/normalized URL/timestamp.
    seen, duplicates = set(), []
    for e in events:
        key = (e.get("browser"), e.get("artifact_type"), e.get("title"),
               normalize_url(e.get("url","")), e.get("timestamp"))
        if key in seen: duplicates.append(e)
        else: seen.add(key)
    # Cross-browser URL correlations within a 10-minute window.
    by_url = defaultdict(list)
    for e in events:
        url = e.get("url","")
        if url.startswith(("http://","https://")):
            by_url[normalize_url(url)].append(e)
    correlations = []
    for url, rows in by_url.items():
        browsers_here = sorted({r.get("browser","") for r in rows})
        if len(browsers_here) > 1:
            rows_sorted = sorted(rows, key=lambda x:x.get("timestamp",""))
            correlations.append({"url":url, "browsers":browsers_here, "count":len(rows_sorted),
                                 "first_seen":rows_sorted[0].get("timestamp",""),
                                 "last_seen":rows_sorted[-1].get("timestamp","")})
    # Conservative URL indicators; flags are leads for review, not malware verdicts.
    suspicious = []
    risky_terms = ("phishing", "malware", "verify-account", "secure-login", "free-gift",
                   "account-suspended", "password-reset")
    for e in events:
        url = e.get("url","")
        try:
            p = urlparse(url)
            host = (p.hostname or "").lower()
            reasons = []
            if host.startswith("xn--") or ".xn--" in host: reasons.append("Punycode hostname")
            if re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", host): reasons.append("IP-address host")
            if len(host) > 55: reasons.append("Unusually long hostname")
            if any(t in (host + p.path + p.query).lower() for t in risky_terms):
                reasons.append("Risk-related keyword in URL")
            if p.scheme == "http" and host and not host.endswith((".local", ".localhost")):
                reasons.append("Unencrypted HTTP")
            if reasons:
                suspicious.append({"timestamp":e.get("timestamp",""),"browser":e.get("browser",""),
                                   "url":url,"reasons":", ".join(reasons),"title":e.get("title","")})
        except Exception:
            continue
    return {"artifact_counts":counts, "browser_counts":browsers,
            "duplicates":duplicates, "correlations":correlations,
            "suspicious":suspicious}

def export_csv(events, path):
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(events)
