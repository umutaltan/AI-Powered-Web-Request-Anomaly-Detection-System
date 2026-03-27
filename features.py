import re
import numpy as np
from urllib.parse import urlparse, unquote_plus
from collections import Counter

# --- GENİŞLETİLMİŞ SALDIRI İMZALARI ---
SQL_KEYS = ["select", "union", "insert", "update", "drop", "exec", "waitfor", "delay", "sleep", "benchmark", "or 1=1", "--", "#", "/*"]
XSS_KEYS = ["<script", "alert", "javascript", "onerror", "onload", "iframe", "src=", "eval(", "document.cookie", "vbscript"]
SHELL_KEYS = ["cmd.exe", "/bin/sh", "wget", "curl", "whoami", "cat /etc/passwd", "ipconfig", "nc ", "netcat", "ping "]
TRAV_KEYS = ["../", "..\\", "/etc/passwd", "c:\\windows", "%2e%2e%2f"]
PROBE_KEYS = ["manager", "web-inf", "phpmyadmin", "cgi-bin", "autodiscover", ".git", ".env", "admin", "config", "setup", "install", "backup"]
BAD_UA_KEYS = ["sqlmap", "nikto", "curl", "python", "wget", "nmap", "burp", "havij", "acunetix"]

def clean_url_universal(raw_url):
    s = str(raw_url or "").strip()
    try:
        if not s.startswith("http"):
            p = urlparse("http://dummy.com" + ("/" if not s.startswith("/") else "") + s)
        else:
            p = urlparse(s)
        path = p.path
        if p.query: path += "?" + p.query
        return unquote_plus(path).strip()
    except: return s

def entropy(s):
    if not s: return 0.0
    c = Counter(s)
    total = len(s)
    if total == 0: return 0.0
    p = np.array([v/total for v in c.values()])
    return -sum(p * np.log2(p) for p in p)

def extract_features(method, path, ua, cookie, content):
    url = clean_url_universal(path)
    parsed = urlparse(url)
    url_path = parsed.path.lower()
    
    # Tüm içeriği tek bir payload olarak birleştirip analiz edelim
    full_payload = (str(url) + " " + str(cookie) + " " + str(content)).lower()
    len_payload = len(full_payload)
    
    # 1. Matematiksel Metrikler
    ent_payload = entropy(full_payload)
    spec_chars = sum(1 for c in full_payload if c in "<>'\"();=%&#")
    spec_ratio = spec_chars / max(1, len_payload)
    digit_ratio = sum(c.isdigit() for c in full_payload) / max(1, len_payload)
    
    # 2. İmza Taraması (Keyword Counting)
    n_sql = sum(full_payload.count(k) for k in SQL_KEYS)
    n_xss = sum(full_payload.count(k) for k in XSS_KEYS)
    n_shell = sum(full_payload.count(k) for k in SHELL_KEYS)
    n_trav = sum(full_payload.count(k) for k in TRAV_KEYS)
    n_probe = sum(full_payload.count(k) for k in PROBE_KEYS)
    
    # 3. Yapısal Özellikler
    is_post = 1.0 if str(method).upper() == "POST" else 0.0
    bad_ext = 1.0 if re.search(r"\.(bak|old|tmp|inc|log|sql|swp|git|svn|env|conf|ini)$", url_path) else 0.0
    path_conf = 1.0 if re.search(r"\.[a-z]{3,4}/", url_path) else 0.0
    
    # 4. İleri Seviye Özellikler
    n_params = full_payload.count("&") + (1 if "?" in url else 0)
    is_bad_ua = 1.0 if any(k in str(ua).lower() for k in BAD_UA_KEYS) else 0.0
    
    return np.array([
        len_payload, ent_payload, spec_ratio, digit_ratio,
        n_sql, n_xss, n_shell, n_trav, n_probe,
        is_post, bad_ext, path_conf,
        n_params, is_bad_ua
    ], dtype=float)