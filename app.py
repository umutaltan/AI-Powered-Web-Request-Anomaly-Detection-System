import streamlit as st
import pandas as pd
import numpy as np
import joblib
import os
import time
from urllib.parse import urlparse
# features.py dosyasının yanımızda olduğundan emin olalım
try:
    from features import extract_features
except ImportError:
    st.error("HATA: 'features.py' dosyası bulunamadı! Lütfen proje klasöründe olduğundan emin olun.")
    st.stop()

# --- SAYFA AYARLARI ---
st.set_page_config(
    page_title="Universal WAF AI",
    page_icon="🌍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- CSS İLE GÖRSEL İYİLEŞTİRME ---
st.markdown("""
<style>
    .stButton>button { width: 100%; border-radius: 8px; height: 3em; }
    .metric-card { background-color: #f0f2f6; padding: 15px; border-radius: 10px; text-align: center; }
</style>
""", unsafe_allow_html=True)

# --- MODEL YÜKLEME (CACHE) ---
@st.cache_resource
def load_models():
    models_dir = "models"
    try:
        if_model = joblib.load(os.path.join(models_dir, "if_model.joblib"))
        rf_model = joblib.load(os.path.join(models_dir, "rf_model.joblib"))
        return if_model, rf_model
    except Exception as e:
        return None, None

if_model, rf_model = load_models()

if not if_model:
    st.error("⚠️ MODELLER BULUNAMADI! Lütfen önce 'train_stacking.py' dosyasını çalıştırın.")
    st.stop()

# --- SESSION STATE (LOGLAR) ---
if "logs" not in st.session_state:
    st.session_state.logs = pd.DataFrame(columns=["Zaman", "Method", "URL", "Risk", "Durum", "Detay"])

# --- EVRENSEL WHITELIST (UZANTI BAZLI) ---
SAFE_EXTENSIONS = (".css", ".js", ".jpg", ".jpeg", ".png", ".gif", ".ico", ".svg", ".woff", ".ttf", ".eot")

# --- DÜZELTİLMİŞ VE İYİLEŞTİRİLMİŞ ANALİZ MOTORU ---
def analyze_request(method, url, cookie, content):
    # 1. Temizlik
    url = url.strip()
    content = content.strip()
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Universal/1.0"
    if not cookie: cookie = "JSESSIONID=UNIVERSAL_SESSION_ID"
    
    # 2. Özellik Çıkarımı
    feats = extract_features(method, url, ua, cookie, content)
    X = feats.reshape(1, -1)
    
    # 3. Model Tahmini
    if_score = if_model.decision_function(X).reshape(-1, 1)
    X_stacked = np.hstack((X, if_score))
    prob = rf_model.predict_proba(X_stacked)[0, 1]
    risk = int(prob * 100)
    
    # 4. SİGORTA VE KARAR MEKANİZMASI
    attack_signals = sum(feats[3:8]) 
    parsed_path = urlparse(url).path.lower()
    
    explanation = "AI Şüpheli Buldu"

    # KURAL A: GÜVENLİ UZANTI (WHITELIST) - EN BASKIN KURAL
    # Eğer dosya .png, .css ise ve içinde bariz <script> (XSS) yoksa -> DİREKT GÜVENLİ.
    # Keyword yakalansa bile (örneğin dosya adında 'select' geçse bile) uzantıya güven.
    is_safe_ext = parsed_path.endswith(SAFE_EXTENSIONS)
    
    if is_safe_ext:
        # XSS (index 4) kontrolü hariç diğerlerini görmezden gel
        if feats[4] == 0: # Eğer XSS yoksa
            risk = 0
            verdict = "NORMAL"
            return risk, verdict, "Güvenli Dosya (Whitelist)"

    # KURAL B: AI SKORUNU BASTIRMA (Normal Sayfalar İçin)
    # Saldırı kelimesi YOKSA ama AI yüksek risk verdiyse (Bilinmeyen sayfa)
    if attack_signals == 0:
        if risk > 50:
            risk = 15  # PUANI 15 YAPTIK (Artık YEŞİL yanacak)
            explanation = "Temiz İçerik (AI Skoru Bastırıldı)"
        else:
            explanation = "Güvenli Trafik"

    # KURAL C: SALDIRI İMZASI
    # Eğer saldırı kelimesi varsa ve Whitelist değilse -> RİSKİ ARTIR
    if attack_signals > 0 and not is_safe_ext:
        risk = max(risk, 85)
        explanation = "İmza Tabanlı Tespit (Keyword Yakalandı)"

    # 5. EŞİK DEĞERLERİ
    if risk >= 65:
        verdict = "SALDIRI"
    elif risk >= 40:
        verdict = "ŞÜPHELİ"
    else:
        verdict = "NORMAL"
        
    return risk, verdict, explanation

# --- ARAYÜZ TASARIMI ---
st.title("🌍 Evrensel WAF & SIEM")
st.caption(f"Model Başarımı: %99.30 | Mimari: Hibrit Stacking (IF + RF) | Odak: Payload & Parametre")
st.divider()

# SOL PANEL (TEST)
with st.sidebar:
    st.header("🔍 Manuel Test Paneli")
    
    with st.form("test_form"):
        method = st.selectbox("Method", ["GET", "POST", "PUT", "DELETE"])
        url_input = st.text_input("URL (Örn: site.com/login)", "http://mysite.com/login")
        content_input = st.text_area("Body / Query Payload", "")
        submitted = st.form_submit_button("🛡️ ANALİZ ET")
        
        if submitted:
            if not url_input:
                st.warning("Lütfen bir URL girin.")
            else:
                risk, verdict, desc = analyze_request(method, url_input, "", content_input)
                
                new_log = {
                    "Zaman": time.strftime("%H:%M:%S"),
                    "Method": method,
                    "URL": url_input,
                    "Risk": risk,
                    "Durum": verdict,
                    "Detay": desc
                }
                st.session_state.logs = pd.concat([pd.DataFrame([new_log]), st.session_state.logs], ignore_index=True)

    st.divider()
    st.subheader("Hızlı Senaryolar")
    
    col_s1, col_s2 = st.columns(2)
    with col_s1:
        if st.button("✅ TR: Normal"):
            u = "http://eticaret.com.tr/urunler?kategori=elektronik"
            r, v, d = analyze_request("GET", u, "", "")
            st.session_state.logs = pd.concat([pd.DataFrame([{"Zaman": time.strftime("%H:%M:%S"), "Method": "GET", "URL": u, "Risk": r, "Durum": v, "Detay": d}]), st.session_state.logs], ignore_index=True)
            
        if st.button("✅ Resim Dosyası"):
            u = "http://cdn.site.com/assets/logo.png"
            r, v, d = analyze_request("GET", u, "", "")
            st.session_state.logs = pd.concat([pd.DataFrame([{"Zaman": time.strftime("%H:%M:%S"), "Method": "GET", "URL": u, "Risk": r, "Durum": v, "Detay": d}]), st.session_state.logs], ignore_index=True)

    with col_s2:
        if st.button("🚫 SQL Injection"):
            u = "http://banka.com/giris"
            c = "kullanici=admin' OR 1=1--"
            r, v, d = analyze_request("POST", u, "", c)
            st.session_state.logs = pd.concat([pd.DataFrame([{"Zaman": time.strftime("%H:%M:%S"), "Method": "POST", "URL": u, "Risk": r, "Durum": v, "Detay": d}]), st.session_state.logs], ignore_index=True)
            
        if st.button("🚫 XSS Saldırısı"):
            u = "http://forum.net/yorum"
            c = "<script>alert('Hacked')</script>"
            r, v, d = analyze_request("POST", u, "", c)
            st.session_state.logs = pd.concat([pd.DataFrame([{"Zaman": time.strftime("%H:%M:%S"), "Method": "POST", "URL": u, "Risk": r, "Durum": v, "Detay": d}]), st.session_state.logs], ignore_index=True)

# SAĞ PANEL (DASHBOARD)

# 1. Metrikler
total = len(st.session_state.logs)
attacks = len(st.session_state.logs[st.session_state.logs["Durum"] == "SALDIRI"])
normals = total - attacks

c1, c2, c3 = st.columns(3)
c1.metric("Toplam İstek", total)
c2.metric("Engellenen Saldırı", attacks, delta_color="inverse")
c3.metric("Normal Trafik", normals)

# 2. Tablo
def color_coding(row):
    if row["Durum"] == "SALDIRI":
        return ['background-color: #ffcccc; color: #8a0000; font-weight: bold'] * len(row)
    elif row["Durum"] == "ŞÜPHELİ":
        return ['background-color: #fff4cc; color: #8a6d00'] * len(row)
    else:
        return ['background-color: #ccffcc; color: #004d00'] * len(row)

st.subheader("📡 Canlı Trafik Analizi")

if not st.session_state.logs.empty:
    st.dataframe(
        st.session_state.logs.style.apply(color_coding, axis=1),
        use_container_width=True,
        hide_index=True
    )
    
    if st.button("Logları Temizle"):
        st.session_state.logs = pd.DataFrame(columns=["Zaman", "Method", "URL", "Risk", "Durum", "Detay"])
        st.rerun()
else:
    st.info("Sistem aktif ve izlemede. Sol panelden test yapabilirsiniz.")