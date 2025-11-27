import streamlit as st
import joblib
from urllib.parse import urlparse
import socket
import ssl
import requests
import base64
from pathlib import Path

from datetime import datetime

try:
    import whois as whois_lib
    WHOIS_AVAILABLE = True
except Exception:
    WHOIS_AVAILABLE = False

model_content = joblib.load("model_content.pkl")
model_struct = joblib.load("model_structural.pkl")
X_content_cols = joblib.load("X_content_cols.pkl")
X_struct_cols = joblib.load("X_struct_cols.pkl")

def domain_exists(domain: str) -> int:
    """Return 1 if domain resolves to an IP, otherwise 0."""
    if not domain:
        return 0
    try:
        socket.gethostbyname(domain)
        return 1
    except socket.gaierror:
        return 0
    except Exception:
        return 0

def dns_a_record(domain: str):
    """Return resolved IP or None."""
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None

def ssl_check(hostname: str) -> str:
    """Quick SSL/TLS check: returns 'Valid SSL' or 'No/Invalid SSL'."""
    if not hostname:
        return "No hostname"
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(4)
            s.connect((hostname, 443))
            cert = s.getpeercert()

            return "Valid SSL"
    except Exception:
        return "No/Invalid SSL"

def whois_age_days(domain: str):
    """Return number of days since domain creation or None/Unknown."""
    if not WHOIS_AVAILABLE or not domain:
        return None
    try:
        w = whois_lib.whois(domain)
        creation = w.creation_date
        if creation is None:
            return None
        if isinstance(creation, list):
            creation = creation[0]
        if creation is None:
            return None
        age_days = (datetime.utcnow() - creation).days
        return max(age_days, 0)
    except Exception:
        return None

def geo_country(ip: str):
    """Return country using ip-api (free, rate-limited) or 'Unknown'."""
    if not ip:
        return "Unknown"
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=country", timeout=4)
        if resp.status_code == 200:
            j = resp.json()
            return j.get("country", "Unknown")
        return "Unknown"
    except Exception:
        return "Unknown"

def reputation_check_urlhaus(hostname: str):
    """
    Simple reputation check using URLhaus host API.
    The API requires POST with form data {"host": hostname}
    Response parsing here is simplistic; treat failures as Unknown.
    """
    if not hostname:
        return "Unknown"
    try:
        resp = requests.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": hostname}, timeout=6)
        if resp.status_code == 200 and "query_status" in resp.text.lower():
            # If the host is known malicious, API returns data; we check presence of 'url_list' or similar
            if "no results" in resp.text.lower():
                return "Clean"
            return "⚠ Blacklisted"
        return "Unknown"
    except Exception:
        return "Unknown"

def extract_content_features(url: str):
    """
    Build a dictionary of content-like features and then return a list
    aligned with X_content_cols. Do NOT add features that were NOT in training.
    """
    parsed = urlparse(url if url.startswith(("http://", "https://")) else "http://" + url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    features = {}

    features["url_len"] = len(url)
    features["url_has_login"] = 1 if "login" in url.lower() else 0
    features["url_has_client"] = 1 if "client" in url.lower() else 0
    features["url_has_server"] = 1 if "server" in url.lower() else 0
    features["url_has_admin"] = 1 if "admin" in url.lower() else 0
    features["url_has_ip"] = 1 if hostname.replace('.', '').isdigit() else 0
    features["url_isshorted"] = 1 if any(s in hostname.lower() for s in ("bit.ly", "t.co", "tinyurl", "goo.gl", "ow.ly")) else 0
    features["url_len"] = len(url)
    features["url_entropy"] = 0  
    row = []

    for col in X_content_cols:
        row.append(float(features.get(col, 0)))
    return row

def extract_structural_features(url: str):
    """
    Build a dictionary of structural features and return a list aligned with X_struct_cols.
    NOTE: do NOT include domain_exists as a model feature unless your model expects it.
    We will use domain_exists as a separate check outside the model.
    """
    parsed = urlparse(url if url.startswith(("http://", "https://")) else "http://" + url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    features = {}
    features["length_url"] = len(url)
    features["length_hostname"] = len(hostname)
    features["ip"] = 1 if hostname.replace('.', '').isdigit() else 0
    features["nb_dots"] = url.count('.')
    features["nb_hyphens"] = url.count('-')
    features["nb_at"] = url.count('@')
    features["nb_qm"] = url.count('?')
    features["nb_and"] = url.count('&')
    features["nb_or"] = url.count('|')
    features["nb_eq"] = url.count('=')
    features["nb_underscore"] = url.count('_')
    features["nb_percent"] = url.count('%')
    features["nb_slash"] = url.count('/')

        row = []
    for col in X_struct_cols:
        row.append(float(features.get(col, 0)))
    return row

def ensemble_predict(url: str):
    """
    Predict using both models and average probability.
    Returns (label, avg_prob, prob_content, prob_struct).
    """
    content_vec = extract_content_features(url)
    struct_vec = extract_structural_features(url)

    prob_content = model_content.predict_proba([content_vec])[0][1] if hasattr(model_content, "predict_proba") else model_content.predict([content_vec])[0]
    prob_struct = model_struct.predict_proba([struct_vec])[0][1] if hasattr(model_struct, "predict_proba") else model_struct.predict([struct_vec])[0]

    avg_prob = (float(prob_content) + float(prob_struct)) / 2.0
    label = "Phishing" if avg_prob > 0.5 else "Legitimate"
    return label, avg_prob, float(prob_content), float(prob_struct)

st.markdown(
    """
    <style>
    [data-testid="stAppViewContainer"] {
        background-image: linear-gradient(180deg, #000000, #4b0082, #f1c232);
    }
    </style>
    """,
    unsafe_allow_html=True
)
st.set_page_config(page_title="Phishing URL Detector (Ensemble + Checks)", layout="wide")
st.markdown('<h1 style="background-color:#f5f7fa;padding:10px;color:#000000;text-align:center;">這是一個用於預測釣魚網站和合法網站的網站。</h1>', unsafe_allow_html=True)
st.markdown("---")
st.markdown('<h2 style="text-align:center;">網路釣魚網址預測器 (Phishing URL Predictor) 🔍</h2>',unsafe_allow_html=True)
st.markdown("<br>", unsafe_allow_html=True)
st.markdown('<h4 style="text-align:center;">輸入單一網址即可獲得預測結果和多項安全檢查。此過程使用您已訓練的兩個模型（內容模型和結構模型）。</h4>',unsafe_allow_html=True)

url_input = st.text_input("URL", value="")

if st.button("Check URL"):
    if not url_input or not url_input.strip():
        st.warning("Please enter a URL (e.g. https://example.com).")
    else:
        with st.spinner("Analyzing..."):
            try:
                parsed = urlparse(url_input if url_input.startswith(("http://", "https://")) else "http://" + url_input)
                hostname = parsed.hostname or parsed.path.split("/")[0]

                label, avg_prob, p_content, p_struct = ensemble_predict(url_input)

                domain_ok = domain_exists(hostname)
                dns_ip = dns_a_record(hostname)

                ssl_status = ssl_check(hostname)
                
                age_days = whois_age_days(hostname)
                age_str = f"{age_days} days" if isinstance(age_days, int) else "Unknown"
                
                country = geo_country(dns_ip) if dns_ip else "Unknown"
                
                rep = reputation_check_urlhaus(hostname)

                if domain_ok == 0:
                    final_label = "Phishing (domain does not resolve)"
                else:
                    final_label = label

                st.subheader("🔎 Result")
                if "phish" in final_label.lower():
                    st.error(f"{final_label} — score: {avg_prob:.3f} (content: {p_content:.3f}, structural: {p_struct:.3f})")
                else:
                    st.success(f"{final_label} — score: {avg_prob:.3f} (content: {p_content:.3f}, structural: {p_struct:.3f})")

                st.subheader("⚠️ Additional checks")
                st.write(f"**Domain:** {hostname}")
                st.write(f"**DNS A record:** {dns_ip if dns_ip else 'None / does not resolve'}")
                st.write(f"**Domain exists:** {'Yes' if domain_ok else 'No'}")
                st.write(f"**SSL:** {ssl_status}")
                st.write(f"**WHOIS domain age:** {age_str} {'(whois not installed)' if not WHOIS_AVAILABLE else ''}")
                st.write(f"**IP geolocation (country):** {country}")
                st.write(f"**Reputation (URLhaus):** {rep}")

                if st.checkbox("Show extracted feature vectors"):
                    st.write("Content vector (aligned to X_content_cols):")
                    st.write(dict(zip(X_content_cols, extract_content_features(url_input))))
                    st.write("Structural vector (aligned to X_struct_cols):")
                    st.write(dict(zip(X_struct_cols, extract_structural_features(url_input))))

            except Exception as e:
                st.exception(f"Error during analysis: {e}")

img_path = Path("phishing.jpg")

if not img_path.exists():
    st.error("Image not found: place phishing.jpg in app folder")
else:
    with open(img_path, "rb") as f:
        data = f.read()
    b64 = base64.b64encode(data).decode("utf-8")
    img_src = f"data:image/jpeg;base64,{b64}"

    html = f"""
    <div style="
        padding: 15px;
        border-radius: 8px;
        background-color: #F6FFF6;
        display: flex;
        align-items: flex-middle;
        gap: 20px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.15);
        max-width: 1920px;
    ">
        <img src="{img_src}" alt="Phishing Example" style="width: 220px; border-radius: 10px; object-fit:cover;" />
        <div>
            <h4 style="color: black; margin: 0 0 10px 0;">什麼是網路釣魚？</h4>
            <p style="color: black; margin: 0 0 8px 0;">
            網路釣魚（Phishing）是一種常見的網路攻擊手法。攻擊者會假裝成可信任的個人、公司或機構，
            誘使人們主動提供敏感資料，例如密碼、信用卡號、銀行帳戶資訊或個人身分資料。
            </p>
            <p style="color: black; margin: 0;">
            網路釣魚最常透過電子郵件、簡訊、假網站或社群平台訊息進行。攻擊者通常會使用緊急或威脅性的語氣，
            例如「你的帳戶即將被停用」，讓使用者在慌張下做出錯誤的決定。
            </p>
        </div>
    </div>
    """

    st.markdown(html, unsafe_allow_html=True)
    
st.markdown("<br>", unsafe_allow_html=True)
st.markdown("<br>", unsafe_allow_html=True)

#box 2
img_path = Path("phishing_effects.jpg")

if not img_path.exists():
    st.error("Image not found: place phishing.jpg in app folder")
else:
    with open(img_path, "rb") as f:
        data = f.read()
    b64 = base64.b64encode(data).decode("utf-8")
    img_src = f"data:image/jpeg;base64,{b64}"


    html = f"""
    <div style="
        padding: 15px;
        border-radius: 8px;
        background-color: #F6FFF6;
        display: flex;
        align-items: flex-start;
        gap: 20px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.15);
        max-width: 1920px;
    ">
        <img src="{img_src}" alt="Phishing Example" style="width: 660px; border-radius: 10px; object-fit:cover;" />
        <div>
            <h4 style="color: black; margin: 0 0 10px 0;">網路釣魚的影響</h4>
            <p style="color: black; margin: 0 0 8px 0;">
            網路釣魚可能帶來嚴重後果，包括:
            </p>
            <p style="color: black; font-weight:bold; margin: 0;">
            1. 金錢損失
            </p>
            <p style="color: black; margin: 0;">
            受害者可能會被盜刷、被騙匯款或損失銀行存款。
            </p>
            <p style="color: black; font-weight:bold; margin: 0;">
            2. 身分盜用
            </p>
            <p style="color: black; margin: 0;">
            攻擊者可能利用被竊取的個資冒用身分，申請信用卡、貸款或進行犯罪行為。
            </p>
            <p style="color: black; font-weight:bold; margin: 0;">
            3. 帳戶被入侵
            </p>
            <p style="color: black; margin: 0;">
            電子郵件、社群帳號或公司系統可能遭到駭入，造成隱私洩漏或更多攻擊。
            </p>
            <p style="color: black; font-weight:bold; margin: 0;">
            4. 資料外洩
            </p>
            <p style="color: black; margin: 0;">
            對企業或學校而言，網路釣魚可能導致大規模資料洩漏，影響更多人。
            </p>
            <p style="color: black; font-weight:bold; margin: 0;">
            5. 心理壓力
            </p>
            <p>
            受害者可能感到焦慮、害怕或尷尬，因為自己被騙。
            </p>
        </div>
    </div>
    """

    st.markdown(html, unsafe_allow_html=True)

# Small footer
st.markdown("---")
st.markdown('<h7 style="text-align:center;">© 第9組. 版權所有</h7>',unsafe_allow_html=True)

