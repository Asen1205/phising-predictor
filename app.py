import streamlit as st
import joblib
import pandas as pd
from urllib.parse import urlparse
from datetime import datetime
import socket
import ssl
import requests
import base64
from pathlib import Path

# -----------------------------
# 1. Load the trained XGBoost pipeline
# -----------------------------
pipeline = joblib.load("xgb_pipeline.pkl")  # your single trained pipeline

# -----------------------------
# 2. Utility functions
# -----------------------------
def domain_exists(domain: str) -> int:
    if not domain:
        return 0
    try:
        socket.gethostbyname(domain)
        return 1
    except:
        return 0

def dns_a_record(domain: str):
    try:
        return socket.gethostbyname(domain)
    except:
        return None

def ssl_check(hostname: str) -> str:
    if not hostname:
        return "No hostname"
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(4)
            s.connect((hostname, 443))
            cert = s.getpeercert()
            return "Valid SSL"
    except:
        return "No/Invalid SSL"

def geo_country(ip: str):
    if not ip:
        return "Unknown"
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=country", timeout=4)
        if resp.status_code == 200:
            j = resp.json()
            return j.get("country", "Unknown")
        return "Unknown"
    except:
        return "Unknown"

def reputation_check_urlhaus(hostname: str):
    if not hostname:
        return "Unknown"
    try:
        resp = requests.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": hostname}, timeout=6)
        if resp.status_code == 200 and "query_status" in resp.text.lower():
            if "no results" in resp.text.lower():
                return "Clean"
            return "⚠ Blacklisted"
        return "Unknown"
    except:
        return "Unknown"

# -----------------------------
# 3. Feature extraction (all expected columns)
# -----------------------------
def extract_features(url: str) -> pd.DataFrame:
    parsed = urlparse(url if url.startswith(("http://", "https://")) else "http://" + url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""

    features = {
        "url_len": len(url),
        "length_hostname": len(hostname),
        "nb_dots": url.count("."),
        "nb_hyphens": url.count("-"),
        "nb_at": url.count("@"),
        "nb_slash": url.count("/"),
        "ip": 1 if hostname.replace('.', '').isdigit() else 0,
        "nb_underscore": url.count("_"),
        "nb_eq": url.count("="),
        "nb_percent": url.count("%"),
        "nb_and": url.count("&"),
        "nb_or": url.count("|"),
        "nb_qm": url.count("?"),
        "nb_star": url.count("*"),
        "nb_colon": url.count(":"),
        "nb_dollar": url.count("$"),
        "nb_comma": url.count(","),
        "nb_semicolumn": url.count(";"),
        "nb_space": url.count(" "),
        "nb_www": 1 if "www." in url.lower() else 0,
        "length_words_raw": len(url.split("/")),
        "longest_word_path": max((len(w) for w in path.split("/") if w), default=0),
        "shortest_word_path": min((len(w) for w in path.split("/") if w), default=0),
        "longest_word_host": max((len(w) for w in hostname.split(".") if w), default=0),
        "shortest_word_host": min((len(w) for w in hostname.split(".") if w), default=0),
    }

    # Add defaults for remaining pipeline features
    for col in pipeline.feature_names_in_:
        if col not in features:
            features[col] = 0

    return pd.DataFrame([features])

# -----------------------------
# 4. Streamlit UI
# -----------------------------
st.markdown(
    """
    <style>
    [data-testid="stAppViewContainer"] {
        background-image: linear-gradient(180deg, #000000, #2779F5);
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

url_input = st.text_input("Enter a URL:")

if st.button("Check URL") and url_input.strip():
    with st.spinner("Analyzing..."):
        try:
            parsed = urlparse(url_input if url_input.startswith(("http://", "https://")) else "http://" + url_input)
            hostname = parsed.hostname or parsed.path.split("/")[0]

            # Extract features and predict
            X = extract_features(url_input)
            prob = pipeline.predict_proba(X)[0][1]
            label = "釣魚網站" if prob > 0.5 else "正常網站"

            # Additional checks
            domain_ok = domain_exists(hostname)
            dns_ip = dns_a_record(hostname)
            ssl_status = ssl_check(hostname)
            country = geo_country(dns_ip) if dns_ip else "Unknown"
            rep = reputation_check_urlhaus(hostname)

            if domain_ok == 0:
                label = "Phishing (domain does not resolve)"

            # Display results
            if "phish" in label.lower():
                st.error(f"{label}")
            else:
                st.success(f"{label}")

            st.subheader("Additional checks")
            st.write(f"**Domain:** {hostname}")
            st.write(f"**DNS A record:** {dns_ip if dns_ip else 'None'}")
            st.write(f"**Domain exists:** {'Yes' if domain_ok else 'No'}")
            st.write(f"**SSL:** {ssl_status}")
            st.write(f"**IP geolocation:** {country}")
            st.write(f"**Reputation (URLhaus):** {rep}")

        except Exception as e:
            st.error(f"Error during analysis: {e}")

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
