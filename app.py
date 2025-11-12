from flask import Flask, render_template, request
from urllib.parse import urlparse
import re
import whois
import socket, ssl, datetime

app = Flask(__name__)

SAMPLE_URLS = {
    "phish1": "http://192.168.1.100/login.php?user=abc",
    "phish2": "http://secure-login-paypal.com.verify.me/login",
    "phish3": "http://example.com@evil.com/login",
    "phish4": "http://very-long-domain-name-" + "a"*60 + ".com/login",
    "safe1": "https://www.google.com",
    "safe2": "https://github.com/login"
}

ip_regex = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
suspicious_words = re.compile(r'(login|verify|secure|update|account|bank|confirm|password)', re.I)



shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "rb.gy", "is.gd", "shorte.st"]

def get_domain_age(domain):
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if not creation:
            return None
        age_days = (datetime.datetime.now() - creation).days
        return age_days
    except:
        return None

def get_ssl_expiry(domain):
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.settimeout(3.0)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        datestr = cert['notAfter']
        expire_date = datetime.datetime.strptime(datestr, "%b %d %H:%M:%S %Y %Z")
        days_left = (expire_date - datetime.datetime.now()).days
        return days_left
    except:
        return None

def analyze_url(u):
    reasons = []
    u_original = u.strip()

    if not u_original:
        return {"score": 100, "reasons": ["Empty URL"], "verdict": "Invalid"}

    if not re.match(r'^[a-zA-Z]+://', u_original):
        u = "http://" + u_original
    else:
        u = u_original

    try:
        p = urlparse(u)
        host = p.hostname or ""
    except:
        return {"score": 100, "reasons": ["Malformed URL"], "verdict": "Invalid"}

    # Old checks
    if p.scheme != "https":
        reasons.append("Not HTTPS connection")

    if ip_regex.match(host):
        reasons.append("Host is an IP address")

    if '@' in u_original:
        reasons.append("Contains '@' trick")

    if len(u_original) > 75:
        reasons.append("URL too long")

    if suspicious_words.search(u_original):
        reasons.append("Contains phishing keywords")

    if host.count('.') >= 4:
        reasons.append("Too many subdomains")

    if '-' in host and host.count('-') >= 2:
        reasons.append("Too many hyphens in domain")

    # ✅ New: Shortened URL detected
    if any(s in host for s in shorteners):
        reasons.append("Shortened URL detected (may hide real site)")

    # ✅ New: WHOIS Check — Domain Age
    domain_age = get_domain_age(host)
    if domain_age is not None:
        if domain_age < 180:  # less than 6 months
            reasons.append(f"Domain very new ({domain_age} days old)")
    else:
        reasons.append("WHOIS info unavailable")

    # ✅ New: SSL Certificate expiry
    if p.scheme == "https":
        days_left = get_ssl_expiry(host)
        if days_left is not None:
            if days_left <= 0:
                reasons.append("SSL Certificate is expired")
            elif days_left < 30:
                reasons.append("SSL Certificate expires soon")
        else:
            reasons.append("Could not verify SSL certificate")

    # score calculation
    score = min(100, len(reasons) * 15)
    if score <= 30:
        verdict = "Low Risk (Likely Safe)"
        color = "green"
    elif score <= 60:
        verdict = "Medium Risk (Suspicious)"
        color = "yellow"
    else:
        verdict = "High Risk (Possible Phishing)"
        color = "red"

    return {
        "original": u_original,
        "score": score,
        "reasons": reasons,
        "verdict": verdict,
        "color": color
    }


def analyze_email(text):
    reasons=[]
    text = (text or "").strip()

    if not text:
        return {"score":100,"reasons":["Empty email"],"verdict":"Invalid"}

    urls = re.findall(r'(https?://[^\s]+)', text)
    if len(urls) >= 2:
        reasons.append("Email contains multiple links")
    if re.search(r'(urgent|verify|immediately|update|account|password|click here)', text, re.I):
        reasons.append("Contains urgent or pressure language")
    if re.search(r'(attachment|download|invoice)', text, re.I):
        reasons.append("Mentions attachment/download")
    if urls:
        first = analyze_url(urls[0])
        if first["score"] >= 40:
            reasons.append("Contained link looks suspicious")

    score = min(100, 20*len(reasons))
    if score == 0:
        verdict = "Low Risk"
    elif score <= 40:
        verdict = "Medium Risk"
    else:
        verdict = "High Risk"

    return {"score":score,"reasons":reasons,"verdict":verdict, "urls":urls}

@app.route("/", methods=["GET","POST"])
def home():
    if request.method == "POST":
        mode = request.form.get("mode")
        text = request.form.get("input_text")
        if mode == "url":
            result = analyze_url(text)
            return render_template("result.html", mode="URL", result=result)
        else:
            result = analyze_email(text)
            return render_template("result.html", mode="EMAIL", result=result)
    return render_template("index.html", samples=SAMPLE_URLS)

if __name__ == "__main__":
    app.run(debug=True)
