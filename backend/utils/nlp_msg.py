import re
import hashlib
from email import message_from_string, policy
from urllib.parse import urlparse, parse_qs, unquote_plus
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

# ---------- Simple heuristic / tiny demo model -----------
PHISH_KEYWORDS = set([
    "kyc","update","verify","urgent","immediately","otp","limited","refund","reward",
    "collect","upi","paytm","gpay","googlepay","bank","account","transfer","payment",
    "login","credentials","click","claim","secure","authenticate","password"
])

# tiny seed dataset (keeps TF-IDF + LR runnable offline)
MSG_SUSP = [
    "urgent verify your account now otp required",
    "upi collect request from unknown sender approve now",
    "update kyc to avoid suspension"
]
MSG_SAFE = [
    "payment received successfully thank you",
    "your order has been dispatched"
]

VEC_MSG = TfidfVectorizer(ngram_range=(1,2), min_df=1, max_features=3000)
VEC_MSG.fit(MSG_SUSP + MSG_SAFE)

MSG_CLS = LogisticRegression(max_iter=1000)
X = VEC_MSG.transform(MSG_SUSP + MSG_SAFE)
y = [1]*len(MSG_SUSP) + [0]*len(MSG_SAFE)
MSG_CLS.fit(X, y)

def nlp_score_msg(text: str) -> float:
    text = (text or "").strip().lower()
    if not text:
        return 0.02
    try:
        v = VEC_MSG.transform([text])
        return float(MSG_CLS.predict_proba(v)[0][1])
    except Exception:
        return 0.5

def is_valid_vpa(pa: str) -> bool:
    return bool(pa and re.fullmatch(r"[a-zA-Z0-9.\-_]{2,}@[a-zA-Z0-9.\-]{2,}", pa))

# ---------------- Message classification ----------------
def classify_message_upi(message: str, sender: str = None, require_upi: bool = True) -> dict:
    t = (message or "").strip()
    lower = t.lower()
    nlp = nlp_score_msg(t)
    heur = min(sum(1 for k in PHISH_KEYWORDS if k in lower) * 0.12, 0.95)
    score = float(0.5*nlp + 0.5*heur)
    reasons = []

    # detect UPI indicators in text
    has_upi_keywords = any(x in lower for x in ["upi", "collect", "paytm", "gpay", "pa=", "pay?pa=", "upi://"])
    if require_upi and not has_upi_keywords:
        reasons.append("No UPI-related keywords found but UPI messages were expected")
        return {
            "risk_score": 0.6,
            "label": "suspicious",
            "reasons": reasons,
            "suggestions": ["Expect only UPI-related messages for validation", "If this is not a UPI message, set require_upi=False"],
            "artifacts": {"message_sha256": hashlib.sha256(t.encode()).hexdigest()}
        }

    # strong rule: message containing "collect" + "upi" => bump
    if "collect" in lower and "upi" in lower:
        score = max(score, 0.7)
        reasons.append("UPI collect language present")

    # strong rule: explicit request to approve or share OTP
    if any(x in lower for x in ["share otp", "share your otp", "enter otp", "upi pin", "share upi pin"]):
        score = max(score, 0.95)
        reasons.append("Asks for OTP/UPI PIN (sensitive)")

    label = "malicious" if score >= 0.85 else ("suspicious" if score >= 0.45 else "safe")
    suggestions = [
        "Never share OTP or UPI PIN",
        "Verify requests via official app or direct call to payee",
        "Avoid tapping unknown links in messages"
    ]
    return {
        "risk_score": round(float(score),3),
        "label": label,
        "reasons": list(dict.fromkeys(reasons)),
        "suggestions": suggestions,
        "artifacts": {"message_sha256": hashlib.sha256(t.encode()).hexdigest(), "nlp": round(nlp,3), "heur": round(heur,3)}
    }

# ---------------- Email inspection ----------------
def parse_email_raw(raw_email: str):
    try:
        msg = message_from_string(raw_email, policy=policy.default)
    except Exception:
        return None
    return msg

def extract_domain(addr: str) -> str:
    m = re.search(r"@([A-Za-z0-9\.\-]+)", addr or "")
    return m.group(1).lower() if m else ""

def inspect_email_upi(raw_email: str, require_upi: bool = True) -> dict:
    msg = parse_email_raw(raw_email)
    if msg is None:
        return {"error":"invalid raw email format"}
    from_hdr = msg.get("From","")
    subject = msg.get("Subject","")
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    body += part.get_content()
                except Exception:
                    pass
    else:
        try:
            body = msg.get_content()
        except Exception:
            body = ""

    text = f"{subject}\n{body}\n{from_hdr}".strip()
    lower = text.lower()

    # UPI expectation
    has_upi_keywords = any(x in lower for x in ["upi", "collect", "pa=", "upi://", "paytm", "gpay"])
    if require_upi and not has_upi_keywords:
        return {
            "risk_score": 0.6,
            "label": "suspicious",
            "reasons": ["Email does not appear to contain UPI-related content but UPI emails were expected"],
            "suggestions": ["Provide UPI-related email (with UPI payload) or disable require_upi"],
            "artifacts": {"from": from_hdr, "subject": subject, "message_sha256": hashlib.sha256(raw_email.encode()).hexdigest()}
        }

    # heuristics
    reasons = []
    heur = 0.0
    if any(k in subject.lower() for k in ["urgent","verify","suspend","account","otp","action required"]):
        heur += 0.2
        reasons.append("Urgent-sounding subject")
    reply_to = msg.get("Reply-To","")
    if reply_to and extract_domain(reply_to) and extract_domain(reply_to) != extract_domain(from_hdr):
        heur += 0.25
        reasons.append("Reply-To domain differs from From domain")
    # attachments check
    attachments = []
    for part in msg.iter_attachments():
        fn = part.get_filename()
        ctype = part.get_content_type()
        attachments.append({"filename": fn, "content_type": ctype})
        if ctype in ("application/x-msdownload","application/x-msdos-program") or (fn and fn.lower().endswith((".exe",".scr"))):
            heur += 0.45
            reasons.append("Executable attachment")

    # combine with a small NLP score (reuse message nlp)
    try:
        nlp = nlp_score_msg(text)
    except Exception:
        nlp = 0.3
    score = float(0.5*nlp + 0.5*min(heur,0.95))

    label = "malicious" if score >= 0.85 else ("suspicious" if score >= 0.45 else "safe")
    suggestions = [
        "Do not click suspicious links",
        "Verify sender via a different channel",
        "Do not open unexpected attachments"
    ]
    return {
        "risk_score": round(score,3),
        "label": label,
        "reasons": list(dict.fromkeys(reasons)),
        "suggestions": suggestions,
        "artifacts": {"from": from_hdr, "subject": subject, "attachments": attachments, "message_sha256": hashlib.sha256(raw_email.encode()).hexdigest()}
    }

# ---------------- URL helpers & classification ----------------
SUSPICIOUS_TLDS = {".ru", ".tk", ".cn", ".ml", ".ga", ".gq", ".cf", ".xyz"}

def extract_url_features_simple(url: str):
    if not url:
        return {"host":"","path":"","tld":"","has_ip_host":False,"many_subdomains":False,"has_at_symbol":False,"long_url":False,"suspicious_tld":False}
    parsed = urlparse(url if "://" in url else "http://" + url)
    host = (parsed.netloc or parsed.path).lower()
    path = parsed.path.lower()
    tld = "." + host.split(".")[-1] if "." in host else ""
    return {
        "host": host, "path": path, "tld": tld,
        "has_ip_host": bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host)),
        "many_subdomains": host.count(".") >= 3,
        "has_at_symbol": "@" in url,
        "long_url": len(url) > 90,
        "suspicious_tld": tld in SUSPICIOUS_TLDS
    }

def heuristic_url_score_simple(feats: dict) -> float:
    score = 0.0
    if feats.get("has_ip_host"): score += 0.35
    if feats.get("many_subdomains"): score += 0.2
    if feats.get("has_at_symbol"): score += 0.25
    if feats.get("long_url"): score += 0.1
    if feats.get("suspicious_tld"): score += 0.3
    if "login" in feats.get("path","") or "verify" in feats.get("path","") or "secure" in feats.get("path",""):
        score += 0.2
    return min(score, 0.99)

def classify_link_upi(url: str, context_text: str = "", require_upi: bool = True) -> dict:
    url = (url or "").strip()
    feats = extract_url_features_simple(url)
    heur = heuristic_url_score_simple(feats)
    text_for_models = f"{context_text or ''} {feats.get('host','')} {feats.get('path','')} {url}"
    nlp = nlp_score_msg(text_for_models)
    score = float(0.5*nlp + 0.5*heur)

    is_upi = url.lower().startswith("upi:") or "pa=" in url or "upi://" in url
    if require_upi and not is_upi:
        return {
            "risk_score": 0.6,
            "label": "suspicious",
            "reasons": ["URL is not a UPI link but UPI link was expected"],
            "suggestions": ["Provide a proper UPI deep link (upi://pay?pa=...) or set require_upi=False"],
            "artifacts": {"features": feats}
        }

    reasons = []
    if feats.get("suspicious_tld"):
        reasons.append("Suspicious TLD")
        score = max(score, 0.75)
    if feats.get("has_ip_host"):
        reasons.append("IP host in URL")
        score = max(score, 0.75)
    if feats.get("has_at_symbol"):
        reasons.append("Contains @ (possible obfuscation)")
        score = max(score, 0.6)

    label = "malicious" if score >= 0.85 else ("suspicious" if score >= 0.45 else "safe")
    suggestions = ["Avoid entering UPI PIN/OTP on web pages", "Verify payee UPI ID in official app", "Open links only from trusted sources"]
    return {"risk_score": round(score,3), "label": label, "reasons": reasons, "suggestions": suggestions, "artifacts": {"features": feats, "nlp": round(nlp,3)}}
