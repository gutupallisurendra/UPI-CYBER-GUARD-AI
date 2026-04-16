from fastapi import APIRouter, Form
from fastapi.responses import JSONResponse
from urllib.parse import urlparse

from utils.nlp_msg import classify_link_upi

router = APIRouter()

@router.post("/link")
async def inspect_link(
    url: str = Form(...),
    context_text: str = Form(""),
    require_upi: bool = Form(True),
):
    """
    Inspect a URL for UPI / fraud risk.
    """
    output = classify_link_upi(url, context_text=context_text, require_upi=require_upi)

    raw_url = (url or "").strip()
    lower_url = raw_url.lower()
    parsed = urlparse(raw_url)
    host = (parsed.netloc or "").lower()
    path = (parsed.path or "").lower()
    ctx = (context_text or "").lower()

    # ---------------- Heuristic groups ----------------
    # Suspicious TLDs often used in scams
    susp_tlds = (".site", ".xyz", ".top", ".online", ".shop", ".buzz", ".info")
    # Common shorteners
    shorteners = ("bit.ly", "tinyurl.com", "t.co", "is.gd", "shorturl", "cutt.ly", "rb.gy")
    # Payment / verification intent
    pay_words = ("pay", "payment", "upi", "verify", "verification", "kyc", "refund", "claim")
    # Fake security / support patterns
    fake_security_words = ("secure-", "security-", "support-", "help-", "verify-", "login-", "auth-")

    is_shortener = any(s in host for s in shorteners)
    has_susp_tld = any(host.endswith(tld) for tld in susp_tlds)
    has_pay_words = any(w in lower_url for w in pay_words)
    has_fake_security = any(w in host for w in fake_security_words)
    looks_like_http = lower_url.startswith("http://") or lower_url.startswith("https://")

    # crude: bank/upi brand names + extra junk
    bankish = ("sbi", "hdfc", "icici", "axis", "paytm", "phonepe", "gpay", "googlepay", "upi")
    has_bankish = any(b in host for b in bankish)

    # --------------------------------------------------
    # RULE 1: Shortener + payment / KYC / refund words
    if is_shortener and has_pay_words:
        old = float(output.get("risk_score", 0.0) or 0.0)
        output["risk_score"] = round(max(old, 0.75), 3)
        if output.get("label") == "safe":
            output["label"] = "suspicious"
        reasons = output.get("reasons") or []
        reasons.append("short_link_with_payment_terms")
        output["reasons"] = reasons

    # RULE 2: Suspicious TLD + payment/verify intent
    if has_susp_tld and has_pay_words:
        old = float(output.get("risk_score", 0.0) or 0.0)
        output["risk_score"] = round(max(old, 0.8), 3)
        if output.get("label") == "safe":
            output["label"] = "suspicious"
        reasons = output.get("reasons") or []
        reasons.append("suspicious_tld_with_payment_terms")
        output["reasons"] = reasons

    # RULE 3: Fake bank/UPI support domains (e.g. sbi-verify-secure.online)
    if has_bankish and (has_susp_tld or has_fake_security):
        old = float(output.get("risk_score", 0.0) or 0.0)
        output["risk_score"] = round(max(old, 0.85), 3)
        if output.get("label") == "safe":
            output["label"] = "suspicious"
        reasons = output.get("reasons") or []
        reasons.append("fake_bankish_support_domain")
        output["reasons"] = reasons

    # RULE 4: Very generic "pay now" style domain on shady TLD
    if has_susp_tld and ("pay" in host or "payment" in host or "pay-" in host or "-pay" in host):
        old = float(output.get("risk_score", 0.0) or 0.0)
        output["risk_score"] = round(max(old, 0.78), 3)
        if output.get("label") == "safe":
            output["label"] = "suspicious"
        reasons = output.get("reasons") or []
        reasons.append("generic_pay_domain_on_suspicious_tld")
        output["reasons"] = reasons

    return JSONResponse(content=output)
