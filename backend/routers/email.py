from fastapi import APIRouter, Form
from fastapi.responses import JSONResponse
from utils.nlp_msg import inspect_email_upi

router = APIRouter()

@router.post("/email")
async def inspect_email(
    raw_email: str = Form(...),
    require_upi: bool = Form(True)
):
    """
    Expects the raw RFC822 email text (or the body) as `raw_email`.
    """
    output = inspect_email_upi(raw_email, require_upi=require_upi)

    artifacts = output.get("artifacts", {}) or {}
    frm = str(artifacts.get("from", "")).lower()
    subj = str(artifacts.get("subject", "")).lower()
    body = raw_email.lower()

    # -------- RULE 1: Refund + Pending in subject --------
    if "refund" in subj and "pending" in subj:
        old_score = float(output.get("risk_score", 0.0) or 0.0)
        new_score = max(old_score, 0.7)
        output["risk_score"] = round(new_score, 3)

        if output.get("label") == "safe":
            output["label"] = "suspicious"

        reasons = output.get("reasons") or []
        reasons.append("refund_subject_pattern")
        output["reasons"] = reasons

    # -------- RULE 2: Account block / suspend threats in subject --------
    block_keywords = ("block", "blocked", "suspend", "suspended", "deactivate", "deactivated")
    if "account" in subj and any(k in subj for k in block_keywords):
        old_score = float(output.get("risk_score", 0.0) or 0.0)
        new_score = max(old_score, 0.75)
        output["risk_score"] = round(new_score, 3)

        if output.get("label") == "safe":
            output["label"] = "suspicious"

        reasons = output.get("reasons") or []
        reasons.append("account_block_threat_subject")
        output["reasons"] = reasons

    # -------- RULE 3: RBI + KYC + UPI/suspension + short link --------
    kyc_in_subj = "kyc" in subj
    kyc_in_body = "kyc" in body
    rbi_in_subj = "rbi" in subj or "reserve bank" in body
    upi_in_body = "upi" in body
    suspend_in_body = any(k in body for k in ("suspend", "suspended", "disable", "deactivate"))

    looks_like_short_link = any(
        s in body for s in ("tinyurl.com", "bit.ly", "t.co", "shorturl", "is.gd")
    )

    if (kyc_in_subj or kyc_in_body) and (rbi_in_subj or upi_in_body or suspend_in_body) and looks_like_short_link:
        old_score = float(output.get("risk_score", 0.0) or 0.0)
        new_score = max(old_score, 0.8)
        output["risk_score"] = round(new_score, 3)

        if output.get("label") == "safe":
            output["label"] = "suspicious"

        reasons = output.get("reasons") or []
        reasons.append("rbi_kyc_upi_link_pattern")
        output["reasons"] = reasons

    # -------- RULE 4: Lottery / Prize / Jackpot email (your new case) --------
    # e.g. "Congratulations! You Won ₹50,00,000"
    lottery_keywords = ("won", "winner", "winnings", "jackpot", "lottery", "prize", "reward")
    has_congrats = "congratulations" in subj or "congrats" in subj
    has_lottery = any(k in subj for k in lottery_keywords)

    if has_congrats and has_lottery:
        old_score = float(output.get("risk_score", 0.0) or 0.0)
        # treat lottery/prize scams as high risk
        new_score = max(old_score, 0.85)
        output["risk_score"] = round(new_score, 3)

        if output.get("label") == "safe":
            output["label"] = "suspicious"

        reasons = output.get("reasons") or []
        reasons.append("lottery_prize_subject_pattern")
        output["reasons"] = reasons

    # -------------------------------------------------------------------

    return JSONResponse(content=output)
