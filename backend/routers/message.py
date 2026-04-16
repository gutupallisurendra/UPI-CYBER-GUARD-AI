from fastapi import APIRouter, Form
from fastapi.responses import JSONResponse
from utils.nlp_msg import classify_message_upi

router = APIRouter()

@router.post("/message")
async def inspect_message(
    message: str = Form(...),
    sender: str = Form(None),
    require_upi: bool = Form(True)
):
    """
    Inspect an SMS/WhatsApp message for UPI / fraud risk.
    """
    output = classify_message_upi(message, sender, require_upi)

    text = (message or "").lower()
    snd = (sender or "").lower()

    # ======================= KEYWORD GROUPS =============================
    refund_keywords = ("refund", "cashback", "winning", "lottery")
    urgency_keywords = ("pending", "immediately", "urgent", "within 30 minutes", "last chance")
    block_keywords = ("account blocked", "suspend", "deactivate", "terminated")
    kyc_keywords = ("kyc", "re-kyc", "e-kyc")

    # NEW: delivery scam keywords
    delivery_keywords = (
        "fedex", "dhl", "bluedart", "parcel", "shipment", "package", "customs", "custom fee",
        "delivery on hold", "parcel on hold"
    )

    # crude link detection
    looks_like_link = any(link in text for link in ("http://", "https://", "bit.ly", "tinyurl", ".site", ".shop", ".online"))

    # suspicious sender
    shady_sender = snd and not snd.isdigit() and not snd.endswith((".com", ".in"))

    # ==================== MATCHING RULES ================================

    has_refund = any(k in text for k in refund_keywords)
    has_urgency = any(k in text for k in urgency_keywords)
    has_block = any(k in text for k in block_keywords)
    has_kyc = any(k in text for k in kyc_keywords)
    has_delivery = any(k in text for k in delivery_keywords)

    # ---- RULE A: Refund + urgency/link → suspicious
    if (has_refund or has_kyc or has_block) and (has_urgency or looks_like_link):
        old = float(output.get("risk_score", 0.0))
        output["risk_score"] = round(max(old, 0.7), 3)
        output["label"] = "suspicious"
        reasons = output.get("reasons") or []
        reasons.append("message_fraud_pattern")
        output["reasons"] = reasons

    # ---- RULE B: Delivery / parcel scam (FedEx, customs fee)
    if has_delivery and looks_like_link:
        old = float(output.get("risk_score", 0.0))
        output["risk_score"] = round(max(old, 0.75), 3)
        output["label"] = "suspicious"
        reasons = output.get("reasons") or []
        reasons.append("delivery_scam_pattern")
        output["reasons"] = reasons

    # ---- RULE C: Super shady sender + link
    if shady_sender and looks_like_link:
        old = float(output.get("risk_score", 0.0))
        output["risk_score"] = round(max(old, 0.65), 3)
        output["label"] = "suspicious"
        reasons = output.get("reasons") or []
        reasons.append("shady_sender_link")
        output["reasons"] = reasons

   

    return JSONResponse(content=output)
