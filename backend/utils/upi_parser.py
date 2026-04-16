import re
from urllib.parse import parse_qs, unquote_plus
import hashlib

def parse_upi_payload(payload: str) -> dict:
    """
    Parse a UPI deep link or a text that contains a UPI deep link.
    Returns a dict with keys: is_upi, pa, pn, tr, am, tn, collect
    """
    p = (payload or "").strip()
    lower = p.lower()
    out = {"is_upi": False, "pa": "", "pn": "", "tr": "", "am": "", "tn": "", "collect": False}

    # Try to locate a UPI substring if the payload isn't a direct upi://...
    if "upi:" not in lower and "upi://" not in lower:
        m = re.search(r"(upi[:/][^\s'\"<>]+)", p, flags=re.IGNORECASE)
        if not m:
            return out
        p = m.group(1)
        lower = p.lower()

    out["is_upi"] = True
    norm = p.replace("upi://", "upi:")
    q = norm.split("?", 1)[1] if "?" in norm else ""
    params = parse_qs(q, keep_blank_values=True)

    decoded = {k.lower(): [unquote_plus(v) for v in vs] for k, vs in params.items()}

    def get(k):
        v = decoded.get(k.lower()) or []
        return v[0] if v else ""

    out["pa"] = get("pa")
    out["pn"] = get("pn")
    out["tr"] = get("tr")
    out["am"] = get("am")
    out["tn"] = get("tn")
    out["collect"] = ("collect" in lower) or (out["tr"] != "")

    return out

def is_valid_vpa(pa: str) -> bool:
    """
    Simple VPA (Virtual Payment Address) validation based on regex used in notebook.
    """
    return bool(pa and re.fullmatch(r"[a-zA-Z0-9.\-_]{2,}@[a-zA-Z0-9.\-]{2,}", pa))

def classify_qr_payload_upi_first(qr_payload: str, context_text="", require_upi=True, require_strict=False):
    """
    Classify a decoded QR payload string focusing on UPI-first logic.
    Returns a dict suitable for JSON response similar to the Colab notebook version.
    """
    parsed = parse_upi_payload(qr_payload)
    artifacts = {"qr_sha256": hashlib.sha256(qr_payload.encode()).hexdigest(), "parsed_upi": parsed}

    if not parsed["is_upi"]:
        return {
            "payload": qr_payload,
            "final_score": 0.01,
            "label": "malicious",
            "reasons": ["Not a UPI payload"],
            "artifacts": artifacts
        }

    pa = parsed.get("pa", "")
    if not is_valid_vpa(pa):
        return {
            "payload": qr_payload,
            "final_score": 0.98,
            "label": "malicious",
            "reasons": ["Invalid/missing VPA"],
            "artifacts": artifacts
        }

    # If we reach here, treat as safe (you can extend heuristics later)
    return {
        "payload": qr_payload,
        "final_score": 0.95,
        "label": "safe",
        "reasons": ["Valid UPI payload"],
        "artifacts": artifacts
    }
