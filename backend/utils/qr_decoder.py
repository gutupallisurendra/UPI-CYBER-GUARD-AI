# from io import BytesIO
# from PIL import Image, ImageOps
# import numpy as np
# import importlib
# import math

# # Check library availability
# _HAS_PYZBAR = importlib.util.find_spec("pyzbar") is not None
# _HAS_CV2 = importlib.util.find_spec("cv2") is not None

# # -----------------------------
# # Helper: Convert PIL → CV2
# # -----------------------------
# def pil_to_cv2(img_pil):
#     return np.array(img_pil.convert("RGB"))[:, :, ::-1]

# # -----------------------------
# # Image variants to increase detection accuracy
# # -----------------------------
# def preprocess_variants(img_pil):
#     w, h = img_pil.size
#     scale_up = 1
#     if max(w, h) < 800:
#         scale_up = int(math.ceil(800.0 / max(w, h)))

#     variants = []

#     base = img_pil.convert("RGB")
#     if scale_up > 1:
#         base = base.resize((w * scale_up, h * scale_up), Image.LANCZOS)
#     variants.append(base)

#     # grayscale
#     g = base.convert("L")
#     variants.append(g)

#     # autocontrast
#     try:
#         variants.append(ImageOps.autocontrast(g))
#     except:
#         variants.append(g)

#     # OTSU thresholding (if cv2 available)
#     if _HAS_CV2:
#         try:
#             import cv2
#             arr = np.array(g)
#             blur = cv2.GaussianBlur(arr, (5, 5), 0)
#             _, otsu = cv2.threshold(blur, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
#             variants.append(Image.fromarray(otsu))
#         except:
#             pass

#     # dedupe variants
#     seen = set()
#     out = []
#     for v in variants:
#         key = (v.size, v.mode)
#         if key not in seen:
#             seen.add(key)
#             out.append(v)
#     return out

# # -----------------------------
# # Pyzbar QR decoding
# # -----------------------------
# def decode_with_pyzbar_list(img_pil):
#     if not _HAS_PYZBAR:
#         return None
#     try:
#         from pyzbar.pyzbar import decode as zbar_decode
#     except:
#         return None

#     results = []
#     for var in preprocess_variants(img_pil):
#         for ang in (0, 90, 180, 270):
#             try:
#                 cand = var.rotate(ang, expand=True) if ang else var
#                 dec = zbar_decode(cand)
#                 for d in dec:
#                     data = getattr(d, "data", None)
#                     if data:
#                         txt = data.decode("utf-8", errors="ignore")
#                         results.append(txt)
#             except:
#                 pass

#     # dedupe
#     if results:
#         out = []
#         seen = set()
#         for r in results:
#             if r not in seen:
#                 seen.add(r)
#                 out.append(r)
#         return out
#     return None

# # -----------------------------
# # OpenCV QR decoding
# # -----------------------------
# def decode_with_opencv_list(img_pil):
#     if not _HAS_CV2:
#         return None
#     try:
#         import cv2
#     except:
#         return None

#     detector = cv2.QRCodeDetector()
#     results = []

#     for var in preprocess_variants(img_pil):
#         arr = pil_to_cv2(var)

#         # multi QR
#         try:
#             if hasattr(detector, "detectAndDecodeMulti"):
#                 ok, decoded_info, pts, _ = detector.detectAndDecodeMulti(arr)
#                 if ok and decoded_info:
#                     for entry in decoded_info:
#                         if entry:
#                             results.append(entry)
#                     continue
#         except:
#             pass

#         # single QR
#         try:
#             data, pts, _ = detector.detectAndDecode(arr)
#             if data:
#                 results.append(data)
#         except:
#             pass

#         # rotations
#         for ang in (90, 180, 270):
#             try:
#                 rot = var.rotate(ang, expand=True)
#                 arr2 = pil_to_cv2(rot)
#                 data, pts, _ = detector.detectAndDecode(arr2)
#                 if data:
#                     results.append(data)
#                     break
#             except:
#                 pass

#     if results:
#         out = []
#         seen = set()
#         for r in results:
#             if r not in seen:
#                 seen.add(r)
#                 out.append(r)
#         return out

#     return None

# # -----------------------------
# # Main decode entry point
# # -----------------------------
# def decode_qr_image_bytes(data: bytes):
#     """
#     Attempts pyzbar first, then OpenCV, then fallback.
#     Returns list of decoded QR payload strings OR None.
#     """
#     try:
#         img = Image.open(BytesIO(data))
#     except:
#         return None

#     # First: pyzbar
#     try:
#         r = decode_with_pyzbar_list(img)
#         if r:
#             return r
#     except:
#         pass

#     # Second: CV2 detector
#     try:
#         r = decode_with_opencv_list(img)
#         if r:
#             return r
#     except:
#         pass

#     # Third: autocontrast fallback
#     try:
#         bright = ImageOps.autocontrast(img.convert("L"))
#         r = decode_with_pyzbar_list(bright) or decode_with_opencv_list(bright)
#         if r:
#             return r
#     except:
#         pass

#     return None

# # ================================
# # Final integrated function
# # ================================
# from utils.upi_parser import classify_qr_payload_upi_first
# from utils.gemini_fallback import gemini_extract_text

# def inspect_qr_image_bytes_top(data: bytes, context_text="", require_upi=True, require_strict=False):
#     """
#     Combines:
#     - Old QR decoder (pyzbar + OpenCV)
#     - Gemini OCR fallback
#     - UPI payload classifier
#     """
#     decoded = decode_qr_image_bytes(data)

#     # If old method detected QR
#     if decoded:
#         per = []
#         overall_score = 0
#         overall_label = "safe"

#         for p in decoded:
#             r = classify_qr_payload_upi_first(p, context_text, require_upi, require_strict)
#             per.append(r)

#             overall_score = max(overall_score, r["final_score"])
#             if r["label"] == "malicious":
#                 overall_label = "malicious"

#         return {
#             "overall_score": round(overall_score, 3),
#             "overall_label": overall_label,
#             "per_payload": per,
#             "gemini_used": False
#         }

#     # If no QR found → Gemini fallback
#     extracted = gemini_extract_text(data)

#     if not extracted.strip():
#         return {"error": "No QR found and Gemini returned no text", "gemini_used": True}

#     # Try to extract UPI-like candidates from Gemini output
#     candidates = []
#     L = extracted.lower()

#     if "upi:" in L or "upi://" in L or "pa=" in L:
#         for word in extracted.replace("\n", " ").split(" "):
#             wl = word.lower().strip()
#             if "upi:" in wl or "upi://" in wl or "pa=" in wl:
#                 candidates.append(word)

#     if not candidates:
#         candidates = [extracted]

#     per = []
#     overall_score = 0
#     overall_label = "safe"

#     for c in candidates:
#         r = classify_qr_payload_upi_first(c, context_text, require_upi, require_strict)
#         per.append(r)

#         overall_score = max(overall_score, r["final_score"])
#         if r["label"] == "malicious":
#             overall_label = "malicious"

#     return {
#         "overall_score": round(overall_score, 3),
#         "overall_label": overall_label,
#         "per_payload": per,
#         "extracted_text": extracted,
#         "gemini_used": True
#     }














# backend/utils/qr_decoder.py
from io import BytesIO
from PIL import Image, ImageOps, ImageFilter
import numpy as np
import math

# Optional imports (wrap to keep module import safe)
try:
    import cv2
    _HAS_CV2 = True
except Exception:
    cv2 = None
    _HAS_CV2 = False

try:
    from pyzbar.pyzbar import decode as zbar_decode
    _HAS_PYZBAR = True
except Exception:
    zbar_decode = None
    _HAS_PYZBAR = False

# Helper: convert PIL -> cv2 BGR
def pil_to_cv2(img_pil):
    return np.array(img_pil.convert("RGB"))[:, :, ::-1]

def cv2_to_pil(img_cv):
    return Image.fromarray(img_cv[:, :, ::-1])

# ---------- Resize helper ----------
def resize_max(img_cv, max_side=1200):
    h, w = img_cv.shape[:2]
    ms = max(h, w)
    if ms <= max_side:
        return img_cv
    scale = max_side / float(ms)
    new = cv2.resize(img_cv, (int(w*scale), int(h*scale)), interpolation=cv2.INTER_AREA)
    return new

# ---------- Order points utility ----------
def order_points(pts):
    pts = np.array(pts, dtype="float32")
    s = pts.sum(axis=1)
    diff = np.diff(pts, axis=1)
    tl = pts[np.argmin(s)]
    br = pts[np.argmax(s)]
    tr = pts[np.argmin(diff)]
    bl = pts[np.argmax(diff)]
    return np.array([tl, tr, br, bl], dtype="float32")

# ---------- Crop / unwarp the largest quadrilateral ----------
def crop_largest_rect(img_cv):
    if not _HAS_CV2:
        return None
    gray = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)
    blur = cv2.GaussianBlur(gray, (5,5), 0)
    _, th = cv2.threshold(blur, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    contours, _ = cv2.findContours(th, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    if not contours:
        return None
    contours = sorted(contours, key=cv2.contourArea, reverse=True)[:8]
    h, w = img_cv.shape[:2]
    for cnt in contours:
        peri = cv2.arcLength(cnt, True)
        approx = cv2.approxPolyDP(cnt, 0.02 * peri, True)
        area = cv2.contourArea(cnt)
        if len(approx) >= 4 and area > (w*h)*0.01:
            pts = approx.reshape(-1, 2)
            if pts.shape[0] > 4:
                hull = cv2.convexHull(pts)
                pts = hull.reshape(-1,2)
            if pts.shape[0] < 4:
                continue
            rect = order_points(pts[:4])
            (tl, tr, br, bl) = rect
            widthA = np.linalg.norm(br - bl)
            widthB = np.linalg.norm(tr - tl)
            maxWidth = int(max(widthA, widthB))
            heightA = np.linalg.norm(tr - br)
            heightB = np.linalg.norm(tl - bl)
            maxHeight = int(max(heightA, heightB))
            if maxWidth < 80 or maxHeight < 80:
                continue
            dst = np.array([[0,0],[maxWidth-1,0],[maxWidth-1,maxHeight-1],[0,maxHeight-1]], dtype="float32")
            try:
                M = cv2.getPerspectiveTransform(rect, dst)
                warp = cv2.warpPerspective(img_cv, M, (maxWidth, maxHeight))
                return warp
            except Exception:
                continue
    return None

# ---------- Inpaint center (logo) ----------
def inpaint_center_logo(img_cv):
    if not _HAS_CV2:
        return img_cv
    h, w = img_cv.shape[:2]
    center_mask = np.zeros((h,w), dtype=np.uint8)
    cx, cy = w//2, h//2
    radius = int(min(w,h)*0.16)
    cv2.circle(center_mask, (cx,cy), radius, 255, -1)
    gray = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)
    _, th = cv2.threshold(gray, 250, 255, cv2.THRESH_BINARY_INV)
    target = cv2.bitwise_and(255 - th, center_mask)
    if cv2.countNonZero(target) < 20:
        return img_cv
    try:
        inpainted = cv2.inpaint(img_cv, target, 3, cv2.INPAINT_TELEA)
        return inpainted
    except Exception:
        return img_cv

# ---------- Generate preprocessing variants ----------
def generate_variants(img_cv):
    variants = []
    img_cv = resize_max(img_cv, max_side=1400)
    variants.append(img_cv)
    try:
        kernel = np.array([[0,-1,0],[-1,5,-1],[0,-1,0]])
        sharp = cv2.filter2D(img_cv, -1, kernel)
        variants.append(sharp)
    except Exception:
        pass
    try:
        gray = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)
        blur = cv2.GaussianBlur(gray, (5,5), 0)
        _, otsu = cv2.threshold(blur, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        variants.append(cv2.cvtColor(otsu, cv2.COLOR_GRAY2BGR))
    except Exception:
        pass
    try:
        gray = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)
        adapt = cv2.adaptiveThreshold(gray,255,cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY,11,2)
        variants.append(cv2.cvtColor(adapt, cv2.COLOR_GRAY2BGR))
    except Exception:
        pass
    try:
        kernel = np.ones((3,3), np.uint8)
        dil = cv2.dilate(otsu, kernel, iterations=1) if 'otsu' in locals() else None
        if dil is not None:
            variants.append(cv2.cvtColor(dil, cv2.COLOR_GRAY2BGR))
    except Exception:
        pass
    try:
        inpainted = inpaint_center_logo(img_cv)
        variants.append(inpainted)
    except Exception:
        pass
    # dedupe by shape to avoid duplicates
    out = []
    seen = set()
    for v in variants:
        if v is None:
            continue
        key = (v.shape[0], v.shape[1], v.shape[2]) if len(v.shape) == 3 else (v.shape[0], v.shape[1], 1)
        if key not in seen:
            seen.add(key)
            out.append(v)
    return out

# ---------- Decoders ----------
def try_pyzbar_on_cv(img_cv):
    if not _HAS_PYZBAR:
        return None
    try:
        pil = cv2_to_pil(img_cv)
        decs = zbar_decode(pil)
        out = []
        for d in decs:
            if d and getattr(d, "data", None):
                txt = d.data.decode("utf-8", errors="ignore")
                out.append(txt)
        return out if out else None
    except Exception:
        return None

def try_opencv_qr_detector(img_cv):
    if not _HAS_CV2:
        return None
    try:
        detector = cv2.QRCodeDetector()
        if hasattr(detector, 'detectAndDecodeMulti'):
            ok, decoded_info, pts, straight_qrcode = detector.detectAndDecodeMulti(img_cv)
            if ok and decoded_info:
                return [s for s in decoded_info if s]
        data, pts, _ = detector.detectAndDecode(img_cv)
        if data:
            return [data]
    except Exception:
        pass
    return None

# ---------- Robust decode main ----------
def robust_decode_image_bytes(data_bytes):
    """Return list of decoded payloads or None."""
    try:
        pil = Image.open(BytesIO(data_bytes)).convert("RGB")
    except Exception:
        return None

    # Fast pyzbar attempts on PIL variants
    try:
        pil_variants = [pil, pil.convert("L"), ImageOps.autocontrast(pil.convert("L")), pil.filter(ImageFilter.SHARPEN)]
        for p in pil_variants:
            if _HAS_PYZBAR:
                res = zbar_decode(p)
                if res:
                    out = []
                    for d in res:
                        if getattr(d, "data", None):
                            out.append(d.data.decode("utf-8", errors="ignore"))
                    if out:
                        return out
    except Exception:
        pass

    # Convert to cv2
    arr = np.array(pil)[:, :, ::-1].copy()
    if _HAS_CV2:
        arr = resize_max(arr, max_side=1400)

    # Try crop & unwarp
    try:
        if _HAS_CV2:
            crop = crop_largest_rect(arr)
            if crop is not None:
                variants = generate_variants(crop)
                for v in variants:
                    res = try_pyzbar_on_cv(v)
                    if res:
                        return res
                    res2 = try_opencv_qr_detector(v)
                    if res2:
                        return res2
    except Exception:
        pass

    # Global variants + rotations
    try:
        if _HAS_CV2:
            variants = generate_variants(arr)
            for v in variants:
                for ang in (0,90,180,270):
                    if ang:
                        if ang == 90:
                            v2 = cv2.rotate(v, cv2.ROTATE_90_CLOCKWISE)
                        elif ang == 180:
                            v2 = cv2.rotate(v, cv2.ROTATE_180)
                        else:
                            v2 = cv2.rotate(v, cv2.ROTATE_90_COUNTERCLOCKWISE)
                    else:
                        v2 = v
                    res = try_pyzbar_on_cv(v2)
                    if res:
                        return res
                    res2 = try_opencv_qr_detector(v2)
                    if res2:
                        return res2
    except Exception:
        pass

    # Last resort: autocontrast PIL fallback
    try:
        bright = ImageOps.autocontrast(pil.convert("L"))
        for p in [bright, bright.filter(ImageFilter.SHARPEN)]:
            if _HAS_PYZBAR:
                res = zbar_decode(p)
                if res:
                    out = [d.data.decode("utf-8", errors="ignore") for d in res if getattr(d,"data",None)]
                    if out:
                        return out
            arr2 = np.array(p)[:, :, ::-1]
            res2 = try_opencv_qr_detector(arr2)
            if res2:
                return res2
    except Exception:
        pass

    return None

# back-compat name used in your code
def decode_qr_image_bytes(data: bytes):
    return robust_decode_image_bytes(data)

# Keep the top-level integrated function external (you already have it in your file)
# Add this to the bottom of backend/utils/qr_decoder.py

from .upi_parser import classify_qr_payload_upi_first
from .gemini_fallback import gemini_extract_text


def inspect_qr_image_bytes_top(data: bytes, context_text: str = "", require_upi: bool = True, require_strict: bool = False):
    """
    Backwards-compatible wrapper used by routers/qr.py.
    - Tries decode_qr_image_bytes (robust decoder).
    - If found, classifies each payload via classify_qr_payload_upi_first.
    - If not, uses Gemini OCR fallback and attempts to extract UPI-like substrings.
    Returns a dict similar to what your router previously produced.
    """
    try:
        decoded = decode_qr_image_bytes(data)
    except Exception:
        decoded = None

    # If old method detected QR payload(s)
    if decoded:
        per = []
        overall_score = 0.0
        overall_label = "safe"

        for p in decoded:
            # classify each payload (keep same args shape as your upi parser)
            try:
                r = classify_qr_payload_upi_first(p, context_text, require_upi, require_strict)
            except Exception as e:
                # fallback minimal structure if classifier errors
                r = {
                    "payload": p,
                    "label": "suspicious",
                    "final_score": 0.6,
                    "reasons": ["classification_error"]
                }
            per.append(r)
            # use field final_score to compute overall
            try:
                overall_score = max(overall_score, float(r.get("final_score", 0)))
            except Exception:
                overall_score = max(overall_score, 0.0)
            if r.get("label") == "malicious":
                overall_label = "malicious"

        return {
            "overall_score": round(overall_score, 3),
            "overall_label": overall_label,
            "per_payload": per,
            "gemini_used": False
        }

    # No QR decoded locally -> Gemini OCR fallback
    try:
        extracted = gemini_extract_text(data) or ""
    except Exception:
        extracted = ""

    if not extracted.strip():
        return {"error": "No QR found and Gemini returned no text", "gemini_used": True}

    # Extract UPI-like substrings from Gemini text
    candidates = []
    L = extracted.lower()

    if "upi:" in L or "upi://" in L or "pa=" in L:
        for token in extracted.replace("\n", " ").split(" "):
            wl = token.strip()
            lw = wl.lower()
            if "upi:" in lw or "upi://" in lw or "pa=" in lw:
                candidates.append(wl)

    if not candidates:
        # if none found, try using the full extracted text as a single candidate
        candidates = [extracted.strip()]

    per = []
    overall_score = 0.0
    overall_label = "safe"

    for c in candidates:
        try:
            r = classify_qr_payload_upi_first(c, context_text, require_upi, require_strict)
        except Exception:
            r = {"payload": c, "label": "suspicious", "final_score": 0.6, "reasons": ["classification_error"]}
        per.append(r)
        try:
            overall_score = max(overall_score, float(r.get("final_score", 0)))
        except Exception:
            overall_score = max(overall_score, 0.0)
        if r.get("label") == "malicious":
            overall_label = "malicious"

    return {
        "overall_score": round(overall_score, 3),
        "overall_label": overall_label,
        "per_payload": per,
        "extracted_text": extracted,
        "gemini_used": True
    }

