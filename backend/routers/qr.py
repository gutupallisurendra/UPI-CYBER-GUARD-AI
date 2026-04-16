# backend/routers/qr.py
from fastapi import APIRouter, File, UploadFile, Form
from fastapi.responses import JSONResponse

from utils.qr_decoder import inspect_qr_image_bytes_top
from utils.upi_parser import classify_qr_payload_upi_first

router = APIRouter()


@router.post("/qr")
async def inspect_qr_text(
    qr_text: str = Form(...),
    require_upi: bool = Form(True),
    require_strict: bool = Form(False),
):
    """
    Inspect a decoded QR payload string (e.g. 'upi://pay?pa=...').
    """
    out = classify_qr_payload_upi_first(
        qr_text,
        context_text="QR decoded payload",
        require_upi=require_upi,
        require_strict=require_strict,
    )
    return JSONResponse(content=out)


@router.post("/qr-image")
async def inspect_qr_image(
    file: UploadFile = File(...),
    context_text: str = Form(""),
    require_upi: bool = Form(False),
    require_strict: bool = Form(True),
):
    """
    Upload an image file containing a QR code and inspect the decoded payload(s).
    """
    data = await file.read()
    out = inspect_qr_image_bytes_top(
        data,
        context_text=context_text or "",
        require_upi=require_upi,
        require_strict=require_strict,
    )
    return JSONResponse(content=out)






# from fastapi import APIRouter, File, UploadFile, Form
# from fastapi.responses import JSONResponse
# from utils.qr_decoder import inspect_qr_image_bytes_top
# from utils.upi_parser import classify_qr_payload_upi_first

# router = APIRouter()

# @router.post("/qr")
# async def inspect_qr_text(qr_text: str = Form(...)):
#     """
#     Inspect a decoded QR payload string (e.g. 'upi://pay?pa=...').
#     """
#     out = classify_qr_payload_upi_first(
#         qr_text,
#         context_text="QR decoded payload",
#         require_upi=True,
#         require_strict=False
#     )
#     return JSONResponse(content=out)


# @router.post("/qr-image")
# async def inspect_qr_image(
#     file: UploadFile = File(...),
#     context_text: str = Form(""),
#     require_upi: bool = Form(False),
# ):
#     """
#     Upload an image file containing QR code. Returns inspection result.
#     """
#     data = await file.read()
#     out = inspect_qr_image_bytes_top(
#         data,
#         context_text=context_text or "",
#         require_upi=require_upi,
#         require_strict=True
#     )
#     return JSONResponse(content=out)
