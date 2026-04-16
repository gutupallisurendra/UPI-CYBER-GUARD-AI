import os
import base64
from dotenv import load_dotenv

# Load vars from .env (GOOGLE_API_KEY, GEMINI_MODEL)
load_dotenv()

# This module provides a small wrapper around google-genai's image-to-text usage
# If google-genai or credentials are missing, functions fall back gracefully.

def _make_gemini_client():
    try:
        # delayed import so the package is optional during dev
        from google import genai
        client = genai.Client()
        return client
    except Exception:
        return None

def gemini_extract_text(data: bytes, model: str | None = None) -> str:
    """
    Attempts to use Gemini (google-genai) to extract text from an image (bytes).
    Returns the extracted text (string) or empty string on failure.
    """
    client = _make_gemini_client()
    if client is None:
        # google-genai not installed or import failed
        return ""

    model = model or os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
    try:
        b64 = base64.b64encode(data).decode("ascii")
        contents = [
            {
                "type": "INPUT_IMAGE",
                "image": {"imageBytes": b64},
                "text": "Extract all plain text. Only text."
            }
        ]
        resp = client.models.generate_content(
            model=model,
            contents=contents,
            max_output_tokens=4096
        )

        if hasattr(resp, "text") and resp.text:
            return resp.text.strip()
        return str(resp).strip()
    except Exception:
        return ""
