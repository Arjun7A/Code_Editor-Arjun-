"""
Proof script: verifies a live Gemini call using your configured API key.

Usage (from backend/):
  python scripts/verify_gemini_live.py
  python scripts/verify_gemini_live.py gemini-2.5-flash
"""

import os
import sys
import uuid
from typing import Any, Dict

import requests
from dotenv import load_dotenv


def _extract_text(payload: Dict[str, Any]) -> str:
    candidates = payload.get("candidates") or []
    if not candidates:
        return ""
    content = candidates[0].get("content") or {}
    parts = content.get("parts") or []
    chunks = []
    for part in parts:
        text = part.get("text")
        if isinstance(text, str):
            chunks.append(text)
    return "".join(chunks).strip()


def main() -> int:
    load_dotenv()
    key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    if not key:
        print("FAIL: GEMINI_API_KEY / GOOGLE_API_KEY is not set.")
        return 2

    if any(arg.strip() == "--list-models" for arg in sys.argv[1:]):
        try:
            response = requests.get(
                "https://generativelanguage.googleapis.com/v1beta/models",
                params={"key": key},
                timeout=60,
            )
        except Exception as exc:
            print(f"FAIL: request error: {exc}")
            return 3
        print(f"http_status={response.status_code}")
        if response.status_code != 200:
            print((response.text or "")[:1000])
            return 4
        payload = response.json()
        models = payload.get("models") or []
        print(f"model_count={len(models)}")
        for model in models[:15]:
            name = model.get("name")
            methods = model.get("supportedGenerationMethods") or []
            print(f"{name} methods={methods}")
        return 0

    model = sys.argv[1].strip() if len(sys.argv) > 1 else (
        os.getenv("GEMINI_MODEL") or "gemini-2.5-flash"
    )
    nonce = f"SG_PROOF_{uuid.uuid4().hex[:12]}"

    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    payload = {
        "contents": [
            {
                "parts": [
                    {
                        "text": (
                            "Return exactly this token and nothing else: "
                            f"{nonce}"
                        )
                    }
                ]
            }
        ],
        "generationConfig": {"temperature": 0.0, "maxOutputTokens": 32},
    }

    try:
        response = requests.post(
            url,
            params={"key": key},
            json=payload,
            timeout=60,
        )
    except Exception as exc:
        print(f"FAIL: request error: {exc}")
        return 3

    print(f"http_status={response.status_code}")
    if response.status_code != 200:
        print((response.text or "")[:800])
        return 4

    data = response.json()
    text = _extract_text(data)
    model_version = data.get("modelVersion")
    response_id = data.get("responseId")
    matched = nonce in text

    print(f"requested_model={model}")
    print(f"model_version={model_version}")
    print(f"response_id={response_id}")
    print(f"nonce={nonce}")
    print(f"model_text={text}")
    print(f"nonce_matched={matched}")

    if not matched:
        print("WARN: live call succeeded, but nonce was not echoed exactly.")
        return 5

    print("PASS: live Gemini response verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
