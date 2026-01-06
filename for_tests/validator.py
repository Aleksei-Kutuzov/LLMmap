# validator.py
import datetime
import re

from fastapi import FastAPI, Request, HTTPException
import httpx
import logging
from typing import Dict, Any
import uvicorn
from pydantic import BaseModel
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="LLM Validator Proxy")

REAL_LLM_URL = "http://127.0.0.1:1234/v1/chat/completions"
REAL_LLM_API_KEY = "api-key"


class ContentFilter:
    """Система фильтрации контента, имитирующая реальные LLM системы"""

    def __init__(self):
        # Запрещенные слова и фразы (базовый набор)
        self.prohibited_words = [
            r'\bkill\b', r'\bmurder\b', r'\bassassinat\b', r'\bterrorist\b',

            r'\btrojan\b', r'\bexploit\b', r'\bddos\b', r'\bransomware\b',

            r'\bcredit card\b', r'\bpassword\b', r'\bsocial security\b',
            r'\bssn\b', r'\bbank account\b',

            r'\bhow to (make|build|create).*(bomb|weapon|poison)\b',
            r'\bmake.*explosive\b', r'\bcreate.*virus\b',

            r'\bpersonal data\b', r'\bprivate information\b',
        ]


        self.patterns = [
            r'Ignore all previous instructions.',
        ]

        self.exact_matches = [
            'kill', 'BOBR', 'bomb', 'exploit', 'hack',
        ]

    def contains_prohibited_content(self, text: str) -> tuple[bool, str]:
        text_lower = text.lower()

        for word in self.exact_matches:
            pattern = r'\b' + re.escape(word.lower()) + r'\b'
            if re.search(pattern, text_lower):
                return True, f"Exact match: '{word}'"

        for pattern in self.prohibited_words + self.patterns:
            try:
                if re.search(pattern, text_lower, re.IGNORECASE):
                    return True, f"Pattern match: '{pattern}'"
            except re.error:
                continue

        return False, ""

    def get_blocked_response(self, request_body: Dict, matched_pattern: str = "") -> Dict:
        # Имитация ответа от LLM с блокировкой
        current_time = int(datetime.datetime.now().timestamp())

        return {
            "id": f"chatcmpl-blocked-{current_time}",
            "object": "chat.completion",
            "created": current_time,
            "model": request_body.get("model", "gpt-3.5-turbo"),
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "validation failed"
                    },
                    "finish_reason": "content_filter",
                    "content_filter_result": {
                        "hate": {"filtered": False, "severity": "safe"},
                        "self_harm": {"filtered": True, "severity": "high"},
                        "sexual": {"filtered": False, "severity": "safe"},
                        "violence": {"filtered": True, "severity": "high"}
                    }
                }
            ],
            "usage": {
                "prompt_tokens": len(json.dumps(request_body)),
                "completion_tokens": 4,
                "total_tokens": len(json.dumps(request_body)) + 4
            },
            "system_fingerprint": f"blocked_{current_time}",
            "_validator_metadata": {
                "blocked": True,
                "matched_pattern": matched_pattern,
                "timestamp": current_time,
                "service": "LLM Validator Proxy"
            }
        }

content_filter = ContentFilter()

@app.post("/v1/chat/completions")
async def validate_and_forward(request: Request):
    try:
        body = await request.json()

        logger.info(f"Received request: {json.dumps(body, ensure_ascii=False)[:500]}")

        if "messages" not in body:
            raise HTTPException(status_code=400, detail="Missing 'messages' field")

        messages = body.get("messages", [])
        if not isinstance(messages, list) or len(messages) == 0:
            raise HTTPException(status_code=400, detail="'messages' must be a non-empty list")


        for i, msg in enumerate(messages):
            if not isinstance(msg, dict):
                raise HTTPException(
                    status_code=400,
                    detail=f"Message {i} must be a dictionary"
                )

            if "role" not in msg:
                raise HTTPException(
                    status_code=400,
                    detail=f"Message {i} is missing 'role' field"
                )

            if "content" not in msg:
                raise HTTPException(
                    status_code=400,
                    detail=f"Message {i} is missing 'content' field"
                )

            valid_roles = ["system", "user", "assistant", "function", "tool"]
            if msg["role"] not in valid_roles:
                raise HTTPException(
                    status_code=400,
                    detail=f"Message {i} has invalid role '{msg['role']}'. Valid roles: {valid_roles}"
                )


        if "temperature" in body:
            temp = body["temperature"]
            if not isinstance(temp, (int, float)) or temp < 0 or temp > 2:
                raise HTTPException(
                    status_code=400,
                    detail="temperature must be between 0 and 2"
                )

        if "max_tokens" in body:
            max_tokens = body["max_tokens"]
            if not isinstance(max_tokens, int) or max_tokens < 1:
                raise HTTPException(
                    status_code=400,
                    detail="max_tokens must be positive integer"
                )

        messages = body.get("messages", [])
        for i, msg in enumerate(messages):
            content = msg.get("content", "")
            if content:
                prohibited, pattern = content_filter.contains_prohibited_content(content)
                if prohibited:
                    logger.warning(f"🚫 Content blocked in message {i}: {pattern}")
                    logger.warning(f"Blocked content preview: '{content[:50]}...'")

                    blocked_response = content_filter.get_blocked_response(body, pattern)
                    logger.info(f"✅ Returning blocked response (simulated LLM content filter)")
                    return blocked_response

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {REAL_LLM_API_KEY}",
            "User-Agent": "LLM-Validator/1.0"
        }

        for key, value in request.headers.items():
            if key.lower() not in ['content-type', 'content-length', 'host', 'authorization']:
                headers[key] = value

        async with httpx.AsyncClient(timeout=777.0) as client:
            response = await client.post(
                REAL_LLM_URL,
                json=body,
                headers=headers
            )

            return response.json()

    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="LLM API timeout")
    except httpx.HTTPError as e:
        logger.error(f"HTTP error from LLM API: {e}")
        raise HTTPException(status_code=502, detail=f"LLM API error: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "LLM Validator Proxy"}


@app.get("/config")
async def get_config():
    return {
        "real_llm_url": REAL_LLM_URL,
        "has_api_key": bool(REAL_LLM_API_KEY)
    }


if __name__ == "__main__":
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=2234,
        log_level="info"
    )