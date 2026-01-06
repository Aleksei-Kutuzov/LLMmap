import json
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Any

import httpx
import typer
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from providers.config.cofig import Config
from providers.config.config_load import config_load


class ErrorType(str, Enum):
    CLIENT_ERROR = "client_error"
    SERVER_ERROR = "server_error"
    RATE_LIMIT = "rate_limit"
    VALIDATION_ERROR = "validation_error"
    CONTENT_FILTER = "content_filter"
    NETWORK_ERROR = "network_error"
    TIMEOUT_ERROR = "timeout_error"
    UNKNOWN = "unknown"

@dataclass
class APIResponse:
    content: str
    metadata: Dict[str, Any]
    status_code: int
    success: bool
    error_type: ErrorType | None = None
    error_message: str | None = None
    raw_response: Dict | None = None

class HTTPError(Exception):
    def __init__(self, message: str, status_code: int = None, error_type: ErrorType = None):
        self.message = message
        self.status_code = status_code
        self.error_type = error_type
        super().__init__(self.message)

class Adapter():
    def __init__(self, config: Config):
        self.config = config

        self.timeout = self.config.endpoint.parameters.get('timeout', 30)
        self.verify_ssl = self.config.endpoint.parameters.get('verify_ssl', True)
        self.max_retries = self.config.endpoint.parameters.get('max_retries', 3)

        self.client = httpx.Client(
            timeout=self.timeout,
            verify=self.verify_ssl,
            headers=self.config.endpoint.headers
        )

    def _build_payload(self, user_prompt: str, system_prompt: str | None, **kwargs):
        messages = []

        system_config = self.config.request.system_prompt
        if system_prompt or (not system_config.get('optional', False)):
            messages.append({
                "role": system_config.get('role', 'system'),
                "content": system_prompt or ""
            })

        user_config = self.config.request.user_prompt
        messages.append({
            "role": user_config.get('role', 'user'),
            "content": user_prompt
        })

        payload = {"messages": messages}

        model_params = {
            'temperature': self.config.request.temperature,
            'max_tokens': self.config.request.max_tokens,
            'top_p': self.config.request.top_p,
            'model': self.config.request.model,
            'stream': self.config.request.stream
        }

        for param_name, param_config in model_params.items():
            field_name = param_config.get('field', param_name)
            default_value = param_config.get('default')

            value = kwargs.get(param_name, default_value)
            if value is not None:
                payload[field_name] = value

            for key, value in kwargs.items():
                if key not in model_params:
                    payload[key] = value

            return payload

    def _extract_nested_value(self, data: Dict, path: str) -> Any:
        # Путь в формате "field.subfield[index]"

        current = data
        parts = path.replace('[', '.').replace(']', '').split('.')

        for part in parts:
            if current is None:
                return None

            if isinstance(current, list) and part.isdigit():
                index = int(part)
                if 0 <= index < len(current):
                    current = current[index]
                else:
                    return None
            elif isinstance(current, dict):
                current = current.get(part)
            else:
                return None

        return current

    def _classify_error(self, status_code: int, error_text: str) -> tuple[ErrorType, str]:
        error_text_lower = error_text.lower()

        for error_type, codes in self.config.response.error_codes.items():
            if status_code in codes:
                if error_type == 'client_error':
                    for msg in self.config.response.error_messages.get('validation_error', []):
                        if msg.lower() in error_text_lower:
                            return ErrorType.VALIDATION_ERROR, error_text

                    for msg in self.config.response.error_messages.get('content_filter', []):
                        if msg.lower() in error_text_lower:
                            return ErrorType.CONTENT_FILTER, error_text

                elif error_type == 'rate_limit':
                    return ErrorType.RATE_LIMIT, error_text

                elif error_type == 'server_error':
                    return ErrorType.SERVER_ERROR, error_text

                return ErrorType(error_type), error_text

        return ErrorType.UNKNOWN, error_text

    def _parse_response(self, response: httpx.Response) -> APIResponse:
        status_code = response.status_code

        try:
            response_data = response.json()
        except json.JSONDecodeError:
            response_data = {"raw_text": response.text}

        if status_code in self.config.response.error_codes.get('success', [200]):
            # Извлекаем контент
            content = self._extract_nested_value(response_data, self.config.response.content_path)

            # Извлекаем метаданные
            metadata = {}
            for meta_key, meta_path in self.config.response.metadata.items():
                metadata[meta_key] = self._extract_nested_value(response_data, meta_path)

            return APIResponse(
                content=str(content) if content is not None else "",
                metadata=metadata,
                status_code=status_code,
                success=True,
                raw_response=response_data
            )

        error_type, error_message = self._classify_error(
            status_code,
            response.text[:200]
        )

        return APIResponse(
            content="",
            metadata={},
            status_code=status_code,
            success=False,
            error_type=error_type,
            error_message=error_message,
            raw_response=response_data
        )

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=60),
           retry=retry_if_exception_type((httpx.NetworkError, httpx.TimeoutException, httpx.HTTPStatusError)),
           reraise=True)
    def query(self, user_prompt: str, system_prompt: str | None, **kwargs):
        try:
            payload = self._build_payload(user_prompt, system_prompt, **kwargs)

            response = self.client.request(
                method=self.config.endpoint.method,
                url=self.config.endpoint.url,
                json=payload,
                headers=self.config.endpoint.headers,
            )

            result = self._parse_response(response)

            if not result.success:
                raise HTTPError(
                    message=result.error_message or "Unknown error",
                    status_code=result.status_code,
                    error_type=result.error_type
                )

            typer.secho(f"Request successful, status: {result.status_code}", color=typer.colors.GREEN)
            return result

        except httpx.TimeoutException as e:
            typer.secho(f"Request timeout: {e}", color=typer.colors.RED)
            raise HTTPError(
                message=f"Request timeout after {self.timeout} seconds",
                error_type=ErrorType.TIMEOUT_ERROR)

        except httpx.NetworkError as e:
            typer.secho(f"Network error: {e}", color=typer.colors.RED)
            raise HTTPError(message=f"Network error: {str(e)}",
                            error_type=ErrorType.NETWORK_ERROR)

        except httpx.HTTPStatusError as e:
            typer.secho(f"HTTP error {e.response.status_code}: {e}", color=typer.colors.RED)

            result = self._parse_response(e.response)
            raise HTTPError(
                message=result.error_message or str(e),
                status_code=e.response.status_code,
                error_type=result.error_type
            )

        except json.JSONDecodeError as e:
            typer.secho(f"JSON decode error: {e}", color=typer.colors.RED)
            raise ValueError(f"Invalid JSON response: {e}")

        except Exception as e:
            typer.secho(f"Unexpected error: {e}", color=typer.colors.RED)
            raise HTTPError(
                message=f"Unexpected error: {str(e)}",
                error_type=ErrorType.UNKNOWN
            )

if __name__ == "__main__":
    config = config_load(r"C:\Users\Admin\PycharmProjects\LLMmap\config_template1.yaml", {})
    adapter = Adapter(config)

    t = adapter.query(user_prompt="hello", system_prompt="отвечай кратко")

    typer.secho(t, color=typer.colors.BLUE)