import litellm
from litellm import completion, adapters
from typing import Dict, Any, Optional, List
import asyncio
import httpx
import requests
from openai import OpenAI

from pydantic import BaseModel, Field
from tenacity import retry, stop_after_attempt, wait_exponential

class LLMConfig(BaseModel):
    model: str = Field(default="gpt-3.5-turbo")
    api_key: str = Field(default=None)
    base_url: str = Field(default=None)
    request_on_endpoint_mode: bool = Field(default=False)
    openai_like_endpoint_mode: bool = Field(default=False)

class LiteLLMAdapter:
    def __init__(self, config: LLMConfig):
        self.config = config
        if self.config.openai_like_endpoint_mode:
            self.openai_client = OpenAI(base_url=self.config.base_url + "/v1", api_key=self.config.api_key if self.config.api_key else "not-needed")

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    async def query(self, prompt: str, system_prompt: Optional[str] = None, temperature: float = 0.7, max_tokens: int = 1000, **kwargs) -> Dict[str, Any]:
        try:
            messages_payload = [{"role": "system", "content": system_prompt} if system_prompt else None,
                                {"role": "user", "content": prompt}]

            if self.config.openai_like_endpoint_mode:
                response = self.openai_client.chat.completions.create(
                    model=self.config.model,
                    messages=messages_payload,
                )
            else:
                response = await completion(
                    base_url=self.config.base_url,
                    api_key=self.config.api_key,
                    model=self.config.model,
                    messages=messages_payload,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    **kwargs
                )

            return {
                "content": response.choices[0].message.content,
                "usage": response.usage,
                "model": response.model,
                "finish_reason": response.choices[0].finish_reason
            }

        except Exception as e:
            return {"error": str(e), "content": None}

    async def batch_query(self, prompts: List[str], **kwargs) -> List[Dict[str, Any]]:
        tasks = [self.query(prompt, **kwargs) for prompt in prompts]
        return await asyncio.gather(*tasks)

    @staticmethod
    def supported_models() -> List[str]:
        return litellm.model_list


if __name__ == "__main__":
    config = LLMConfig(
        model="google/gemma-3-4b",
        base_url="http://127.0.0.1:1234",
        openai_like_endpoint_mode=True,
    )

    adapter = LiteLLMAdapter(config)
    result = asyncio.run(adapter.query(
        prompt="Что такое солнце?",
        system_prompt="Объясни простым языком"
    ))
    print(result)
