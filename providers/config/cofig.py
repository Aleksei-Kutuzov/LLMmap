from typing import Dict, List

from pydantic import BaseModel, Field


class Endpoint(BaseModel):
    url: str
    method: str
    headers: dict
    parameters: dict

class Request(BaseModel):
    system_prompt: Dict
    user_prompt: Dict[str, str]
    temperature: Dict
    max_tokens: Dict
    top_p: Dict
    model: Dict[str, str]
    stream: Dict

class Response(BaseModel):
    content_path: str
    metadata: Dict[str, str]
    error_codes: Dict[str, List[int]]
    error_messages: Dict[str, List[str]]

class Authentication(BaseModel):
    type: str | None
    location: str | None
    field: str  | None
    format: str | None
    env_vars: Dict[str, str] | None



class Config(BaseModel):
    endpoint: Endpoint
    request: Request
    response: Response
    authentication: Authentication
