import yaml
from pydantic import BaseModel, Field
from typing import List, Literal
from pathlib import Path

import providers.adapter


class ReportingConfig(BaseModel):
    format: Literal["json", "html", "pdf", "markdown"] = Field(default="json")
    output_dir: Path = Field(default=Path("./reports"))
    include_examples: bool = Field(default=True)
    include_recommendations: bool = Field(default=True)
    severity_levels: List[Severity] = Field(default=[Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL])
    max_examples_per_vuln: int = Field(default=3, ge=1)


class ScanConfig(BaseModel):
    llm: providers.adapter.Adapter = Field(default_factory=providers.adapter.Config)
    tests: TestsConfig = Field(default_factory=TestsConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)


    @classmethod
    def from_yaml(cls, path: Path) -> 'ScanConfig':
        with open(path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        return cls(**data)

    def to_yaml(self, path: Path) -> None:
        with open(path, 'w', encoding='utf-8') as f:
            data = self.model_dump(exclude={'llm': {'api_key'}})
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True)