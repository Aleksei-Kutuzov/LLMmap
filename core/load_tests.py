import json
import os
import statistics
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, Any, Optional, List
from unittest import load_tests

import typer
from pydantic import BaseModel, Field


@dataclass
class TestCase:
    id: str
    name: str
    description: str
    category: str
    severity: str
    payload: Dict[str, str]
    expected: Dict[str, Any]

    @classmethod
    def from_dict(cls, data: Dict) -> 'TestCase':
        return cls(
            id=data['id'],
            name=data['name'],
            description=data['description'],
            category=data['category'],
            severity=data['severity'],
            payload=data['payload'],
            expected=data['expected']
        )

class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


standards_category = ["prompt_injection",
                     "rag",
                     "llmjacking",
                     "data_leakage",
                     "configuration",
                     "output_validation",
                     "data_exfiltration"]
class TestsConfig(BaseModel):
    enabled_categories: List[str] = Field(default=[cat for cat in standards_category])
    severity_filter: List[Severity] = Field(default=[s for s in Severity])
    test_suites_path: Path = Field(default=Path("./test_suites"))
    custom_tests_path: Path | None = Field(default=None)
    max_concurrent_tests: int = Field(default=5, ge=1, le=50)

def load_test_suite_file(path: Path) -> List[TestCase] | None:
    test_cases: List[TestCase] = []


    with open(path, 'r', encoding='utf-8') as f:
        test_suite = json.load(f)

        if 'tests' in test_suite:
            test_suite = test_suite['tests']
        else:
            test_suite = test_suite


        for test_data in test_suite:
            try:
                test_case = TestCase(
                    id=test_data['id'],
                    name=test_data['name'],
                    description=test_data['description'],
                    category=test_data['category'],
                    severity=test_data['severity'],
                    payload=test_data['payload'],
                    expected=test_data['expected']
                )
                test_cases.append(test_case)

            except KeyError as e:
                typer.secho(f"{test_data['id']} not found line: {e}", fg="red")
                continue
            except Exception as e:
                typer.secho(f"Error of loading test suite: {e}", fg="red")
                continue

        return test_cases

def load_tests(test_config: TestsConfig):
    test_cases = {}

    paths_to_load: List[Path] = []

    if test_config.test_suites_path and os.path.exists(test_config.test_suites_path):
        paths_to_load.append(test_config.test_suites_path)

    if test_config.custom_tests_path and os.path.exists(test_config.custom_tests_path):
        paths_to_load.append(test_config.custom_tests_path)

    if not paths_to_load:
        typer.secho("No dirs tests found", fg="red")

    for test_path in paths_to_load:
        if not os.path.exists(test_path):
            typer.secho(f"Dir {test_path.name} no found", fg="red")

        json_files = list(test_path.glob("*.json"))

        if not json_files:
            typer.secho(f"No json files found in directory {test_path}", fg="red")
            return test_cases

        for json_file in json_files:
            category_name = json_file.stem

            if category_name not in test_config.enabled_categories:
                continue

            loaded_cases = load_test_suite_file(json_file)
            if not loaded_cases:
                continue

            filtered_cases = []
            for test_case in loaded_cases:
                try:
                    test_severity = Severity(test_case.severity.lower())
                    if test_severity in test_config.severity_filter:
                        filtered_cases.append(test_case)
                except ValueError:
                    typer.secho(f"Unknown severity '{test_case.severity}' in test {test_case.id}", fg="red")
                    continue

            if not filtered_cases:
                typer.secho(f"  There are no tests with the appropriate severity in {category_name}", fg="red")
                continue

            if category_name not in test_cases:
                test_cases[category_name] = []
            test_cases[category_name].extend(filtered_cases)

            if json_file.name.replace(".json", "") in test_config.enabled_categories:
                test_cases[json_file.name.replace(".json", "")] = load_test_suite_file(json_file)

            typer.secho(f"Successfully {len(filtered_cases)}/{len(loaded_cases)} tests in category '{category_name}'", fg="green")
    return test_cases


if __name__ == "__main__":
    load_tests(TestsConfig(test_suites_path=Path("../test_suites")))