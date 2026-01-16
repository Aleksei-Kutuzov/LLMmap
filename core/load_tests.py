import json
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, Any, List

from pydantic import BaseModel, Field

from core.utils.logging import success, error


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


class TestsConfig(BaseModel):
    enabled_categories: List[str] | str = Field(default="all")
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
                error(f"{test_data['id']} not found line: {e}")
                continue
            except Exception as e:
                error(f"Error of loading test suite: {e}")
                continue

        return test_cases

def load_tests(test_config: TestsConfig):
    test_cases = {}
    categories: List[str] = []

    paths_to_load: List[Path] = []

    if test_config.test_suites_path and os.path.exists(test_config.test_suites_path):
        paths_to_load.append(test_config.test_suites_path)

    if test_config.custom_tests_path and os.path.exists(test_config.custom_tests_path):
        paths_to_load.append(test_config.custom_tests_path)

    if not paths_to_load:
        error("No dirs tests found")

    for test_path in paths_to_load:
        if not os.path.exists(test_path):
            error(f"Dir {test_path.name} no found")

        json_files = list(test_path.glob("*.json"))

        if not json_files:
            error(f"No json files found in directory {test_path}")
            return test_cases

        for json_file in json_files:
            loaded_cases = load_test_suite_file(json_file)
            if not loaded_cases:
                continue

            filtered_cases = []
            for test_case in loaded_cases:
                if test_config.enabled_categories != "all":
                    if test_case.category not in test_config.enabled_categories:
                        continue
                try:
                    test_severity = Severity(test_case.severity.lower())
                    if test_severity in test_config.severity_filter:
                        filtered_cases.append(test_case)
                except ValueError:
                    error(f"Unknown severity '{test_case.severity}' in test {test_case.id}")
                    continue

            if not filtered_cases:
                error(f"  There are no tests with the appropriate severity in {json_file}")
                continue

            for case in filtered_cases:
                if case.category not in test_cases:
                    test_cases[case.category] = []
                test_cases[case.category].append(case)

            if test_config.enabled_categories != "all":
                if json_file.name.replace(".json", "") in test_config.enabled_categories:
                    test_cases[json_file.name.replace(".json", "")] = load_test_suite_file(json_file)
            else:
                test_cases[json_file.name.replace(".json", "")] = load_test_suite_file(json_file)

            success(f"Successfully {len(filtered_cases)}/{len(loaded_cases)} tests in file '{json_file}'")
    return test_cases


if __name__ == "__main__":
    load_tests(TestsConfig(test_suites_path=Path("../test_suites")))