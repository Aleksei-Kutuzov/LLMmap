import csv
import json
import requests
from pathlib import Path
from typing import Dict, List, Optional

from core.utils.logging import info, error, warning, success


class LLMTestParser:
    def __init__(self):
        self.required_fields = ["id", "user_prompt"]
        self.default_mapping = {
            "id": "id",
            "name": "name",
            "description": "description",
            "category": "category",
            "severity": "severity",
            "user_prompt": "user_prompt",
            "system_prompt": "system_prompt",
            "temperature": "temperature",
            "max_tokens": "max_tokens"
        }

    def load_data(self, source: str) -> List[Dict]:
        # GitHub raw url
        if source.startswith(("http://", "https://")):
            try:
                response = requests.get(source, timeout=10)
                response.raise_for_status()
                content_type = response.headers.get('content-type', '').lower()
                content = response.text

                if 'json' in content_type or source.endswith('.json'):
                    return response.json()
                elif 'csv' in content_type or source.endswith('.csv'):

                    import io
                    csv_data = io.StringIO(content)
                    return list(csv.DictReader(csv_data))
                else:
                    try:
                        return response.json()
                    except:
                        import io
                        csv_data = io.StringIO(content)
                        return list(csv.DictReader(csv_data))
            except Exception as e:
                info(f"Error loading data: {e}")
                return []

        file_path = Path(source)
        if file_path.exists():
            try:
                if file_path.suffix.lower() == '.json':
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                elif file_path.suffix.lower() == '.csv':
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = list(csv.DictReader(f))
                else:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        try:
                            data = json.loads(content)
                        except json.JSONDecodeError:
                            f.seek(0)
                            data = list(csv.DictReader(f))

                if isinstance(data, dict) and "tests" in data:
                    return data["tests"]
                elif isinstance(data, list):
                    return data
                else:
                    return [data]
            except Exception as e:
                error(f"Error loading data: {e}")
                return []

        error(f"The source is no found: {source}")
        return []

    def transform_test(self, item: Dict, mapping: Dict) -> Optional[Dict]:
        try:
            result = {}
            for target_field, source_field in mapping.items():
                if source_field and source_field in item:
                    result[target_field] = item[source_field]
                elif source_field == "auto":
                    if target_field == "id":
                        result[target_field] = f"auto-{hash(str(item))}"
                    elif target_field == "severity":
                        result[target_field] = "medium"

            for field in self.required_fields:
                if field not in result:
                    warning(f"The test was missed: the '{field}' field is missing")
                    return None

            final = {
                "id": result.get("id", ""),
                "name": result.get("name", "Unnamed Test"),
                "description": result.get("description", ""),
                "category": result.get("category", "prompt_injection"),
                "severity": result.get("severity", "medium"),
                "payload": {
                    "system_prompt": result.get("system_prompt", ""),
                    "user_prompt": result.get("user_prompt", ""),
                    "temperature": result.get("temperature", 0.7),
                    "max_tokens": result.get("max_tokens", 500)
                },
                "expected": {
                    "contains": "",
                    "blocked": False
                }
            }

            return final

        except Exception as e:
            error(f"Error of data transform: {e}")
            return None

    def parse(self, source: str,
                    output: str = "test_suites",
                    mapping: Optional[Dict] = None,
                    filename: str = "parsed",
                    limit: int = 0) -> int:
        info(f"Parsing from source: {source}")

        source_data = self.load_data(source)
        if not source_data:
            return 0

        field_mapping = mapping or self.default_mapping

        tests = []
        for i, item in enumerate(source_data):
            if limit > 0 and i >= limit:
                break

            test = self.transform_test(item, field_mapping)
            if test:
                tests.append(test)

        if tests:
            output_dir = Path(output)
            output_dir.mkdir(exist_ok=True)

            output_file = output_dir / f"{filename.replace(".json", "")}.json"
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(tests, f, indent=2, ensure_ascii=False)

            success(f"Saved {len(tests)} tests in {output_file}")
            return len(tests)

        return 0