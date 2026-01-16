import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional
from jinja2 import Environment, FileSystemLoader

from core.utils.logging import success, error


class ReportGenerator:
    def __init__(self, template_dir: Path = Path(".")):
        self.template_dir = template_dir
        self.env = Environment(loader=FileSystemLoader(template_dir),
                               trim_blocks=True,
                               lstrip_blocks=True)

    def generate_html_report(self,
                            test_results: List[Dict],
                            evaluation_summary: Dict,
                            category_stats: List[Dict],
                            model_name: str = "Unknown Model",
                            output_path: Path = Path("scan_results.html")) -> bool:
        try:
            template = self.env.get_template("report.html.j2")

            critical_count = sum(1 for r in test_results if r.get('hack_score', 0) > 0.8)

            summary = { **evaluation_summary,
                       'critical_count': critical_count }

            tests_data = []
            for result in test_results:
                if hasattr(result, '__dict__'):
                    tests_data.append(result.__dict__)
                else:
                    tests_data.append(result)

            for test in tests_data:
                test['severity_lower'] = test.get('severity', '').lower()
                test['response_time_str'] = f"{test.get('response_time', 0):.2f}"
                test['hack_score_str'] = f"{test.get('hack_score', 0):.3f}"

            html_content = template.render(scan_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                           model_name=model_name,
                                           summary=summary,
                                           tests=tests_data,
                                           category_stats=category_stats)

            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)

            success(f"HTML report saved to {output_path}")
            return True

        except Exception as e:
            error(f"Error generating HTML report: {e}")
            return False

    def generate_markdown_report(self,
            test_results: List[Dict],
            evaluation_summary: Dict,
            category_stats: List[Dict],
            model_name: str = "Unknown Model",
            output_path: Path = Path("scan_results.md")) -> bool:
        try:
            template = self.env.get_template("report.md.j2")

            critical_count = sum(1 for r in test_results if r.get('hack_score', 0) > 0.8)

            summary = { **evaluation_summary,
                        'critical_count': critical_count }

            tests_data = []
            for result in test_results:
                if hasattr(result, '__dict__'):
                    tests_data.append(result.__dict__)
                else:
                    tests_data.append(result)

            for test in tests_data:
                test['response_time_str'] = f"{test.get('response_time', 0):.2f}"
                test['hack_score_str'] = f"{test.get('hack_score', 0):.3f}"

            markdown_content = template.render(scan_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                               model_name=model_name,
                                               summary=summary,
                                               tests=tests_data,
                                               category_stats=category_stats)

            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(markdown_content)

            success(f"Markdown report saved to {output_path}")
            return True

        except Exception as e:
            error(f"Error generating Markdown report: {e}")
            return False

    def save_results_json(self,
                         test_results: List[Dict],
                         evaluation_summary: Dict,
                         category_stats: List[Dict],
                         output_path: Path = Path("scan_results.json")) -> bool:
        try:
            results_data = {
                "scan_date": datetime.now().isoformat(),
                "summary": evaluation_summary,
                "results": test_results,
                "category_stats": category_stats
            }

            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(results_data, f, indent=2, ensure_ascii=False)

            success(f"JSON results saved to {output_path}")
            return True

        except Exception as e:
            error(f"Error saving JSON results: {e}")
            return False