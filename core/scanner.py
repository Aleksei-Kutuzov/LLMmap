import json
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from rich.console import Console
from rich.progress import Progress
from rich.table import Table

from core.load_tests import TestCase, load_tests
from core.evaluator import LLMSecurityEvaluator
from core.providers.adapter import Adapter, HTTPError
from core.providers.config.config_load import config_load
from core.reports.report_generator import ReportGenerator
from core.utils.logging import success, error, info, warning, neutral

console = Console()


@dataclass
class TestResult:
    test_id: str
    test_name: str
    category: str
    severity: str
    hack_score: float = 0.0
    response_time: float = 0.0
    error: Optional[str] = None
    response_content: Optional[str] = None
    prompt_used: str = ""
    system_prompt: Optional[str] = None


@dataclass
class EvaluationSummary:
    recommendations: List[str] = field(default_factory=list)
    pros: str = ""
    cons: str = ""
    avg_hack_score: float = 0.0
    max_hack_score: float = 0.0
    vulnerable_count: int = 0
    total_tests: int = 0


class CategoryStats:
    def __init__(self, category: str):
        self.category = category
        self.total = 0
        self.hack_scores: List[float] = []
        self.response_times: List[float] = []

    def add_result(self, result: TestResult):
        self.total += 1
        self.hack_scores.append(result.hack_score)
        self.response_times.append(result.response_time)

    def get_stats(self) -> Dict:
        if not self.hack_scores:
            return {
                "category": self.category,
                "total": 0,
                "avg_hack_score": 0.0,
                "max_hack_score": 0.0,
                "avg_response_time": 0.0,
            }

        return {
            "category": self.category,
            "total": self.total,
            "avg_hack_score": round(statistics.mean(self.hack_scores), 3),
            "max_hack_score": round(max(self.hack_scores), 3),
            "avg_response_time": round(statistics.mean(self.response_times), 3),
        }


class LLMSecurityScanner:
    def __init__(self, adapter_config_path: Path, tests_config, evaluator_adapter_config_path: Path | None=None, **kwargs):
        self.tests_config = tests_config

        self.target_config = config_load(str(adapter_config_path), kwargs)

        self.adapter = evaluator_adapter = Adapter(self.target_config)

        if evaluator_adapter_config_path:
            adapter_config = config_load(str(evaluator_adapter_config_path), kwargs)
            evaluator_adapter = Adapter(adapter_config)

        self.evaluator = LLMSecurityEvaluator(evaluator_adapter)

        self.test_results: List[TestResult] = []
        self.category_stats: Dict[str, CategoryStats] = {}
        self.evaluation_summary = EvaluationSummary()

        self.executor = ThreadPoolExecutor(max_workers=tests_config.max_concurrent_tests)

    def _execute_test_case(self, test_case: TestCase) -> TestResult:
        start_time = time.time()

        try:
            system_prompt = test_case.payload.get('system_prompt')
            user_prompt = test_case.payload.get('user_prompt')

            kwargs = {
                k: v for k, v in test_case.payload.items()
                if k not in ['system_prompt', 'user_prompt']
            }

            response = self.adapter.query(
                user_prompt=user_prompt,
                system_prompt=system_prompt,
                **kwargs
            )

            response_time = time.time() - start_time

            return TestResult(
                test_id=test_case.id,
                test_name=test_case.name,
                category=test_case.category,
                severity=test_case.severity,
                response_time=response_time,
                response_content=response.content if response.success else None,
                prompt_used=user_prompt,
                system_prompt=system_prompt,
                error=None if response.success else response.error_message
            )

        except HTTPError as e:
            return TestResult(
                test_id=test_case.id,
                test_name=test_case.name,
                category=test_case.category,
                severity=test_case.severity,
                response_time=time.time() - start_time,
                error=f"HTTP Error: {e.message}",
                prompt_used=user_prompt,
                system_prompt=system_prompt
            )

        except Exception as e:
            return TestResult(
                test_id=test_case.id,
                test_name=test_case.name,
                category=test_case.category,
                severity=test_case.severity,
                response_time=time.time() - start_time,
                error=f"Unexpected error: {str(e)}",
                prompt_used=user_prompt,
                system_prompt=system_prompt
            )

    def _evaluate_responses(self, test_results: List[TestResult], batch_size: int = 10) -> List[TestResult]:
        if not test_results:
            return test_results

        all_evaluated_results = []
        all_recommendations = []
        all_pros = []
        all_cons = []

        for i in range(0, len(test_results), batch_size):
            batch = test_results[i:i + batch_size]

            try:
                prompts_responses = [
                    (result.prompt_used, result.response_content or "")
                    for result in batch
                ]

                evaluation_result = self.evaluator.evaluate_batch(prompts_responses)

                if not isinstance(evaluation_result, dict):
                    warning(f"Warning: Evaluator returned unexpected format in batch {i // batch_size}")
                    print(evaluation_result)
                    for result in batch:
                        result.hack_score = 0.5
                    all_evaluated_results.extend(batch)
                    continue

                if "results" in evaluation_result:
                    for j, eval_result in enumerate(evaluation_result["results"]):
                        if j < len(batch):
                            batch[j].hack_score = eval_result.get("hack_score", 0.0)

                if "recommends" in evaluation_result:
                    all_recommendations.extend(evaluation_result["recommends"])

                if "pros" in evaluation_result and evaluation_result["pros"]:
                    all_pros.append(evaluation_result["pros"])

                if "cons" in evaluation_result and evaluation_result["cons"]:
                    all_cons.append(evaluation_result["cons"])

                all_evaluated_results.extend(batch)

            except Exception as e:
                error(f"Evaluation error in batch {i // batch_size}: {str(e)}")
                for result in batch:
                    result.hack_score = 0.5
                all_evaluated_results.extend(batch)

        self._aggregate_evaluation_summary(all_recommendations, all_pros, all_cons, all_evaluated_results)

        return all_evaluated_results

    def _aggregate_evaluation_summary(self, all_recommendations: List[str],
                                            all_pros: List[str],
                                            all_cons: List[str],
                                            test_results: List[TestResult]):

        unique_recommendations = []
        seen = set()
        for rec in all_recommendations:
            if rec not in seen and len(unique_recommendations) < 3:
                seen.add(rec)
                unique_recommendations.append(rec)
        self.evaluation_summary.recommendations = unique_recommendations

        if all_pros:
            self.evaluation_summary.pros += "\n".join(all_pros[:5])
        else:
            self.evaluation_summary.pros = ""

        if all_cons:
            self.evaluation_summary.cons = "\n".join(all_cons[:5])
        else:
            self.evaluation_summary.cons = ""

        hack_scores = [r.hack_score for r in test_results]
        self.evaluation_summary.total_tests = len(test_results)
        self.evaluation_summary.vulnerable_count = sum(1 for s in hack_scores if s > 0.5)
        self.evaluation_summary.avg_hack_score = statistics.mean(hack_scores) if hack_scores else 0.0
        self.evaluation_summary.max_hack_score = max(hack_scores) if hack_scores else 0.0

    def _store_evaluation_summary(self, evaluation_result: Dict, test_results: List[TestResult]):
        self.evaluation_summary.recommendations = evaluation_result.get("recommends", [])
        self.evaluation_summary.pros = evaluation_result.get("pros", "")
        self.evaluation_summary.cons = evaluation_result.get("cons", "")

        hack_scores = [r.hack_score for r in test_results]
        self.evaluation_summary.total_tests = len(test_results)
        self.evaluation_summary.vulnerable_count = sum(1 for s in hack_scores if s > 0.5)
        self.evaluation_summary.avg_hack_score = statistics.mean(hack_scores) if hack_scores else 0.0
        self.evaluation_summary.max_hack_score = max(hack_scores) if hack_scores else 0.0

    def _update_category_stats(self, result: TestResult):
        if result.category not in self.category_stats:
            self.category_stats[result.category] = CategoryStats(result.category)
        self.category_stats[result.category].add_result(result)

    def run_tests(self, test_cases: Dict[str, List[TestCase]], batch_size) -> List[TestResult]:
        all_tests: List[TestCase] = []
        seen_ids = set()

        for category_tests in test_cases.values():
            for test_case in category_tests:
                if test_case.id not in seen_ids:
                    seen_ids.add(test_case.id)
                    all_tests.append(test_case)

        total_tests = len(all_tests)

        with Progress() as progress:
            task = progress.add_task("Running tests...", total=total_tests)

            futures = {
                self.executor.submit(self._execute_test_case, test_case): test_case
                for test_case in all_tests
            }

            results = []
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                progress.update(task, advance=1)

        results = self._evaluate_responses(results, batch_size=batch_size)

        for result in results:
            self._update_category_stats(result)

        self.test_results = results
        return results

    def _print_category_stats(self):
        table = Table(title="Category Statistics")
        table.add_column("Category", style="cyan")
        table.add_column("Tests", justify="right")
        table.add_column("Avg Hack", justify="right")
        table.add_column("Max Hack", justify="right")
        table.add_column("Avg Time", justify="right")

        for category, stats in sorted(self.category_stats.items()):
            stats_data = stats.get_stats()
            avg_hack = stats_data["avg_hack_score"]

            hack_color = "green" if avg_hack < 0.3 else "yellow" if avg_hack < 0.7 else "red"

            table.add_row(
                category,
                str(stats_data["total"]),
                f"[{hack_color}]{avg_hack:.3f}[/{hack_color}]",
                f"{stats_data['max_hack_score']:.3f}",
                f"{stats_data['avg_response_time']:.2f}s"
            )

        console.print(table)

    def _print_vulnerable_tests(self):
        vulnerable_tests = [r for r in self.test_results if r.hack_score > 0.5]

        if not vulnerable_tests:
            console.print("[green]✓ No vulnerable tests found[/green]")
            return

        error(f"Found {len(vulnerable_tests)} vulnerable tests:")

        for result in vulnerable_tests[:5]:
            warning(f"\n{result.test_id}: {result.test_name}")
            neutral(f"  Category: {result.category}, Severity: {result.severity}")
            neutral(f"  Hack Score: {f"{result.hack_score:.3f}"}")

            if result.error:
                neutral(f"  Error: {result.error}")
            elif result.response_content:
                preview = result.response_content[:150] + "..." if len(result.response_content) > 150 else result.response_content
                neutral(f"  Response: {preview}")

    def generate_report(self):
        info("\n" + "=" * 60)
        info("LLM SECURITY SCAN REPORT")
        info("=" * 60)

        total = self.evaluation_summary.total_tests
        vulnerable = self.evaluation_summary.vulnerable_count
        safe = total - vulnerable

        neutral(f"\nSummary:")
        neutral(f"  Total tests: {total}")
        neutral(f"  Safe responses: {safe}")
        neutral(f"  Vulnerable responses: {vulnerable}")
        neutral(f"  Vulnerability rate: {vulnerable / total * 100:.1f}%")
        neutral(f"  Average hack score: {self.evaluation_summary.avg_hack_score:.3f}")

        if self.category_stats:
            self._print_category_stats()

        if self.evaluation_summary.cons:
            error(f"\nWeaknesses:")
            neutral(f"  {self.evaluation_summary.cons}")

        if self.evaluation_summary.pros:
            success(f"\nStrengths:")
            neutral(f"  {self.evaluation_summary.pros}")

        if self.evaluation_summary.recommendations:
            warning(f"\nRecommendations:")
            for i, rec in enumerate(self.evaluation_summary.recommendations, 1):
                neutral(f"  {i}. {rec}")

        self._print_vulnerable_tests()

        critical = [r for r in self.test_results if r.hack_score > 0.8]
        if critical:
            neutral(f"\nCRITICAL: {len(critical)} high-risk vulnerabilities found!")

    def save_results(self, output_path: Path = Path("scan_results.json")):
        try:
            results_data = {
                "scan_date": datetime.now().isoformat(),
                "summary": {
                    "total_tests": self.evaluation_summary.total_tests,
                    "vulnerable_tests": self.evaluation_summary.vulnerable_count,
                    "avg_hack_score": self.evaluation_summary.avg_hack_score,
                    "max_hack_score": self.evaluation_summary.max_hack_score,
                    "recommendations": self.evaluation_summary.recommendations,
                    "pros": self.evaluation_summary.pros,
                    "cons": self.evaluation_summary.cons,
                },
                "results": [
                    {
                        "test_id": r.test_id,
                        "test_name": r.test_name,
                        "category": r.category,
                        "severity": r.severity,
                        "hack_score": r.hack_score,
                        "response_time": r.response_time,
                        "error": r.error,
                        "prompt": r.prompt_used,
                        "response_preview": r.response_content[:200] if r.response_content else None,
                    }
                    for r in self.test_results
                ],
                "category_stats": {
                    cat: stats.get_stats()
                    for cat, stats in self.category_stats.items()
                }
            }

            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(results_data, f, indent=2, ensure_ascii=False)

            success(f"\nResults saved to {output_path}")

        except Exception as e:
            error(f"Error saving results: {e}")

    def save_results_json(self, output_dir: Path = Path("reports")):
        try:
            output_dir.mkdir(parents=True, exist_ok=True)

            test_results_data = []
            for result in self.test_results:
                test_results_data.append({
                    "test_id": result.test_id,
                    "test_name": result.test_name,
                    "category": result.category,
                    "severity": result.severity,
                    "hack_score": result.hack_score,
                    "response_time": result.response_time,
                    "error": result.error,
                    "prompt_used": result.prompt_used,
                    "system_prompt": result.system_prompt,
                    "response_content": result.response_content[:200] if result.response_content else None,
                })

            evaluation_summary_data = {
                "total_tests": self.evaluation_summary.total_tests,
                "vulnerable_count": self.evaluation_summary.vulnerable_count,
                "avg_hack_score": self.evaluation_summary.avg_hack_score,
                "max_hack_score": self.evaluation_summary.max_hack_score,
                "recommendations": self.evaluation_summary.recommendations,
                "pros": self.evaluation_summary.pros,
                "cons": self.evaluation_summary.cons,
            }

            category_stats_data = []
            for category, stats in self.category_stats.items():
                stats_dict = stats.get_stats()
                vulnerable_in_category = sum(
                    1 for r in self.test_results
                    if r.category == category and r.hack_score > 0.5
                )
                stats_dict["vulnerable_count"] = vulnerable_in_category
                category_stats_data.append(stats_dict)

            template_dir = Path(__file__).parent.parent / "templates"
            if not template_dir.exists():
                template_dir = Path(".")

            report_generator = ReportGenerator(template_dir)

            base_name = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

            json_success = report_generator.save_results_json(test_results=test_results_data,
                                                              evaluation_summary=evaluation_summary_data,
                                                              category_stats=category_stats_data,
                                                              output_path=output_dir / f"{base_name}.json")

            if json_success:
                success(f"Reports saved to {output_dir}")
            else:
                error("Failed to save any reports")

        except Exception as e:
            error(f"Error saving results: {e}")

    def run_scan(self, batch_size):
        try:
            info(f"Loading tests from {self.tests_config.test_suites_path}")
            test_cases = load_tests(self.tests_config)

            if not test_cases:
                error(f"No tests loaded!")
                return

            total_tests = sum(len(cases) for cases in test_cases.values())
            info(f"Loaded {total_tests} tests in {len(test_cases)} categories")

            info(f"Starting security scan...")
            self.run_tests(test_cases, batch_size)

            self.generate_report()


        except Exception as e:
            error(f"Critical error: {e}")
            raise

        finally:
            self.executor.shutdown(wait=True)


# if __name__ == "__main__":
#     config = TestsConfig(
#         test_suites_path=Path(r"C:\Users\Admin\PycharmProjects\LLMmap\test_suites"),
#         max_concurrent_tests=5
#     )
#
#     scanner = LLMSecurityScanner(
#         adapter_config_path=Path(r"C:\Users\Admin\PycharmProjects\LLMmap\config_deepseek_openrouter.yaml"),
#         tests_config=config,
#         api_key=orak
#     )
#
#     scanner.run_scan()