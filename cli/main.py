from typing import Optional, List

import typer
from pathlib import Path

from core.load_tests import load_tests, TestsConfig, TestCase, Severity
from core.scanner import LLMSecurityScanner
from core.parser.parser import LLMTestParser
from core.utils.logging import success, info, neutral, warning

app = typer.Typer(help="LLM Vulnerability Scanner", rich_markup_mode="rich")

@app.command("list-tests")
def list_tests(category: str | None = typer.Option(None, "--category", "-c",
                                               help="Фильтр по категории"),
               severity: str | None = typer.Option(None, "--severity", "-s",
                                               help="Фильтр по уровню критичности"),
               test_suites_path: str = typer.Option("./test_suites", "--test_suites_path", "-p",
                                               help="Путь к директории с тестами"),
               detail: bool = typer.Option(False, "--detail", "-d",
                                               help="Показывать детальную информацию")):
    """
    Показать список доступных тестов.
    """

    default_config = TestsConfig()

    if not category:
        category = default_config.enabled_categories
    if not severity:
        severity = default_config.severity_filter
    if not test_suites_path:
        test_suites_path = default_config.test_suites_path

    config = TestsConfig(enabled_categories=category, severity_filter=severity, test_suites_path=test_suites_path)

    tests = load_tests(config)

    for category_key in tests:
        category = tests[category_key]
        typer.secho(f"Category {category_key}")
        for test in category:
            test: TestCase
            if detail:
                typer.secho(f"• {test.id} {test.name} - {test.severity}\n{test.description}\npayload: {test.payload}")
            else:
                typer.echo(f"• {test.id} {test.name} - {test.severity}")


@app.command()
def scan(adapter_config: str = typer.Argument(..., help="Путь к конфигурационному файлу адаптера (YAML)"),
         concurrent: int = typer.Option(2,help="Максимальное количество параллельных тестов"),
         categories: Optional[List[str]] = typer.Option(None, "--category", "-c",
            help="Категории тестов для запуска (можно указать несколько раз). Пример: -c prompt_injection -c rag" ),
         severity: Optional[List[Severity]] = typer.Option(None,
            "--severity", "-s",
            help="Уровни серьезности для фильтрации (можно указать несколько раз). Пример: -s high -s critical"),
        test_suites_path: Optional[str] = typer.Option(None,"--test-suites",
            help="Путь к директории с тест-сьютами. По умолчанию используется стандартная директория"),
        custom_tests_path: Optional[str] = typer.Option(None, "--custom-tests", help="Путь к директории с пользовательскими тестами"),
        enable_all_categories: bool = typer.Option(True,"--all-categories/--no-all-categories",
            help="Включить все категории тестов (если не указаны конкретные через -c)"),
        enable_all_severities: bool = typer.Option(True,"--all-severities/--no-all-severities",
            help="Включить все уровни серьезности (если не указаны конкретные через -s)"),
        output_format: str = typer.Option("console", "--output", "-o",
                                           help="Формат вывода результатов: console, json, html, md, all"),
        output_dir: Optional[str] = typer.Option("reports", "--output-dir",
                                                  help="Директория для сохранения отчетов"),
        batch_size: int = typer.Option(10,"--batch-size",
            help="Размер батча для оценки ответов (количество тестов, передаваемых оценщику за раз)"),
        dry_run: bool = typer.Option(False,"--dry-run",
            help="Показать какие тесты будут запущены без фактического выполнения")):
    """

    Базовое сканирование:
       scan config.yaml

    Сканирование определенных категорий:
       scan config.yaml -c prompt_injection -c data_leakage

    Сканирование критических уязвимостей:
       scan config.yaml -s critical

    Сканирование с пользовательскими тестами:
       scan config.yaml --custom-tests ./my_tests

    Сканирование с сохранением в HTML:
       scan config.yaml -o html --output-file report.html
    """
    if test_suites_path:
        test_suites = Path(test_suites_path)
    else:
        test_suites = Path(r"C:\Users\Admin\PycharmProjects\LLMmap\test_suites")

    if categories:
        enabled_categories = categories
    elif enable_all_categories:
        enabled_categories = "all"
    else:
        enabled_categories = []

    if severity:
        severity_filter = list(severity)
    elif enable_all_severities:
        severity_filter = [s for s in Severity]
    else:
        severity_filter = []

    tests_config = TestsConfig(test_suites_path=test_suites,
                               custom_tests_path=Path(custom_tests_path) if custom_tests_path else None,
                               enabled_categories=enabled_categories,
                               severity_filter=severity_filter,
                               max_concurrent_tests=concurrent)

    if dry_run:
        from core.load_tests import load_tests
        test_cases = load_tests(tests_config)

        info("\n" + "=" * 60)
        info("DRY RUN: The following tests will be performed:")
        info("=" * 60)

        total_tests = 0
        for category, cases in test_cases.items():
            warning(f"\n{category.upper()}: {len(cases)} тестов")

            severity_groups = {}
            for case in cases:
                if case.severity not in severity_groups:
                    severity_groups[case.severity] = []
                severity_groups[case.severity].append(case)

            for sev, sev_cases in severity_groups.items():
                severity_color = {
                    "low": "green",
                    "medium": "yellow",
                    "high": "red",
                    "critical": "red"
                }.get(sev.lower(), "white")

                typer.secho(f"  {sev}: {len(sev_cases)} тестов", fg=severity_color)

                for i, case in enumerate(sev_cases[:3]):
                    neutral(f"    - {case.name} (ID: {case.id})")

                if len(sev_cases) > 3:
                    neutral(f"    ... and {len(sev_cases) - 3}")

            total_tests += len(cases)

        info("\n" + "=" * 60)
        info(f"TOTAL: {total_tests} tests in {len(test_cases)} categories")
        info("=" * 60 + "\n")

        return

    scanner = LLMSecurityScanner(adapter_config_path=Path(adapter_config), tests_config=tests_config)

    scanner.run_scan(batch_size)

    save_formats = []
    if output_format == "all":
        save_formats = ["json", "html", "md"]
    elif output_format != "console":
        save_formats = [output_format]

    if save_formats:
        output_dir_path = Path(output_dir)

        if "json" in save_formats:
            json_path = output_dir_path / "scan_results.json"
            scanner.save_results_json(json_path)

        if "html" in save_formats or "md" in save_formats:
            test_results_data = []
            for result in scanner.test_results:
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
                "total_tests": scanner.evaluation_summary.total_tests,
                "vulnerable_count": scanner.evaluation_summary.vulnerable_count,
                "avg_hack_score": scanner.evaluation_summary.avg_hack_score,
                "max_hack_score": scanner.evaluation_summary.max_hack_score,
                "recommendations": scanner.evaluation_summary.recommendations,
                "pros": scanner.evaluation_summary.pros,
                "cons": scanner.evaluation_summary.cons,
            }

            category_stats_data = []
            for category, stats in scanner.category_stats.items():
                stats_dict = stats.get_stats()
                vulnerable_in_category = sum(
                    1 for r in scanner.test_results
                    if r.category == category and r.hack_score > 0.5
                )
                stats_dict["vulnerable_count"] = vulnerable_in_category
                category_stats_data.append(stats_dict)

            template_dir = Path(__file__).parent.parent / "core" / "reports" / "templates"
            warning(template_dir)
            if not template_dir.exists():
                template_dir = Path(".")

            from core.reports.report_generator import ReportGenerator
            report_generator = ReportGenerator(template_dir)

            if "html" in save_formats:
                html_path = output_dir_path / "scan_report.html"
                html_success = report_generator.generate_html_report(
                    test_results=test_results_data,
                    evaluation_summary=evaluation_summary_data,
                    category_stats=category_stats_data,
                    model_name=scanner.target_config.model_config.get("model", "model_name"),
                    output_path=html_path
                )
                if html_success:
                    success(f"HTML report saved to {html_path}")


            if "md" in save_formats:
                md_path = output_dir_path / "scan_report.md"
                md_success = report_generator.generate_markdown_report(
                    test_results=test_results_data,
                    evaluation_summary=evaluation_summary_data,
                    category_stats=category_stats_data,
                    model_name=scanner.target_config.model_config.get("model", "model_name"),
                    output_path=md_path
                )
                if md_success:
                    success(f"Markdown report saved to {md_path}")

        info(f"\nReports saved to directory: {output_dir_path.absolute()}")

    if output_format == "console":
        success("Report displayed in console only. Use --output option to save to files.")


@app.command()
def parse(source: str = typer.Argument(..., help="Источник: URL или путь к файлу"),
          output: str = typer.Option("test_suites", help="Выходная директория"),
          filename: str = typer.Option("filename", help="Имя выходного файла"),
          id_field: str = typer.Option("id", help="Поле для ID"),
          name_field: str = typer.Option("name", help="Поле для названия"),
          prompt_field: str = typer.Option("user_prompt", help="Поле для промпта"),
          category_field: str = typer.Option("category", help="Поле для категории"),
          severity_field: str = typer.Option("severity", help="Поле для серьезности"),
          limit: int = typer.Option(0, help="Лимит тестов (0 = без лимита)")):
    """Парсит тесты безопасности LLM из различных источников."""
    parser = LLMTestParser()

    mapping = {
        "id": id_field,
        "name": name_field,
        "user_prompt": prompt_field,
        "category": category_field,
        "severity": severity_field,
        # опциональные
        "description": "description",
        "system_prompt": "system_prompt",
        "temperature": "temperature",
        "max_tokens": "max_tokens"
    }

    count = parser.parse(source, output, mapping, filename, limit=limit)
    success(f"Total processed: {count} tests")