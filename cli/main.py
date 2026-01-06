import typer
from pathlib import Path
import json

from core.load_tests import load_tests, TestsConfig, TestCase
from core.scanner import LLMSecurityScanner

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
def scan(adapter_config: str = typer.Argument( ..., help="Путь к конфигурационному файлу адаптера (YAML)"),
        concurrent: int = typer.Option(
             2,
                    help="Максимальное количество параллельных тестов")):
        tests_config = TestsConfig(
            test_suites_path=Path(r"C:\Users\Admin\PycharmProjects\LLMmap\test_suites"),
            max_concurrent_tests=concurrent
        )

        scanner = LLMSecurityScanner(Path(adapter_config), tests_config)
        scanner.run_scan()
