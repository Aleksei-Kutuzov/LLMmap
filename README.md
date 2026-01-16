# LLMmap - Инструмент тестирования безопасности LLM-систем

## Описание проекта

LLMmap — инструмент для автоматизированного аудита безопасности в системах, построенных на больших языковых моделях (LLM). Позволяет проводить комплексное тестирование на уязвимости.
[Вики](https://github.com/Aleksei-Kutuzov/LLMmap.wiki.git)

## Быстрый старт

### Установка

```bash
git clone https://github.com/Aleksei-Kutuzov/LLMmap.git
cd LLMmap
pip install -r requirements.txt
```

### Основные команды

#### 1. Просмотр доступных тестов
```bash
python LLMmap.py list-tests [аргументы]
```

**Аргументы:**
- `-c, --category` — фильтр по категории тестов
- `-s, --severity` — фильтр по уровню серьезности (low, medium, high, critical)
- `-d, --detail` — детальный вывод информации
- `-p, --test_suites_path` — путь к директории с тестами

**Примеры:**
```bash
# Все тесты
python LLMmap.py list-tests

# Только критические тесты категории prompt_injection
python LLMmap.py list-tests -c prompt_injection -s critical -d
```

#### 2. Импорт тестов из внешних источников
```bash
python LLMmap.py parse <source> [аргументы]
```

**Параметры:**
- `source` — URL или путь к файлу (поддерживает JSON, CSV)
- `--output` — выходная директория (по умолчанию: test_suites)
- `--filename` — имя выходного файла
- `--limit` — лимит тестов (0 = без лимита)

**Аргументы маппинга:**
- `--id-field` — поле для ID
- `--name-field` — поле для названия
- `--prompt-field` — поле для промпта
- `--category-field` — поле для категории
- `--severity-field` — поле для серьезности

**Примеры:**
```bash
# Импорт из локального JSON
python LLMmap.py parse file425.json --output ./test_suites --id-field "uid" --limit 100

# Импорт из CSV с GitHub
python LLMmap.py parse https://raw.githubusercontent.com/.../dataset.csv --output ./test_suites --id-field "BehaviorID"
```

#### 3. Запуск сканирования
```bash
python LLMmap.py scan <adapter_config> [аргументы]
```

**Основные аргументы:**
- `--concurrent` — количество параллельных тестов (по умолчанию: 2)
- `-c, --category` — категории тестов (можно несколько)
- `-s, --severity` — уровни серьезности (можно несколько)
- `--custom-tests` — путь к пользовательским тестам
- `-o, --output` — формат отчета (console, json, html, md, all)
- `--output-dir` — директория для отчетов (по умолчанию: reports)
- `--dry-run` — предпросмотр тестов без выполнения

**Примеры:**
```bash
# Базовое сканирование
python LLMmap.py scan config.yaml

# Сканирование с фильтрацией
python LLMmap.py scan config.yaml -c prompt_injection -s critical --concurrent 4

# Сканирование с сохранением отчетов
python LLMmap.py scan config.yaml -o all --output-dir ./scan_results

# Предварительный просмотр
python LLMmap.py scan config.yaml --dry-run
```

## Конфигурация адаптеров

Адаптеры настраиваются через YAML-файлы. Основные разделы:

### Минимальный пример
```yaml
endpoint:
  url: "http://localhost:11434/api/generate"
  method: "POST"

request_template:
  user_prompt:
    field: "prompt"
  model_parameters:
    model:
      field: "model"
      default: "llama3.2"

response_template:
  content_path: "response"

authentication:
  type: "none"
```

### Пример для OpenAI-совместимых API
```yaml
endpoint:
  url: "https://api.openai.com/v1/chat/completions"
  method: "POST"
  headers:
    Content-Type: "application/json"

request_template:
  system_prompt:
    field: "messages[0].content"
    role: "system"
    optional: true
  user_prompt:
    field: "messages[-1].content"
    role: "user"
  model_parameters:
    model:
      field: "model"
      default: "gpt-4"

response_template:
  content_path: "choices[0].message.content"

authentication:
  type: "api_key"
  location: "header"
  field: "Authorization"
  format: "Bearer {api_key}"
  env_vars:
    api_key: "OPENAI_API_KEY"
```

## Поддерживаемые форматы отчетов

1. **Console** — вывод в терминал (по умолчанию)
2. **JSON** — структурированные данные для автоматической обработки
3. **HTML** — визуальный отчет с графиками
4. **Markdown** — текстовый отчет для документации

## Пример вывода отчета

```
LLM SECURITY SCAN REPORT
=======================

Summary:
• Total tests: 650
• Safe responses: 645
• Vulnerable responses: 5
• Vulnerability rate: 0.8%
• Average hack score: 0.014

CRITICAL ISSUES DETECTED:
Found 3 critical vulnerabilities that require immediate attention!

Category Statistics:
• prompt_injection: 639 tests, 5 vulnerable, max score: 1.000
• data_leakage: 2 tests, 0 vulnerable
• jailbreak: 3 tests, 0 vulnerable

Recommendations:
1. Implement stricter validation for prompts attempting to override system instructions
2. Enhance detection of malicious intent in prompts
3. Improve detection and prevention of fake news generation
```

## Архитектура

### Основные компоненты:
1. **Парсер** — конвертация тестов из различных форматов
2. **Адаптер** — универсальное подключение к LLM API
3. **Сканер** — выполнение тестов и сбор результатов
4. **Генератор отчетов** — формирование результатов в различных форматах

### Технологический стек:
- Python 3.8+
- Typer (CLI интерфейс)
- Pydantic (валидация данных)
- HTTPX (HTTP-запросы)
- Jinja2 (генерация отчетов)

## Перспективы развития

1. Поддержка большего количества типов аутентификации
2. Возможность отправки файлов в тестах
3. Генерация тестов на основе шаблонов
4. Открытая библиотека тестов
5. Веб-интерфейс для управления аудитами

## Лицензия

Проект распространяется под лицензией MIT.
