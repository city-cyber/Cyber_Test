# Итоговое задание (Homework 14): Анализ угроз и реагирование

Этот проект реализует итоговое задание с двумя источниками данных:
- данные об уязвимостях (Vulners API или локальный JSON);
- события безопасности Suricata (логи JSONL).

## Что делает скрипт
- Загружает данные из API или локальных файлов.
- Находит опасные уязвимости по порогу CVSS.
- Выявляет подозрительные IP по событиям Suricata (алерты + всплеск DNS-запросов).
- Имитирует реагирование на инциденты (блокировка IP + уведомления).
- Сохраняет результаты анализа в JSON/CSV.
- Строит и сохраняет график в PNG.

## Структура проекта
- `final_task.py` — основной скрипт.
- `data/sample_vulners.json` — локальный набор уязвимостей (fallback).
- `data/sample_suricata_eve.jsonl` — пример логов Suricata.
- `results/` — папка с результатами выполнения.

## Запуск
```bash
python final_task.py
```

## Переменные окружения (опционально)
- `VULNERS_API_KEY` — включить получение данных из Vulners API.
- `TELEGRAM_BOT_TOKEN` и `TELEGRAM_CHAT_ID` — имитация отправки уведомлений в Telegram.
- `ALERT_EMAIL` — имитация отправки email-уведомлений.

## Выходные файлы
- `results/high_cvss_vulns.csv`
- `results/suspicious_ips.csv`
- `results/alerts.csv`
- `results/analysis_report.json`
- `results/top_suspicious_ips.png`
