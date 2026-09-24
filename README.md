# Recon-agent

Автоматизация разведки для **авторизованного** bug bounty. BBOT собирает
активы в граф Neo4j, LLM-оркестратор работает поверх графа через Go/MCP.
Собственный **scope-guard** блокирует любые действия вне скоупа программы.

> ⚠️ Инструмент предназначен только для программ, где у вас есть явное
> разрешение на тестирование. scope-guard — страховка, а не индульгенция.

## Стек

- **Go** — ядро, оркестрация, CLI
- **BBOT** — сбор активов (запускается как subprocess, парсится NDJSON)
- **Neo4j 5** — граф активов
- **MCP** — интерфейс для LLM поверх графа *(в работе)*
- **scope-guard** — двойная проверка границ скоупа

## Архитектура

```
                 ┌────────────────┐
                 │  scope.yaml    │  границы программы
                 └───────┬────────┘
                         │
              ┌──────────▼───────────┐
              │     scope-guard      │  ← проверка №1 и №2
              └──────────┬───────────┘
                         │
   ┌─────────────┐   ┌───▼────────┐   ┌──────────────┐
   │ orchestrator│──▶│   queue    │──▶│   scanner    │
   │ observe/    │   │ + rate     │   │ (bbot и др.) │
   │ decide/act  │   │  limiter   │   └──────┬───────┘
   └─────────────┘   └────────────┘          │
          ▲                                   ▼
          │            ┌──────────────────────────┐
          └────────────│         Neo4j (граф)      │
                       └──────────────────────────┘
```

Онтология графа:

```
(Program)-[:HAS_SCOPE]->(Domain)-[:HAS_SUBDOMAIN]->(Subdomain)
(Subdomain)-[:RESOLVES_TO]->(IP)-[:HAS_PORT]->(Port)-[:RUNS]->(Service)
(Service)-[:HAS_FINDING]->(Finding)
```

### Двойной scope-guard

1. **orchestrator** — проверяет цель перед постановкой задачи в очередь.
2. **scanner** — проверяет цель ещё раз перед запуском инструмента, и
   каждый найденный актив перед записью в граф.

Так галлюцинация LLM или "лишний" результат BBOT не приведёт к действию
вне скоупа.

## Быстрый старт

```bash
# 1. поднять Neo4j
export NEO4J_PASSWORD=change-me
make neo4j-up

# 2. задать скоуп
cp configs/scope.example.yaml configs/scope.yaml
$EDITOR configs/scope.yaml

# 3. проверить одну цель через scope-guard (без сети)
make check TARGET=api.standoff365.com

# 4. запустить разведку
make run
```

## Пайплайн разведки

Задачи связаны в цепочку, каждый этап ставит следующий через scope-guard:

```
subdomain_enum (bbot)  ──▶  dns_resolve (Go net)  ──┬─▶  http_probe (httpx)
   Domain→Subdomain          Subdomain→IP           └─▶  port_scan (nmap)
                                                          IP→Port→Service
```

Оркестратор дедуплицирует задачи (один IP не сканируется дважды) и не ставит
задачу шумнее, чем разрешает `profile` программы: на `passive` пройдёт только
пассивный сбор, `port_scan` требует `active`. Прогон завершается сам, когда
очередь опустела; Ctrl+C прерывает досрочно. Все активы прогона помечаются
`run_id` (метка по времени старта), а сам прогон записывается узлом `(:Run)`.

## Статус

- [x] scope-guard (домены + wildcard + CIDR, приоритет out_of_scope) + тесты
- [x] граф Neo4j (клиент, схема, узлы Domain/Subdomain/IP/Service/Port)
- [x] очередь задач + rate limiter (global / per-target) + дедуп
- [x] subdomain-enum через BBOT (парсинг NDJSON)
- [x] DNS-резолв (Subdomain→IP, чистый Go)
- [x] http-probe через httpx (status, title, webserver, tech)
- [x] port scan через nmap (top-100, определение сервисов)
- [x] оркестратор (seed из скоупа, цепочка follow-up задач)
- [x] каталог CWE: `data/cwe/cwe.json` (938 слабостей, RU+EN), загрузка в граф, HTML-атлас
- [x] импорт скоупа из текста или файла в `scope.yaml` со сводкой перед записью
- [x] профили инструментов (`passive`/`light`/`active`), `run_id`, самозавершение прогона
- [ ] MCP-сервер для LLM
- [ ] Finding-узлы и приоритизация

Полный план развития — [docs/PLAN.md](docs/PLAN.md).

## Скоуп из текста

Скоуп можно не писать руками, а вставить как есть со страницы программы:
по одной цели в строке, можно через запятую.

```text
In scope:
- *.example.com
- https://api.example.com/v2   (Public API)
- app.example.com:8443, shop.example.com
- 203.0.113.0/24
Out of scope:
- blog.example.com
!203.0.113.128/25
```

```bash
make scope-import IN=targets.txt PROGRAM=Example PLATFORM=hackerone
# или без make; '-' — читать из stdin, без -scope-out — YAML в stdout
pbpaste | ./bin/agent -scope-import - -program Example
```

Понимает домены, `*.wildcard`, URL (берётся хост), `host:port`, IP (станет
`/32` или `/128`) и CIDR. Вне скоупа — префикс `!` или заголовок секции
(`Out of scope:`, `Вне скоупа:`). Текст после цели (описание) отбрасывается.
Перед записью команда печатает сводку: что попало в скоуп, что вне, какие
строки отброшены и почему. Файл записывается только после подтверждения или с
флагом `-yes`.

## Каталог CWE

Справочник слабостей MITRE CWE (представление CWE-1000 Research Concepts)
с русским переводом названий и описаний. На него опираются правила
«сигнал → CWE» и проверка ответов LLM: CWE-ID принимается, только если он есть
в каталоге.

```bash
make cwe-load     # загрузить каталог в Neo4j: (:CWE)-[:CHILD_OF]->(:CWE)
make cwe-atlas    # собрать HTML-атлас в build/cwe_atlas.html

# пересобрать data/cwe/cwe.json из свежего XML MITRE
# (https://cwe.mitre.org/data/xml/cwec_latest.xml.zip)
make cwe-extract CWE_XML=cwec_latest.xml.zip
```

Перевод хранится отдельно в `data/cwe/cwe_ru.tsv` (`id<TAB>название<TAB>описание`),
поэтому при обновлении каталога MITRE он подмешивается заново, а для новых
записей экстрактор выводит список CWE без перевода.
```
