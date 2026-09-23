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

Оркестратор дедуплицирует задачи (один IP не сканируется дважды).

## Статус

- [x] scope-guard (домены + wildcard + CIDR, приоритет out_of_scope) + тесты
- [x] граф Neo4j (клиент, схема, узлы Domain/Subdomain/IP/Service/Port)
- [x] очередь задач + rate limiter (global / per-target) + дедуп
- [x] subdomain-enum через BBOT (парсинг NDJSON)
- [x] DNS-резолв (Subdomain→IP, чистый Go)
- [x] http-probe через httpx (status, title, webserver, tech)
- [x] port scan через nmap (top-100, определение сервисов)
- [x] оркестратор (seed из скоупа, цепочка follow-up задач)
- [ ] MCP-сервер для LLM
- [ ] Finding-узлы и приоритизация
```
