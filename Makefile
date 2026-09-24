.PHONY: build test tidy neo4j-up neo4j-down run check scope-import archive map cwe-extract cwe-atlas cwe-load

build:
	go build -o bin/agent ./cmd/agent

test:
	go test ./...

tidy:
	go mod tidy

neo4j-up:
	docker compose up -d neo4j

neo4j-down:
	docker compose down

# make run SCOPE=configs/scope.yaml
run: build
	./bin/agent -scope $(or $(SCOPE),configs/scope.yaml)

# make check TARGET=api.standoff365.com
check: build
	./bin/agent -scope $(or $(SCOPE),configs/scope.yaml) -check $(TARGET)

# Скоуп из текста (docs/PLAN.md, фаза 1): сводка, подтверждение, запись.
# make scope-import IN=targets.txt PROGRAM=Example PLATFORM=hackerone
scope-import: build
	./bin/agent -scope-import $(IN) -scope-out $(or $(SCOPE),configs/scope.yaml) -program "$(PROGRAM)" -platform "$(PLATFORM)"

# Архив прогона из графа (docs/PLAN.md, фаза 3).
# make archive RUN=latest   — выгрузить в runs/<run_id>/
archive: build
	./bin/agent -archive $(or $(RUN),latest)

# Сопоставление наблюдений прогона с CWE по правилам (docs/PLAN.md, фаза 5).
# make map RUN=latest
map: build
	./bin/agent -map $(or $(RUN),latest)

# Каталог CWE (см. docs/PLAN.md, фаза 0).
# make cwe-extract CWE_XML=cwec_v4.14.xml   — пересобрать data/cwe/cwe.json из XML MITRE
cwe-extract:
	python3 tools/cwe/extract.py --xml $(CWE_XML)

# make cwe-atlas  — HTML-атлас в build/cwe_atlas.html
cwe-atlas:
	python3 tools/cwe/atlas.py

# make cwe-load   — загрузить каталог в Neo4j
cwe-load: build
	./bin/agent -cwe-load data/cwe/cwe.json
