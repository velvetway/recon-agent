.PHONY: build test tidy neo4j-up neo4j-down run check

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
