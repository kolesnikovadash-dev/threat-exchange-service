.PHONY: run build test test-integration coverage lint fmt docker-up docker-down

run:
	go run ./cmd/server

build:
	mkdir -p bin
	go build -o bin/server ./cmd/server

test:
	go test ./...

test-integration:
	@test -n "$(TEST_DATABASE_URL)" || (echo "Укажи TEST_DATABASE_URL для отдельной тестовой базы"; exit 1)
	TEST_DATABASE_URL="$(TEST_DATABASE_URL)" go test -tags=integration ./internal/integration -v

coverage:
	go test ./... -coverprofile=coverage.out
	go tool cover -func=coverage.out | grep total

lint:
	go vet ./...

fmt:
	gofmt -w .

docker-up:
	docker compose up -d --build

docker-down:
	docker compose down
