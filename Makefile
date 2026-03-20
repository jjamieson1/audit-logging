SHELL := /bin/sh

.PHONY: up down test logs ps restart clean health verify sample-log smoke retry-sim retry-sim-fast retry-sim-slow retry-sim-bursty forwarder-validate forwarder-run

up:
	docker compose up --build

down:
	docker compose down

test:
	go test ./...

logs:
	docker compose logs -f

ps:
	docker compose ps

restart:
	docker compose down
	docker compose up --build

clean:
	docker compose down -v

health:
	curl -s http://localhost:8080/v1/health

verify:
	curl -s http://localhost:8080/v1/verify

sample-log:
	curl -s -X POST http://localhost:8080/v1/logs \
		-H "content-type: application/json" \
		-d '{"app":"sample-app","level":"INFO","message":"sample log","metadata":{"source":"make"}}'

smoke: health sample-log verify

retry-sim:
	node ./clients/retry-sim.mjs

retry-sim-fast:
	SIM_ATTEMPTS=6 SIM_INITIAL_BACKOFF_MS=50 SIM_MAX_BACKOFF_MS=500 SIM_MAX_JITTER_MS=25 node ./clients/retry-sim.mjs

retry-sim-slow:
	SIM_ATTEMPTS=6 SIM_INITIAL_BACKOFF_MS=500 SIM_MAX_BACKOFF_MS=5000 SIM_MAX_JITTER_MS=500 node ./clients/retry-sim.mjs

retry-sim-bursty:
	SIM_ATTEMPTS=8 SIM_INITIAL_BACKOFF_MS=100 SIM_MAX_BACKOFF_MS=4000 SIM_MAX_JITTER_MS=1200 node ./clients/retry-sim.mjs

forwarder-validate:
	go run ./cmd/log-forwarder -config ./configs/log-forwarder.example.json -validate-only

forwarder-run:
	go run ./cmd/log-forwarder -config ./configs/log-forwarder.example.json
