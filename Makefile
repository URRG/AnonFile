.DEFAULT_GOAL := help

.PHONY: help up down logs ps build test api-test web-test clean

help:
	@echo "Targets: up, down, logs, ps, build, test, api-test, web-test, clean"

up:
	docker compose up --build -d

down:
	docker compose down

logs:
	docker compose logs -f

ps:
	docker compose ps

build:
	docker compose build

test: api-test web-test

api-test:
	docker compose run --rm api pytest

web-test:
	docker compose --profile test run --build --rm web-test

clean:
	docker compose down --remove-orphans
