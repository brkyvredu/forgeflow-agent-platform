.PHONY: install test lint typecheck dev compose-up compose-down java-test

install:
	python -m pip install -e '.[dev]'

test:
	pytest

lint:
	ruff check .

typecheck:
	mypy forgeflow forgeflow_mcp

dev:
	adk web .

compose-up:
	docker compose up --build

compose-down:
	docker compose down -v

java-test:
	cd services/java-analysis && mvn test
