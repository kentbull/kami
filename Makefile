.PHONY: lint mypy

lint:
	@echo "Linting..."
	pipenv run ruff check .

mypy:
	@echo "Running mypy..."
	pipenv run mypy .