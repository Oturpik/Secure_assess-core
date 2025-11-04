.PHONY: help setup install dev down clean test logs db-migrate db-upgrade

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

setup: ## Initial setup - copy .env.example to .env
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "✓ Created .env file from .env.example"; \
		echo "⚠ Please update .env with your configuration"; \
	else \
		echo "✓ .env file already exists"; \
	fi

install: ## Install Python dependencies
	pip install --upgrade pip
	pip install -r requirements.txt
	@echo "✓ Dependencies installed"

dev: ## Start all services in development mode
	docker-compose up -d
	@echo "✓ Services starting..."
	@echo "  - PostgreSQL:  localhost:5432"
	@echo "  - Redis:       localhost:6379"
	@echo "  - MongoDB:     localhost:27017"
	@echo "  - RabbitMQ:    localhost:5672"
	@echo "  - RabbitMQ UI: http://localhost:15672 (user: scanner_user, pass: scanner_pass)"
	@echo ""
	@echo "Run 'make run-api' to start the FastAPI application"

run-api: ## Run the FastAPI application locally
	python -m uvicorn src.main:app --reload --host 0.0.0.0 --port 8000

down: ## Stop all services
	docker-compose down
	@echo "✓ Services stopped"

clean: ## Stop services and remove volumes
	docker-compose down -v
	@echo "✓ Services stopped and volumes removed"

restart: ## Restart all services
	docker-compose restart
	@echo "✓ Services restarted"

logs: ## Show logs from all services
	docker-compose logs -f

logs-api: ## Show API logs only
	docker-compose logs -f api

ps: ## Show running services
	docker-compose ps

test: ## Run tests
	pytest tests/ -v --cov=src --cov-report=html --cov-report=term

test-unit: ## Run unit tests only
	pytest tests/unit -v

test-integration: ## Run integration tests only
	pytest tests/integration -v

db-shell: ## Open PostgreSQL shell
	docker-compose exec postgres psql -U scanner_user -d scanner_platform

redis-cli: ## Open Redis CLI
	docker-compose exec redis redis-cli

mongo-shell: ## Open MongoDB shell
	docker-compose exec mongodb mongosh -u scanner_user -p scanner_pass

db-migrate: ## Create a new database migration
	@read -p "Enter migration message: " message; \
	alembic revision --autogenerate -m "$$message"

db-upgrade: ## Apply database migrations
	alembic upgrade head

db-downgrade: ## Rollback last database migration
	alembic downgrade -1

format: ## Format code with black
	black src/ tests/

lint: ## Lint code with ruff
	ruff check src/ tests/

type-check: ## Type check with mypy
	mypy src/

check: format lint type-check ## Run all code quality checks

create-user: ## Create a superuser (interactive)
	python scripts/create_user.py

seed-data: ## Seed database with initial data
	python scripts/seed_compliance_data.py