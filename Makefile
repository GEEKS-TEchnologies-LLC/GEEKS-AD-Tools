# GEEKS-AD-Plus Makefile
# Provides additional build targets and automation

.PHONY: help build clean test package install dev run docker-build docker-run docs lint format update system-deps

# Default target
help:
	@echo "GEEKS-AD-Plus Build System"
	@echo "=========================="
	@echo ""
	@echo "Available targets:"
	@echo "  build      - Full build (Python dependencies, database, credential provider)"
	@echo "  clean      - Clean build artifacts"
	@echo "  test       - Run tests only"
	@echo "  package    - Create distribution package"
	@echo "  install    - Install dependencies only"
	@echo "  dev        - Setup development environment"
	@echo "  run        - Run the application"
	@echo "  start      - Start with virtual environment"
	@echo "  start-auto - Start with auto-update functionality"
	@echo "  network-info - Show network access information"
	@echo "  update     - Update files from git repository"
	@echo "  system-deps - Install system dependencies"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-run   - Run with Docker"
	@echo "  docs       - Generate documentation"
	@echo "  lint       - Run code linting"
	@echo "  format     - Format code"
	@echo ""

# Detect OS
ifeq ($(OS),Windows_NT)
	PYTHON := python
	PIP := pip
	BUILD_SCRIPT := build.bat
else
	PYTHON := python3
	PIP := pip3
	BUILD_SCRIPT := ./build.sh
endif

# Full build
build:
	@echo "Starting full build..."
	$(PYTHON) build.py

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	$(PYTHON) build.py clean

# Run tests
test:
	@echo "Running tests..."
	$(PYTHON) build.py test

# Create package
package:
	@echo "Creating package..."
	$(PYTHON) build.py package

# Install dependencies only
install:
	@echo "Installing dependencies..."
	$(PYTHON) -m pip install -r requirements.txt

# Development setup
dev: install
	@echo "Setting up development environment..."
	$(PYTHON) -c "from app import create_app, db; app = create_app(); app.app_context().push(); db.create_all()"
	@echo "Development environment ready!"

# Run application
run:
	@echo "Starting GEEKS-AD-Plus on http://0.0.0.0:5000..."
	$(PYTHON) app.py

# Start with virtual environment activation
start:
	@echo "Starting GEEKS-AD-Plus with virtual environment on http://0.0.0.0:5000..."
	@if [ -d "venv" ]; then \
		venv/bin/python app.py; \
	else \
		echo "Virtual environment not found. Run 'make build' first."; \
		exit 1; \
	fi

# Start with auto-update functionality
start-auto:
	@echo "Starting GEEKS-AD-Plus with auto-update on http://0.0.0.0:5000..."
	$(PYTHON) run_forever.py

# Show network access information
network-info:
	@echo "GEEKS-AD-Plus Network Access Information"
	$(PYTHON) get-ip.py

# Update from git repository
update:
	@echo "Updating from git repository..."
	$(PYTHON) build.py update

# Install system dependencies
system-deps:
	@echo "Installing system dependencies..."
	$(PYTHON) build.py system-deps

# Docker build
docker-build:
	@echo "Building Docker image..."
	docker build -t geeks-ad-plus .

# Docker run
docker-run:
	@echo "Running with Docker..."
	docker run -p 5000:5000 --name geeks-ad-plus geeks-ad-plus

# Generate documentation
docs:
	@echo "Generating documentation..."
	@if command -v pydoc3 >/dev/null 2>&1; then \
		mkdir -p docs; \
		pydoc3 -w app/; \
		mv *.html docs/; \
		echo "Documentation generated in docs/"; \
	else \
		echo "pydoc3 not found, skipping documentation generation"; \
	fi

# Code linting
lint:
	@echo "Running code linting..."
	@if command -v flake8 >/dev/null 2>&1; then \
		flake8 app/ --max-line-length=120 --ignore=E501,W503; \
	else \
		echo "flake8 not found, install with: pip install flake8"; \
	fi

# Code formatting
format:
	@echo "Formatting code..."
	@if command -v black >/dev/null 2>&1; then \
		black app/ --line-length=120; \
	else \
		echo "black not found, install with: pip install black"; \
	fi

# Quick start (install + run)
quick-start: dev run

# Production build
production: clean build test package
	@echo "Production build completed!"

# CI/CD build
ci: clean install test lint
	@echo "CI build completed!"

# Windows-specific build
windows-build:
	@echo "Windows build..."
	build.bat

# Unix-specific build
unix-build:
	@echo "Unix build..."
	chmod +x build.sh
	./build.sh

# Check system requirements
check-requirements:
	@echo "Checking system requirements..."
	@echo "Python version:"
	$(PYTHON) --version
	@echo "Pip version:"
	$(PIP) --version
	@echo "Platform:"
	$(PYTHON) -c "import platform; print(platform.system())"

# Backup current configuration
backup-config:
	@echo "Backing up configuration..."
	@if [ -f config.json ]; then \
		cp config.json config.json.backup.$$(date +%Y%m%d_%H%M%S); \
		echo "Configuration backed up"; \
	else \
		echo "No config.json found to backup"; \
	fi

# Restore configuration
restore-config:
	@echo "Restoring configuration..."
	@if [ -f config.json.backup.* ]; then \
		ls -t config.json.backup.* | head -1 | xargs -I {} cp {} config.json; \
		echo "Configuration restored"; \
	else \
		echo "No backup configuration found"; \
	fi

# Update dependencies
update-deps:
	@echo "Updating dependencies..."
	$(PIP) install --upgrade -r requirements.txt

# Security audit
security-audit:
	@echo "Running security audit..."
	@if command -v safety >/dev/null 2>&1; then \
		safety check; \
	else \
		echo "safety not found, install with: pip install safety"; \
	fi

# Performance test
perf-test:
	@echo "Running performance tests..."
	@if command -v locust >/dev/null 2>&1; then \
		echo "Starting Locust performance test..."; \
		locust -f tests/locustfile.py --host=http://localhost:5000; \
	else \
		echo "locust not found, install with: pip install locust"; \
	fi 