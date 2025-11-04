# Secure_assess-core
core for the scanner app.
# Security Scanner Platform - Backend

A comprehensive security scanning platform that provides SAST, SCA, DAST, and IAST capabilities with industry-specific compliance checking.

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- Docker & Docker Compose
- Git

### 1. Clone the repository

```bash
git clone <your-repo-url>
cd security-scanner-platform
```

### 2. Initial Setup

```bash
# Copy environment variables template
make setup

# Update .env file with your configuration
# At minimum, change the SECRET_KEY to a strong random string (32+ chars)
nano .env  # or use your preferred editor
```

### 3. Start Development Environment

```bash
# Start all infrastructure services (PostgreSQL, Redis, MongoDB, RabbitMQ)
make dev

# Install Python dependencies
make install

# Run the FastAPI application
make run-api
```

The API will be available at:
- **API**: http://localhost:8000
- **API Docs**: http://localhost:8000/api/v1/docs
- **Health Check**: http://localhost:8000/api/v1/health

Infrastructure services:
- **PostgreSQL**: localhost:5432
- **Redis**: localhost:6379
- **MongoDB**: localhost:27017
- **RabbitMQ**: localhost:5672
- **RabbitMQ Management UI**: http://localhost:15672 (user: `scanner_user`, pass: `scanner_pass`)

### 4. Test the API

```bash
# Health check
curl http://localhost:8000/api/v1/health

# API info
curl http://localhost:8000/
```

## 📁 Project Structure

```
security-scanner-platform/
├── src/                          # Application source code
│   ├── main.py                   # FastAPI entry point
│   ├── config.py                 # Configuration management
│   ├── api/                      # API layer
│   ├── services/                 # Business logic
│   ├── db/                       # Database models & connections
│   ├── workers/                  # Background workers (Celery)
│   ├── integrations/             # External service integrations
│   └── messaging/                # Message queue handling
├── tests/                        # Test suite
├── scripts/                      # Utility scripts
├── alembic/                      # Database migrations
├── k8s/                          # Kubernetes manifests
├── docker-compose.yml            # Local development environment
├── requirements.txt              # Python dependencies
├── Makefile                      # Common commands
└── .env                          # Environment variables (not in git)
```

## 🛠 Development Commands

```bash
# Start services
make dev              # Start all Docker services
make run-api          # Run FastAPI application

# Stop services
make down             # Stop services
make clean            # Stop services and remove volumes

# Database
make db-migrate       # Create new migration
make db-upgrade       # Apply migrations
make db-shell         # Open PostgreSQL shell

# Testing
make test             # Run all tests
make test-unit        # Run unit tests only
make test-integration # Run integration tests

# Code quality
make format           # Format code with black
make lint             # Lint with ruff
make type-check       # Type check with mypy
make check            # Run all quality checks

# Logs
make logs             # Show all service logs
make logs-api         # Show API logs only
make ps               # Show running services
```

## 🔧 Configuration

Key environment variables in `.env`:

### Application
- `APP_NAME` - Application name
- `ENVIRONMENT` - Environment (development/staging/production)
- `DEBUG` - Debug mode (True/False)
- `SECRET_KEY` - **REQUIRED** - JWT secret key (32+ characters)

### Databases
- `DATABASE_URL` - PostgreSQL connection string
- `REDIS_URL` - Redis connection string
- `MONGODB_URL` - MongoDB connection string
- `RABBITMQ_URL` - RabbitMQ connection string

### Security
- `ACCESS_TOKEN_EXPIRE_MINUTES` - JWT access token expiry
- `REFRESH_TOKEN_EXPIRE_DAYS` - JWT refresh token expiry

### Scanning
- `WORKSPACE_TTL_MINUTES` - How long to keep code workspaces (default: 30)
- `MAX_CONCURRENT_SCANS` - Maximum parallel scans (default: 10)
- `ENABLE_INCREMENTAL_SCAN` - Enable delta scanning (default: True)

### Integrations
- `GITHUB_CLIENT_ID` - GitHub OAuth app client ID
- `GITHUB_CLIENT_SECRET` - GitHub OAuth app secret
- `NVD_API_KEY` - National Vulnerability Database API key

## 🏗 Architecture

### Layers

1. **Policy Layer** - Compliance policy service for industry-specific rules
2. **Ingestion Layer** - API Gateway and authentication
3. **Orchestration Layer** - Intelligent scan scheduler
4. **Scanning Layer** - Ephemeral workspaces with SAST/SCA/DAST/IAST workers
5. **Reporting Layer** - Result aggregation and compliance scoring

### Key Features

- ✅ **Ephemeral Code Handling** - Customer code never persists, encrypted in-memory processing
- ✅ **Industry Compliance** - PCI-DSS, HIPAA, SOC 2, GDPR, ISO 27001 support
- ✅ **Incremental Scanning** - Delta scanning for faster repeat scans
- ✅ **Multi-Scanner Support** - SAST, SCA, DAST, IAST capabilities
- ✅ **Microservices Architecture** - Scalable, resilient design
- ✅ **Async Processing** - Message queue-based workflow

## 📝 API Endpoints (Coming Soon)

### Authentication
- `POST /api/v1/auth/register` - User registration
- `POST /api/v1/auth/login` - User login
- `POST /api/v1/auth/refresh` - Refresh access token

### Scans
- `POST /api/v1/scans` - Submit new scan
- `GET /api/v1/scans/{scan_id}` - Get scan status
- `GET /api/v1/scans/{scan_id}/results` - Get scan results

### Integrations
- `POST /api/v1/integrations/github` - Connect GitHub account
- `GET /api/v1/integrations` - List connected integrations

### Compliance
- `GET /api/v1/compliance/frameworks` - List available frameworks
- `GET /api/v1/compliance/industries` - List supported industries

## 🧪 Testing

```bash
# Run all tests with coverage
make test

# Run specific test file
pytest tests/unit/test_config.py -v

# Run with coverage report
pytest --cov=src --cov-report=html
```

## 🚢 Deployment

### Docker

```bash
# Build production image
docker build -t scanner-api:latest .

# Run production container
docker run -p 8000:8000 --env-file .env scanner-api:latest
```

### Kubernetes

```bash
# Apply manifests
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmaps/
kubectl apply -f k8s/secrets/
kubectl apply -f k8s/deployments/
kubectl apply -f k8s/services/
```

## 🔒 Security Considerations

- Always use strong `SECRET_KEY` (32+ characters, random)
- Never commit `.env` file to version control
- Use environment-specific secrets in production
- Enable HTTPS/TLS in production
- Implement rate limiting (configured in `.env`)
- Regular security audits of dependencies

## 📚 Documentation

- API documentation available at `/api/v1/docs` when running
- ReDoc alternative at `/api/v1/redoc`
- OpenAPI spec at `/api/v1/openapi.json`

## 🤝 Contributing

1. Create a feature branch (`git checkout -b feature/amazing-feature`)
2. Make your changes
3. Run tests and quality checks (`make check`)
4. Commit your changes (`git commit -m 'Add amazing feature'`)
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

## 📄 License

[Your License Here]

## 🆘 Support

For issues and questions:
- Open an issue on GitHub
- Contact: [Your Contact Info]

---

## Next Steps

Now that the foundation is set up, the next phases are:

1. **Phase 1B**: Database models and connections
2. **Phase 1C**: Authentication system (register/login)
3. **Phase 2A**: Scan submission API
4. **Phase 2B**: Background workers
5. **Phase 3**: Compliance policy service
6. **Phase 4**: Scanner integrations

Run `make help` to see all available commands!