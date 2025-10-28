"""
Application configuration management using Pydantic Settings.
Loads configuration from environment variables with validation.
"""

from typing import List, Optional
from pydantic import Field, validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Application
    app_name: str = Field(default="Security Scanner Platform", alias="APP_NAME")
    app_version: str = Field(default="0.1.0", alias="APP_VERSION")
    environment: str = Field(default="development", alias="ENVIRONMENT")
    debug: bool = Field(default=True, alias="DEBUG")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    
    # API Configuration
    api_host: str = Field(default="0.0.0.0", alias="API_HOST")
    api_port: int = Field(default=8000, alias="API_PORT")
    api_prefix: str = Field(default="/api/v1", alias="API_PREFIX")
    
    # Security
    secret_key: str = Field(..., alias="SECRET_KEY")
    algorithm: str = Field(default="HS256", alias="ALGORITHM")
    access_token_expire_minutes: int = Field(default=30, alias="ACCESS_TOKEN_EXPIRE_MINUTES")
    refresh_token_expire_days: int = Field(default=7, alias="REFRESH_TOKEN_EXPIRE_DAYS")
    
    # Database - PostgreSQL
    database_url: str = Field(..., alias="DATABASE_URL")
    db_pool_size: int = Field(default=20, alias="DB_POOL_SIZE")
    db_max_overflow: int = Field(default=0, alias="DB_MAX_OVERFLOW")
    db_echo: bool = Field(default=False, alias="DB_ECHO")
    
    # Redis
    redis_url: str = Field(..., alias="REDIS_URL")
    redis_cache_ttl: int = Field(default=3600, alias="REDIS_CACHE_TTL")
    
    # MongoDB
    mongodb_url: str = Field(..., alias="MONGODB_URL")
    mongodb_db_name: str = Field(default="scan_results", alias="MONGODB_DB_NAME")
    
    # RabbitMQ
    rabbitmq_url: str = Field(..., alias="RABBITMQ_URL")
    rabbitmq_exchange: str = Field(default="scanner_exchange", alias="RABBITMQ_EXCHANGE")
    
    # Workspace Configuration
    workspace_ttl_minutes: int = Field(default=30, alias="WORKSPACE_TTL_MINUTES")
    max_workspace_size_gb: int = Field(default=2, alias="MAX_WORKSPACE_SIZE_GB")
    workspace_cleanup_interval_minutes: int = Field(default=5, alias="WORKSPACE_CLEANUP_INTERVAL_MINUTES")
    
    # Scanning Configuration
    max_concurrent_scans: int = Field(default=10, alias="MAX_CONCURRENT_SCANS")
    scan_timeout_minutes: int = Field(default=60, alias="SCAN_TIMEOUT_MINUTES")
    enable_incremental_scan: bool = Field(default=True, alias="ENABLE_INCREMENTAL_SCAN")
    full_scan_file_threshold: int = Field(default=100, alias="FULL_SCAN_FILE_THRESHOLD")
    
    # SCM Integrations
    github_client_id: Optional[str] = Field(default=None, alias="GITHUB_CLIENT_ID")
    github_client_secret: Optional[str] = Field(default=None, alias="GITHUB_CLIENT_SECRET")
    github_webhook_secret: Optional[str] = Field(default=None, alias="GITHUB_WEBHOOK_SECRET")
    
    gitlab_client_id: Optional[str] = Field(default=None, alias="GITLAB_CLIENT_ID")
    gitlab_client_secret: Optional[str] = Field(default=None, alias="GITLAB_CLIENT_SECRET")
    
    # External Services
    nvd_api_key: Optional[str] = Field(default=None, alias="NVD_API_KEY")
    nvd_api_url: str = Field(default="https://services.nvd.nist.gov/rest/json/cves/2.0", alias="NVD_API_URL")
    
    # Celery
    celery_broker_url: str = Field(..., alias="CELERY_BROKER_URL")
    celery_result_backend: str = Field(..., alias="CELERY_RESULT_BACKEND")
    
    # CORS
    cors_origins: List[str] = Field(default=["http://localhost:3000"], alias="CORS_ORIGINS")
    cors_credentials: bool = Field(default=True, alias="CORS_CREDENTIALS")
    cors_methods: List[str] = Field(default=["*"], alias="CORS_METHODS")
    cors_headers: List[str] = Field(default=["*"], alias="CORS_HEADERS")
    
    # Rate Limiting
    rate_limit_per_minute: int = Field(default=60, alias="RATE_LIMIT_PER_MINUTE")
    rate_limit_enabled: bool = Field(default=True, alias="RATE_LIMIT_ENABLED")
    
    # File Upload
    max_upload_size_mb: int = Field(default=100, alias="MAX_UPLOAD_SIZE_MB")
    allowed_file_extensions: List[str] = Field(default=[".json", ".yaml", ".yml", ".txt"], alias="ALLOWED_FILE_EXTENSIONS")
    
    # Feature Flags
    enable_sast: bool = Field(default=True, alias="ENABLE_SAST")
    enable_sca: bool = Field(default=True, alias="ENABLE_SCA")
    enable_dast: bool = Field(default=True, alias="ENABLE_DAST")
    enable_iast: bool = Field(default=False, alias="ENABLE_IAST")
    
    # Compliance
    default_compliance_frameworks: List[str] = Field(default=["OWASP", "CWE"], alias="DEFAULT_COMPLIANCE_FRAMEWORKS")
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )
    
    @validator("cors_origins", pre=True)
    def parse_cors_origins(cls, v):
        """Parse comma-separated CORS origins string into list."""
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v
    
    @validator("cors_methods", pre=True)
    def parse_cors_methods(cls, v):
        """Parse comma-separated CORS methods string into list."""
        if isinstance(v, str):
            if v == "*":
                return ["*"]
            return [method.strip() for method in v.split(",")]
        return v
    
    @validator("cors_headers", pre=True)
    def parse_cors_headers(cls, v):
        """Parse comma-separated CORS headers string into list."""
        if isinstance(v, str):
            if v == "*":
                return ["*"]
            return [header.strip() for header in v.split(",")]
        return v
    
    @validator("allowed_file_extensions", pre=True)
    def parse_file_extensions(cls, v):
        """Parse comma-separated file extensions string into list."""
        if isinstance(v, str):
            return [ext.strip() for ext in v.split(",")]
        return v
    
    @validator("default_compliance_frameworks", pre=True)
    def parse_compliance_frameworks(cls, v):
        """Parse comma-separated compliance frameworks string into list."""
        if isinstance(v, str):
            return [framework.strip() for framework in v.split(",")]
        return v
    
    @validator("secret_key")
    def validate_secret_key(cls, v):
        """Ensure secret key is strong enough."""
        if len(v) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters long")
        return v
    
    @property
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.environment.lower() == "production"
    
    @property
    def is_development(self) -> bool:
        """Check if running in development environment."""
        return self.environment.lower() == "development"
    
    @property
    def database_url_async(self) -> str:
        """Get async database URL for SQLAlchemy."""
        return self.database_url.replace("postgresql://", "postgresql+asyncpg://")


# Global settings instance
settings = Settings()