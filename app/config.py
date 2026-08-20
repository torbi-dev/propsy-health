"""Application configuration using Pydantic Settings."""
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )

    # Application Info
    app_name: str = "Sanpsy Health"
    
    # Google OAuth
    google_client_id: str
    google_client_secret: str

    google_secret_file_test: str
    google_secret_file_prod: str
    
    # Application Security
    secret_key: str
    encryption_key: str  # Must be 32 bytes for Fernet
    rate_limit_window: int = 60
    rate_limit_requests: int = 100
    environment: str = "production"

    admin_password: str
    
    # MongoDB
    mongodb_uri: str
    mongodb_db_name: str
    
    # OAuth Redirect
    base_url: str
    redirect_path: str = "/oauth/callback"
    
    # Logging
    log_level: str = "INFO"
    
    @property
    def redirect_uri(self) -> str:
        """Build full redirect URI from base URL and path."""
        return f"{self.base_url.rstrip('/')}{self.redirect_path}"
    
    @property
    def is_production(self) -> bool:
        """Check if running in production mode."""
        return self.environment.lower() == "production"
    
    @property
    def google_health_scopes(self) -> list[str]:
        """Return required Google Health API scopes."""
        return [
            "https://www.googleapis.com/auth/googlehealth.activity_and_fitness.readonly",
            "https://www.googleapis.com/auth/googlehealth.health_metrics_and_measurements.readonly",
            "https://www.googleapis.com/auth/googlehealth.sleep.readonly",
            "https://www.googleapis.com/auth/googlehealth.profile.readonly",
        ]


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()