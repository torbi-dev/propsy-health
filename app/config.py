"""Application configuration using Pydantic Settings."""
import os
import json
from functools import lru_cache
from typing import Any
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import model_validator


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
    environment: str = "production"
    
    # --- Google OAuth ---
    # Avoid pydantic's error for complex nested structures by using Any type
    google_oauth_config: Any = None
    
    # Application Security
    secret_key: str
    encryption_key: str
    rate_limit_window: int = 60
    rate_limit_requests: int = 100
    admin_password: str
    
    # MongoDB
    mongodb_uri: str
    mongodb_db_name: str
    
    # OAuth Redirect
    base_url: str
    redirect_path: str = "/oauth/callback"
    
    # Logging
    log_level: str = "INFO"
    
    @model_validator(mode='after')
    def resolve_google_oauth_config(self) -> 'Settings':
        """
        Charge et valide la configuration OAuth depuis la variable d'environnement JSON.
        """
        env_json = os.getenv("GOOGLE_OAUTH_CONFIG_JSON")
        
        if env_json:
            try:
                self.google_oauth_config = json.loads(env_json)
            except json.JSONDecodeError as e:
                raise ValueError(f"Le JSON dans GOOGLE_OAUTH_CONFIG_JSON est invalide : {e}")
        else:
            # Security : if the env variable is missing, raise an error to prevent misconfiguration
            raise ValueError(
                "La variable d'environnement 'GOOGLE_OAUTH_CONFIG_JSON' est requise. "
                "Veuillez la définir dans votre fichier .env (local) ou dans Secret Manager (Cloud Run)."
            )
            
        return self

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