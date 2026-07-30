"""
Centralized logging configuration for Propsy Health OAuth Connector.

Features:
- Structured logging with timestamps, levels, and module names
- Color-coded console output for development
- JSON logging for production (ELK/Datadog compatible)
- Sensitive data filtering (tokens, secrets never logged)
- Log rotation for production
- Configurable via LOG_LEVEL and LOG_FORMAT in .env
"""
import regex  # Replaces the standard 'import re'
import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Any

from app.config import get_settings


# ============================================================================
# SENSITIVE DATA FILTER - Prevents tokens/secrets from appearing in logs
# ============================================================================

class SensitiveDataFilter(logging.Filter):
    """
    Filter that redacts sensitive information from log messages.
    Uses the 'regex' module with execution timeouts to guarantee ReDoS immunity.
    """
    
    # Patterns compiled normally (timeout is applied during execution, not compilation)
    PATTERNS = [
        # OAuth tokens
        (regex.compile(r'(access_token["\s:=]+)["\']?([A-Za-z0-9\-_.]{20,2000})["\']?', regex.IGNORECASE), r'\1[REDACTED]'),
        (regex.compile(r'(refresh_token["\s:=]+)["\']?([A-Za-z0-9\-_.]{20,2000})["\']?', regex.IGNORECASE), r'\1[REDACTED]'),
        
        # Bearer tokens in headers
        (regex.compile(r'(Bearer\s+)([A-Za-z0-9\-_.]{1,2000})', regex.IGNORECASE), r'\1[REDACTED]'),
        
        # JWT tokens
        (regex.compile(r'(eyJ[A-Za-z0-9\-_]{1,2000}\.eyJ[A-Za-z0-9\-_]{1,2000}\.[A-Za-z0-9\-_]{1,2000})'), '[REDACTED_JWT]'),
        
        # API keys (generic)
        (regex.compile(r'(api[_-]?key["\s:=]+)["\']?([A-Za-z0-9\-_]{20,2000})["\']?', regex.IGNORECASE), r'\1[REDACTED]'),
        
        # Passwords
        (regex.compile(r'(password["\s:=]+)["\']?([^"\s,}]{1,2000})["\']?', regex.IGNORECASE), r'\1[REDACTED]'),
        
        # Google OAuth codes
        (regex.compile(r'(code=)([A-Za-z0-9\-_/]{20,2000})'), r'\1[REDACTED]'),
        
        # Fernet encrypted tokens (start with gAAAA)
        (regex.compile(r'gAAAAAB[A-Za-z0-9\-_]{50,2000}'), '[REDACTED_ENCRYPTED]'),
    ]
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Apply redaction to log messages."""
        if isinstance(record.msg, str):
            record.msg = self._redact(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: self._redact_value(v) for k, v in record.args.items()}
            elif isinstance(record.args, tuple):
                record.args = tuple(self._redact_value(arg) for arg in record.args)
        return True
    
    def _redact(self, text: str) -> str:
        """Apply all redaction patterns to text with a timeout to prevent ReDoS."""
        for pattern, replacement in self.PATTERNS:
            try:
                # timeout=0.1 (100ms) is passed to sub() to prevent ReDoS
                text = pattern.sub(replacement, text, timeout=0.1)
            except regex.TimeoutError:
                # If a regex times out, we aggressively redact the whole string to be safe
                logging.getLogger(__name__).warning("Regex timeout during log redaction. Redacting entire message.")
                return "[REDACTED_DUE_TO_TIMEOUT]"
        return text
    
    def _redact_value(self, value: Any) -> Any:
        """Redact sensitive values recursively."""
        if isinstance(value, str):
            return self._redact(value)
        if isinstance(value, dict):
            return {k: self._redact_value(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return type(value)(self._redact_value(v) for v in value)
        return value


# ============================================================================
# CUSTOM FORMATTERS
# ============================================================================

class ColoredFormatter(logging.Formatter):
    """
    Color-coded formatter for development console output.
    
    Colors:
    - DEBUG: Cyan
    - INFO: Green
    - WARNING: Yellow
    - ERROR: Red
    - CRITICAL: Red + Bold
    """
    
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[1;31m', # Red + Bold
    }
    RESET = '\033[0m'
    
    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, self.RESET)
        record.levelname = f"{color}{record.levelname:<8}{self.RESET}"
        record.name = f"\033[35m{record.name}{self.RESET}"  # Magenta for module
        return super().format(record)


class JSONFormatter(logging.Formatter):
    """
    JSON formatter for production logs (ELK/Datadog/CloudWatch compatible).
    
    Output format:
    {
        "timestamp": "2026-06-03T12:00:00.000Z",
        "level": "INFO",
        "logger": "app.api.auth",
        "message": "Token stored",
        "module": "auth",
        "function": "oauth_callback",
        "line": 123
    }
    """
    
    def format(self, record: logging.LogRecord) -> str:
        import json
        from datetime import datetime, timezone
        
        log_data = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        # Add extra fields if present
        for key in ['legacy_id', 'health_id', 'request_id', 'user_id']:
            if hasattr(record, key):
                log_data[key] = getattr(record, key)
        
        return json.dumps(log_data, ensure_ascii=False)


# ============================================================================
# LOGGING SETUP
# ============================================================================

def setup_logging() -> None:
    """
    Configure application-wide logging.
    
    Call this once at application startup (in main.py).
    """
    settings = get_settings()
    log_level = getattr(logging, settings.log_level.upper(), logging.INFO)
    use_json = settings.is_production
    
    # 1. Configure Root Logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.handlers.clear()
    
    # Add sensitive data filter globally
    sensitive_filter = SensitiveDataFilter()
    
    # 2. Console Handler (Common to both Dev and Prod)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.addFilter(sensitive_filter)
    
    if use_json:
        console_handler.setFormatter(JSONFormatter())
    else:
        console_format = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
        console_handler.setFormatter(ColoredFormatter(console_format, datefmt="%H:%M:%S"))
        
    root_logger.addHandler(console_handler)
    
    # 3. File Handlers (Production only)
    if use_json:
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        formatter = JSONFormatter()
        
        # Helper function to eliminate RotatingFileHandler redundancy
        def create_rotating_handler(filename: str, level: int) -> logging.handlers.RotatingFileHandler:
            handler = logging.handlers.RotatingFileHandler(
                log_dir / filename,
                maxBytes=10 * 1024 * 1024,  # 10 MB
                backupCount=10,
                encoding="utf-8"
            )
            handler.setLevel(level)
            handler.setFormatter(formatter)
            handler.addFilter(sensitive_filter)
            return handler

        root_logger.addHandler(create_rotating_handler("app.log", log_level))
        root_logger.addHandler(create_rotating_handler("error.log", logging.ERROR))
        
        # Log startup info for production
        logger = logging.getLogger(__name__)
        logger.info(f"📝 Logging configured: level={settings.log_level}, format=JSON")
        logger.info(f"📂 Log files: logs/app.log, logs/error.log")
    else:
        # Log startup info for development
        logger = logging.getLogger(__name__)
        logger.info(f"📝 Logging configured: level={settings.log_level}, format=colored")
    
    # 4. Reduce noise from third-party libraries (DRY dictionary approach)
    third_party_levels = {
        "uvicorn.access": logging.WARNING,
        "uvicorn.error": logging.INFO,
        "google_auth_oauthlib": logging.WARNING,
        "oauthlib": logging.WARNING,
        "requests_oauthlib": logging.WARNING,
        "motor": logging.WARNING,
        "pymongo": logging.WARNING,
    }
    
    for lib_name, level in third_party_levels.items():
        logging.getLogger(lib_name).setLevel(level)


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance with the given name.
    
    Convenience wrapper for consistency across the application.
    
    Usage:
        from app.core.logging import get_logger
        logger = get_logger(__name__)
        logger.info("Something happened")
    """
    return logging.getLogger(name)


# ============================================================================
# CONTEXT-AWARE LOGGING HELPERS
# ============================================================================

class LoggerAdapter(logging.LoggerAdapter):
    """
    Logger adapter that automatically adds context to log messages.
    
    Usage:
        logger = LoggerAdapter(get_logger(__name__), {
            'legacy_id': '123',
            'request_id': 'abc'
        })
        logger.info("Processing token")
        # Output includes legacy_id and request_id in structured logs
    """
    
    def process(self, msg: str, kwargs: dict) -> tuple[str, dict]:
        extra = kwargs.get('extra', {})
        extra.update(self.extra)
        kwargs['extra'] = extra
        return msg, kwargs


def get_context_logger(name: str, **context) -> LoggerAdapter:
    """
    Get a logger with pre-bound context fields.
    
    Usage:
        logger = get_context_logger(__name__, legacy_id="123", request_id="abc")
        logger.info("Processing")  # Automatically includes legacy_id and request_id
    """
    return LoggerAdapter(get_logger(name), context)