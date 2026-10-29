"""Manages token validation and refreshing."""
import logging
from datetime import datetime, timedelta, timezone
from motor.motor_asyncio import AsyncIOMotorDatabase
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
import google.auth.exceptions

from app.auth.token_storage import TokenStorageService
from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

async def ensure_valid_token(db: AsyncIOMotorDatabase, legacy_id: str) -> str:
    """
    Checks if the token is valid. If expired, refreshes it using the refresh_token.
    Returns a valid access_token.
    """
    storage = TokenStorageService(db)
    token_doc = await storage.get_token_with_details(legacy_id)
    
    if not token_doc:
        raise ValueError("No token found for user.")
    
    # 0. Check if token is not revoked
    if token_doc.get("status") == "revoked":
        raise ValueError("Token has been revoked. Re-authentication required.")
        
    token_info = token_doc["token"]
    expires_at_str = token_info.get("expires_at")

    
    # 1. Check if token is still valid (with 5 min buffer)
    if expires_at_str:
        try:
            expiry = datetime.fromisoformat(expires_at_str)
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
                
            if expiry > datetime.now(timezone.utc) + timedelta(minutes=5):
                return token_info["access_token"]
        except Exception:
            pass
            
    # 2. Token is expired, attempt refresh
    refresh_token = token_info.get("refresh_token")
    if not refresh_token:
        raise ValueError("No refresh token available. Re-authentication required.")
        
    logger.info(f"Token expired for {legacy_id}. Attempting refresh...")
    try:
        # We use the client_secret from settings, NOT from the DB (for security)
        creds = Credentials(
            token=token_info.get("access_token"),
            refresh_token=refresh_token,
            token_uri="https://oauth2.googleapis.com/token",
            client_id=settings.google_oauth_config["web"]["client_id"],
            client_secret=settings.google_oauth_config["web"]["client_secret"],
            scopes=token_info.get("scopes")
        )
        
        # Synchronous call to Google's auth server (required by google-auth library)
        creds.refresh(Request())
        
        # 3. Update the new tokens in MongoDB
        new_token_info = token_info.copy()
        new_token_info["access_token"] = creds.token
        new_token_info["expires_at"] = creds.expiry.isoformat() if creds.expiry else None
        
        await storage.update_token(legacy_id, {"token": new_token_info})
        logger.info(f"Token refreshed successfully for {legacy_id}")
        return creds.token
        
    except google.auth.exceptions.RefreshError as e:
        logger.error(f"Refresh failed for {legacy_id}: {e}")
        raise ValueError("Token refresh failed. The user must reconnect their account.")