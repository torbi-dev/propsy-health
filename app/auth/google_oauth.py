"""Google OAuth service integrating with existing GoogleHealthAuthManager."""
import logging
import secrets
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import Flow
from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

# Import existing components from your codebase
# Adjust import path as needed for your project structure
try:
    from app.google_health_auth import GoogleHealthAuthManager, get_legacy_user_id
except ImportError:
    # Fallback for development - replace with actual implementation
    logger.warning("⚠️ google_health_auth module not found - using stubs")
    
    class GoogleHealthAuthManager:
        """Stub class - replace with actual implementation."""
        def __init__(self, *args, **kwargs):
            pass
    
    def get_legacy_user_id(access_token: str) -> tuple[str, str]:
        """Stub function - replace with actual implementation."""
        return "stub-legacy-id", "stub-health-id"


class GoogleOAuthService:
    """
    Service for handling Google OAuth flow for Google Health API.
    
    Converts the existing run_local_server() flow to web-compatible
    authorization_url() and fetch_token() pattern.
    """
    
    def __init__(self, client_secrets_path: str):
        self.client_secrets_path = client_secrets_path
        self.scopes = settings.google_health_scopes
    
    def _create_flow(self, redirect_uri: str | None = None) -> Flow:
        """Create OAuth flow instance with proper configuration."""
        uri = redirect_uri or settings.redirect_uri
        
        return Flow.from_client_secrets_file(
            self.client_secrets_path,
            scopes=self.scopes,
            redirect_uri=uri
        )
    
    def generate_state(self) -> str:
        """Generate cryptographically secure state parameter for CSRF protection."""
        return secrets.token_urlsafe(32)
    
    def get_authorization_url(self, state: str, redirect_uri: str | None = None) -> tuple[str, str]:
        """
        Build Google authorization URL.
        
        Returns:
            tuple: (authorization_url, code_verifier)
        """
        flow = self._create_flow(redirect_uri)
        
        authorization_url, state = flow.authorization_url(
            access_type="offline",
            prompt="consent",
            state=state,
            include_granted_scopes="true"
        )
        
        # Extract and return the code_verifier for PKCE
        code_verifier = flow.code_verifier
        
        logger.debug(f"Generated authorization URL with code_verifier: {code_verifier[:10] if code_verifier else None}...")
        return authorization_url, code_verifier
    
    async def handle_callback(
        self, 
        code: str, 
        state: str, 
        redirect_uri: str | None = None,
        code_verifier: str | None = None  # ← NEW PARAM
    ) -> dict:
        """Handle OAuth callback with PKCE support."""
        flow = self._create_flow(redirect_uri)
        
        # Exchange code for tokens - pass code_verifier if using PKCE
        fetch_kwargs = {"code": code}
        if code_verifier:
            fetch_kwargs["code_verifier"] = code_verifier
        
        try:
            flow.fetch_token(**fetch_kwargs)  # ← Use kwargs
        except Exception as e:
            logger.error(f"❌ Token exchange failed: {e}")
            raise ValueError(f"Failed to exchange code for tokens: {e}")
        
        creds = flow.credentials
        
        # Extract token information
        token_data = {
            "access_token": creds.token,
            "refresh_token": creds.refresh_token,
            "expires_at": creds.expiry.isoformat() if creds.expiry else None,
            "scopes": creds.scopes,
            "token_type": "Bearer"
        }
        
        # Get user identifiers using existing function
        try:
            legacy_id, health_id = get_legacy_user_id(creds.token)
        except Exception as e:
            logger.error(f"❌ Failed to retrieve user IDs: {e}")
            raise ValueError(f"Failed to retrieve user identifiers: {e}")
        
        # Extract client info from credentials
        client_info = {
            "client_id": creds.client_id,
            "client_secret": creds.client_secret,
        }
        
        logger.info(f"✅ OAuth successful for legacy_id: {legacy_id}")
        
        return {
            "legacy_id": legacy_id,
            "health_id": health_id,
            "token": token_data,
            "client_id": client_info["client_id"],
            "client_secret": client_info["client_secret"],
        }
    
    def refresh_access_token(
        self, 
        refresh_token: str, 
        client_id: str, 
        client_secret: str,
        scopes: list[str] | None = None
    ) -> dict:
        """
        Refresh an expired access token using refresh_token.
        
        Args:
            refresh_token: The refresh token
            client_id: Google OAuth client ID
            client_secret: Google OAuth client secret
            scopes: Optional scope list (defaults to configured scopes)
            
        Returns:
            Updated token information
        """
        scopes = scopes or self.scopes
        
        creds = Credentials(
            token=None,
            refresh_token=refresh_token,
            token_uri="https://oauth2.googleapis.com/token",
            client_id=client_id,
            client_secret=client_secret,
            scopes=scopes
        )
        
        try:
            creds.refresh(Request())
        except Exception as e:
            logger.error(f"❌ Token refresh failed: {e}")
            raise
        
        return {
            "access_token": creds.token,
            "refresh_token": creds.refresh_token,  # May be rotated
            "expires_at": creds.expiry.isoformat() if creds.expiry else None,
            "scopes": creds.scopes,
            "token_type": "Bearer"
        }
    
    def is_token_expired(self, expires_at: str, buffer_minutes: int = 5) -> bool:
        """
        Check if a token is expired or expiring soon.
        
        Args:
            expires_at: ISO format expiry timestamp
            buffer_minutes: Minutes before expiry to consider token expired
            
        Returns:
            True if token needs refresh
        """
        from datetime import datetime, timedelta, timezone
        
        try:
            expiry = datetime.fromisoformat(expires_at)
            # Handle timezone-naive timestamps
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            
            buffer = timedelta(minutes=buffer_minutes)
            return datetime.now(timezone.utc) + buffer >= expiry
        except (ValueError, AttributeError) as e:
            logger.warning(f"⚠️ Could not parse expiry timestamp: {e}")
            return True  # Assume expired if we can't parse