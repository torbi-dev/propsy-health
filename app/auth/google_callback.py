import logging
from fastapi import Request, status
from fastapi.responses import HTMLResponse
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.templates import templates
from app.auth.token_storage import TokenStorageService
from app.auth.google_oauth import GoogleOAuthService, get_legacy_user_id
from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

# Initialize services
client_secrets_path = (settings.google_secret_file_prod if settings.is_production else settings.google_secret_file_test)

oauth_service = GoogleOAuthService(client_secrets_path=client_secrets_path)

# Custom Exceptions
class OAuthCallbackError(Exception):
    """Custom exception for structured OAuth callback errors."""
    def __init__(self, title: str, message: str, details: str = "", status_code: int = status.HTTP_400_BAD_REQUEST):
        self.title = title
        self.message = message
        self.details = details
        self.status_code = status_code
        super().__init__(self.message)


# Helper Functions
def create_error_response(
    request: Request, 
    title: str, 
    message: str, 
    details: str = "", 
    status_code: int = status.HTTP_400_BAD_REQUEST
) -> HTMLResponse:
    """Unified error response generator to avoid repetitive TemplateResponse code."""
    logger.error(f"❌ {title}: {message} | Details: {details}")
    return templates.TemplateResponse(
        "error.html",
        {
            "request": request,
            "title": title,
            "message": message,
            "details": details,
        },
        status_code=status_code,
    )


# Service Layer
class OAuthCallbackService:
    """Encapsulates the business logic of the OAuth callback flow."""
    
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db

    async def process_callback(
        self,
        code: str,
        state: str,
        code_verifier: str | None,
        redirect_uri: str,
    ) -> tuple[str, str]:
        """
        Executes the core OAuth callback steps: token exchange, ID resolution, and storage.
        Returns: (legacy_id, health_id)
        """
        # Step A: Exchange code for tokens
        logger.info("🔄 Exchanging code for tokens")
        oauth_data = await oauth_service.handle_callback(
            code=code,
            state=state,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
        )
        logger.info("✅ Token exchange successful")

        # Step B: Resolve user identifiers
        logger.info("🔍 Retrieving user identifiers")
        try:
            legacy_id, health_id = get_legacy_user_id(oauth_data["token"]["access_token"])
            logger.info(f"✅ Retrieved IDs: legacy={legacy_id}, health={health_id}")
        except Exception as e:
            raise OAuthCallbackError(
                title="Identity Retrieval Failed",
                message="Could not retrieve user identifiers",
                details=str(e),
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        # Step C: Store in MongoDB
        await self._store_token(legacy_id, health_id, oauth_data)
        
        return legacy_id, health_id

    async def _store_token(self, legacy_id: str, health_id: str, oauth_data: dict) -> None:
        """Handles upsert logic for token storage."""
        token_storage = TokenStorageService(self.db)
        token_document = {
            "legacy_id": legacy_id,
            "health_id": health_id,
            "client_id": oauth_data["client_id"],
            "token": oauth_data["token"],
        }

        existing = await token_storage.get_token_by_legacy_id(legacy_id)
        if existing:
            await token_storage.update_token(legacy_id, {
                "token": oauth_data["token"],
                "health_id": health_id,
            })
            logger.info("🔄 Updated existing token")
        else:
            await token_storage.create_token(token_document)
            logger.info("✅ Created new token document")