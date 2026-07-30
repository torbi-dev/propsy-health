"""OAuth authentication API endpoints."""
import logging
from fastapi import APIRouter, Depends, Path, Request, status
from fastapi.responses import RedirectResponse, HTMLResponse
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.session import set_user_session, get_current_user, SessionUser
from app.core.templates import templates
from app.database import get_database, health_check as db_health_check
from app.auth.google_oauth import GoogleOAuthService, get_legacy_user_id
from app.auth.token_storage import TokenStorageService
from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

router = APIRouter(prefix="/api", tags=["authentication"])
public_router = APIRouter(tags=["public"])

# Initialize services
client_secrets_path = (settings.google_secret_file_prod if settings.is_production else settings.google_secret_file_test)

oauth_service = GoogleOAuthService(client_secrets_path=client_secrets_path)

SESSION_STATE_KEY = "oauth_state"

@public_router.get("/", response_class=HTMLResponse)
async def homepage(
    request: Request,
    current_user: SessionUser | None = Depends(get_current_user)
):
    """Render the OAuth onboarding homepage."""
    return templates.TemplateResponse(
        request,
        "index.html",
        {"current_user": current_user}
    )


@public_router.get("/privacy", response_class=HTMLResponse)
async def privacy_policy(
    request: Request,
    current_user: SessionUser | None = Depends(get_current_user)
):
    """Render the Privacy Policy page."""
    return templates.TemplateResponse(
        request,
        "privacy.html",
        {"current_user": current_user}
    )


@public_router.get("/contact", response_class=HTMLResponse)
async def contact_page(
    request: Request,
    current_user: SessionUser | None = Depends(get_current_user)
):
    """Render the Contact Us page."""
    return templates.TemplateResponse(
        request,
        "contact.html",
        {"current_user": current_user}
    )


@public_router.get("/terms", response_class=HTMLResponse)
async def terms_page(request: Request, current_user = Depends(get_current_user)):
    return templates.TemplateResponse(request, "terms.html", {"current_user": current_user})


@public_router.get("/login")
async def start_oauth_flow(request: Request):
    """Initiate Google OAuth flow with PKCE support."""
    state = oauth_service.generate_state()
    
    # Get auth URL AND code_verifier
    auth_url, code_verifier = oauth_service.get_authorization_url(
        state=state,
        redirect_uri=settings.redirect_uri
    )
    
    # Store BOTH in session for callback
    if hasattr(request, "session"):
        request.session[SESSION_STATE_KEY] = state
        request.session["oauth_code_verifier"] = code_verifier  # ← NEW
    
    logger.info(f"🔐 Redirecting to Google OAuth (state: {state[:8]}...)")
    return RedirectResponse(url=auth_url)


@public_router.get("/oauth/callback", response_class=HTMLResponse)
async def oauth_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Handle Google OAuth callback with PKCE and proper error handling."""

    # === 1. Handle OAuth errors from Google ===
    if error:
        logger.error(f"❌ OAuth error: {error} - {error_description}")
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "title": "Authentication Failed",
                "message": f"Google error: {error}",
                "details": error_description,
            },
        )

    # === 2. Validate required parameters ===
    if not code or not state:
        logger.error("❌ Missing code or state in callback")
        return templates.TemplateResponse(
            request,
            "error.html",
            {
                "title": "Invalid Callback",
                "message": "Missing code or state parameter",
                "details": f"Received: code={bool(code)}, state={bool(state)}",
            },
        )

    # === 3. Verify CSRF state + retrieve PKCE verifier ===
    stored_state = None
    code_verifier = None

    if hasattr(request, "session"):
        stored_state = request.session.pop(SESSION_STATE_KEY, None)
        code_verifier = request.session.pop("oauth_code_verifier", None)

    if stored_state and stored_state != state:
        logger.error(f"❌ State mismatch: {stored_state} != {state}")
        return templates.TemplateResponse(
            request,
            "error.html",
            {
                "title": "Security Error",
                "message": "Invalid state parameter",
                "details": "CSRF validation failed",
            },
        )

    # === 4. Exchange code for tokens ===
    try:
        logger.info("🔄 Exchanging code for tokens")

        oauth_data = await oauth_service.handle_callback(
            code=code,
            state=state,
            redirect_uri=settings.redirect_uri,
            code_verifier=code_verifier,
        )

        logger.info(
            "✅ Token exchange successful"
        )

    except Exception as e:
        logger.error(f"❌ Token exchange failed: {e}", exc_info=True)
        return templates.TemplateResponse(
            request,
            "error.html",
            {
                "title": "Token Exchange Failed",
                "message": "Could not complete authentication",
                "details": str(e),
            },
        )

    # === 5. Resolve user identifiers ===
    try:
        logger.info("🔍 Calling get_legacy_user_id()...")

        legacy_id, health_id = get_legacy_user_id(
            oauth_data["token"]["access_token"]
        )

        logger.info("✅ Retrieved IDs: legacy, health")

    except Exception as e:
        logger.error(f"❌ Failed to get user IDs: {e}", exc_info=True)
        return templates.TemplateResponse(
            request,
            "error.html",
            {
                "title": "Identity Retrieval Failed",
                "message": "Could not retrieve user identifiers",
                "details": str(e),
            },
        )

    # === 6. Store in MongoDB ===
    try:
        token_storage = TokenStorageService(db)

        token_document = {
            "legacy_id": legacy_id,
            "health_id": health_id,
            "client_id": oauth_data["client_id"],
            "token": oauth_data["token"],
        }

        logger.info("💾 Storing token for legacy_id")

        existing = await token_storage.get_token_by_legacy_id(legacy_id)

        if existing:
            await token_storage.update_token(
                legacy_id,
                {
                    "token": oauth_data["token"],
                    "health_id": health_id,
                },
            )
            logger.info("🔄 Updated existing token")
        else:
            await token_storage.create_token(token_document)
            logger.info("✅ Created new token document")

    except Exception as e:
        logger.error(f"❌ MongoDB storage failed: {e}", exc_info=True)
        return templates.TemplateResponse(
            request,
            "error.html",
            {
                "title": "Storage Failed",
                "message": "Could not save authentication data",
                "details": str(e),
            },
        )

    # === 7. Success page ===
    set_user_session(request, legacy_id, health_id)

    logger.info("🎉 OAuth flow complete for legacy_id")

    return RedirectResponse(url="/consent", status_code=status.HTTP_303_SEE_OTHER)


# ============================================================================
# Token Management API (Protected - add authentication middleware as needed)
# ============================================================================

#@router.get("/tokens")
#async def list_tokens(
#    limit: int = 100,
#    db: AsyncIOMotorDatabase = Depends(get_database)
#):
#    """List all active token documents (excluding sensitive fields)."""
#    token_storage = TokenStorageService(db)
#    tokens = await token_storage.get_all_tokens(limit=limit)
#    return {"count": len(tokens), "tokens": tokens}
#
#
#@router.get("/tokens/{legacy_id}")
#async def get_token(
#    legacy_id: str,
#    db: AsyncIOMotorDatabase = Depends(get_database)
#):
#    """Retrieve token document by legacy_id."""
#    token_storage = TokenStorageService(db)
#    token = await token_storage.get_token_by_legacy_id(legacy_id)
#    
#    if not token:
#        raise HTTPException(
#            status_code=status.HTTP_404_NOT_FOUND,
#            detail=f"No token found for legacy_id: {legacy_id}"
#        )
#    
#    # Return token without sensitive fields in list view
#    safe_token = token.copy()
#    if "token" in safe_token:
#        safe_token["token"] = {
#            "token_type": safe_token["token"].get("token_type"),
#            "scopes": safe_token["token"].get("scopes"),
#            "expires_at": safe_token["token"].get("expires_at"),
#        }
#    
#    return safe_token
#
#
#@router.delete("/tokens/{legacy_id}", status_code=status.HTTP_204_NO_CONTENT)
#async def revoke_token(
#    legacy_id: str,
#    db: AsyncIOMotorDatabase = Depends(get_database)
#):
#    """Soft-delete (revoke) a token document."""
#    token_storage = TokenStorageService(db)
#    success = await token_storage.delete_token(legacy_id)
#    
#    if not success:
#        raise HTTPException(
#            status_code=status.HTTP_404_NOT_FOUND,
#            detail="No active token found for legacy_id"
#        )
#    
#    return None