"""
Middleware to validate that session users still exist in the database.

This solves the "stale session" problem where an admin deletes a user
but their browser session cookie remains valid.
"""
import logging
from fastapi import Request, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import RedirectResponse

from app.database import get_database

logger = logging.getLogger(__name__)

class SessionValidationMiddleware(BaseHTTPMiddleware):
    # Paths that don't require session validation
    PUBLIC_PATHS = {
        "/", "/login", "/oauth/callback", "/consent", "/privacy", "/health", "/contact",
        "/admin/login", "/admin/logout", "/docs", "/redoc", "/openapi.json"
    }
    
    async def dispatch(self, request: Request, call_next):
        # Skip validation for public paths and static files
        if request.url.path in self.PUBLIC_PATHS or request.url.path.startswith("/static"):
            return await call_next(request)
        
        # Skip if no session middleware
        if "session" not in request.scope:
            return await call_next(request)
        
        legacy_id = request.session.get("legacy_id")
        
        # If user is logged in, verify their state in the database
        if legacy_id:
            try:
                db = get_database()
                
                # Check 1: Does user have an OAuth token?
                token_col = db["oauth_tokens"]
                has_token = await token_col.find_one({"legacy_id": legacy_id}) is not None
                
                # Check 2: Does user have a consent record?
                consent_col = db["user_consents"]
                consent_record = await consent_col.find_one({"legacy_id": legacy_id})
                
                # Check 3: Is the consent ACTIVE?
                has_active_consent = False
                if consent_record:
                    has_active_consent = consent_record.get("status") == "active"
                
                # ==========================================
                # DECISION LOGIC
                # ==========================================
                should_invalidate = False
                reason = ""
                
                # Case 1: NO token + NO consent → User was deleted by admin or never existed
                if not has_token and not consent_record:
                    should_invalidate = True
                    reason = "no token, no consent (deleted user)"
                
                # Case 2: Has token + INACTIVE consent → User withdrew or consent was revoked
                elif has_token and consent_record and not has_active_consent:
                    should_invalidate = True
                    reason = "consent is inactive (user withdrew)"
                
                # Case 3: NO token + ACTIVE consent → Edge case (token revoked/deleted but consent exists)
                elif not has_token and has_active_consent:
                    should_invalidate = True
                    reason = "no token but active consent (orphaned consent)"
                
                # Case 4: Has token + NO consent → User in onboarding flow (just did OAuth)
                # -> Let them through so they can reach /consent
                
                # Case 5: Has token + ACTIVE consent → Valid user
                # -> Let them through to dashboard
                
                # ==========================================
                
                if should_invalidate:
                    logger.warning(f"🚨 Invalid session for {legacy_id}: {reason}. Clearing session.")
                    request.session.clear()
                    
                    if not request.url.path.startswith("/admin"):
                        return RedirectResponse(url="/?session_expired=true", status_code=status.HTTP_303_SEE_OTHER)
                
            except Exception as e:
                logger.error(f"Session validation error: {e}")
        
        return await call_next(request)