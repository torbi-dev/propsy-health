"""Session management for authenticated users."""
from fastapi import Request, HTTPException, status


class SessionUser:
    """Represents an authenticated user from session."""
    
    def __init__(self, legacy_id: str, health_id: str, consent_given: bool = False):
        self.legacy_id = legacy_id
        self.health_id = health_id
        self.consent_given = consent_given
    
    def __repr__(self):
        return f"SessionUser(legacy_id={self.legacy_id}, consent={self.consent_given})"


async def get_current_user(request: Request) -> SessionUser | None:
    """Get current authenticated user from session."""
    legacy_id = request.session.get("legacy_id")
    health_id = request.session.get("health_id")
    
    if not legacy_id or not health_id:
        return None
    
    return SessionUser(
        legacy_id=legacy_id,
        health_id=health_id,
        consent_given=request.session.get("consent_given", False)
    )


async def get_current_user_with_consent(request: Request) -> SessionUser:
    """
    Get current user AND verify they have given informed consent.
    
    Use this dependency for any route that accesses health data.
    """
    user = await get_current_user(request)
    
    if not user.consent_given:
        # Double-check in database (in case session was cleared but consent exists)
        from app.database import get_database
        from app.services.consent_storage import ConsentStorageService
        
        db = get_database()
        storage = ConsentStorageService(db)
        
        if await storage.has_active_consent(user.legacy_id):
            # Consent exists in DB, update session
            request.session["consent_given"] = True
            user.consent_given = True
        else:
            # No consent found, redirect to consent form
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Informed consent required. Please complete the consent form.",
                headers={"Location": "/consent"}
            )
    
    return user


def set_user_session(request: Request, legacy_id: str, health_id: str):
    """Store user info in session after successful OAuth."""
    request.session["legacy_id"] = legacy_id
    request.session["health_id"] = health_id
    request.session["authenticated"] = True
    # Note: consent_given is NOT set here - must go through /consent first


def clear_user_session(request: Request):
    """Clear user session on logout/withdrawal."""
    request.session.pop("legacy_id", None)
    request.session.pop("health_id", None)
    request.session.pop("authenticated", None)
    request.session.pop("consent_given", None)
    request.session.pop("consent_id", None)
    request.session.pop("consent_version", None)