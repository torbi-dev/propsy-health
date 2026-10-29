"""Admin dashboard routes for managing users and monitoring the system."""
import logging
from fastapi import APIRouter, Depends, Request, HTTPException, Form, status
from fastapi.responses import RedirectResponse, HTMLResponse
from motor.motor_asyncio import AsyncIOMotorDatabase
from datetime import datetime, timezone, timedelta

from authlib.integrations.starlette_client import OAuth
from starlette.config import Config

from app.core.templates import templates
from app.database import get_database
from app.config import get_settings
from app.services.consent_storage import ConsentStorageService
from app.auth.token_storage import TokenStorageService
from app.services.health_data_storage import HealthDataStorage
from app.services.health_data_fetcher import fetch_daily_health_data
from app.services.token_manager import ensure_valid_token

logger = logging.getLogger(__name__)
settings = get_settings()

router = APIRouter(prefix="/admin", tags=["admin"])

# Configuration OAuth (utilise les mêmes identifiants Google que ton app principale)
config = Config(environ={
    "GOOGLE_CLIENT_ID": settings.google_oauth_admin["web"]["client_id"],
    "GOOGLE_CLIENT_SECRET": settings.google_oauth_admin["web"]["client_secret"],
})
oauth = OAuth(config)

# On enregistre Google avec les scopes nécessaires pour récupérer l'email
oauth.register(
    name='google',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)


# ============================================================================
# ADMIN AUTHENTICATION
# ============================================================================

class AdminAuthError(Exception):
    """Custom exception to redirect unauthenticated admin users."""
    pass

async def require_admin_email(request: Request):
    """Vérifie que l'utilisateur est connecté ET que son email est celui de l'admin."""
    is_admin = request.session.get("is_admin")
    admin_email = request.session.get("admin_email")
    
    # Sécurité en profondeur : on revérifie l'email à chaque requête
    if not is_admin or admin_email != settings.admin_mail:
        request.session.clear()
        raise HTTPException(status_code=403, detail="Accès refusé.")

# ============================================================================
# AUTH ROUTES
# ============================================================================

@router.get("/login")
async def admin_login(request: Request):
    """Redirige vers la page de connexion Google."""
    # prompt=select_account force l'utilisateur à choisir son compte (utile si plusieurs connectés)
    redirect_uri = request.url_for('admin_auth_callback')
    return await oauth.google.authorize_redirect(request, redirect_uri, prompt="select_account")

@router.get("/auth/callback")
async def admin_auth_callback(request: Request):
    """Google renvoie l'utilisateur ici après connexion. On vérifie l'email."""
    try:
        token = await oauth.google.authorize_access_token(request)
        userinfo = token.get('userinfo')
        
        if not userinfo:
            raise HTTPException(status_code=400, detail="Impossible de récupérer les infos utilisateur.")
            
        user_email = userinfo.get('email')
        
        # 🔒 VÉRIFICATION CRITIQUE : L'email correspond-il à l'admin autorisé ?
        if user_email == settings.admin_mail:
            request.session["is_admin"] = True
            request.session["admin_email"] = user_email
            logger.info(f"✅ Admin login successful via Google OAuth: {user_email}")
            return RedirectResponse(url="/admin/", status_code=status.HTTP_303_SEE_OTHER)
        else:
            # L'utilisateur est connecté à Google, mais n'est pas l'admin
            logger.warning(f" Unauthorized admin access attempt by: {user_email}")
            return templates.TemplateResponse(request, "admin/access_denied.html", {
                "email": user_email
            })
            
    except Exception as e:
        logger.error(f"❌ Admin OAuth error: {e}")
        raise HTTPException(status_code=500, detail="Erreur d'authentification.")

@router.get("/logout")
async def admin_logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)

# ============================================================================
# DASHBOARD & STATS
# ============================================================================

@router.get("/", response_class=HTMLResponse, dependencies=[Depends(require_admin_email)])
async def admin_dashboard(request: Request, db: AsyncIOMotorDatabase = Depends(get_database)):
    consent_col = db[ConsentStorageService.COLLECTION_NAME]
    token_col = db[TokenStorageService.COLLECTION_NAME]
    health_col = db[HealthDataStorage.COLLECTION_NAME]
    
    stats = {
        "total_consents": await consent_col.count_documents({}),
        "active_consents": await consent_col.count_documents({"status": "active"}),
        "withdrawn_consents": await consent_col.count_documents({"status": "withdrawn"}),
        "total_tokens": await token_col.count_documents({}),
        "total_health_records": await health_col.count_documents({}),
    }
    
    recent_cursor = consent_col.find().sort("consented_at", -1).limit(10)
    recent_users = [doc async for doc in recent_cursor]
    
    return templates.TemplateResponse(request, "admin/dashboard.html", {
        "stats": stats,
        "recent_users": recent_users
    })

# ============================================================================
# USER MANAGEMENT
# ============================================================================

@router.get("/users", response_class=HTMLResponse, dependencies=[Depends(require_admin_email)])
async def admin_users_list(request: Request, db: AsyncIOMotorDatabase = Depends(get_database)):
    consent_col = db[ConsentStorageService.COLLECTION_NAME]
    cursor = consent_col.find().sort("consented_at", -1)
    users = [doc async for doc in cursor]
    
    return templates.TemplateResponse(request, "admin/users.html", {"users": users})

@router.get("/users/{legacy_id}", response_class=HTMLResponse, dependencies=[Depends(require_admin_email)])
async def admin_user_detail(request: Request, legacy_id: str, db: AsyncIOMotorDatabase = Depends(get_database)):
    consent_storage = ConsentStorageService(db)
    token_storage = TokenStorageService(db)
    health_storage = HealthDataStorage(db)
    
    consent = await consent_storage.get_consent(legacy_id)
    token = await token_storage.get_token_by_legacy_id(legacy_id)
    
    health_col = db[HealthDataStorage.COLLECTION_NAME]
    health_count = await health_col.count_documents({"legacy_id": legacy_id})
    latest_health = await health_col.find_one({"legacy_id": legacy_id}, sort=[("date_of_datas", -1)])
    
    if not consent and not token:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        
    return templates.TemplateResponse(request, "admin/user_detail.html", {
        "user": consent or {"legacy_id": legacy_id, "status": "unknown"},
        "token": token,
        "health_count": health_count,
        "latest_health": latest_health,
        "deleted": request.query_params.get("deleted") == "true",
        "sync_success": request.query_params.get("sync_success") == "true",
        "sync_count": request.query_params.get("count"),
        "sync_error": request.query_params.get("sync_error")
    })

@router.post("/users/{legacy_id}/sync", dependencies=[Depends(require_admin_email)])
async def admin_sync_user_data(
    request: Request, 
    legacy_id: str, 
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Admin action: Fetches the last 7 days of health data for a specific user."""
    token_storage = TokenStorageService(db)
    health_storage = HealthDataStorage(db)
    
    try:
        token_doc = await token_storage.get_token_by_legacy_id(legacy_id)
        if not token_doc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User token not found")
            
        health_id = token_doc.get("health_id")
        access_token = await ensure_valid_token(db, legacy_id)
        
        today = datetime.now(timezone.utc).date()
        dates_to_sync = [(today - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(7)]
        
        synced_count = 0
        
        for date in dates_to_sync:
            existing = await health_storage.get_record(legacy_id, date)
            if existing:
                continue # Skip if already cached
                
            parsed_data = await fetch_daily_health_data(access_token, date)
            
            await health_storage.save_record(
                legacy_id=legacy_id,
                health_id=health_id,
                date=date,
                data=parsed_data
            )
            synced_count += 1
            
        logger.info(f"✅ Admin synced {synced_count} days of data for {legacy_id}")
        return RedirectResponse(
            url=f"/admin/users/{legacy_id}?sync_success=true&count={synced_count}", 
            status_code=status.HTTP_303_SEE_OTHER
        )
        
    except ValueError as e:
        logger.error(f"Auth error during admin sync for {legacy_id}: {e}")
        return RedirectResponse(url=f"/admin/users/{legacy_id}?sync_error=auth", status_code=status.HTTP_303_SEE_OTHER)
    except Exception as e:
        logger.error(f"Error during admin sync for {legacy_id}: {e}", exc_info=True)
        return RedirectResponse(url=f"/admin/users/{legacy_id}?sync_error=general", status_code=status.HTTP_303_SEE_OTHER)

@router.post("/users/{legacy_id}/delete", dependencies=[Depends(require_admin_email)])
async def admin_force_delete_user(
    request: Request, 
    legacy_id: str, 
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """EMERGENCY ACTION: Permanently deletes all traces of a user."""
    consent_storage = ConsentStorageService(db)
    token_storage = TokenStorageService(db)
    health_storage = HealthDataStorage(db)
    
    revoked_col = db["revoked_sessions"]
    await revoked_col.update_one(
        {"legacy_id": legacy_id},
        {"$set": {
            "legacy_id": legacy_id,
            "revoked_at": datetime.now(timezone.utc).isoformat(),
            "reason": "admin_force_delete"
        }},
        upsert=True
    )
    
    await consent_storage.collection.delete_one({"legacy_id": legacy_id})
    await token_storage.hard_delete_token(legacy_id)
    await health_storage.delete_all_records(legacy_id)
    
    logger.warning(f"🚨 ADMIN FORCE DELETED ALL DATA FOR USER: {legacy_id}")
    return RedirectResponse(url=f"/admin/users/{legacy_id}?deleted=true", status_code=status.HTTP_303_SEE_OTHER)