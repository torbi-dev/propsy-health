"""Admin dashboard routes for managing users and monitoring the system."""
import logging
from fastapi import APIRouter, Depends, Request, HTTPException, Form
from fastapi.responses import RedirectResponse, HTMLResponse
from motor.motor_asyncio import AsyncIOMotorDatabase
from datetime import datetime, timezone

from app.core.templates import templates
from app.database import get_database
from app.config import get_settings
from app.services.consent_storage import ConsentStorageService
from app.auth.token_storage import TokenStorageService
from app.services.health_data_storage import HealthDataStorage

logger = logging.getLogger(__name__)
settings = get_settings()

router = APIRouter(prefix="/admin", tags=["admin"])

# ============================================================================
# ADMIN AUTHENTICATION
# ============================================================================

class AdminAuthError(Exception):
    """Custom exception to redirect unauthenticated admin users."""
    pass

async def require_admin(request: Request):
    """Dependency to enforce admin access."""
    if not request.session.get("is_admin"):
        raise AdminAuthError()

# ============================================================================
# AUTH ROUTES
# ============================================================================

@router.get("/login", response_class=HTMLResponse)
async def admin_login_page(request: Request):
    if request.session.get("is_admin"):
        return RedirectResponse(url="/admin/", status_code=303)
    return templates.TemplateResponse(request, "admin/login.html", {"error": None})

@router.post("/login")
async def admin_login_submit(request: Request, password: str = Form(...)):
    if password == settings.admin_password:
        request.session["is_admin"] = True
        logger.info(f"✅ Admin login successful from {request.client.host}")
        return RedirectResponse(url="/admin/", status_code=303)
    
    logger.warning(f"❌ Failed admin login attempt from {request.client.host}")
    return templates.TemplateResponse(request, "admin/login.html", {"error": "Invalid password"})

@router.get("/logout")
async def admin_logout(request: Request):
    request.session.pop("is_admin", None)
    return RedirectResponse(url="/admin/login", status_code=303)

# ============================================================================
# DASHBOARD & STATS
# ============================================================================

@router.get("/", response_class=HTMLResponse, dependencies=[Depends(require_admin)])
async def admin_dashboard(request: Request, db: AsyncIOMotorDatabase = Depends(get_database)):
    consent_col = db[ConsentStorageService.COLLECTION_NAME]
    token_col = db[TokenStorageService.COLLECTION_NAME]
    health_col = db[HealthDataStorage.COLLECTION_NAME]
    
    # Gather statistics
    stats = {
        "total_consents": await consent_col.count_documents({}),
        "active_consents": await consent_col.count_documents({"status": "active"}),
        "withdrawn_consents": await consent_col.count_documents({"status": "withdrawn"}),
        "total_tokens": await token_col.count_documents({}),
        "total_health_records": await health_col.count_documents({}),
    }
    
    # Get recent consent activity
    recent_cursor = consent_col.find().sort("consented_at", -1).limit(10)
    recent_users = [doc async for doc in recent_cursor]
    
    return templates.TemplateResponse(request, "admin/dashboard.html", {
        "stats": stats,
        "recent_users": recent_users
    })

# ============================================================================
# USER MANAGEMENT
# ============================================================================

@router.get("/users", response_class=HTMLResponse, dependencies=[Depends(require_admin)])
async def admin_users_list(request: Request, db: AsyncIOMotorDatabase = Depends(get_database)):
    consent_col = db[ConsentStorageService.COLLECTION_NAME]
    cursor = consent_col.find().sort("consented_at", -1)
    users = [doc async for doc in cursor]
    
    return templates.TemplateResponse(request, "admin/users.html", {"users": users})

@router.get("/users/{legacy_id}", response_class=HTMLResponse, dependencies=[Depends(require_admin)])
async def admin_user_detail(request: Request, legacy_id: str, db: AsyncIOMotorDatabase = Depends(get_database)):
    consent_storage = ConsentStorageService(db)
    token_storage = TokenStorageService(db)
    health_storage = HealthDataStorage(db)
    
    # Fetch data (ConsentStorage automatically decrypts IP/UA)
    consent = await consent_storage.get_consent(legacy_id)
    token = await token_storage.get_token_by_legacy_id(legacy_id)
    
    # Health data summary
    health_col = db[HealthDataStorage.COLLECTION_NAME]
    health_count = await health_col.count_documents({"legacy_id": legacy_id})
    latest_health = await health_col.find_one({"legacy_id": legacy_id}, sort=[("date_of_datas", -1)])
    
    if not consent and not token:
        raise HTTPException(status_code=404, detail="User not found")
        
    return templates.TemplateResponse(request, "admin/user_detail.html", {
        "user": consent or {"legacy_id": legacy_id, "status": "unknown"},
        "token": token,
        "health_count": health_count,
        "latest_health": latest_health,
        "deleted": request.query_params.get("deleted") == "true"
    })

@router.post("/users/{legacy_id}/delete", dependencies=[Depends(require_admin)])
async def admin_force_delete_user(
    request: Request, 
    legacy_id: str, 
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """EMERGENCY ACTION: Permanently deletes all traces of a user."""
    consent_storage = ConsentStorageService(db)
    token_storage = TokenStorageService(db)
    health_storage = HealthDataStorage(db)
    
    # 1. Add to revoked sessions list (for immediate invalidation)
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
    
    # 2. Delete all user data
    await consent_storage.collection.delete_one({"legacy_id": legacy_id})
    await token_storage.hard_delete_token(legacy_id)
    await health_storage.delete_all_records(legacy_id)
    
    logger.warning(f"🚨 ADMIN FORCE DELETED ALL DATA FOR USER: {legacy_id}")
    return RedirectResponse(url=f"/admin/users/{legacy_id}?deleted=true", status_code=303)