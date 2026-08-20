"""
User dashboard routes for managing Google Health connection.
"""
import logging
import io
import json
from fastapi import APIRouter, Depends, Request, HTTPException, status
from fastapi.responses import RedirectResponse, HTMLResponse, StreamingResponse
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.session import SessionUser, clear_user_session, get_current_user_with_consent, get_current_user
from app.core.templates import templates
from app.database import get_database
from app.auth.token_storage import TokenStorageService
from app.config import get_settings
from app.services.sync_service import SyncService


logger = logging.getLogger(__name__)
settings = get_settings()

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/", response_class=HTMLResponse)
async def dashboard_home(
    request: Request,
    current_user: SessionUser = Depends(get_current_user_with_consent)
):
    
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "current_user": current_user,
            "legacy_id": current_user.legacy_id,
            "health_id": current_user.health_id,
        }
    )


@router.post("/sync-data")
async def trigger_sync(
    current_user: SessionUser = Depends(get_current_user_with_consent),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Trigger a sync of missing data from Google Health API.
    Progress is tracked in MongoDB and can be polled via /api/sync-progress.
    """
    # 1. Get the Google Access Token
    token_storage = TokenStorageService(db)
    token_doc = await token_storage.get_token_with_details(current_user.legacy_id)
    
    if not token_doc or not token_doc.get("token"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No active Google connection.")
        
    access_token = token_doc["token"].get("access_token")
    if not access_token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Access token missing.")

    # 2. Run the sync via the service
    sync_service = SyncService(db)
    result = await sync_service.sync_missing_data(
        access_token=access_token,
        legacy_id=current_user.legacy_id,
        health_id=current_user.health_id,
    )
    
    return {
        "status": "completed",
        "synced": result["synced"],
        "failed": result["failed"],
        "total": result["total"],
    }


@router.get("/sync-progress")
async def get_sync_progress(
    current_user: SessionUser = Depends(get_current_user_with_consent),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """Returns the current sync progress for the authenticated user."""
    sync_service = SyncService(db)
    return await sync_service.get_progress(current_user.legacy_id)


# =========================================================================
# DOWNLOAD ROUTE
# =========================================================================

@router.get("/download-data")
async def download_my_data(
    current_user: SessionUser = Depends(get_current_user_with_consent),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    GDPR Article 20: Right to Data Portability.
    Exports all user health records as a downloadable JSON file.
    """
    sync_service = SyncService(db)
    
    # 1. Export all records
    records = await sync_service.export_all_data(current_user.legacy_id)
    
    # 2. Clean up progress record (sync is complete)
    await sync_service.clear_progress(current_user.legacy_id)
    
    # 3. Convert to JSON
    json_data = json.dumps(records, indent=2, default=str)
    
    # 4. Return as downloadable file
    return StreamingResponse(
        io.BytesIO(json_data.encode("utf-8")),
        media_type="application/json",
        headers={
            "Content-Disposition": f"attachment; filename=propsy_health_raw_data_{current_user.legacy_id}.json"
        }
    )


@router.post("/disconnect")
async def disconnect_account(
    request: Request,
    current_user: SessionUser = Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Disconnect Google Health account.
    """
    
    # Clear session
    clear_user_session(request)
    
    return RedirectResponse(url="/?disconnected=true", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/withdraw", response_class=HTMLResponse)
async def show_withdraw_page(
    request: Request,
    current_user: SessionUser = Depends(get_current_user_with_consent)
):

    return templates.TemplateResponse(
        request,
        "withdraw.html",
        {
            "current_user": current_user,
            "legacy_id": current_user.legacy_id,
            "health_id": current_user.health_id,
        }
    )