"""
API routes for retrieving and caching Google Health data.

NOT USE IN CURRENT VERSION: you need this for a dashboard that shows health data. The current version of the app does not have a dashboard, so this is not used.

"""
import logging
import json
from fastapi import APIRouter, Depends, HTTPException, Path, status
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.database import get_database
from app.core.session import SessionUser, get_current_user_with_consent
from app.core.encryption import decrypt
from app.services.health_data_storage import HealthDataStorage
from app.services.token_manager import ensure_valid_token
from app.services.health_data_fetcher import fetch_daily_health_data

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/health-data", tags=["health-data"])

@router.get("/{date}")
async def get_health_data(
    date: str = Path(..., description="Date in YYYY-MM-DD format", regex=r"^\d{4}-\d{2}-\d{2}$"),
    current_user: SessionUser = Depends(get_current_user_with_consent),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Retrieves health data for a specific date.
    1. Checks MongoDB cache.
    2. If missing, fetches from Google Health API, parses, saves to DB, and returns.
    """
    storage = HealthDataStorage(db)
    
    # --- 1. Check Cache ---
    existing_record = await storage.get_record(current_user.legacy_id, date)
    if existing_record:
        # Remove internal MongoDB fields before returning
        existing_record.pop("_id", None)
        existing_record.pop("created_at", None)

        # Decrypt Tier 2 sensitive fields before returning
        if existing_record.get("raw_heart_rate"):
            existing_record["raw_heart_rate"] = json.loads(decrypt(existing_record["raw_heart_rate"]))
        if existing_record.get("raw_sleep"):
            existing_record["raw_sleep"] = json.loads(decrypt(existing_record["raw_sleep"]))
        if existing_record.get("sleep_start"):
            existing_record["sleep_start"] = decrypt(existing_record["sleep_start"])
        if existing_record.get("sleep_end"):
            existing_record["sleep_end"] = decrypt(existing_record["sleep_end"])

        return {"source": "database", "data": existing_record}
        
    # --- 2. Fetch from API ---
    logger.info(f"📡 Data not found in DB for {current_user.legacy_id} on {date}. Fetching from Google Health API...")
    
    try:
        # Ensure we have a valid access token
        access_token = await ensure_valid_token(db, current_user.legacy_id)
        
        # Fetch and parse data from Google
        parsed_data = await fetch_daily_health_data(access_token, date)

        copy_of_parsed_data = parsed_data.copy()
        
        # Save to MongoDB for future requests
        await storage.save_record(
            legacy_id=current_user.legacy_id,
            health_id=current_user.health_id,
            date=date,
            data=copy_of_parsed_data
        )
        
        return {"source": "api", "data": parsed_data}
        
    except ValueError as e:
        logger.error(f"Authentication error: {e}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    except Exception as e:
        logger.error(f"Error fetching health data: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to fetch health data from Google.")