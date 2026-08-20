"""
Service for managing Google Health data synchronization.
Handles missing date detection, data fetching, progress tracking, and cleanup.
"""
import logging
from datetime import datetime, timedelta, timezone
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.services.health_data_storage import HealthDataStorage
from app.services.health_data_fetcher import fetch_daily_health_data

logger = logging.getLogger(__name__)


class SyncService:
    """
    Manages the synchronization of Google Health data.
    
    Responsibilities:
    - Detect which dates are missing from the database
    - Fetch missing data from Google Health API
    - Track sync progress in MongoDB (for real-time UI updates)
    - Clean up progress records after completion
    """
    
    COLLECTION_NAME = "sync_progress"
    
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.health_storage = HealthDataStorage(db)
        self.progress_col = db[self.COLLECTION_NAME]
    
    # MISSING DATE DETECTION
    
    async def get_missing_dates(self, legacy_id: str) -> list[str]:
        """
        Identifies which dates need to be fetched from Google API.
        
        Returns a list of date strings (YYYY-MM-DD) from the day after 
        the last DB record up to yesterday.
        """
        # Find the latest record in the DB
        latest_record = await self.health_storage.collection.find_one(
            {"legacy_id": legacy_id},
            sort=[("date_of_datas", -1)]
        )
        
        if latest_record:
            last_date = datetime.strptime(latest_record["date_of_datas"], "%Y-%m-%d").date()
            start_date = last_date + timedelta(days=1)
        else:
            # If the user has no data yet, fetch the last 30 days as a baseline
            start_date = (datetime.now(timezone.utc) - timedelta(days=30)).date()
            
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).date()
        
        missing_dates = []
        current_date = start_date
        while current_date <= yesterday:
            missing_dates.append(current_date.strftime("%Y-%m-%d"))
            current_date += timedelta(days=1)
            
        return missing_dates
    
    # PROGRESS TRACKING
    
    async def get_progress(self, legacy_id: str) -> dict:
        """
        Get the current sync progress for a user.
        
        Returns: {"current": int, "total": int, "done": bool}
        """
        progress = await self.progress_col.find_one({"legacy_id": legacy_id})
        
        if not progress:
            return {"current": 0, "total": 0, "done": True}
            
        return {
            "current": progress.get("current", 0),
            "total": progress.get("total", 0),
            "done": progress.get("done", False),
            "started_at": progress.get("started_at"),
            "updated_at": progress.get("updated_at"),
        }
    
    async def _init_progress(self, legacy_id: str, total: int):
        """Initialize a new progress record in MongoDB."""
        await self.progress_col.update_one(
            {"legacy_id": legacy_id},
            {"$set": {
                "legacy_id": legacy_id,
                "current": 0,
                "total": total,
                "done": False,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }},
            upsert=True
        )
    
    async def _update_progress(self, legacy_id: str, current: int):
        """Update the current progress counter."""
        await self.progress_col.update_one(
            {"legacy_id": legacy_id},
            {"$set": {
                "current": current,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }}
        )
    
    async def _mark_done(self, legacy_id: str):
        """Mark the sync as complete."""
        await self.progress_col.update_one(
            {"legacy_id": legacy_id},
            {"$set": {
                "done": True,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }}
        )
    
    async def clear_progress(self, legacy_id: str):
        """Delete the progress record (called after successful download)."""
        await self.progress_col.delete_one({"legacy_id": legacy_id})
        logger.info(f"🧹 Cleared sync progress for {legacy_id}")
    
    # MAIN SYNC LOGIC
    
    async def sync_missing_data(
        self,
        access_token: str,
        legacy_id: str,
        health_id: str,
    ) -> dict:
        """
        Main sync method. Detects missing dates, fetches them from Google,
        and tracks progress in MongoDB.
        
        Returns a summary dict: {"synced": int, "failed": int, "total": int}
        """
        # 1. Detect missing dates
        missing_dates = await self.get_missing_dates(legacy_id)
        total = len(missing_dates)
        
        logger.info(f"🔍 Found {total} missing dates for {legacy_id}")
        
        # 2. If nothing to sync, mark as done immediately
        if total == 0:
            await self._init_progress(legacy_id, 0)
            await self._mark_done(legacy_id)
            return {"synced": 0, "failed": 0, "total": 0}
        
        # 3. Initialize progress tracker
        await self._init_progress(legacy_id, total)
        
        # 4. Fetch each missing date sequentially (to respect Google API rate limits)
        synced_count = 0
        failed_count = 0
        
        for i, date_str in enumerate(missing_dates, 1):
            try:
                logger.info(f"📥 Syncing {date_str} for {legacy_id} ({i}/{total})")
                
                # Fetch from Google Health API
                daily_data = await fetch_daily_health_data(access_token, date_str)
                
                # Save to database
                await self.health_storage.save_record(
                    legacy_id=legacy_id,
                    health_id=health_id,
                    date=date_str,
                    data=daily_data
                )
                
                synced_count += 1
                
            except Exception as e:
                logger.error(f"❌ Failed to sync {date_str} for {legacy_id}: {e}")
                failed_count += 1
                # Continue to the next date instead of failing the whole sync
            
            # 5. Update progress in MongoDB
            await self._update_progress(legacy_id, i)
        
        # 6. Mark as done
        await self._mark_done(legacy_id)
        
        logger.info(
            f"✅ Sync complete for {legacy_id}: "
            f"{synced_count} synced, {failed_count} failed, {total} total"
        )
        
        return {
            "synced": synced_count,
            "failed": failed_count,
            "total": total,
        }
    
    # DATA EXPORT
    
    async def export_all_data(self, legacy_id: str) -> list[dict]:
        """
        Export all health records for a user from the database.
        Removes MongoDB internal fields (_id) before returning.
        """
        cursor = self.health_storage.collection.find(
            {"legacy_id": legacy_id}
        ).sort("date_of_datas", 1)
        
        records = []
        async for doc in cursor:
            doc.pop("_id", None)
            records.append(doc)
        
        return records