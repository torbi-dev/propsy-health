"""Async Google Health API fetcher and parser."""
import httpx
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)
BASE_URL = "https://health.googleapis.com/v4"


# RAW API FETCHING (Handles Pagination)

async def _fetch_rollup(access_token: str, data_type: str, payload: dict) -> dict:
    url = f"{BASE_URL}/users/me/dataTypes/{data_type}/dataPoints:rollUp"
    headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
    
    all_points = []
    async with httpx.AsyncClient(timeout=30.0) as client:
        while True:
            resp = await client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
            
            if "rollupDataPoints" in data:
                all_points.extend(data["rollupDataPoints"])
                
            next_token = data.get("nextPageToken")
            if not next_token:
                break
            payload["pageToken"] = next_token
            
    return {"rollupDataPoints": all_points}

async def _fetch_list(access_token: str, data_type: str, payload: dict) -> dict:
    url = f"{BASE_URL}/users/me/dataTypes/{data_type}/dataPoints"
    headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
    
    all_points = []
    async with httpx.AsyncClient(timeout=30.0) as client:
        while True:
            resp = await client.get(url, headers=headers, params=payload)
            resp.raise_for_status()
            data = resp.json()
            
            if "dataPoints" in data:
                all_points.extend(data["dataPoints"])
                
            next_token = data.get("nextPageToken")
            if not next_token:
                break
            payload["pageToken"] = next_token
            
    return {"dataPoints": all_points}


# PARSING LOGIC

def _parse_steps(data: dict) -> int:
    total = 0
    for point in data.get("rollupDataPoints", []):
        steps_data = point.get("steps", {})
        total += int(steps_data.get("countSum", 0))
    return total

def _parse_calories(data: dict) -> int:
    total = 0.0
    for point in data.get("rollupDataPoints", []):
        cal_data = point.get("totalCalories", {})
        total += float(cal_data.get("kcalSum", 0.0))
    return int(round(total))

def _parse_wear_time(data: dict) -> int:
    total_seconds = 0.0
    for point in data.get("rollupDataPoints", []):
        start_str = point.get("startTime")
        end_str = point.get("endTime")
        if start_str and end_str:
            start_dt = datetime.fromisoformat(start_str.replace('Z', '+00:00'))
            end_dt = datetime.fromisoformat(end_str.replace('Z', '+00:00'))
            total_seconds += (end_dt - start_dt).total_seconds()
    return int(round(total_seconds / 60.0))

def _parse_heart_rate(data: dict) -> dict:
    raw_points = []
    total_avg = 0
    count = 0
    max_hr = 0
    min_hr = 999
    
    for point in data.get("rollupDataPoints", []):
        hr_data = point.get("heartRate", {})
        avg = hr_data.get("beatsPerMinuteAvg")
        max_val = hr_data.get("beatsPerMinuteMax")
        min_val = hr_data.get("beatsPerMinuteMin")
        
        if avg:
            total_avg += avg
            count += 1
        if max_val and max_val > max_hr:
            max_hr = max_val
        if min_val and min_val < min_hr:
            min_hr = min_val
            
        raw_points.append({
            "startTime": point.get("startTime"),
            "endTime": point.get("endTime"),
            "avg": avg, "max": max_val, "min": min_val
        })
        
    return {
        "avg_hr": int(total_avg / count) if count > 0 else None,
        "max_hr": int(max_hr) if max_hr > 0 else None,
        "resting_hr": int(min_hr) if min_hr < 999 else None, # Approximation using daily min
        "raw_heart_rate": raw_points
    }


def _parse_sleep(data_points: list) -> dict:
    """
    Parses sleep data using the pre-calculated 'summary' field provided by the Google Health API.
    This is much more accurate and faster than manually iterating through the raw 'stages' array.
    """
    if not data_points:
        return {}
        
    total_in_bed = 0
    total_asleep = 0
    deep = 0
    light = 0
    rem = 0
    awake = 0
    earliest_start = None
    latest_end = None
    raw_sessions = []
    
    for dp in data_points:
        # The API returns the sleep data directly in the dataPoint, not nested under a "sleep" key
        raw_sessions.append(dp)
        
        # 1. Parse Interval for Start/End times
        interval = dp.get("sleep", {}).get("interval", {})
        start_str = interval.get("startTime")
        end_str = interval.get("endTime")
        
        if start_str and end_str:
            start_dt = datetime.fromisoformat(start_str.replace('Z', '+00:00'))
            end_dt = datetime.fromisoformat(end_str.replace('Z', '+00:00'))
            
            if not earliest_start or start_dt < earliest_start:
                earliest_start = start_dt
            if not latest_end or end_dt > latest_end:
                latest_end = end_dt
                
        # 2. Parse Summary (The robust way!)
        summary = dp.get("sleep", {}).get("summary", {})
        
        # Get total minutes in bed and asleep
        # Note: The API returns these as STRINGS (e.g., "545"), so we must cast to int
        mins_in_bed = int(summary.get("minutesInSleepPeriod", 0))
        mins_asleep = int(summary.get("minutesAsleep", 0))
        mins_awake_summary = int(summary.get("minutesAwake", 0))
        
        total_in_bed += mins_in_bed
        total_asleep += mins_asleep
        awake += mins_awake_summary
        
        # 3. Get stages from stagesSummary
        stages_summary = summary.get("stagesSummary", [])
        for stage in stages_summary:
            stage_type = stage.get("type", "").upper()
            # The API returns minutes as strings! e.g., "318"
            mins = int(stage.get("minutes", 0))
            
            if stage_type == "DEEP":
                deep += mins
            elif stage_type == "LIGHT":
                light += mins
            elif stage_type == "REM":
                rem += mins
                
    # 4. Calculate Efficiency
    # Efficiency = (Time Asleep / Time in Bed) * 100
    efficiency = int((total_asleep / total_in_bed) * 100) if total_in_bed > 0 else None
    
    # Fallback for total_in_bed if summary was missing for some reason
    if total_in_bed == 0 and earliest_start and latest_end:
        total_in_bed = int((latest_end - earliest_start).total_seconds() / 60)
        
    return {
        "sleep_start": earliest_start.isoformat() if earliest_start else None,
        "sleep_end": latest_end.isoformat() if latest_end else None,
        "sleep_duration": total_in_bed,
        "deep_sleep": deep,
        "light_sleep": light,
        "rem_sleep": rem,
        "sleep_efficiency": efficiency,
        "raw_sleep": raw_sessions
    }


# MAIN ORCHESTRATOR

async def fetch_daily_health_data(access_token: str, date: str) -> dict:
    """Fetches all required data types for a specific date and returns a parsed dictionary."""
    date_obj = datetime.strptime(date, "%Y-%m-%d")
    start_time = date_obj.strftime('%Y-%m-%dT00:00:00.000Z')
    end_time = (date_obj + timedelta(days=1)).strftime('%Y-%m-%dT00:00:00.000Z')
    date_today = (date_obj + timedelta(days=1)).strftime('%Y-%m-%d')
    
    # 1. Define Payloads
    payload_heart = {"range": {"startTime": start_time, "endTime": end_time}, "windowSize": "10s", "pageSize": 10000}
    payload_steps = {"range": {"startTime": start_time, "endTime": end_time}, "windowSize": "3600s", "pageSize": 1000}
    payload_calories = {"range": {"startTime": start_time, "endTime": end_time}, "windowSize": "3600s", "pageSize": 300}
    
    # Sleep filter: We look for sleep sessions that ended on this specific date (morning wake up)
    payload_sleep = {
        "filter": f'sleep.interval.civil_end_time >= "{date}" AND sleep.interval.civil_end_time < "{date_today}"'
    }

    # 2. Fetch Raw Data in Parallel
    import asyncio
    heart_raw, steps_raw, calories_raw, sleep_raw = await asyncio.gather(
        _fetch_rollup(access_token, "heart-rate", payload_heart),
        _fetch_rollup(access_token, "steps", payload_steps),
        _fetch_rollup(access_token, "total-calories", payload_calories),
        _fetch_list(access_token, "sleep", payload_sleep)
    )

    # 3. Parse and Build Record
    hr_data = _parse_heart_rate(heart_raw)
    sleep_data = _parse_sleep(sleep_raw.get("dataPoints", []))
    
    return {
        "steps": _parse_steps(steps_raw),
        "calories": _parse_calories(calories_raw),
        "wear_time": _parse_wear_time(heart_raw), # Wear time is derived from heart rate intervals
        
        "avg_hr": hr_data["avg_hr"],
        "max_hr": hr_data["max_hr"],
        "resting_hr": hr_data["resting_hr"],
        "raw_heart_rate": hr_data["raw_heart_rate"],
        
        "sleep_start": sleep_data.get("sleep_start"),
        "sleep_end": sleep_data.get("sleep_end"),
        "sleep_duration": sleep_data.get("sleep_duration"),
        "deep_sleep": sleep_data.get("deep_sleep"),
        "light_sleep": sleep_data.get("light_sleep"),
        "rem_sleep": sleep_data.get("rem_sleep"),
        "sleep_efficiency": sleep_data.get("sleep_efficiency"),
        "raw_sleep": sleep_data.get("raw_sleep"),
    }