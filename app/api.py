# app/api.py (FINAL, CORRECTED, AND ROBUST VERSION)
import sqlite3
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime # <--- ADD THIS IMPORT

from app.db import dao

app = FastAPI(
    title="Project Argus API",
    description="API for accessing threat intelligence and narrative data from Project Argus.",
    version="1.0.0"
)

# --- Pydantic Models (CORRECTED DATA TYPES) ---
class NarrativeEvent(BaseModel):
    id: int
    event_type: str
    actor_user_id: str
    ts: datetime # <--- FIX: Changed from str to datetime
    file_name: Optional[str] = None
    stage: Optional[str] = None

class NarrativeDetails(BaseModel):
    narrative_id: int
    narrative_type: str
    primary_actor_id: str
    start_time: datetime # <--- FIX: Changed from str to datetime
    end_time: datetime   # <--- FIX: Changed from str to datetime
    final_score: float

class NarrativeTimelineResponse(BaseModel):
    details: NarrativeDetails
    events: List[NarrativeEvent]


# --- API Endpoint Definition (ROBUST LOGIC) ---
@app.get("/api/v1/narrative/{narrative_id}/timeline", response_model=NarrativeTimelineResponse)
def get_narrative_timeline(narrative_id: int):
    """
    Retrieves the full timeline for a specific narrative incident.
    """
    try:
        with dao.get_db_connection() as conn:
            cursor = conn.cursor()
            
            narrative_details_row = dao.get_narrative_details(cursor, narrative_id)
            if not narrative_details_row:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Narrative with ID {narrative_id} not found."
                )

            narrative_events_rows = dao.get_events_for_narrative(cursor, narrative_id)

            # Manually and explicitly convert database rows to Pydantic models
            details_model = NarrativeDetails(**dict(narrative_details_row))
            
            event_models = [NarrativeEvent(**dict(row)) for row in narrative_events_rows]
            
            response = NarrativeTimelineResponse(
                details=details_model,
                events=event_models
            )
            return response

    except Exception as e:
        import traceback
        print("--- DETAILED EXCEPTION ---")
        traceback.print_exc()
        print("--------------------------")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An internal server error occurred. Check server logs for details."
        )