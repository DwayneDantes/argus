# main.py (Final, Corrected Version with Optional Initialization)

import argparse
import uvicorn 
from app.db.dao import initialize_database

def main():
    """Main function to run Argus with command-line arguments."""

    parser = argparse.ArgumentParser(description="Argus: A Google Drive Security Guardian.")
    
    # --- START OF FIX ---
    # Add a new argument to control database initialization
    parser.add_argument(
        "--init-db", 
        action="store_true", 
        help="Initialize a new, empty database from the schema. Should only be run once."
    )
    # --- END OF FIX ---

    parser.add_argument("--start-guardian", action="store_true", help="Start the Argus Guardian background service.")
    parser.add_argument("--scan-all", action="store_true", help="Full file scan.")
    parser.add_argument("--ingest-once", action="store_true", help="Ingest new activity.")
    parser.add_argument("--learn-baseline", action="store_true", help="Calculate user behavior.")
    parser.add_argument("--test-scoring", action="store_true", help="Display score analysis for recent events.")
    parser.add_argument("--start-api", action="store_true", help="Start the FastAPI server for the Argus API.")
    parser.add_argument("--scan-for-threats", action="store_true", help="Scan files against VirusTotal.")
    parser.add_argument("--train-model",action="store_true",help="Train the ML anomaly detection model on all historical data.")
    parser.add_argument(
        "--scan-everything", 
        action="store_true", 
        help="Run a one-time analysis of all unprocessed events and save detected narratives."
    )
    
    args = parser.parse_args()

    # --- START OF FIX ---
    # Only run the initialization if the specific command is given
    if args.init_db:
        initialize_database()
        print("Database has been initialized.")
        return # Exit after initializing, as it's a standalone setup task
    # --- END OF FIX ---

    if args.start_guardian:
        from app.guardian.service import start_guardian_service
        start_guardian_service()
    
    elif args.scan_all or args.ingest_once:
        from app.oauth.google_auth import get_credentials
        from app.drive.ingest import scan_all_files, ingest_once
        creds = get_credentials()
        
        if args.scan_all:
            # --- START OF IMPROVED WORKFLOW ---
            # Step 1: Ingest all historical data
            print("\n--- [PHASE 1/3] Starting Full Drive Scan ---")
            scan_all_files(creds)
            print("\n--- [PHASE 1/3] Full Drive Scan Complete ---")

            # Step 2: Automatically learn the baseline from the data we just ingested
            print("\n--- [PHASE 2/3] Learning User Behavioral Baseline ---")
            from app.analysis.baseline_analyzer import update_baseline
            update_baseline()
            print("\n--- [PHASE 2/3] Baseline Learning Complete ---")

            # Step 3: Automatically scan all the ingested events for threats
            print("\n--- [PHASE 3/3] Scanning All Events for Threats ---")
            from app.guardian.service import run_analysis_once
            run_analysis_once()
            print("\n--- [PHASE 3/3] Threat Scan Complete ---")
            # --- END OF IMPROVED WORKFLOW ---
        else:
            # The --ingest-once command remains a simple, single operation
            ingest_once(creds)
    elif args.learn_baseline:
        from app.analysis.baseline_analyzer import update_baseline
        update_baseline()
    
    elif args.test_scoring:
        from app.analysis.ntw import test_scoring_harness
        test_scoring_harness()
    
    elif args.scan_for_threats:
        from app.analysis.threat_scanner import scan_unscanned_files
        scan_unscanned_files()
    
    elif args.train_model:
        from app.analysis.ml_trainer import train_model
        train_model()
    elif args.start_api:
        print("Starting Argus FastAPI server...")
        print("API Documentation will be available at http://127.0.0.1:8000/docs")
        uvicorn.run("app.api:app", host="127.0.0.1", port=8000, reload=True)
    elif args.scan_everything:
        from app.guardian.service import run_analysis_once
        run_analysis_once()
    
    
    else:
        # Check if any other argument was passed. If not, print help.
        # This handles the case where the script is run with no arguments.
        if not any(vars(args).values()):
            print("\nNo action specified. Use an argument to perform a task.")
            parser.print_help()


if __name__ == "__main__":
    main()