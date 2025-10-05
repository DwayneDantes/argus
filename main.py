# main.py (Final, Corrected Version with Optional Initialization)

import argparse
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
    parser.add_argument("--scan-for-threats", action="store_true", help="Scan files against VirusTotal.")
    parser.add_argument("--train-model",action="store_true",help="Train the ML anomaly detection model on all historical data.")
    
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
            scan_all_files(creds)
        else:
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
    
    else:
        # Check if any other argument was passed. If not, print help.
        # This handles the case where the script is run with no arguments.
        if not any(vars(args).values()):
            print("\nNo action specified. Use an argument to perform a task.")
            parser.print_help()


if __name__ == "__main__":
    main()