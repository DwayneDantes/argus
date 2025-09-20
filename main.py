# main.py (Final, Corrected Version)

import argparse
from app.db.dao import initialize_database

def main():
    """Main function to run Argus with command-line arguments."""
    initialize_database()

    parser = argparse.ArgumentParser(description="Argus: A Google Drive Security Guardian.")
    parser.add_argument("--start-guardian", action="store_true", help="Start the Argus Guardian background service.")
    parser.add_argument("--scan-all", action="store_true", help="Full file scan.")
    parser.add_argument("--ingest-once", action="store_true", help="Ingest new activity.")
    parser.add_argument("--learn-baseline", action="store_true", help="Calculate user behavior.")
    parser.add_argument("--test-scoring", action="store_true", help="Display score analysis for recent events.")
    parser.add_argument("--scan-for-threats", action="store_true", help="Scan files against VirusTotal.")
    # Removed the old --find-narratives as it's now part of --test-scoring
    args = parser.parse_args()

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
        # Import from its new, correct home
        from app.analysis.baseline_analyzer import update_baseline
        update_baseline()
    
    elif args.test_scoring:
        # Import from the orchestrator file
        from app.analysis.ntw import test_scoring_harness
        test_scoring_harness()
    
    elif args.scan_for_threats:
        from app.analysis.threat_scanner import scan_unscanned_files
        scan_unscanned_files()
    
    else:
        print("\nNo action specified. Use --start-guardian or another command.")
        parser.print_help()


if __name__ == "__main__":
    main()