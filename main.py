# main.py (Correct and Final)

import argparse
from app.oauth.google_auth import get_credentials
from app.db.dao import initialize_database
from app.drive.ingest import ingest_once, scan_all_files
from app.analysis.ntw import update_baseline, test_scoring
from app.analysis.threat_scanner import scan_unscanned_files
from app.analysis.narrative_builder import find_data_exfiltration_narratives, find_mass_deletion_narratives



def main():
    """Main function to run Argus with command-line arguments."""
    initialize_database()

    parser = argparse.ArgumentParser(description="Argus: A Google Drive Security Guardian.")
    parser.add_argument("--start-guardian",action="store_true",help="Start the Argus Guardian background monitoring service.")
    parser.add_argument("--scan-all", action="store_true", help="Perform a full scan of all files to build the baseline.")
    parser.add_argument("--ingest-once", action="store_true", help="Ingest new activity since the last run.")
    parser.add_argument("--learn-baseline", action="store_true", help="Analyze history to calculate user behavior.")
    parser.add_argument("--test-scoring", action="store_true", help="Fetch recent events and display a score analysis.")
    parser.add_argument("--scan-for-threats", action="store_true", help="Slowly scan unscanned files against the VirusTotal database.")
    parser.add_argument("--find-narratives", action="store_true", help="Analyze the event log to find high-threat event sequences (narratives).")
    
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
        from app.analysis.ntw import update_baseline
        update_baseline()
    
    elif args.test_scoring:
        from app.analysis.ntw import test_scoring
        test_scoring()
    
    elif args.scan_for_threats:
        from app.analysis.threat_scanner import scan_unscanned_files
        scan_unscanned_files()
    
    elif args.find_narratives:
        from app.analysis.narrative_builder import find_data_exfiltration_narratives, find_mass_deletion_narratives
        find_data_exfiltration_narratives()
        find_mass_deletion_narratives()
    
    else:
        print("\nNo action specified. Use --start-guardian or another command.")
        parser.print_help()


if __name__ == "__main__":
    main()