import argparse
from app.oauth.google_auth import get_credentials
from app.db.dao import initialize_database
from app.drive.ingest import ingest_once

def main():
    """Main function to run Argus with command-line arguments."""

    # Step 1: Initialize the database.
    # This creates the argus.db file and all necessary tables if they don't exist.
    # This MUST be called before any other function that needs the database.
    initialize_database()

    # Step 2: Set up the ability to accept commands from the user.
    parser = argparse.ArgumentParser(description="Argus: A Google Drive Security Guardian.")
    parser.add_argument(
        "--ingest-once",
        action="store_true",
        help="Perform a one-time scan to ingest new activity from Google Drive."
    )
    args = parser.parse_args()

    # Step 3: Get the user's login credentials. This is needed for the API call.
    creds = get_credentials()

    # Step 4: If the user typed '--ingest-once', run the ingestion process.
    if args.ingest_once:
        ingest_once(creds)
    else:
        # If the user just ran 'python main.py' with no command, guide them.
        print("\nNo action specified. Use --ingest-once to scan for new activity.")
        print("Example: python main.py --ingest-once")
        parser.print_help()


if __name__ == "__main__":
    main()