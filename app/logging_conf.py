# app/logging_conf.py
"""
Configures logging for the Argus application.
This should be imported early in main.py to set up logging.
"""

import logging
import sys
from pathlib import Path

def setup_logging(verbose: bool = False):
    """
    Sets up logging configuration for Argus.
    
    Args:
        verbose: If True, sets logging to DEBUG level. Otherwise INFO.
    """
    log_level = logging.DEBUG if verbose else logging.INFO
    
    # Create logs directory
    log_dir = Path.home() / ".argus" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Configure root logger
    # FIX: Add UTF-8 encoding for console to support emojis on Windows
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    
    # Force UTF-8 encoding for console output on Windows
    if sys.platform == 'win32':
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            console_handler,
            # File handler with UTF-8 encoding
            logging.FileHandler(log_dir / "argus.log", encoding='utf-8')
        ]
    )
    
    # Set specific loggers to appropriate levels
    logging.getLogger('app.analysis.narrative_builder').setLevel(logging.INFO)
    logging.getLogger('app.analysis.contextual_risk').setLevel(logging.INFO)
    logging.getLogger('app.analysis.ntw').setLevel(logging.INFO)
    
    # Quiet down noisy third-party libraries
    logging.getLogger('googleapiclient').setLevel(logging.WARNING)
    logging.getLogger('google').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    
    logging.info("Logging configured successfully")