#!/usr/bin/env python3
"""
ArgusPI v2 - USB Virus Scanner
Main application entry point
"""

import os
import sys
import signal
import logging
import argparse
from pathlib import Path

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from core.application import ArgusApplication
from argus_logging.logger import setup_logging


def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    logging.info(f"Received signal {signum}, shutting down...")
    sys.exit(0)


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="ArgusPI v2 - USB Virus Scanner for Raspberry Pi",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py                   # Start in normal console mode
  python3 main.py --kiosk           # Start in kiosk mode
  python3 main.py --config custom.yaml  # Use custom config file
        """
    )
    
    parser.add_argument(
        '--kiosk', 
        action='store_true',
        help='Start in kiosk mode for public use'
    )
    
    parser.add_argument(
        '--config', '-c',
        type=str,
        help='Path to configuration file'
    )
    
    parser.add_argument(
        '--version', '-v',
        action='version',
        version='ArgusPI v2.0.0'
    )
    
    return parser.parse_args()


def main():
    """Main application entry point"""
    # Parse command line arguments
    args = parse_arguments()
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Setup logging
    setup_logging()
    
    try:
        # Create and run the application
        app = ArgusApplication(config_file=args.config, kiosk_mode=args.kiosk)
        app.run()
    except KeyboardInterrupt:
        logging.info("Application interrupted by user")
    except Exception as e:
        logging.error(f"Application error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()