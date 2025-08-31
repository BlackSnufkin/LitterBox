import os
import sys
import ctypes
import argparse
from app import create_app, setup_logging  

def is_running_as_admin():
    """Check if the script is running with administrative privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except AttributeError:
        return os.geteuid() == 0

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--ip', type=str, help='Specify host IP address (e.g., --ip 192.168.1.120)')
    args = parser.parse_args()
    
    if not is_running_as_admin():
        print("[!] This script requires administrative privileges. Please run as administrator.")
        sys.exit(1)
    
    app = create_app()
    
    # Set host IP if provided
    if args.ip:
        app.config['application']['host'] = args.ip
        print(f"[+] Host IP set to: {args.ip}")
    
    # Enable debug mode based on the `--debug` flag
    if args.debug:
        app.config['DEBUG'] = True
        app.config['application']['debug'] = True  # Optional if your custom config also uses it
    
    # Set up logging based on the debug mode
    setup_logging(app)
    
    # Run the app
    app.run(
        host=app.config['application']['host'],
        port=app.config['application']['port'],
        debug=app.config['DEBUG']  # Flask debug mode
    )

if __name__ == '__main__':
    main()
