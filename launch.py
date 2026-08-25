"""
CyberSure — One-Click Launcher
================================
Double-click start.cmd (Windows) or run: python launch.py

What it does:
  1. Loads the FastAPI server with all scanners
  2. Starts the server on http://localhost:8000
  3. Waits for the server to be ready
  4. Opens your default browser to the CyberSure dashboard
"""

import os
import sys
import time
import threading
import webbrowser
import traceback
import socket

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
os.chdir(PROJECT_ROOT)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

HOST = "127.0.0.1"
PORT = 8000
URL = f"http://{HOST}:{PORT}"


def check_port_available(port: int) -> bool:
    """Check if a port is available."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((HOST, port))
            return True
        except OSError:
            return False


def open_browser():
    time.sleep(2)
    print(f"\n  Opening browser at {URL} ...")
    try:
        webbrowser.open(URL)
    except Exception as e:
        print(f"  Could not auto-open browser: {e}")
        print(f"  Please open {URL} manually in your browser.")


def wait_for_server(timeout=20):
    import urllib.request
    import urllib.error
    for i in range(timeout):
        try:
            urllib.request.urlopen(f"{URL}/api/health", timeout=2)
            return True
        except Exception:
            if i == 5:
                print("  Still loading scanners...")
            time.sleep(1)
    return False


def main():
    print()
    print("  ============================================")
    print("    CyberSure - Security Platform")
    print("  ============================================")
    print()

    # Check if port is already in use
    if not check_port_available(PORT):
        print(f"  Port {PORT} is already in use.")
        print(f"  Try opening {URL} in your browser.")
        print(f"  Or kill the existing process and try again.")
        try:
            webbrowser.open(URL)
        except Exception:
            pass
        input("\n  Press Enter to exit...")
        return

    print("  Loading scanners...")
    try:
        from msme_auditor.api.server import app
    except Exception:
        print("\n  FAILED TO LOAD:\n")
        traceback.print_exc()
        print("\n  Install dependencies: pip install fastapi uvicorn pydantic httpx dnspython fpdf2")
        input("  Press Enter to exit...")
        return

    print("  Starting server...")

    def run_server():
        import uvicorn
        uvicorn.run(app, host=HOST, port=PORT, log_level="info")

    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()

    print("  Waiting for server to be ready...")
    if wait_for_server():
        browser_thread = threading.Thread(target=open_browser, daemon=True)
        browser_thread.start()

        print(f"\n  ============================================")
        print(f"    Server running at {URL}")
        print(f"")
        print(f"    Frontend:  {URL}")
        print(f"    Dashboard: {URL}/dashboard.html")
        print(f"    API Docs:  {URL}/docs")
        print(f"")
        print(f"    Press Ctrl+C to stop")
        print(f"  ============================================\n")

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n  Server stopped. Goodbye!\n")
    else:
        print("\n  Server failed to start within 20 seconds.")
        print("  Check if another instance is running on port 8000.")
        input("  Press Enter to exit...")


if __name__ == "__main__":
    main()
