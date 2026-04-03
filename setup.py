"""
Sentinel Firewall — Setup & Installation Script
Handles dependency installation and initial configuration.
"""

import os
import sys
import subprocess
import platform


def check_python_version():
    if sys.version_info < (3, 9):
        print("ERROR: Python 3.9+ is required.")
        print(f"Current version: {sys.version}")
        sys.exit(1)
    print(f"[OK] Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")


def check_admin():
    """Check if running with administrator privileges."""
    if platform.system() == "Windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.getuid() == 0


def install_dependencies():
    print("\n[*] Installing Python dependencies...")
    subprocess.check_call([
        sys.executable, "-m", "pip", "install", "-r", "requirements.txt", "--quiet"
    ])
    print("[OK] Dependencies installed")


def install_npcap_instructions():
    """Print Npcap installation instructions for Windows."""
    if platform.system() != "Windows":
        return

    print("\n" + "=" * 60)
    print("IMPORTANT: Npcap Required for Packet Capture")
    print("=" * 60)
    print("""
Scapy on Windows requires Npcap for packet capture.

1. Download Npcap from: https://npcap.com/#download
2. Run the installer
3. During installation, check:
   - [x] Install Npcap in WinPcap API-compatible mode
   - [x] Support raw 802.11 traffic

Without Npcap, the IDS module will not work (DNS filtering
and dashboard will still function).
""")


def create_directories():
    os.makedirs("logs", exist_ok=True)
    os.makedirs("data", exist_ok=True)
    print("[OK] Created logs/ and data/ directories")


def configure_windows_dns():
    """Print instructions for configuring Windows to use Sentinel DNS."""
    if platform.system() != "Windows":
        return

    print("\n" + "=" * 60)
    print("DNS FILTERING SETUP")
    print("=" * 60)
    print("""
To route DNS through Sentinel's filtering proxy:

Option A — Use nslookup for testing:
    nslookup example.com 127.0.0.1 -port=5353

Option B — System-wide (PowerShell as Admin):
    # Find your network adapter name first:
    Get-NetAdapter | Select-Object Name, Status

    # Set DNS to localhost:
    Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ServerAddresses "127.0.0.1"

    # To revert:
    Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ResetServerAddresses

Option C — Use dnscrypt-proxy or stubby as a local DNS forwarder
    that forwards to Sentinel on port 5353.

Note: Since Sentinel runs on port 5353 (not 53), Option B requires
an additional port redirect. For easiest setup, use Option A for
testing or configure your router's DNS to point to your machine.
""")


def main():
    print("=" * 60)
    print("Sentinel Firewall — Setup")
    print("=" * 60)

    check_python_version()

    admin = check_admin()
    if admin:
        print("[OK] Running with administrator privileges")
    else:
        print("[!] Not running as admin — packet capture will require elevation")

    install_dependencies()
    create_directories()
    install_npcap_instructions()
    configure_windows_dns()

    print("\n" + "=" * 60)
    print("SETUP COMPLETE")
    print("=" * 60)
    print(f"""
To start Sentinel Firewall:

    # Full suite (DNS + IDS + Dashboard):
    python -m src.main

    # DNS filtering only:
    python -m src.main --dns-only

    # With custom config:
    python -m src.main -c config/my_config.yaml

    # Custom dashboard port:
    python -m src.main --port 9090

Dashboard will be available at: http://127.0.0.1:8080

For packet capture (IDS), run as Administrator:
    - Right-click Command Prompt → Run as Administrator
    - Or: runas /user:Administrator "python -m src.main"
""")


if __name__ == "__main__":
    main()
