import socket
import psutil
import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import logging
import logging.handlers
import re
import platform
import sys
import os
import ctypes
import io
from datetime import datetime
import threading

# ── Auto-install qrcode + Pillow if missing ───────────────────────────────────
def _ensure_packages():
    if getattr(sys, 'frozen', False):
        return
    missing = []
    try:
        import qrcode
    except ImportError:
        missing.append('qrcode[pil]')
    try:
        from PIL import Image, ImageTk
    except ImportError:
        missing.append('Pillow')
    if missing:
        import subprocess as _sp
        _sp.check_call(
            [sys.executable, '-m', 'pip', 'install', '--quiet'] + missing,
            creationflags=0x08000000
        )

_ensure_packages()

import qrcode
from PIL import Image, ImageTk
try:
    import pystray
    from PIL import ImageDraw
    HAS_PYSTRAY = True
except Exception:
    HAS_PYSTRAY = False


# Tray icon helper 
def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)


# ─────────────────────────────────────────────
#  Single Instance Enforcement
# ─────────────────────────────────────────────

SINGLE_INSTANCE_MUTEX = "Global\\NetworkInfoApp_SingleInstance"
IPC_PORT = 49152

def enforce_single_instance():
    """
    Prevents multiple instances of the app from running simultaneously.
    - Named Mutex  → detects if another instance is already running.
    - Local Socket → signals the existing instance to restore its window.
    If a second instance is launched, it signals the first and exits silently.
    Returns the mutex handle — MUST be stored so it stays alive.
    """
    if platform.system() != "Windows":
        return None

    kernel32 = ctypes.windll.kernel32
    mutex    = kernel32.CreateMutexW(None, False, SINGLE_INSTANCE_MUTEX)

    if kernel32.GetLastError() == 183:          # ERROR_ALREADY_EXISTS
        log.info("Another instance is already running — sending SHOW signal and exiting.")
        try:
            import socket as _s
            sock = _s.socket(_s.AF_INET, _s.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect(('127.0.0.1', IPC_PORT))
            sock.sendall(b'SHOW')
            sock.close()
        except Exception as e:
            log.debug(f"IPC signal failed: {e}")
        sys.exit(0)

    log.info("Single-instance mutex acquired — this is the primary instance.")
    return mutex                                # keep handle alive in caller


# ─────────────────────────────────────────────
#  Logging Setup
# ─────────────────────────────────────────────

NO_WINDOW = 0x08000000
LOG_FILE  = "network_info.log"

def setup_logging():
    """
    Two handlers:
      - RotatingFileHandler  → DEBUG and above, max 2MB, keeps 3 backups
      - StreamHandler        → WARNING and above (keeps terminal clean)
    Format: timestamp | level | function name | line number | message
    """
    log = logging.getLogger("NetInfoApp")
    log.setLevel(logging.DEBUG)

    fmt = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(funcName)-35s | L%(lineno)-4d | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    fh = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.WARNING)
    ch.setFormatter(fmt)

    log.addHandler(fh)
    log.addHandler(ch)
    return log

log = setup_logging()
log.info("=" * 80)
log.info(f"Network Information Viewer started — Python {sys.version.split()[0]} | {platform.platform()}")
log.info("=" * 80)


# ─────────────────────────────────────────────
#  Logging filter: redact known sensitive values
# ─────────────────────────────────────────────
class RedactPasswordsFilter(logging.Filter):
    """Logging filter that replaces any occurrence of known saved
    Wi-Fi passwords in log messages with a redaction token.
    """
    def __init__(self, passwords=None):
        super().__init__()
        self.update_passwords(passwords)

    def update_passwords(self, passwords):
        vals = []
        try:
            if isinstance(passwords, dict):
                vals = list(passwords.values())
            elif passwords:
                vals = list(passwords)
        except Exception:
            vals = []
        # keep only non-empty, non-placeholder strings
        self._pw_set = set(p for p in vals if p and p not in (
            'Open / No Password', 'N/A', 'Unable to Retrieve', 'Not in saved profiles'))

    def filter(self, record):
        try:
            msg = record.getMessage()
            for pw in self._pw_set:
                if pw and pw in msg:
                    msg = msg.replace(pw, '***REDACTED***')
            # replace the message and clear args so formatting does not re-insert sensitive data
            record.msg = msg
            record.args = ()
        except Exception:
            pass
        return True


# ─────────────────────────────────────────────
#  WiFi Password Retrieval
# ─────────────────────────────────────────────

def get_all_wifi_passwords_windows():
    """
    Returns dict { ssid: password } for every saved WiFi profile on Windows.
    Source: netsh wlan show profiles  +  netsh wlan show profile <n> key=clear
    """
    log.debug("Starting WiFi password retrieval via netsh wlan show profiles")

    if platform.system() != "Windows":
        log.warning("Not on Windows — skipping WiFi password retrieval")
        return {}

    passwords = {}
    try:
        profiles_raw = subprocess.check_output(
            ['netsh', 'wlan', 'show', 'profiles'],
            encoding='utf-8', errors='ignore',
            creationflags=NO_WINDOW
        )
        log.debug(f"netsh wlan show profiles raw output ({len(profiles_raw)} chars):\n{profiles_raw}")

        profile_names = re.findall(r'All User Profile\s*:\s*(.*)', profiles_raw)
        log.info(f"Found {len(profile_names)} saved WiFi profile(s): {profile_names}")

        for name in profile_names:
            name = name.strip()
            log.debug(f"Fetching key for profile: '{name}'")
            try:
                profile_info = subprocess.check_output(
                    ['netsh', 'wlan', 'show', 'profile', name, 'key=clear'],
                    encoding='utf-8', errors='ignore',
                    creationflags=NO_WINDOW
                )
                match = re.search(r'Key Content\s*:\s*(.*)', profile_info)
                if match:
                    passwords[name] = match.group(1).strip()
                    log.debug(f"  Profile '{name}' → password found (length {len(passwords[name])})")
                else:
                    passwords[name] = "Open / No Password"
                    log.debug(f"  Profile '{name}' → no key content (open network)")
            except subprocess.CalledProcessError as e:
                passwords[name] = "Unable to Retrieve"
                log.warning(f"  CalledProcessError for profile '{name}': {e}")

    except Exception as e:
        log.error(f"Unexpected error during WiFi password retrieval: {e}", exc_info=True)

    log.info(f"Password retrieval complete — {len(passwords)} profile(s) loaded")
    return passwords


# ─────────────────────────────────────────────
#  WiFi Security Type
# ─────────────────────────────────────────────

def get_wifi_security_type(ssid):
    """
    Returns one of: 'WPA2', 'WPA', 'WEP', 'nopass'
    Reads the Authentication field from: netsh wlan show profile <ssid>
    """
    log.debug(f"Detecting security type for SSID: '{ssid}'")

    if platform.system() != "Windows":
        log.warning("Not on Windows — returning default WPA2")
        return "WPA2"

    try:
        profile_info = subprocess.check_output(
            ['netsh', 'wlan', 'show', 'profile', ssid],
            encoding='utf-8', errors='ignore',
            creationflags=NO_WINDOW
        )
        auth_match = re.search(r'Authentication\s*:\s*(.*)', profile_info)
        if auth_match:
            auth = auth_match.group(1).strip().upper()
            log.debug(f"  Authentication field for '{ssid}': '{auth}'")
            if 'WPA2' in auth or 'WPA3' in auth or 'SAE' in auth or '802.1X' in auth:
                log.debug("  Resolved security: WPA2")
                return 'WPA2'
            elif 'WPA' in auth:
                log.debug("  Resolved security: WPA")
                return 'WPA'
            elif 'WEP' in auth:
                log.debug("  Resolved security: WEP")
                return 'WEP'
            elif 'OPEN' in auth or 'NONE' in auth:
                log.debug("  Resolved security: nopass")
                return 'nopass'
        else:
            log.warning(f"  No Authentication field found in profile for '{ssid}'")

    except Exception as e:
        log.error(f"Security type detection error for '{ssid}': {e}", exc_info=True)

    log.debug("  Falling back to default security: WPA2")
    return 'WPA2'


# ─────────────────────────────────────────────
#  Connected SSID Detection
# ─────────────────────────────────────────────

def get_all_connected_ssids_windows(saved_profiles: dict = None):
    """
    Returns dict { interface_alias: ssid } where ssid is ALWAYS a key that
    exists (or best-matches) in saved_profiles.

    Strategy (in order):
      1. netsh wlan show interfaces  — real broadcasted SSID, perfect match.
         Fails on machines where WLAN AutoConfig service (wlansvc) is stopped.
      2. PowerShell Get-NetConnectionProfile  — fallback. Returns Windows
         *network profile names* which Windows can auto-rename (e.g. "just a fan 3").
         When this path is used, each returned name is reconciled against
         saved_profiles keys: if the PowerShell name is not a direct key,
         we find the saved profile whose name is a prefix/substring of it
         (handles the " 2", " 3" suffix Windows appends).
    """
    log.debug("Starting connected SSID detection")
    result = {}

    if platform.system() != "Windows":
        log.warning("Not on Windows — skipping SSID detection")
        return result

    # ── Method 1: netsh wlan show interfaces ──────────────────────────────
    try:
        raw = subprocess.check_output(
            ['netsh', 'wlan', 'show', 'interfaces'],
            encoding='utf-8', errors='ignore',
            creationflags=NO_WINDOW
        )
        log.debug(f"netsh wlan show interfaces output ({len(raw)} chars):\n{raw}")

        current_adapter = None
        for line in raw.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            key_part, _, val_part = stripped.partition(':')
            key_norm = key_part.strip().lower()
            val      = val_part.strip()

            if key_norm == 'name':
                current_adapter = val
                log.debug(f"  Adapter: '{current_adapter}'")
            elif key_norm == 'ssid' and current_adapter:
                log.debug(f"  SSID '{val}' → adapter '{current_adapter}'")
                result[current_adapter] = val

        if result:
            log.info(f"[netsh] Connected SSID map: {result}")
            return result

        log.warning("[netsh] Succeeded but returned no interfaces — falling back to PowerShell")

    except subprocess.CalledProcessError as e:
        log.warning(f"[netsh] wlan show interfaces failed (rc={e.returncode}) — "
                    f"WLAN AutoConfig service may be stopped. Falling back to PowerShell.")
    except Exception as e:
        log.error(f"[netsh] Unexpected error: {e}", exc_info=True)

    # ── Method 2: PowerShell Get-NetConnectionProfile (fallback) ─────────
    log.debug("Attempting PowerShell Get-NetConnectionProfile fallback")
    try:
        ps_cmd = (
            "Get-NetConnectionProfile | "
            "Select-Object -Property InterfaceAlias,Name | "
            "Format-List"
        )
        proc = subprocess.run(
            ['powershell', '-NoProfile', '-NonInteractive', '-Command', ps_cmd],
            capture_output=True, encoding='utf-8', errors='ignore',
            creationflags=NO_WINDOW
        )
        log.debug(f"PowerShell output ({len(proc.stdout)} chars):\n{proc.stdout}")

        ps_result   = {}   # { interface_alias: powershell_profile_name }
        current_alias = None
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                current_alias = None
                continue
            if line.lower().startswith('interfacealias'):
                _, _, val = line.partition(':')
                current_alias = val.strip()
            elif line.lower().startswith('name') and current_alias:
                _, _, val = line.partition(':')
                ps_name = val.strip()
                if ps_name and ps_name not in ('Unidentified network', 'Identifying...'):
                    ps_result[current_alias] = ps_name

        log.debug(f"[PowerShell] Raw profile name map: {ps_result}")

        # ── Reconcile PowerShell names → saved profile keys ────────────
        # Windows appends " 2", " 3" etc. to profile names when it considers
        # them duplicates.  Find the saved key that is a prefix of (or equal
        # to) the PowerShell name so the password lookup never fails.
        for iface, ps_name in ps_result.items():
            if saved_profiles and ps_name not in saved_profiles:
                # Try to find a saved key that ps_name starts with
                match = next(
                    (k for k in saved_profiles
                     if ps_name.startswith(k) or k.startswith(ps_name)),
                    None
                )
                if match:
                    log.info(f"[PowerShell] Reconciled '{ps_name}' → saved key '{match}' "
                             f"for interface '{iface}'")
                    result[iface] = match
                else:
                    log.warning(f"[PowerShell] '{ps_name}' not in saved profiles and "
                                f"no prefix match found — using as-is")
                    result[iface] = ps_name
            else:
                result[iface] = ps_name

        log.info(f"[PowerShell] Reconciled SSID map: {result}")

    except Exception as e:
        log.error(f"[PowerShell] Fallback failed: {e}", exc_info=True)

    if not result:
        log.warning("No connected WiFi SSIDs detected from either method. "
                    "Device may be on Ethernet only or WiFi adapter is off.")
    return result


# ─────────────────────────────────────────────
#  QR Code Generator
# ─────────────────────────────────────────────

def build_wifi_qr_image(ssid, password, security):
    """
    Returns a PIL Image containing the WiFi QR code.
    Format: WIFI:T:<security>;S:<ssid>;P:<password>;;
    Special characters escaped: \\ ; , " :
    """
    log.debug(f"Building QR — SSID: '{ssid}' | Security: '{security}'")

    def _escape(s):
        for ch in ('\\', ';', ',', '"', ':'):
            s = s.replace(ch, '\\' + ch)
        return s

    if security == 'nopass' or password in ('Open / No Password', 'N/A', ''):
        wifi_string = f"WIFI:T:nopass;S:{_escape(ssid)};P:;;"
        log.debug("  QR type: open network (no password)")
    else:
        wifi_string = f"WIFI:T:{security};S:{_escape(ssid)};P:{_escape(password)};;"
        log.debug(f"  QR string (password hidden): WIFI:T:{security};S:{_escape(ssid)};P:***;;")

    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8, border=3,
    )
    qr.add_data(wifi_string)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    log.debug("  QR image generated successfully")
    return img


# ─────────────────────────────────────────────
#  Main Application
# ─────────────────────────────────────────────

class NetworkInfoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        log.info("Initialising NetworkInfoApp UI")

        try:
            icon_path = resource_path("logo.ico")
            self.iconbitmap(icon_path)
        except Exception as e:
            log.debug(f"Failed to load taskbar icon: {e}")
        
        self.title("Network Information Viewer")
        self.geometry("1250x480")
        self.configure(bg="#2E2E2E")

        self.style = ttk.Style(self)
        self.style.theme_use("clam")
        self.style.configure("Treeview",
                             background="#1E1E1E", foreground="white",
                             fieldbackground="#1E1E1E", rowheight=26)
        self.style.configure("Treeview.Heading",
                             background="#333333", foreground="white",
                             font=("Arial", 10, "bold"))
        self.style.map("Treeview.Heading", background=[("active", "#333333")])
        self.style.map("Treeview",         background=[("selected", "#4A90D9")])
        self.style.configure("TButton",
                             background="#4A4A4A", foreground="white",
                             font=("Arial", 10, "bold"), padding=6)
        self.style.map("TButton", background=[("active", "#5A5A5A")])

        self.all_wifi_passwords = get_all_wifi_passwords_windows()
        # attach a redact filter so plaintext saved passwords are not written to logs
        try:
            self.log_filter = RedactPasswordsFilter(self.all_wifi_passwords)
            log.addFilter(self.log_filter)
        except Exception:
            self.log_filter = None

        self.last_net_io        = psutil.net_io_counters(pernic=True)
        self.create_widgets()
        self.update_speed()
        # start IPC listener so a second instance can signal us to restore
        self._start_ipc_listener()
        
        # try to create a system tray icon (optional)
        try:
            if HAS_PYSTRAY:
                self._create_tray_icon()
        except Exception:
            log.debug("pystray unavailable or tray init failed; continuing without tray")

        log.info("NetworkInfoApp initialised successfully")

    # ── UI Layout ──────────────────────────────

    def create_widgets(self):
        log.debug("Creating UI widgets")

        tk.Label(self, text="Network Information Viewer",
                 bg="#2E2E2E", fg="white",
                 font=("Arial", 16, "bold")).pack(pady=10)

        self.columns = (
            "Interface", "SSID", "IP Address", "Password",
            "MAC Address", "Config Type", "Router IP",
            "Download Speed", "Upload Speed"
        )
        self.PASSWORD_COL_INDEX = self.columns.index("Password")  # = 3

        col_widths = {
            "Interface": 140, "SSID": 160, "IP Address": 120,
            "Password": 160,  "MAC Address": 140, "Config Type": 110,
            "Router IP": 110, "Download Speed": 115, "Upload Speed": 110
        }

        frame = tk.Frame(self, bg="#2E2E2E")
        frame.pack(pady=10, fill=tk.BOTH, expand=True, padx=10)

        scrollbar_y = ttk.Scrollbar(frame, orient=tk.VERTICAL)
        scrollbar_x = ttk.Scrollbar(frame, orient=tk.HORIZONTAL)

        self.tree = ttk.Treeview(frame, columns=self.columns, show="headings",
                                 height=14,
                                 yscrollcommand=scrollbar_y.set,
                                 xscrollcommand=scrollbar_x.set)
        scrollbar_y.config(command=self.tree.yview)
        scrollbar_x.config(command=self.tree.xview)
        scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
        scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)
        self.tree.pack(fill=tk.BOTH, expand=True)

        for col in self.columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor="center", width=col_widths.get(col, 100))

        self.tree.heading("Password", text="Password")
        self.tree.tag_configure("wifi_connected", background="#1A3A1A", foreground="#7FFF7F")
        self.tree.bind("<Double-1>", self._on_main_table_double_click)

        btn_frame = tk.Frame(self, bg="#2E2E2E")
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="🔄  Refresh Info",
                   command=self.refresh_info).pack(side=tk.LEFT, padx=8)
        ttk.Button(btn_frame, text="🔑  Show All Saved WiFi Passwords",
                   command=self.show_all_passwords_window).pack(side=tk.LEFT, padx=8)
        ttk.Button(btn_frame, text="📋  View Logs",
                   command=self.show_log_window).pack(side=tk.LEFT, padx=8)

        self.status_var = tk.StringVar(value="Ready")
        tk.Label(self, textvariable=self.status_var,
                 bg="#1A1A1A", fg="#AAAAAA",
                 font=("Arial", 9), anchor="w").pack(fill=tk.X, side=tk.BOTTOM)

        self.refresh_info()
        # minimize-to-tray behaviour: when user closes window, hide instead
        try:
            self.protocol("WM_DELETE_WINDOW", self._on_close)
        except Exception:
            pass

    def _on_main_table_double_click(self, event):
        # ── Double-click: main table ───────────────
        col_id = self.tree.identify_column(event.x)
        row_id = self.tree.identify_row(event.y)
        if not row_id:
            return

        clicked_col = int(col_id.replace('#', '')) - 1
        log.debug(f"Main table double-click — col_index={clicked_col}, row_id='{row_id}'")

        if clicked_col != self.PASSWORD_COL_INDEX:
            log.debug(f"  Not Password column (expected {self.PASSWORD_COL_INDEX}) — ignoring")
            return

        values   = self.tree.item(row_id, 'values')
        ssid     = values[self.columns.index("SSID")]
        password = values[self.PASSWORD_COL_INDEX]
        log.info(f"QR requested — SSID: '{ssid}'")

        if ssid in ('N/A', '') or password in ('N/A', 'Unable to Retrieve',
                                                'Not in saved profiles', ''):
            log.warning(f"  Cannot generate QR — invalid credentials for '{ssid}'")
            messagebox.showwarning("QR Code",
                f"Cannot generate QR code — no valid credentials for '{ssid}'.")
            return

        security = get_wifi_security_type(ssid)
        self.show_qr_popup(ssid, password, security)

    # ── Router IP ──────────────────────────────

    def simplify_interface_name(self, ipconfig_name):
        name = ipconfig_name.lower()
        if 'wi-fi' in name or 'wireless' in name:
            return "Wi-Fi"
        elif 'ethernet adapter ethernet' in name:
            return "Ethernet"
        elif 'virtualbox host-only network' in name:
            return "VirtualBox Host-Only Network"
        return ipconfig_name.strip()

    def get_router_ip(self):
        log.debug("Retrieving router IP via ipconfig")
        try:
            output = subprocess.check_output(['ipconfig'], text=True, creationflags=NO_WINDOW)
            router_ip_map   = {}
            current_iface   = None
            is_gateway_line = False

            for line in output.splitlines():
                line_lower    = line.lower()
                line_stripped = line.strip()

                if "adapter" in line_lower and ":" in line_lower and not line_stripped.startswith(' '):
                    current_iface   = line_lower.split("adapter")[-1].strip().split(":")[0].strip()
                    is_gateway_line = False

                if "default gateway" in line_lower and current_iface:
                    is_gateway_line = True
                    try:
                        ip_candidate = line[line.index(':') + 1:].strip()
                    except ValueError:
                        ip_candidate = ""
                    if not ip_candidate.startswith('fe80::') and ip_candidate.count('.') == 3:
                        simplified = self.simplify_interface_name(current_iface)
                        router_ip_map[simplified] = ip_candidate
                        log.debug(f"  Router IP for '{simplified}': {ip_candidate}")
                        is_gateway_line = False

                elif is_gateway_line and line_stripped and line_stripped.count('.') == 3:
                    clean_ip = line_stripped.split('%')[0].strip()
                    if clean_ip and clean_ip != "0.0.0.0":
                        simplified = self.simplify_interface_name(current_iface)
                        router_ip_map[simplified] = clean_ip
                        log.debug(f"  Router IP (cont.) for '{simplified}': {clean_ip}")
                        is_gateway_line = False

            log.info(f"Router IP map: {router_ip_map}")
            return router_ip_map

        except Exception as e:
            log.error(f"Error retrieving router IP: {e}", exc_info=True)
            return {}

    # ── Network Info ───────────────────────────

    def get_mac_address(self, interface_name):
        try:
            for addr in psutil.net_if_addrs()[interface_name]:
                if addr.family == psutil.AF_LINK:
                    return addr.address
        except KeyError:
            log.debug(f"  MAC address not found for interface '{interface_name}'")
        return "N/A"

    def get_config_type(self, interface_name):
        try:
            output = subprocess.check_output(['ipconfig', '/all'], text=True, creationflags=NO_WINDOW)
            interface_found = False
            for line in output.splitlines():
                if interface_name in line:
                    interface_found = True
                    continue
                if interface_found and "DHCP Enabled" in line:
                    result = "Dynamic (DHCP)" if "Yes" in line else "Static"
                    log.debug(f"  Config type for '{interface_name}': {result}")
                    return result
        except Exception as e:
            log.error(f"Config type error for '{interface_name}': {e}", exc_info=True)
        return "Unknown"

    def get_ip_info(self):
        log.info("─── get_ip_info() called ───────────────────────────────────────")
        ip_info    = {}
        router_ips = self.get_router_ip()

        self.all_wifi_passwords = get_all_wifi_passwords_windows()
        connected_ssids         = get_all_connected_ssids_windows(saved_profiles=self.all_wifi_passwords)
        # ensure redact filter is up-to-date with any newly loaded passwords
        try:
            if hasattr(self, 'log_filter') and self.log_filter:
                self.log_filter.update_passwords(self.all_wifi_passwords)
        except Exception:
            pass
        psutil_ifaces           = list(psutil.net_if_addrs().keys())

        # ── Diagnostic summary log ─────────────────────────────────────
        log.info(f"Saved WiFi profiles  ({len(self.all_wifi_passwords)}): {list(self.all_wifi_passwords.keys())}")
        log.info(f"Connected SSID map   ({len(connected_ssids)}): {connected_ssids}")
        log.info(f"psutil interfaces    ({len(psutil_ifaces)}): {psutil_ifaces}")

        try:
            for iface_name, addresses in psutil.net_if_addrs().items():
                log.debug(f"Processing interface: '{iface_name}'")

                # ── Router IP ──────────────────────────────────────────
                router_ip = 'N/A'
                if iface_name in router_ips:
                    router_ip = router_ips[iface_name]
                    log.debug(f"  Router IP (exact): {router_ip}")
                else:
                    for simplified, ip in router_ips.items():
                        if simplified.lower() in iface_name.lower() or \
                                iface_name.lower() in simplified.lower():
                            router_ip = ip
                            log.debug(f"  Router IP (fuzzy '{simplified}'): {router_ip}")
                            break

                # ── SSID: exact match first, then case-insensitive fuzzy ──
                ssid        = connected_ssids.get(iface_name)
                match_method = "exact"

                if ssid:
                    log.debug(f"  SSID (exact match on key '{iface_name}'): '{ssid}'")
                else:
                    iface_lower = iface_name.lower().strip()
                    for netsh_iface, netsh_ssid in connected_ssids.items():
                        netsh_lower = netsh_iface.lower().strip()
                        if netsh_lower == iface_lower or \
                                netsh_lower in iface_lower or \
                                iface_lower in netsh_lower:
                            ssid         = netsh_ssid
                            match_method = f"fuzzy ('{netsh_iface}' ↔ '{iface_name}')"
                            break

                    if ssid:
                        log.debug(f"  SSID ({match_method}): '{ssid}'")
                    else:
                        log.debug(f"  No SSID found for '{iface_name}' — "
                                  f"connected_ssids keys: {list(connected_ssids.keys())}")

                # ── Password lookup ────────────────────────────────────
                if ssid and ssid in self.all_wifi_passwords:
                    password = self.all_wifi_passwords[ssid]
                    log.debug(f"  Password found for SSID '{ssid}'")
                elif ssid:
                    password = "Not in saved profiles"
                    log.warning(f"  SSID '{ssid}' is connected but NOT in saved profiles dict. "
                                f"Saved keys: {list(self.all_wifi_passwords.keys())}")
                else:
                    ssid     = "N/A"
                    password = "N/A"

                # ── Store IPv4 entries only ────────────────────────────
                for addr in addresses:
                    if addr.family == socket.AF_INET:
                        log.debug(f"  Storing IPv4 {addr.address} — SSID='{ssid}'")
                        ip_info[iface_name] = {
                            'SSID':        ssid,
                            'IP Address':  addr.address,
                            'Password':    password,
                            'MAC Address': self.get_mac_address(iface_name),
                            'Config Type': self.get_config_type(iface_name),
                            'Router IP':   router_ip,
                            'is_wifi':     ssid != "N/A"
                        }

        except Exception as e:
            log.error(f"Critical error in get_ip_info: {e}", exc_info=True)
            messagebox.showerror("Error",
                "Failed to retrieve network information.\n"
                "Check network_info.log for details.")

        wifi_ifaces = [k for k, v in ip_info.items() if v.get('is_wifi')]
        log.info(f"get_ip_info complete — {len(ip_info)} interface(s) | WiFi: {wifi_ifaces}")
        return ip_info

    # ── Table Population ───────────────────────

    def refresh_info(self):
        log.info("refresh_info() triggered")
        self.status_var.set("Refreshing network information...")
        self.update_idletasks()

        self.ip_info = self.get_ip_info()

        for row in self.tree.get_children():
            self.tree.delete(row)

        for iface, info in self.ip_info.items():
            tag = ("wifi_connected",) if info.get('is_wifi') else ()
            self.tree.insert("", "end", iid=iface, tags=tag, values=(
                iface,
                info.get('SSID',        'N/A'),
                info.get('IP Address',  'N/A'),
                info.get('Password',    'N/A'),
                info.get('MAC Address', 'N/A'),
                info.get('Config Type', 'N/A'),
                info.get('Router IP',   'N/A'),
                'Calculating...',
                'Calculating...'
            ))

        count      = len(self.ip_info)
        wifi_count = sum(1 for v in self.ip_info.values() if v.get('is_wifi'))
        self.status_var.set(
            f"Found {count} interface(s) — {wifi_count} WiFi connected  |  "
            f"{len(self.all_wifi_passwords)} saved WiFi profile(s)  |  "
            f"💡 Double-click Password cell to generate WiFi QR code"
        )
        log.info(f"Table refreshed — {count} interface(s), {wifi_count} WiFi connected")

    # ── Speed ──────────────────────────────────

    def format_bytes(self, bytes_count):
        if not bytes_count:
            return "0 B/s"
        units = ["B/s", "KB/s", "MB/s", "GB/s", "TB/s"]
        i = 0
        while bytes_count >= 1024 and i < len(units) - 1:
            bytes_count /= 1024
            i += 1
        return f"{bytes_count:.2f} {units[i]}"

    def calculate_speed(self):
        current_net_io = psutil.net_io_counters(pernic=True)
        speeds = {}
        for iface, current in current_net_io.items():
            if iface in self.last_net_io:
                last = self.last_net_io[iface]
                speeds[iface] = {
                    "Download Speed": self.format_bytes(current.bytes_recv - last.bytes_recv),
                    "Upload Speed":   self.format_bytes(current.bytes_sent - last.bytes_sent)
                }
        self.last_net_io = current_net_io
        return speeds

    def update_speed(self):
        speeds = self.calculate_speed()
        for iface in self.tree.get_children():
            if iface in speeds:
                vals = list(self.tree.item(iface, 'values'))
                if len(vals) >= 9:
                    vals[7] = speeds[iface]["Download Speed"]
                    vals[8] = speeds[iface]["Upload Speed"]
                    self.tree.item(iface, values=tuple(vals))
        self.after(1000, self.update_speed)

    # ── Tray / minimize helpers ─────────────────────────
    def _create_tray_icon(self):
        if not HAS_PYSTRAY:
            return

        # --- NEW CODE: Load your actual icon file ---
        import os
        # icon_path = "logo.ico" # Change this to your icon's file name
        icon_path = resource_path("logo.ico")
        
        if os.path.exists(icon_path):
            img = Image.open(icon_path)
        else:
            # Fallback placeholder if your icon file is missing
            img = Image.new('RGB', (64, 64), color=(30, 30, 30))
            draw = ImageDraw.Draw(img)
            draw.ellipse((8, 8, 56, 56), outline=(80, 160, 240), width=4)
            draw.line((16, 40, 48, 40), fill=(80,160,240), width=3)
        # --------------------------------------------

        def on_show(icon, item):
            self.after(0, self._show_from_tray)

        def on_exit(icon, item):
            self.after(0, self._destroy_and_exit)

        menu = pystray.Menu(pystray.MenuItem('Show', on_show), pystray.MenuItem('Exit', on_exit))
        self._tray_icon = pystray.Icon('NetInfoApp', img, 'Network Information Viewer', menu)

        def run_icon():
            try:
                self._tray_icon.run()
            except Exception as e:
                log.debug(f"Tray icon run failed: {e}")

        self._tray_thread = threading.Thread(target=run_icon, daemon=True)
        self._tray_thread.start()

    def _on_close(self):
        # minimize to tray when available, otherwise exit
        if HAS_PYSTRAY and hasattr(self, '_tray_icon'):
            try:
                self._hide_to_tray()
                messagebox.showinfo('Minimized', 'Application minimized to tray. Use the tray icon to restore or exit.')
                return
            except Exception:
                pass
        # fallback: destroy
        try:
            self._destroy_and_exit()
        except Exception:
            try:
                self.destroy()
            except Exception:
                pass

    def _hide_to_tray(self):
        try:
            self.withdraw()
            self.status_var.set('Minimized to tray')
        except Exception:
            pass

    def _show_from_tray(self):
        try:
            self.deiconify()
            self.lift()
            self.status_var.set('Restored')
        except Exception:
            pass
    
    # ── IPC Listener (single-instance: receive SHOW signal) ────────────────
    def _start_ipc_listener(self):
        """Listens on localhost for a 'SHOW' signal from a second instance."""
        import socket as _s
        def _listen():
            try:
                srv = _s.socket(_s.AF_INET, _s.SOCK_STREAM)
                srv.setsockopt(_s.SOL_SOCKET, _s.SO_REUSEADDR, 1)
                srv.bind(('127.0.0.1', IPC_PORT))
                srv.listen(5)
                srv.settimeout(1.0)
                log.debug(f"IPC listener started on port {IPC_PORT}")
                while True:
                    try:
                        conn, _ = srv.accept()
                        data    = conn.recv(16)
                        conn.close()
                        if data == b'SHOW':
                            log.info("IPC: SHOW signal received — restoring window.")
                            self.after(0, self._show_from_tray)
                    except _s.timeout:
                        continue
                    except Exception:
                        break
            except Exception as e:
                log.debug(f"IPC listener failed to start: {e}")
        threading.Thread(target=_listen, daemon=True).start()
    
    def _destroy_and_exit(self):
        try:
            if hasattr(self, '_tray_icon'):
                try:
                    self._tray_icon.stop()
                except Exception:
                    pass
            self.destroy()
        except Exception:
            try:
                self.quit()
            except Exception:
                pass

    # ── QR Code Popup ──────────────────────────

    def show_qr_popup(self, ssid, password, security):
        log.info(f"Opening QR popup — SSID: '{ssid}' | Security: '{security}'")
        win = tk.Toplevel(self)
        win.title(f"WiFi QR Code — {ssid}")
        win.configure(bg="#2E2E2E")
        win.resizable(False, False)
        win.grab_set()

        tk.Label(win, text="📶  Scan to Connect",
                 bg="#2E2E2E", fg="white",
                 font=("Arial", 14, "bold")).pack(pady=(14, 2))
        tk.Label(win, text=f"Network:  {ssid}",
                 bg="#2E2E2E", fg="#AAFFAA",
                 font=("Arial", 10)).pack()

        sec_label = {
            'WPA2':   'WPA2 / WPA3',
            'WPA':    'WPA',
            'WEP':    'WEP',
            'nopass': 'Open (no password)',
        }.get(security, security)

        tk.Label(win, text=f"Security: {sec_label}",
                 bg="#2E2E2E", fg="#AAAAFF",
                 font=("Arial", 10)).pack(pady=(0, 8))

        try:
            pil_img = build_wifi_qr_image(ssid, password, security)
            pil_img = pil_img.resize((280, 280), Image.LANCZOS)
            tk_img  = ImageTk.PhotoImage(pil_img)

            qr_frame = tk.Frame(win, bg="white", padx=6, pady=6)
            qr_frame.pack(padx=20, pady=4)

            lbl = tk.Label(qr_frame, image=tk_img, bg="white")
            lbl.image = tk_img
            lbl.pack()
            log.debug("QR image rendered in popup successfully")
            
            # Actions: copy SSID/password and save QR image
            action_frame = tk.Frame(win, bg="#2E2E2E")
            action_frame.pack(pady=(8, 10))

            def copy_to_clipboard(text):
                try:
                    win.clipboard_clear()
                    win.clipboard_append(text)
                    self.status_var.set("Copied to clipboard")
                except Exception as e:
                    messagebox.showerror("Copy Failed", f"Failed to copy to clipboard:\n{e}", parent=win)

            def save_qr_png():
                try:
                    from tkinter import filedialog
                    path = filedialog.asksaveasfilename(parent=win, defaultextension='.png',
                                                        filetypes=[('PNG Image','*.png')],
                                                        title='Save QR as PNG')
                    if path:
                        pil_img.save(path)
                        messagebox.showinfo("Saved", f"QR saved to {path}", parent=win)
                except Exception as e:
                    messagebox.showerror("Save Failed", f"Failed to save QR:\n{e}", parent=win)

            tk.Button(action_frame, text="Copy SSID", command=lambda: copy_to_clipboard(ssid)).pack(side=tk.LEFT, padx=6)
            tk.Button(action_frame, text="Copy Password", command=lambda: copy_to_clipboard(password)).pack(side=tk.LEFT, padx=6)
            tk.Button(action_frame, text="Save QR as PNG", command=save_qr_png).pack(side=tk.LEFT, padx=6)

        except Exception as e:
            tk.Label(win, text=f"QR generation failed:\n{e}",
                     bg="#2E2E2E", fg="red",
                     font=("Arial", 10)).pack(padx=20, pady=20)
            log.error(f"QR generation error for '{ssid}': {e}", exc_info=True)

        tk.Label(win,
                 text="Point your phone camera at the QR code to connect",
                 bg="#2E2E2E", fg="#888888",
                 font=("Arial", 9)).pack(pady=(6, 2))
        ttk.Button(win, text="✖  Close", command=win.destroy).pack(pady=12)

    # ── All Passwords Popup ────────────────────

    def show_all_passwords_window(self):
        log.info("Opening All Saved WiFi Passwords window")
        win = tk.Toplevel(self)
        win.title("All Saved WiFi Passwords")
        win.geometry("640x480")
        win.configure(bg="#2E2E2E")
        win.grab_set()

        tk.Label(win, text="All Saved WiFi Passwords",
                 bg="#2E2E2E", fg="white",
                 font=("Arial", 14, "bold")).pack(pady=10)
        tk.Label(win,
                 text="🟢 Green = currently connected   |   💡 Double-click Password to get QR",
                 bg="#2E2E2E", fg="#7FFF7F",
                 font=("Arial", 9)).pack()

        tframe = tk.Frame(win, bg="#2E2E2E")
        tframe.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)

        sb_y = ttk.Scrollbar(tframe, orient=tk.VERTICAL)
        sb_x = ttk.Scrollbar(tframe, orient=tk.HORIZONTAL)

        POPUP_COLS    = ("#", "SSID", "Password", "Status")
        POPUP_PWD_IDX = 2

        popup_tree = ttk.Treeview(
            tframe, columns=POPUP_COLS, show="headings", height=16,
            yscrollcommand=sb_y.set, xscrollcommand=sb_x.set
        )
        sb_y.config(command=popup_tree.yview)
        sb_x.config(command=popup_tree.xview)
        sb_y.pack(side=tk.RIGHT, fill=tk.Y)
        sb_x.pack(side=tk.BOTTOM, fill=tk.X)
        popup_tree.pack(fill=tk.BOTH, expand=True)

        for col, w in [("#", 40), ("SSID", 200), ("Password", 220), ("Status", 120)]:
            popup_tree.heading(col, text=col)
            popup_tree.column(col, width=w,
                              anchor="center" if col in ("#", "Status") else "w")

        popup_tree.tag_configure("connected", background="#1A3A1A", foreground="#7FFF7F")
        popup_tree.tag_configure("saved",     background="#1E1E1E", foreground="white")

        connected_ssids = set(get_all_connected_ssids_windows().values())
        log.debug(f"All-passwords popup — connected SSIDs: {connected_ssids}")

        def populate(passwords_dict):
            for row in popup_tree.get_children():
                popup_tree.delete(row)
            for idx, (ssid, pwd) in enumerate(sorted(passwords_dict.items()), 1):
                tag    = "connected" if ssid in connected_ssids else "saved"
                status = "✔ Connected" if tag == "connected" else "Saved"
                popup_tree.insert("", "end", iid=str(idx), tags=(tag,),
                                  values=(idx, ssid, pwd, status))

        populate(self.all_wifi_passwords)

        def _on_popup_double_click(event):
            col_id = popup_tree.identify_column(event.x)
            row_id = popup_tree.identify_row(event.y)
            if not row_id:
                return
            clicked_col = int(col_id.replace('#', '')) - 1
            log.debug(f"Popup double-click — col_index={clicked_col}, row_id='{row_id}'")
            if clicked_col != POPUP_PWD_IDX:
                return

            values   = popup_tree.item(row_id, 'values')
            ssid     = values[1]
            password = values[2]
            log.info(f"Popup QR requested — SSID: '{ssid}'")

            if password in ('N/A', 'Unable to Retrieve', 'Not in saved profiles',
                            'Open / No Password', ''):
                log.warning(f"  Cannot generate QR — invalid password for '{ssid}'")
                messagebox.showwarning("QR Code",
                    f"Cannot generate QR code — no valid password for '{ssid}'.",
                    parent=win)
                return

            security = get_wifi_security_type(ssid)
            self.show_qr_popup(ssid, password, security)

        popup_tree.bind("<Double-1>", _on_popup_double_click)

        btn_frame = tk.Frame(win, bg="#2E2E2E")
        btn_frame.pack(pady=8)

        def refresh_popup():
            log.info("Popup refresh triggered")
            fresh = get_all_wifi_passwords_windows()
            self.all_wifi_passwords = fresh
            try:
                if hasattr(self, 'log_filter') and self.log_filter:
                    self.log_filter.update_passwords(fresh)
            except Exception:
                pass
            populate(fresh)
            status_lbl.config(text=f"{len(fresh)} saved profile(s) found")

        def export_csv():
            try:
                from tkinter import filedialog
                path = filedialog.asksaveasfilename(parent=win, defaultextension='.csv',
                                                    filetypes=[('CSV','*.csv')],
                                                    title='Export Wi-Fi profiles as CSV')
                if not path:
                    return
                import csv
                with open(path, 'w', newline='', encoding='utf-8') as csvf:
                    writer = csv.writer(csvf)
                    writer.writerow(['SSID', 'Password', 'Status'])
                    for idx, (ssid, pwd) in enumerate(sorted(self.all_wifi_passwords.items()), 1):
                        status = 'Connected' if ssid in connected_ssids else 'Saved'
                        writer.writerow([ssid, pwd, status])
                messagebox.showinfo('Exported', f'Exported {len(self.all_wifi_passwords)} profiles to {path}', parent=win)
            except Exception as e:
                log.error(f"CSV export failed: {e}", exc_info=True)
                messagebox.showerror('Export Failed', f'Could not export CSV:\n{e}', parent=win)

        ttk.Button(btn_frame, text="🔄  Refresh", command=refresh_popup).pack(side=tk.LEFT, padx=8)
        ttk.Button(btn_frame, text="📤  Export CSV", command=export_csv).pack(side=tk.LEFT, padx=8)
        ttk.Button(btn_frame, text="✖  Close",   command=win.destroy).pack(side=tk.LEFT, padx=8)

        status_lbl = tk.Label(win,
                              text=f"{len(self.all_wifi_passwords)} saved profile(s) found",
                              bg="#1A1A1A", fg="#AAAAAA", font=("Arial", 9))
        status_lbl.pack(fill=tk.X, side=tk.BOTTOM)

    # ── Log Viewer Popup ───────────────────────

    def show_log_window(self):
        """Scrollable, colour-coded window showing the live log file."""
        log.info("Opening log viewer window")
        win = tk.Toplevel(self)
        win.title("Diagnostic Logs — network_info.log")
        win.geometry("900x550")
        win.configure(bg="#1A1A1A")

        tk.Label(win, text="📋  Diagnostic Logs",
                 bg="#1A1A1A", fg="white",
                 font=("Arial", 13, "bold")).pack(pady=(10, 4))
        tk.Label(win, text=os.path.abspath(LOG_FILE),
                 bg="#1A1A1A", fg="#888888",
                 font=("Arial", 9)).pack()

        txt_frame = tk.Frame(win, bg="#1A1A1A")
        txt_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)

        sb = ttk.Scrollbar(txt_frame)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        txt = tk.Text(txt_frame, bg="#0D0D0D", fg="#CCCCCC",
                      font=("Courier New", 8),
                      yscrollcommand=sb.set, wrap=tk.NONE, state=tk.DISABLED)
        txt.pack(fill=tk.BOTH, expand=True)
        sb.config(command=txt.yview)

        txt.tag_configure("DEBUG",    foreground="#555577")
        txt.tag_configure("INFO",     foreground="#AAAAAA")
        txt.tag_configure("WARNING",  foreground="#FFCC44")
        txt.tag_configure("ERROR",    foreground="#FF5555")
        txt.tag_configure("CRITICAL", foreground="#FF0000")

        def load_logs():
            txt.config(state=tk.NORMAL)
            txt.delete("1.0", tk.END)
            try:
                with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        level = "INFO"
                        for lvl in ("DEBUG", "WARNING", "ERROR", "CRITICAL", "INFO"):
                            if f"| {lvl}" in line:
                                level = lvl
                                break
                        txt.insert(tk.END, line, level)
            except FileNotFoundError:
                txt.insert(tk.END,
                    "Log file not found yet — click Refresh Info first.\n", "WARNING")
            txt.see(tk.END)
            txt.config(state=tk.DISABLED)

        load_logs()

        btn_frame = tk.Frame(win, bg="#1A1A1A")
        btn_frame.pack(pady=6)
        ttk.Button(btn_frame, text="🔄  Refresh Logs", command=load_logs).pack(side=tk.LEFT, padx=8)
        ttk.Button(btn_frame, text="✖  Close",         command=win.destroy).pack(side=tk.LEFT, padx=8)


# ─────────────────────────────────────────────

if __name__ == "__main__":
    _mutex_handle = enforce_single_instance()   # must stay in scope — keeps mutex alive
    try:
        app = NetworkInfoApp()
        app.mainloop()
    except Exception as e:
        log.critical(f"Unhandled top-level exception: {e}", exc_info=True)
        raise
