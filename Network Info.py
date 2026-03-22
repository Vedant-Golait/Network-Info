# =========================
# Standard Library Imports
# =========================
import ctypes, io, json, logging, os, platform, queue, re, socket, subprocess, sys, threading, time
from datetime import datetime
from logging import handlers

# =========================
# Third-Party Imports
# =========================
import psutil

# =========================
# GUI Imports (Tkinter)
# =========================
import tkinter as tk
from tkinter import ttk, messagebox


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
#  Settings Management
# ─────────────────────────────────────────────

def get_base_dir():
    """Returns the directory where the script or .exe is located."""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

def get_settings_path():
    return os.path.join(get_base_dir(), "settings.json")

# These are the default values if the user hasn't changed anything yet
DEFAULT_SETTINGS = {
    "enable_tray": True,
    "autostart": False,
    "log_directory": "",
    "refresh_interval": 5000,
    "theme": "dark",
    "notifications": True  
}

def load_settings():
    """Loads settings from settings.json, merging with defaults."""
    path = get_settings_path()
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                user_settings = json.load(f)
                merged = DEFAULT_SETTINGS.copy()
                merged.update(user_settings)
                return merged
        except Exception:
            pass # Fallback to defaults if file is corrupted
    return DEFAULT_SETTINGS.copy()

def save_settings(settings_dict):
    """Saves the current settings dictionary to settings.json."""
    path = get_settings_path()
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(settings_dict, f, indent=4)
    except Exception as e:
        print(f"Failed to save settings: {e}")

# Load settings globally so the whole app can access them
APP_SETTINGS = load_settings()

# ─────────────────────────────────────────────
#  Single Instance Enforcement
# ─────────────────────────────────────────────

SINGLE_INSTANCE_MUTEX = "Global\\NetworkInfoApp_SingleInstance"
IPC_PORT = 49152

def enforce_single_instance():
    """
    Bulletproof single-instance check using thread-safe error handling.
    """
    if platform.system() != "Windows":
        return None

    # We use WinDLL with use_last_error=True to capture codes reliably
    # This prevents the Python interpreter from resetting the error status.
    k32 = ctypes.WinDLL('kernel32', use_last_error=True)
    
    # 1. Attempt to create the mutex
    mutex = k32.CreateMutexW(None, False, SINGLE_INSTANCE_MUTEX)
    last_err = ctypes.get_last_error()

    # 183 = ERROR_ALREADY_EXISTS
    # 5   = ERROR_ACCESS_DENIED (Happens if Instance 1 is Admin and Instance 2 is User)
    if last_err in (183, 5):
        log.info(f"Duplicate instance detected (Error Code: {last_err}). Signaling primary instance.")
        try:
            import socket as _s
            sock = _s.socket(_s.AF_INET, _s.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect(('127.0.0.1', IPC_PORT))
            sock.sendall(b'SHOW')
            sock.close()
        except Exception as e:
            log.debug(f"IPC signal failed: {e}")
        
        # Exit this second instance immediately
        sys.exit(0)

    log.info("Single-instance mutex acquired — this is the primary instance.")
    return mutex


# ─────────────────────────────────────────────
#  Logging Setup
# ─────────────────────────────────────────────

NO_WINDOW = 0x08000000
if getattr(sys, 'frozen', False):
    # If compiled with PyInstaller, use the .exe's directory
    BASE_DIR = os.path.dirname(sys.executable)
else:
    # If running as a standard Python script, use the script's directory
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def get_log_file_path():
    """Determines where the log file should be saved based on settings."""
    custom_dir = APP_SETTINGS.get("log_directory", "")
    # If a custom directory exists, use it. Otherwise, use the base app folder.
    if custom_dir and os.path.isdir(custom_dir):
        return os.path.join(custom_dir, "network_info.log")
    return os.path.join(get_base_dir(), "network_info.log")

LOG_FILE = get_log_file_path()

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
#  Admin Privilege Check
# ─────────────────────────────────────────────

def is_admin():
    """Checks if the script is currently running with Administrator privileges."""
    if platform.system() != "Windows":
        return True
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

# ─────────────────────────────────────────────
#  Main Application
# ─────────────────────────────────────────────

class NetworkInfoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.ui_queue = queue.Queue()
        self._process_ui_queue()
        self.after(5000, self._auto_refresh_loop) # Start the background engine
        # Start the live ping monitor in a background thread
        threading.Thread(target=self._ping_background_loop, daemon=True).start()
        log.info("Initialising NetworkInfoApp UI")

        try:
            icon_path = resource_path("logo.ico")
            self.iconbitmap(icon_path)
        except Exception as e:
            log.debug(f"Failed to load taskbar icon: {e}")
        
        self.title("Network Information Viewer")
        self.geometry("1250x550")
        self.configure(bg="#2E2E2E")
        self.protocol("WM_DELETE_WINDOW", self._on_close)

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
        try:
            self.log_filter = RedactPasswordsFilter(self.all_wifi_passwords)
            log.addFilter(self.log_filter)
        except Exception:
            self.log_filter = None

        self.last_net_io = psutil.net_io_counters(pernic=True)
        self.ip_info = {}
        
        # Base container for swapping views
        self.main_container = tk.Frame(self, bg="#2E2E2E")
        self.main_container.pack(fill=tk.BOTH, expand=True)

        # Status Bar Frame (Holds left info and right latency)
        status_frame = tk.Frame(self, bg="#1A1A1A")
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)

        self.status_var = tk.StringVar(value="Ready")
        tk.Label(status_frame, textvariable=self.status_var,
                 bg="#1A1A1A", fg="#AAAAAA",
                 font=("Arial", 9), anchor="w").pack(side=tk.LEFT, padx=5, pady=2)

        self.latency_var = tk.StringVar(value="🌐 Latency: Calculating...")
        tk.Label(status_frame, textvariable=self.latency_var,
                 bg="#1A1A1A", fg="#7FFF7F",
                 font=("Arial", 9, "bold"), anchor="e").pack(side=tk.RIGHT, padx=15, pady=2)

        self.show_dashboard()
        self.update_speed()
        self._start_ipc_listener()
        
        if not is_admin():
            self.after(500, self._prompt_admin_elevation)
        
        try:
            # Check the settings before building the tray icon!
            if HAS_PYSTRAY and APP_SETTINGS.get("enable_tray", True):
                self._create_tray_icon()
        except Exception:
            log.debug("pystray unavailable or tray init failed")

        log.info("NetworkInfoApp initialised successfully")
        
    def _process_ui_queue(self):
        """Safely processes UI updates from background threads."""
        try:
            while True:
                task = self.ui_queue.get_nowait()
                task()
        except queue.Empty:
            pass
        self.after(100, self._process_ui_queue)

    # ── Quick Network State Check ──────────────────────────────────────────
    def _get_quick_network_state(self):
        """Instantly reads the kernel for active interfaces and IPs. Super lightweight."""
        state = {}
        try:
            # Get up/down status
            stats = psutil.net_if_stats()
            # Get actual IP addresses
            addrs = psutil.net_if_addrs()
            
            for iface, stat in stats.items():
                if stat.isup: # Only care about interfaces that are turned on
                    ips = [a.address for a in addrs.get(iface, []) if a.family == socket.AF_INET]
                    if ips:
                        state[iface] = ips
        except Exception as e:
            log.debug(f"Quick state check failed: {e}")
        return str(state) # Return as a string so it's easy to compare!
    
    # ── Auto Refresh Loop ──────────────────────────────────────────
    def _auto_refresh_loop(self):
        """Smart Auto-Refresh: Only does a heavy refresh if the lightweight scout detects a change."""
        interval_sec = APP_SETTINGS.get("refresh_interval", 0)
        
        if interval_sec > 0:
            # 1. Send the scout to get the current fast state
            current_state = self._get_quick_network_state()
            
            # 2. Check if we have a previous state to compare to
            if not hasattr(self, 'last_quick_state'):
                self.last_quick_state = current_state
                
            # 3. Compare! Did the IP addresses or active adapters change?
            if current_state != self.last_quick_state:
                log.info("Scout detected a network change! Triggering heavy refresh.")
                self.refresh_info(fetch_data=True)
                self.last_quick_state = current_state # Update memory
            else:
                # Network is identical. Skip the heavy lifting!
                pass 
                
            self.after(interval_sec * 1000, self._auto_refresh_loop)
        else:
            self.after(2000, self._auto_refresh_loop)
    
    def _ping_background_loop(self):
        """Silently pings Google DNS. Triggers a scout check if internet drops OR reconnects."""
        was_offline = False # Track our previous state
        
        while True:
            is_offline = False
            try:
                output_bytes = subprocess.check_output(
                    ['ping', '-n', '1', '-w', '2000', '8.8.8.8'], 
                    creationflags=NO_WINDOW
                )
                output = output_bytes.decode('utf-8', errors='ignore').lower()
                
                # robust regex to catch "time=15ms" or "time<1ms"
                match = re.search(r'time[=<]\s*(\d+ms)', output)
                if match:
                    latency = match.group(1)
                    self.ui_queue.put(lambda l=latency: self.latency_var.set(f"🌐 Latency: {l}"))
                else:
                    self.ui_queue.put(lambda: self.latency_var.set("🌐 Latency: Offline (No Internet)"))
                    is_offline = True
                    
            except subprocess.CalledProcessError:
                self.ui_queue.put(lambda: self.latency_var.set("🌐 Latency: Offline (Request Timed Out)"))
                is_offline = True
            except Exception as e:
                log.debug(f"Ping failed: {e}")
                is_offline = True
                
            # --- The Smart Integration ---
            if is_offline != was_offline:
                log.info(f"Ping state changed (Offline: {is_offline}). Forcing quick network check.")
                self.ui_queue.put(self._force_smart_check)
                was_offline = is_offline
                
            time.sleep(2)

    
    
    def _force_smart_check(self):
        """Called by the ping monitor when things go wrong to instantly check for changes."""
        current_state = self._get_quick_network_state()
        if getattr(self, 'last_quick_state', None) != current_state:
            log.info("Ping failure confirmed network change. Triggering heavy refresh.")
            self.refresh_info(fetch_data=True)
            self.last_quick_state = current_state
    
    # ── View Manager ──────────────────────────────────────

    def clear_container(self, container):
        for widget in container.winfo_children():
            widget.destroy()

    def show_dashboard(self):
        log.debug("Loading Dashboard View")
        self.clear_container(self.main_container)

        tk.Label(self.main_container, text="Network Information Viewer",
                 bg="#2E2E2E", fg="white",
                 font=("Arial", 16, "bold")).pack(pady=10)

        self.columns = (
            "Interface", "SSID", "IP Address", "Password",
            "MAC Address", "Config Type", "Router IP",
            "Download Speed", "Upload Speed"
        )
        self.PASSWORD_COL_INDEX = self.columns.index("Password")

        col_widths = {
            "Interface": 140, "SSID": 160, "IP Address": 120,
            "Password": 160,  "MAC Address": 140, "Config Type": 170, 
            "Router IP": 110, "Download Speed": 115, "Upload Speed": 110
        }

        frame = tk.Frame(self.main_container, bg="#2E2E2E")
        frame.pack(pady=10, fill=tk.BOTH, expand=True, padx=10)

        scrollbar_y = ttk.Scrollbar(frame, orient=tk.VERTICAL)
        scrollbar_x = ttk.Scrollbar(frame, orient=tk.HORIZONTAL)

        self.tree = ttk.Treeview(frame, columns=self.columns, show="headings",
                                 height=14, yscrollcommand=scrollbar_y.set,
                                 xscrollcommand=scrollbar_x.set)
        scrollbar_y.config(command=self.tree.yview)
        scrollbar_x.config(command=self.tree.xview)
        scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
        scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)
        self.tree.pack(fill=tk.BOTH, expand=True)

        for col in self.columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor="center", width=col_widths.get(col, 100))

        self.tree.tag_configure("wifi_connected", background="#1A3A1A", foreground="#7FFF7F")
        self.tree.bind("<Double-1>", self._on_main_table_double_click)

        btn_frame = tk.Frame(self.main_container, bg="#2E2E2E")
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="🔄  Refresh Info", command=self.refresh_info).pack(side=tk.LEFT, padx=8)
        ttk.Button(btn_frame, text="⚙️  Advanced", command=self.show_advanced).pack(side=tk.LEFT, padx=8)

        # If we already have network data, just draw the table (fetch_data=False).
        # If it's empty (1st startup), do a full scan (fetch_data=True).
        if not self.ip_info:
            self.refresh_info(fetch_data=True)
        else:
            self.refresh_info(fetch_data=False)

    def show_advanced(self):
        log.debug("Loading Advanced View")
        self.clear_container(self.main_container)

        # Top Bar
        top_bar = tk.Frame(self.main_container, bg="#1E1E1E", height=45)
        top_bar.pack(side=tk.TOP, fill=tk.X)
        top_bar.pack_propagate(False)
        ttk.Button(top_bar, text="⬅  Back to Dashboard", command=self.show_dashboard).pack(side=tk.LEFT, padx=10, pady=8)

        # Split Layout
        sidebar = tk.Frame(self.main_container, bg="#1A1A1A", width=200)
        sidebar.pack(side=tk.LEFT, fill=tk.Y)
        sidebar.pack_propagate(False)
        
        self.adv_content = tk.Frame(self.main_container, bg="#2E2E2E")
        self.adv_content.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Sidebar Menu
        tk.Label(sidebar, text="Advanced Options", bg="#1A1A1A", fg="#888888", font=("Arial", 10, "bold")).pack(pady=(15, 5))
        
        ttk.Button(sidebar, text="ℹ️  About", command=lambda: self.load_adv_pane(self.adv_about)).pack(fill=tk.X, padx=10, pady=5)
        ttk.Button(sidebar, text="🔑  Show Password", command=lambda: self.load_adv_pane(self.adv_passwords)).pack(fill=tk.X, padx=10, pady=5)
        ttk.Button(sidebar, text="🌐  Network Profiler", command=lambda: self.load_adv_pane(self.adv_profiler)).pack(fill=tk.X, padx=10, pady=5)
        ttk.Button(sidebar, text="📋  View Logs", command=lambda: self.load_adv_pane(self.adv_logs)).pack(fill=tk.X, padx=10, pady=5)

        # Load default
        self.load_adv_pane(self.adv_about)

    def load_adv_pane(self, pane_func):
        self.clear_container(self.adv_content)
        pane_func()

    # ── Advanced Sub-Views ────────────────────────────────

    def adv_about(self):
        # ─── TOP SECTION: Network Info (Existing behavior) ─────────────────
        info_frame = tk.Frame(self.adv_content, bg="#2E2E2E")
        info_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=20, pady=(20, 0))

        tk.Label(info_frame, text="About Connected Networks", bg="#2E2E2E", fg="white", font=("Arial", 14, "bold")).pack(anchor="w", pady=(0, 10))
        
        active_networks = {
            iface: data for iface, data in self.ip_info.items() 
            if data.get('Router IP') != 'N/A' or data.get('is_wifi')
        }

        if not active_networks:
            tk.Label(info_frame, text="No active connections found. Go to Dashboard and refresh.", bg="#2E2E2E", fg="#AAAAAA").pack(anchor="w")
        else:
            # We add height=10 so it doesn't push the settings off the bottom of the screen
            text_widget = tk.Text(info_frame, bg="#1E1E1E", fg="#7FFF7F", font=("Consolas", 10), state=tk.NORMAL, wrap=tk.WORD, height=10)
            text_widget.pack(fill=tk.BOTH, expand=True)

            about_text = ""
            for iface, data in active_networks.items():
                about_text += f"Interface: {iface}\n"
                about_text += f"  ├─ IP Address:  {data.get('IP Address')}\n"
                about_text += f"  ├─ MAC Address: {data.get('MAC Address')}\n"
                about_text += f"  ├─ Router IP:   {data.get('Router IP')}\n"
                about_text += f"  ├─ Config Type: {data.get('Config Type')}\n"
                if data.get('is_wifi'):
                    about_text += f"  ├─ SSID:        {data.get('SSID')}\n"
                    pwd = data.get('Password')
                    pwd_display = pwd if pwd != 'Not in saved profiles' else '<Requires manual retrieval>'
                    about_text += f"  └─ Password:    {pwd_display}\n"
                about_text += "\n"

            text_widget.insert(tk.END, about_text)
            text_widget.config(state=tk.DISABLED)

        # ─── BOTTOM SECTION: Settings ──────────────────────────────────────
        settings_frame = tk.Frame(self.adv_content, bg="#2E2E2E")
        settings_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=(10, 20))

        tk.Label(settings_frame, text="Settings", bg="#2E2E2E", fg="white", font=("Arial", 14, "bold")).pack(anchor="w", pady=(0, 10))

        # --- Custom Log Directory ---
        log_frame = tk.Frame(settings_frame, bg="#2E2E2E")
        log_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(log_frame, text="Custom Log Directory:", bg="#2E2E2E", fg="#AAAAAA", font=("Arial", 10)).pack(side=tk.LEFT)
        
        current_log_dir = APP_SETTINGS.get("log_directory") or get_base_dir()
        log_dir_var = tk.StringVar(value=current_log_dir)
        
        tk.Entry(log_frame, textvariable=log_dir_var, state="readonly", width=50, bg="#1E1E1E", fg="white").pack(side=tk.LEFT, padx=10)

        def browse_log_dir():
            from tkinter import filedialog
            new_dir = filedialog.askdirectory(title="Select Log Directory", initialdir=current_log_dir)
            if new_dir:
                log_dir_var.set(new_dir)
                APP_SETTINGS["log_directory"] = new_dir
                save_settings(APP_SETTINGS) # Saves to settings.json instantly
                messagebox.showinfo("Settings Saved", "Log directory updated.\n\nRestart the application for changes to take effect.")

        ttk.Button(log_frame, text="Browse...", command=browse_log_dir).pack(side=tk.LEFT)
        
        # --- System Tray Toggle ---
        tray_frame = tk.Frame(settings_frame, bg="#2E2E2E")
        tray_frame.pack(fill=tk.X, pady=(10, 5))
        
        tray_var = tk.BooleanVar(value=APP_SETTINGS.get("enable_tray", True))
        
        def toggle_tray():
            new_val = tray_var.get()
            APP_SETTINGS["enable_tray"] = new_val
            save_settings(APP_SETTINGS) # Saves to settings.json instantly
            
            # Apply the change immediately without needing a restart!
            if new_val:
                if HAS_PYSTRAY and not hasattr(self, '_tray_icon'):
                    self._create_tray_icon()
            else:
                if hasattr(self, '_tray_icon'):
                    try:
                        self._tray_icon.stop()
                        del self._tray_icon
                    except Exception as e:
                        log.error(f"Failed to stop tray icon: {e}")

        tk.Checkbutton(
            tray_frame, text="Enable System Tray Icon (Minimize to tray instead of closing)", 
            variable=tray_var, command=toggle_tray,
            bg="#2E2E2E", fg="#AAAAAA", selectcolor="#1E1E1E", 
            activebackground="#2E2E2E", activeforeground="white"
        ).pack(side=tk.LEFT)
        
        # --- Windows Autostart Toggle ---
        auto_frame = tk.Frame(settings_frame, bg="#2E2E2E")
        auto_frame.pack(fill=tk.X, pady=(5, 5))
        
        auto_var = tk.BooleanVar(value=APP_SETTINGS.get("autostart", False))
        
        def toggle_autostart():
            new_val = auto_var.get()
            APP_SETTINGS["autostart"] = new_val
            save_settings(APP_SETTINGS) # Saves to settings.json instantly
            
            if platform.system() == "Windows":
                import winreg
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                app_name = "NetworkInfoViewer"
                try:
                    # Open the registry key for the current user
                    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE | winreg.KEY_READ)
                    
                    if new_val:
                        # Check if it's an .exe or a .py script to format the path correctly
                        if getattr(sys, 'frozen', False):
                            exe_path = f'"{sys.executable}"'
                        else:
                            # Swap to pythonw.exe so it starts silently without a cmd window
                            py_exe = sys.executable.replace("python.exe", "pythonw.exe")
                            exe_path = f'"{py_exe}" "{os.path.abspath(sys.argv[0])}"'
                            
                        winreg.SetValueEx(key, app_name, 0, winreg.REG_SZ, exe_path)
                    else:
                        # Remove from autostart
                        try:
                            winreg.DeleteValue(key, app_name)
                        except FileNotFoundError:
                            pass # It was already removed, no big deal
                            
                    winreg.CloseKey(key)
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to modify registry for Autostart.\n\n{e}")
                    # Revert the checkbox if it failed
                    auto_var.set(not new_val)

        tk.Checkbutton(
            auto_frame, text="Launch automatically when Windows starts", 
            variable=auto_var, command=toggle_autostart,
            bg="#2E2E2E", fg="#AAAAAA", selectcolor="#1E1E1E", 
            activebackground="#2E2E2E", activeforeground="white"
        ).pack(side=tk.LEFT)
        
        # --- Auto-Refresh Spinbox & Presets ---
        refresh_frame = tk.Frame(settings_frame, bg="#2E2E2E")
        refresh_frame.pack(fill=tk.X, pady=(15, 0))

        tk.Label(refresh_frame, text="Auto-Refresh (Seconds):", bg="#2E2E2E", fg="#AAAAAA", font=("Arial", 10)).pack(side=tk.LEFT)

        # Variables
        current_interval = APP_SETTINGS.get("refresh_interval", 0)
        interval_var = tk.IntVar(value=current_interval)
        preset_var = tk.StringVar()

        # The Spinbox (Up/Down Arrows)
        spinbox = ttk.Spinbox(refresh_frame, from_=0, to=3600, textvariable=interval_var, width=6)
        spinbox.pack(side=tk.LEFT, padx=10)

        # The Dropdown for Presets
        presets = ["Manual Refresh", "Instant Refresh", "Urgent Refresh", "Fast Refresh", "Stable Refresh"]
        preset_box = ttk.Combobox(refresh_frame, textvariable=preset_var, values=presets, state="readonly", width=18)
        preset_box.pack(side=tk.LEFT, padx=10)

        # Dynamic Description Label (Acts like your hover tooltip)
        desc_label = tk.Label(settings_frame, text="", bg="#2E2E2E", fg="#888888", font=("Arial", 9, "italic"), justify=tk.LEFT)
        desc_label.pack(fill=tk.X, padx=20, pady=(5, 10))

        # Dictionary holding the descriptions you requested
        descriptions = {
            0:  "Manual Refresh: 0s\nLoad: None. Use this for general viewing to save system resources.",
            2:  "Instant Refresh: 2s\nLoad: EXTREME. App may freeze. Use only for critical real-time monitoring.",
            5:  "Urgent Refresh: 5s\nLoad: High. Good for actively troubleshooting a dropping connection.",
            15: "Fast Refresh: 15s\nLoad: Moderate. Ideal for waiting for a router to reboot and reconnect.",
            30: "Stable Refresh: 30s\nLoad: Low. Best for keeping the app open in the background daily."
        }

        # Logic to sync the Spinbox, Combobox, and Description Label
        def sync_ui(*args):
            try:
                val = interval_var.get()
            except tk.TclError:
                val = 0 # Fallback if user types a letter

            # Update settings.json
            APP_SETTINGS["refresh_interval"] = val
            save_settings(APP_SETTINGS)

            # Match combo box to spinbox
            if val == 0: preset_var.set("Manual Refresh")
            elif val == 2: preset_var.set("Instant Refresh")
            elif val == 5: preset_var.set("Urgent Refresh")
            elif val == 15: preset_var.set("Fast Refresh")
            elif val == 30: preset_var.set("Stable Refresh")
            else: preset_var.set("Custom")

            # Update the description label based on the closest match
            if val in descriptions:
                desc_label.config(text=descriptions[val], fg="#888888" if val > 2 else "#FF5555")
            else:
                # Convert seconds to minutes and format it to 1 decimal place
                minutes = val / 60
                desc_label.config(text=f"Custom Refresh: {minutes:.1f} minutes\nLoad: Variable based on selected time.", fg="#888888")

        # Logic for when user selects a preset from the dropdown
        def on_preset_select(event):
            selection = preset_var.get()
            if selection == "Manual Refresh": interval_var.set(0)
            elif selection == "Instant Refresh": interval_var.set(2)
            elif selection == "Urgent Refresh": interval_var.set(5)
            elif selection == "Fast Refresh": interval_var.set(15)
            elif selection == "Stable Refresh": interval_var.set(30)
            sync_ui()

        # Bind the triggers so everything updates instantly
        interval_var.trace_add("write", sync_ui)
        preset_box.bind("<<ComboboxSelected>>", on_preset_select)

        # Run once to set the initial label text
        sync_ui()

    def adv_passwords(self):
        tk.Label(self.adv_content, text="All Saved WiFi Passwords", bg="#2E2E2E", fg="white", font=("Arial", 14, "bold")).pack(pady=(20, 5))
        tk.Label(self.adv_content, text="🟢 Green = currently connected   |   💡 Double-click Password to get QR", bg="#2E2E2E", fg="#7FFF7F", font=("Arial", 9)).pack(pady=(0, 10))

        tframe = tk.Frame(self.adv_content, bg="#2E2E2E")
        tframe.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        sb_y = ttk.Scrollbar(tframe, orient=tk.VERTICAL)
        popup_tree = ttk.Treeview(tframe, columns=("#", "SSID", "Password", "Status"), show="headings", yscrollcommand=sb_y.set)
        sb_y.config(command=popup_tree.yview)
        sb_y.pack(side=tk.RIGHT, fill=tk.Y)
        popup_tree.pack(fill=tk.BOTH, expand=True)

        for col, w in [("#", 40), ("SSID", 200), ("Password", 220), ("Status", 120)]:
            popup_tree.heading(col, text=col)
            popup_tree.column(col, width=w, anchor="center" if col in ("#", "Status") else "w")

        popup_tree.tag_configure("connected", background="#1A3A1A", foreground="#7FFF7F")
        popup_tree.tag_configure("saved", background="#1E1E1E", foreground="white")

        connected_ssids = set(get_all_connected_ssids_windows(saved_profiles=self.all_wifi_passwords).values())
        for idx, (ssid, pwd) in enumerate(sorted(self.all_wifi_passwords.items()), 1):
            tag = "connected" if ssid in connected_ssids else "saved"
            popup_tree.insert("", "end", iid=str(idx), tags=(tag,), values=(idx, ssid, pwd, "✔ Connected" if tag == "connected" else "Saved"))

        def _on_pw_double_click(event):
            row_id = popup_tree.identify_row(event.y)
            if not row_id or int(popup_tree.identify_column(event.x).replace('#', '')) - 1 != 2: return
            vals = popup_tree.item(row_id, 'values')
            if vals[2] in ('N/A', 'Unable to Retrieve', 'Not in saved profiles', 'Open / No Password', ''):
                messagebox.showwarning("QR Code", f"No valid password for '{vals[1]}'.")
                return
            self.show_qr_popup(vals[1], vals[2], get_wifi_security_type(vals[1]))

        popup_tree.bind("<Double-1>", _on_pw_double_click)

    def adv_profiler(self):
        tk.Label(self.adv_content, text="Network Profiler", bg="#2E2E2E", fg="white", font=("Arial", 14, "bold")).pack(pady=(20, 5))
        tk.Label(self.adv_content, text="Change connection profile between Public and Private", bg="#2E2E2E", fg="#AAAAAA", font=("Arial", 9)).pack(pady=(0, 10))

        profiles = self.get_network_categories()
        
        if not profiles:
            tk.Label(self.adv_content, text="No network profiles detected.", bg="#2E2E2E", fg="red").pack()
            return

        frame = tk.Frame(self.adv_content, bg="#2E2E2E")
        frame.pack(fill=tk.BOTH, expand=True, padx=40, pady=10)

        def toggle_profile(alias, current_cat, btn_widget, status_lbl):
            new_cat = "Public" if current_cat.lower() == "private" else "Private"
            try:
                ps_cmd = f'Set-NetConnectionProfile -InterfaceAlias "{alias}" -NetworkCategory {new_cat}'
                subprocess.run(['powershell', '-Command', ps_cmd], check=True, creationflags=NO_WINDOW)
                btn_widget.config(text=f"Switch to {'Private' if new_cat == 'Public' else 'Public'}")
                status_lbl.config(text=new_cat, fg="#7FFF7F" if new_cat == "Private" else "#FFCC44")
                
                # Update click action to flip back
                btn_widget.config(command=lambda: toggle_profile(alias, new_cat, btn_widget, status_lbl))
                self.status_var.set(f"Successfully changed {alias} to {new_cat}")
            except subprocess.CalledProcessError:
                messagebox.showerror("Permission Denied", "Failed to change profile.\nAre you running as Administrator?")

        for alias, cat in profiles.items():
            row = tk.Frame(frame, bg="#1E1E1E", pady=10, padx=15)
            row.pack(fill=tk.X, pady=5)
            
            tk.Label(row, text=alias, bg="#1E1E1E", fg="white", font=("Arial", 11, "bold"), width=30, anchor="w").pack(side=tk.LEFT)
            lbl_cat = tk.Label(row, text=cat, bg="#1E1E1E", fg="#7FFF7F" if cat == "Private" else "#FFCC44", font=("Arial", 10, "bold"), width=15)
            lbl_cat.pack(side=tk.LEFT)
            
            opp_cat = "Public" if cat.lower() == "private" else "Private"
            btn = ttk.Button(row, text=f"Switch to {opp_cat}")
            btn.pack(side=tk.RIGHT)
            btn.config(command=lambda a=alias, c=cat, b=btn, l=lbl_cat: toggle_profile(a, c, b, l))

    def adv_logs(self):
        tk.Label(self.adv_content, text="Diagnostic Logs", bg="#2E2E2E", fg="white", font=("Arial", 14, "bold")).pack(pady=(20, 5))
        
        tframe = tk.Frame(self.adv_content, bg="#2E2E2E")
        tframe.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        sb = ttk.Scrollbar(tframe)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        txt = tk.Text(tframe, bg="#0D0D0D", fg="#CCCCCC", font=("Courier New", 8), yscrollcommand=sb.set, wrap=tk.NONE)
        txt.pack(fill=tk.BOTH, expand=True)
        sb.config(command=txt.yview)

        txt.tag_configure("DEBUG", foreground="#555577")
        txt.tag_configure("INFO", foreground="#AAAAAA")
        txt.tag_configure("WARNING", foreground="#FFCC44")
        txt.tag_configure("ERROR", foreground="#FF5555")

        try:
            with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    level = "INFO"
                    for lvl in ("DEBUG", "WARNING", "ERROR", "CRITICAL", "INFO"):
                        if f"| {lvl}" in line:
                            level = lvl
                            break
                    txt.insert(tk.END, line, level)
        except Exception:
            txt.insert(tk.END, "Log file not found.")
        txt.see(tk.END)
        txt.config(state=tk.DISABLED)

    # ── Core Data Fetching ────────────────────────────────

    def get_router_ip(self):
        try:
            output = subprocess.check_output(['ipconfig'], text=True, creationflags=NO_WINDOW)
            router_map, current_iface, is_gw = {}, None, False
            for line in output.splitlines():
                if "adapter" in line.lower() and ":" in line:
                    current_iface = line.lower().split("adapter")[-1].strip().split(":")[0].strip()
                    is_gw = False
                if "default gateway" in line.lower() and current_iface:
                    is_gw = True
                    try:
                        ip = line[line.index(':') + 1:].strip()
                        if not ip.startswith('fe80::') and ip.count('.') == 3:
                            router_map[current_iface] = ip
                            is_gw = False
                    except: pass
                elif is_gw and line.strip().count('.') == 3:
                    ip = line.strip().split('%')[0].strip()
                    if ip and ip != "0.0.0.0":
                        router_map[current_iface] = ip
                        is_gw = False
            return router_map
        except: return {}

    def get_mac_address(self, iface):
        try:
            for addr in psutil.net_if_addrs()[iface]:
                if addr.family == psutil.AF_LINK: return addr.address
        except: pass
        return "N/A"

    def get_config_type(self, iface):
        try:
            out = subprocess.check_output(['ipconfig', '/all'], text=True, creationflags=NO_WINDOW)
            found = False
            for line in out.splitlines():
                if iface in line: found = True; continue
                if found and "DHCP Enabled" in line:
                    return "DHCP" if "Yes" in line else "Static"
        except: pass
        return "Unknown"

    def get_network_categories(self):
        cats = {}
        if platform.system() != "Windows": return cats
        try:
            proc = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-Command', 
                                   "Get-NetConnectionProfile | Select-Object InterfaceAlias, NetworkCategory | Format-List"],
                                  capture_output=True, text=True, creationflags=NO_WINDOW)
            alias = None
            for line in proc.stdout.splitlines():
                line = line.strip()
                if line.lower().startswith('interfacealias'): alias = line.partition(':')[2].strip()
                elif line.lower().startswith('networkcategory') and alias: cats[alias] = line.partition(':')[2].strip()
        except: pass
        return cats

    def get_ip_info(self):
        self.ip_info = {}
        cats = self.get_network_categories()
        routers = self.get_router_ip()
        ssids = get_all_connected_ssids_windows(saved_profiles=self.all_wifi_passwords)

        for iface, addrs in psutil.net_if_addrs().items():
            router = next((ip for r, ip in routers.items() if r in iface.lower() or iface.lower() in r), "N/A")
            ssid = ssids.get(iface, next((s for i, s in ssids.items() if i.lower() in iface.lower() or iface.lower() in i.lower()), "N/A"))
            pwd = self.all_wifi_passwords.get(ssid, "Not in saved profiles" if ssid != "N/A" else "N/A")
            
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    base_cfg = self.get_config_type(iface)
                    final_cfg = f"{base_cfg} / {cats.get(iface)}" if cats.get(iface) else base_cfg
                    self.ip_info[iface] = {
                        'SSID': ssid, 'IP Address': addr.address, 'Password': pwd,
                        'MAC Address': self.get_mac_address(iface), 'Config Type': final_cfg,
                        'Router IP': router, 'is_wifi': ssid != "N/A"
                    }
        return self.ip_info

    # ── Refresh & Speed ───────────────────────────────────

    def refresh_info(self, fetch_data=True):
        if fetch_data:
            self.status_var.set("Refreshing network information...")
            self.update_idletasks()
            self.get_ip_info() # Only do the heavy lifting if fetch_data is True
            
        for row in self.tree.get_children(): 
            self.tree.delete(row)
            
        current_ssids = [] # Track SSIDs for notifications
        
        for iface, info in self.ip_info.items():
            tag = ("wifi_connected",) if info.get('is_wifi') else ()
            self.tree.insert("", "end", iid=iface, tags=tag, values=(
                iface, info.get('SSID', 'N/A'), info.get('IP Address', 'N/A'), info.get('Password', 'N/A'),
                info.get('MAC Address', 'N/A'), info.get('Config Type', 'N/A'), info.get('Router IP', 'N/A'), '...', '...'
            ))
            
            # Save the connected SSID if it's Wi-Fi
            if info.get('is_wifi') and info.get('SSID') != 'N/A':
                current_ssids.append(info.get('SSID'))
            
        self.status_var.set(f"Found {len(self.ip_info)} interface(s) | Double-click Password to generate QR")

        # --- Feature 5: Network Change Notification Logic ---
        primary_ssid = current_ssids[0] if current_ssids else "Offline"
        
        # If the network changed from what we last knew, trigger the toast!
        if getattr(self, 'last_notified_ssid', None) != primary_ssid:
            # Don't notify on the very first boot-up, only on changes
            if hasattr(self, 'last_notified_ssid') and APP_SETTINGS.get("notifications", True):
                if hasattr(self, '_tray_icon') and self._tray_icon is not None:
                    try:
                        if primary_ssid == "Offline":
                            self._tray_icon.notify("Wi-Fi has been disconnected.", "Network Offline")
                        else:
                            self._tray_icon.notify(f"Successfully connected to {primary_ssid}", "Network Connected")
                    except Exception as e:
                        log.debug(f"Notification failed: {e}")
            # Update our memory
            self.last_notified_ssid = primary_ssid

    def format_bytes(self, b):
        if not b: return "0 B/s"
        for unit in ["B/s", "KB/s", "MB/s", "GB/s", "TB/s"]:
            if b < 1024: return f"{b:.2f} {unit}"
            b /= 1024

    def update_speed(self):
        if hasattr(self, 'tree') and self.tree.winfo_exists():
            curr = psutil.net_io_counters(pernic=True)
            for iface in self.tree.get_children():
                if iface in curr and iface in self.last_net_io:
                    vals = list(self.tree.item(iface, 'values'))
                    if len(vals) >= 9:
                        vals[7] = self.format_bytes(curr[iface].bytes_recv - self.last_net_io[iface].bytes_recv)
                        vals[8] = self.format_bytes(curr[iface].bytes_sent - self.last_net_io[iface].bytes_sent)
                        self.tree.item(iface, values=tuple(vals))
            self.last_net_io = curr
        self.after(1000, self.update_speed)

    # ── Double Click & Popups ─────────────────────────────

    def _on_main_table_double_click(self, event):
        row_id = self.tree.identify_row(event.y)
        if not row_id or int(self.tree.identify_column(event.x).replace('#', '')) - 1 != self.PASSWORD_COL_INDEX: return
        vals = self.tree.item(row_id, 'values')
        if vals[3] in ('N/A', 'Unable to Retrieve', 'Not in saved profiles', ''):
            messagebox.showwarning("QR Code", f"Cannot generate QR code for '{vals[1]}'.")
            return
        self.show_qr_popup(vals[1], vals[3], get_wifi_security_type(vals[1]))

    def show_qr_popup(self, ssid, pwd, sec):
        win = tk.Toplevel(self)
        win.title(f"QR Code — {ssid}")
        win.configure(bg="#2E2E2E")
        win.grab_set()
        tk.Label(win, text="📶 Scan to Connect", bg="#2E2E2E", fg="white", font=("Arial", 14, "bold")).pack(pady=10)
        
        try:
            pil_img = build_wifi_qr_image(ssid, pwd, sec).resize((280, 280), Image.LANCZOS)
            tk_img = ImageTk.PhotoImage(pil_img)
            lbl = tk.Label(win, image=tk_img, bg="white", padx=10, pady=10)
            lbl.image = tk_img
            lbl.pack(padx=20, pady=10)
        except Exception as e:
            tk.Label(win, text=f"Failed: {e}", bg="#2E2E2E", fg="red").pack()
        ttk.Button(win, text="✖ Close", command=win.destroy).pack(pady=10)

    # ── Admin & IPC ───────────────────────────────────────
    def _prompt_admin_elevation(self):
        if messagebox.askyesno("Admin Privileges Recommended", "You are running as a standard user. Restart as Admin for better password/profile retrieval?"):
            try:
                # Determine the executable
                exe = sys.executable
                
                # If running as a standard .py script, swap 'python.exe' for 'pythonw.exe'
                if not getattr(sys, 'frozen', False):
                    if exe.lower().endswith("python.exe"):
                        exe = exe[:-10] + "pythonw.exe"
                        
                # Set up the arguments
                if getattr(sys, 'frozen', False):
                    params = " ".join(sys.argv[1:])
                else:
                    params = f'"{os.path.abspath(sys.argv[0])}"'

                # Execute with admin privileges (runas)
                ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
                
                self._destroy_and_exit()
            except Exception as e: 
                messagebox.showerror("Elevation Failed", f"Could not restart.\n{e}")

    def _start_ipc_listener(self):
        def _listen():
            try:
                srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind(('127.0.0.1', IPC_PORT))
                srv.listen(5)
                srv.settimeout(1.0)
                while True:
                    try:
                        conn, _ = srv.accept()
                        if conn.recv(16) == b'SHOW': self.after(0, self._show_from_tray)
                        conn.close()
                    except socket.timeout: continue
                    except: break
            except: pass
        threading.Thread(target=_listen, daemon=True).start()

    # ── Tray ──────────────────────────────────────────────
    def _create_tray_icon(self):
        img = Image.open(resource_path("logo.ico")) if os.path.exists(resource_path("logo.ico")) else Image.new('RGB', (64, 64), (30, 30, 30))
        
        # We break the menu out into a variable to make it readable, 
        # and add 'default=True' to the Show option!
        menu = pystray.Menu(
            pystray.MenuItem('Open', lambda i, j: self.after(0, self._show_from_tray), default=True),
            pystray.MenuItem('End Process', lambda i, j: self.after(0, self._destroy_and_exit))
        )
        
        self._tray_icon = pystray.Icon('NetInfoApp', img, 'Network Info Viewer', menu)
        threading.Thread(target=self._tray_icon.run, daemon=True).start()

    def _on_close(self):
        if HAS_PYSTRAY and hasattr(self, '_tray_icon'):
            self.withdraw()
            self.status_var.set('Minimized to tray')
        else: self._destroy_and_exit()

    def _show_from_tray(self):
        self.deiconify()
        self.lift()
        self.status_var.set('Restored')

    def _destroy_and_exit(self):
        if hasattr(self, '_tray_icon'): self._tray_icon.stop()
        self.destroy()

# ─────────────────────────────────────────────

if __name__ == "__main__":
    _mutex_handle = enforce_single_instance()   # must stay in scope — keeps mutex alive
    try:
        app = NetworkInfoApp()
        app.mainloop()
    except Exception as e:
        log.critical(f"Unhandled top-level exception: {e}", exc_info=True)
        raise
    
