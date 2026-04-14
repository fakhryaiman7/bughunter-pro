"""
utils.py — Shared utilities: logging, colors, validation, helpers
"""

import os
import re
import sys
import json
import hashlib
import subprocess
import shutil
from pathlib import Path
from datetime import datetime
from typing import Optional, List


# ─────────────────────────────────────────────
#  ANSI Colors
# ─────────────────────────────────────────────

class Colors:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"


def log(msg: str, color: str = Colors.WHITE, file=None):
    """Thread-safe colored log line."""
    ts = datetime.now().strftime("%H:%M:%S")
    output = f"{color}[{ts}] {msg}{Colors.RESET}"
    print(output, file=file or sys.stdout)


def banner():
    b = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║     ██████╗ ██╗   ██╗ ██████╗ ██╗  ██╗██╗   ██╗            ║
║     ██╔══██╗██║   ██║██╔════╝ ██║  ██║██║   ██║            ║
║     ██████╔╝██║   ██║██║  ███╗███████║██║   ██║            ║
║     ██╔══██╗██║   ██║██║   ██║██╔══██║██║   ██║            ║
║     ██████╔╝╚██████╔╝╚██████╔╝██║  ██║╚██████╔╝            ║
║     ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝             ║
║                                                              ║
║         H U N T E R   P R O  v1.0                           ║
║    Bug Bounty Automation — Safe | Smart | Open Source       ║
╚══════════════════════════════════════════════════════════════╝
{Colors.RESET}
{Colors.YELLOW}  ⚠  LEGAL: Use ONLY on authorized targets.
  ⚠  Unauthorized scanning is ILLEGAL.{Colors.RESET}
"""
    print(b)


# ─────────────────────────────────────────────
#  Validation
# ─────────────────────────────────────────────

DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)

def validate_domain(domain: str) -> bool:
    return bool(DOMAIN_RE.match(domain.strip()))


def sanitize_input(value: str) -> str:
    """Strip shell metacharacters — never pass raw user input to shell."""
    return re.sub(r"[;&|`$<>]", "", value)


# ─────────────────────────────────────────────
#  Filesystem
# ─────────────────────────────────────────────

def ensure_dirs(*dirs):
    for d in dirs:
        Path(d).mkdir(parents=True, exist_ok=True)
    # Always ensure sub-dirs
    base = Path(dirs[0])
    for sub in ("knowledge", "screenshots", "wordlists"):
        (base / sub).mkdir(exist_ok=True)


def hash_file(path: str) -> str:
    """SHA256 of a file, used for change detection."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
    except FileNotFoundError:
        return ""
    return h.hexdigest()


# ─────────────────────────────────────────────
#  Subprocess wrapper (safe)
# ─────────────────────────────────────────────

def run_cmd(cmd: List[str], timeout: int = 300,
            capture: bool = True) -> tuple:
    """
    Safe subprocess runner.
    Returns (returncode, stdout, stderr).
    Raises ValueError if any arg contains shell metacharacters.
    """
    for arg in cmd:
        if any(c in str(arg) for c in [";", "&", "|", "`", "$", "<", ">"]):
            raise ValueError(f"Dangerous character in argument: {arg}")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except FileNotFoundError:
        return 127, "", f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout}s"
    except Exception as e:
        return -1, "", str(e)


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


# ─────────────────────────────────────────────
#  JSON helpers
# ─────────────────────────────────────────────

def load_json(path: Path, default=None):
    if default is None:
        default = {}
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def save_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)


# ─────────────────────────────────────────────
#  URL helpers
# ─────────────────────────────────────────────

def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def extract_domain(url: str) -> str:
    url = url.replace("https://", "").replace("http://", "")
    return url.split("/")[0].split(":")[0]

# ─────────────────────────────────────────────
#  Progress Tracking
# ─────────────────────────────────────────────

import time
import threading

class ProgressBar:
    """
    Real-time multi-line progress tracker with ETA and speed calculation.
    """
    def __init__(self, stage_num: int, stage_name: str, total: int, total_stages: int = 17):
        self.stage_num = stage_num
        self.stage_name = stage_name
        self.total = max(1, total)
        self.total_stages = total_stages
        self.completed = 0
        self.failed = 0
        self.start_time = time.time()
        self.lock = threading.Lock()
        self._last_line_count = 0
        self._active = True

        # Initial draw
        self.update(0)

    def update(self, inc: int = 1, status: str = "Running...", is_fail: bool = False):
        if not self._active:
            return

        with self.lock:
            self.completed += inc
            if is_fail:
                self.failed += 1
            
            elapsed = time.time() - self.start_time
            speed = self.completed / elapsed if elapsed > 0 else 0
            remaining = self.total - self.completed
            
            # Simple Smoothing for ETA
            if self.completed > 0:
                eta = (elapsed / self.completed) * remaining
            else:
                eta = 0
            
            eta_str = f"{int(eta)}s" if eta < 60 else f"{int(eta//60)}m {int(eta%60)}s"
            percent = int((self.completed / self.total) * 100)
            
            # ANSI escape codes for multi-line overwrite
            # Move cursor up to previous drawn lines
            if self._last_line_count > 0:
                sys.stdout.write(f"\033[{self._last_line_count}F")
            
            # Build output
            output = (
                f"{Colors.BOLD}{Colors.CYAN}[STAGE {self.stage_num}/{self.total_stages} — {self.stage_name}]{Colors.RESET}\n"
                f"Progress: {self.completed}/{self.total} ({percent}%) | Failed: {self.failed}\n"
                f"Speed: {speed:.1f} t/s | ETA: {eta_str} remaining\n"
                f"Status: {status}\033[K\n"
            )
            
            self._last_line_count = output.count('\n')
            sys.stdout.write(output)
            sys.stdout.flush()

    def complete(self, final_msg: str = "Completed successfully"):
        if not self._active:
            return
        
        with self.lock:
            # Clear the progress block and print a standard log
            if self._last_line_count > 0:
                sys.stdout.write(f"\033[{self._last_line_count}F")
                sys.stdout.write("\033[J")
            
            log(f"{Colors.GREEN}[✓]{Colors.RESET} Stage {self.stage_num}: {self.stage_name} — {final_msg}", Colors.WHITE)
            self._active = False
            self._last_line_count = 0
