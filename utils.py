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
    Production-grade CLI Dashboard for real-time observability.
    Supports hierarchical tracking: Stage -> Batch -> Tasks.
    """
    def __init__(self, stage_num: int, stage_name: str, total_tasks: int, total_stages: int = 17):
        self.stage_num = stage_num
        self.stage_name = stage_name
        self.total = max(1, total_tasks)
        self.total_stages = total_stages
        
        self.completed = 0
        self.failed = 0
        self.batch_current = 0
        self.batch_total = 0
        
        self.start_time = time.time()
        self.lock = threading.Lock()
        self._last_line_count = 0
        self._active = True

        # Initial Draw
        self._draw_header()
        self.update(0)

    def _draw_header(self):
        header = (
            f"\n{Colors.CYAN}╔{ '═'*38 }╗\n"
            f"║   {Colors.BOLD}BUGHUNTER PRO v2.0{Colors.RESET}{Colors.CYAN}                 ║\n"
            f"╚{ '═'*38 }╝{Colors.RESET}\n"
        )
        sys.stdout.write(header)
        sys.stdout.flush()

    def set_batch(self, current: int, total: int):
        with self.lock:
            self.batch_current = current
            self.batch_total = total

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
            
            # ETA Calculation
            if self.completed > 0:
                eta = (elapsed / self.completed) * remaining
            else:
                eta = 0
            
            eta_str = f"{int(eta)}s" if eta < 60 else f"{int(eta//60)}m {int(eta%60)}s"
            percent = int((self.completed / self.total) * 100) if self.total > 0 else 0
            
            # ANSI escape codes for multi-line overwrite
            if self._last_line_count > 0:
                sys.stdout.write(f"\033[{self._last_line_count}F")
            
            # Dashboard Layout
            output = (
                f"{Colors.BOLD}{Colors.YELLOW}[STAGE {self.stage_num}/{self.total_stages} — {self.stage_name}]{Colors.RESET}\n\n"
                f"  Tasks   : {self.completed}/{self.total} ({percent}%)\n"
                f"  Success : {Colors.GREEN}{self.completed - self.failed}{Colors.RESET} | Failed: {Colors.RED}{self.failed}{Colors.RESET}\n"
                f"  Speed   : {speed:.1f} tasks/sec\n"
                f"  ETA     : {eta_str} remaining\n\n"
            )
            
            if self.batch_total > 0:
                output += f"  Batch   : {self.batch_current}/{self.batch_total}\n"
            
            output += f"  Status  : {status[:60]}\033[K\n"
            
            self._last_line_count = output.count('\n')
            sys.stdout.write(output)
            sys.stdout.flush()

    def complete(self, final_msg: str = "Completed successfully"):
        if not self._active:
            return
        
        with self.lock:
            if self._last_line_count > 0:
                sys.stdout.write(f"\033[{self._last_line_count}F")
                sys.stdout.write("\033[J")
            
            log(f"{Colors.GREEN}[✓] STAGE {self.stage_num} COMPLETE: {self.stage_name}{Colors.RESET}", Colors.WHITE)
            log(f"    {final_msg}\n", Colors.CYAN)
            self._active = False
            self._last_line_count = 0

