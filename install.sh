#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════
#  BugHunter Pro v2.0 — Auto Installer & Launcher
#  Supports: Kali Linux, Ubuntu, Parrot OS, Debian
#  Usage:
#    chmod +x install.sh
#    ./install.sh                  # install + run interactive
#    ./install.sh -t example.com   # install + run immediately
#    ./install.sh --only-install   # install only, don't run
# ══════════════════════════════════════════════════════════════

set -e  # exit on error

# ── Colors ──────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Icons ───────────────────────────────────────────────────
OK="${GREEN}[✓]${RESET}"
FAIL="${RED}[✗]${RESET}"
INFO="${CYAN}[*]${RESET}"
WARN="${YELLOW}[!]${RESET}"
STEP="${MAGENTA}[→]${RESET}"

# ── Parse Arguments ─────────────────────────────────────────
TARGET=""
ONLY_INSTALL=false
ARGS_PASSTHROUGH=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--target)     TARGET="$2"; shift 2 ;;
        --only-install)  ONLY_INSTALL=true; shift ;;
        *)               ARGS_PASSTHROUGH="$ARGS_PASSTHROUGH $1"; shift ;;
    esac
done

# ── Banner ──────────────────────────────────────────────────
banner() {
    echo ""
    echo -e "${CYAN}${BOLD}"
    echo "  ██████╗ ██╗   ██╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗"
    echo "  ██╔══██╗██║   ██║██╔════╝ ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗"
    echo "  ██████╔╝██║   ██║██║  ███╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝"
    echo "  ██╔══██╗██║   ██║██║   ██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗"
    echo "  ██████╔╝╚██████╔╝╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║"
    echo "  ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝"
    echo -e "${RESET}"
    echo -e "  ${BOLD}BugHunter Pro v2.0${RESET} — Advanced Bug Bounty Automation"
    echo -e "  ${YELLOW}⚠  Use ONLY on targets you have explicit permission to test${RESET}"
    echo ""
}

# ── Helper: print step ──────────────────────────────────────
step() { echo -e "\n${STEP} ${BOLD}$1${RESET}"; }
ok()   { echo -e "  ${OK} $1"; }
warn() { echo -e "  ${WARN} $1"; }
fail() { echo -e "  ${FAIL} $1"; }
info() { echo -e "  ${INFO} $1"; }

# ── Helper: check tool ──────────────────────────────────────
has() { command -v "$1" &>/dev/null; }

# ── Helper: install Go tool ─────────────────────────────────
install_go_tool() {
    local name=$1
    local pkg=$2
    local desc=${3:-$name}
    if has "$name"; then
        ok "$desc already installed"
    else
        echo -e "  ${INFO} Installing ${BOLD}${desc}${RESET} (Go tool)..."
        # Show go output filtered to meaningful lines
        go install -v "$pkg" 2>&1 | \
            grep --line-buffered -E '(downloading|go: downloading|Downloading|fetching)' | \
            while IFS= read -r line; do
                mod=$(echo "$line" | awk '{print $3}' 2>/dev/null || echo "$line")
                ver=$(echo "$line" | awk '{print $4}' 2>/dev/null || echo "")
                echo -e "    ${CYAN}↓${RESET} $mod ${YELLOW}$ver${RESET}"
            done
        if has "$name"; then
            echo -e "  ${GREEN}[✓] $desc installed${RESET}"
        else
            echo -e "  ${RED}[✗] $desc failed (non-critical)${RESET}"
        fi
    fi
}

# ════════════════════════════════════════════════════════════
#  MAIN
# ════════════════════════════════════════════════════════════

banner

# ── 0. Check OS ─────────────────────────────────────────────
step "System Check"
OS=$(lsb_release -is 2>/dev/null || echo "Unknown")
VER=$(lsb_release -rs 2>/dev/null || echo "")
info "OS: $OS $VER"

if [[ "$EUID" -eq 0 ]]; then
    SUDO=""
    ok "Running as root"
else
    SUDO="sudo"
    info "Running as user — will use sudo where needed"
fi

# Python check
if has python3; then
    PY_VER=$(python3 --version)
    ok "Python: $PY_VER"
else
    fail "Python 3 not found! Install python3 first."
    exit 1
fi

# ── 1. Create Directories ────────────────────────────────────
step "Creating Directories"
mkdir -p outputs/knowledge outputs/screenshots wordlists logs
ok "Directories created: outputs/ wordlists/ logs/"

# ── 2. Python Virtual Environment ───────────────────────────
step "Python Virtual Environment"
if [[ ! -d "venv" ]]; then
    python3 -m venv venv
    ok "Virtual environment created: ./venv"
else
    ok "Virtual environment already exists"
fi

source venv/bin/activate
ok "Virtual environment activated"

# ── 3. Python Dependencies ───────────────────────────────────
step "Installing Python Dependencies"
echo -e "  ${INFO} Upgrading pip..."
pip install --upgrade pip
echo -e "  ${INFO} Installing packages from requirements.txt..."
pip install -r requirements.txt
ok "Python packages installed"

# ── 4. APT Packages ─────────────────────────────────────────
step "Installing APT Packages"

# Helper: install apt package — direct output (no pipe hang)
apt_install() {
    local pkg=$1
    local desc=${2:-$pkg}
    if has "$pkg"; then
        ok "$desc already installed"
        return
    fi
    echo -e "  ${INFO} Installing ${BOLD}${desc}${RESET}..."
    export DEBIAN_FRONTEND=noninteractive
    if $SUDO apt-get install -y "$pkg" ; then
        ok "$desc installed successfully"
    else
        warn "$desc installation failed (non-critical — some features may be skipped)"
    fi
}

echo -e "  ${INFO} Updating package lists..."
export DEBIAN_FRONTEND=noninteractive
$SUDO apt-get update
ok "Package lists updated"

apt_install "nmap"    "Nmap (port scanner)"
apt_install "amass"   "Amass (subdomain enumeration)"
apt_install "whatweb" "WhatWeb (tech detection)"

# SecLists
if [[ -d "/usr/share/seclists" ]] || [[ -d "/usr/share/wordlists/seclists" ]]; then
    ok "SecLists already installed"
else
    echo -e "  ${INFO} Installing ${BOLD}SecLists${RESET} (~450MB — this may take several minutes)..."
    echo -e "  ${YELLOW}  ⏳ Please wait...${RESET}"
    export DEBIAN_FRONTEND=noninteractive
    if $SUDO apt-get install -y seclists ; then
        ok "SecLists installed"
    else
        warn "SecLists skipped — will use built-in minimal wordlists"
    fi
fi

# ── 5. Go Installation ───────────────────────────────────────
step "Go Language Setup"
if has go; then
    GO_VER=$(go version)
    ok "Go already installed: $GO_VER"
else
    warn "Go not found — downloading and installing..."
    GO_VER="1.21.8"
    GO_ARCH="linux-amd64"
    GO_PKG="go${GO_VER}.${GO_ARCH}.tar.gz"
    GO_URL="https://go.dev/dl/${GO_PKG}"

    echo -e "  ${INFO} Downloading Go ${GO_VER} (~67MB)..."
    wget --progress=bar:force "$GO_URL" -O "/tmp/$GO_PKG" 2>&1

    echo -ne "  ${INFO} Installing Go..."
    $SUDO rm -rf /usr/local/go
    $SUDO tar -C /usr/local -xzf "/tmp/$GO_PKG"
    echo -e " ${GREEN}done${RESET}"

    # Add to PATH
    if ! grep -q '/usr/local/go/bin' ~/.bashrc; then
        echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
    fi
    export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"

    rm -f "/tmp/$GO_PKG"
    ok "Go installed successfully"
fi

# Ensure Go bin is in PATH
export PATH="$PATH:$HOME/go/bin:/usr/local/go/bin"

# ── 6. Go-Based Security Tools ───────────────────────────────
step "Installing Go Security Tools"
install_go_tool "subfinder"   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"   "Subfinder (subdomain discovery)"
install_go_tool "httpx"       "github.com/projectdiscovery/httpx/cmd/httpx@latest"               "httpx (alive check + tech detect)"
install_go_tool "nuclei"      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"          "Nuclei (vulnerability scanner)"
install_go_tool "dnsx"        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"                 "dnsx (DNS bruteforce)"
install_go_tool "ffuf"        "github.com/ffuf/ffuf/v2@latest"                                   "ffuf (web fuzzer)"
install_go_tool "assetfinder" "github.com/tomnomnom/assetfinder@latest"                          "Assetfinder (passive recon)"
install_go_tool "gowitness"   "github.com/sensepost/gowitness@latest"                            "Gowitness (screenshots)"

# ── 7. Nuclei Templates ──────────────────────────────────────
step "Nuclei Templates"
if has nuclei; then
    echo -ne "  ${INFO} Updating nuclei templates..."
    nuclei -update-templates -silent 2>/dev/null || true
    echo -e " ${GREEN}done${RESET}"
else
    warn "nuclei not found — skipping template update"
fi

# ── 8. Verify Installation ───────────────────────────────────
step "Verification"
TOOLS=("subfinder" "httpx" "nuclei" "ffuf" "dnsx" "amass" "nmap" "gowitness" "whatweb")
MISSING=()

for tool in "${TOOLS[@]}"; do
    if has "$tool"; then
        ok "$tool ✓"
    else
        warn "$tool ✗ (not found — some features will be skipped)"
        MISSING+=("$tool")
    fi
done

echo ""
echo -e "  ${BOLD}Python packages:${RESET}"
python3 -c "
import importlib, sys
pkgs = ['requests', 'urllib3', 'colorama', 'dotenv', 'dns']
for p in pkgs:
    try:
        importlib.import_module(p)
        print(f'  \033[32m[✓]\033[0m {p}')
    except ImportError:
        print(f'  \033[31m[✗]\033[0m {p} (missing!)')
"

# ── 9. Summary ──────────────────────────────────────────────
echo ""
echo -e "${CYAN}${BOLD}══════════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD}  ✅  Installation Complete!${RESET}"
echo -e "${CYAN}${BOLD}══════════════════════════════════════════${RESET}"
echo ""

if [[ ${#MISSING[@]} -gt 0 ]]; then
    warn "Missing tools (non-critical — fallbacks exist): ${MISSING[*]}"
    echo ""
fi

echo -e "  ${INFO} Quick Start Examples:"
echo -e "  ${CYAN}python3 main.py -t example.com${RESET}"
echo -e "  ${CYAN}python3 main.py -t example.com -s scope.txt -o ./results${RESET}"
echo -e "  ${CYAN}python3 main.py -t example.com --no-nuclei --no-screenshots${RESET}"
echo ""

# ── 10. Run the Tool ─────────────────────────────────────────
if [[ "$ONLY_INSTALL" == "true" ]]; then
    info "Installation only mode — not starting scan"
    echo ""
    exit 0
fi

if [[ -n "$TARGET" ]]; then
    echo -e "${CYAN}${BOLD}══════════════════════════════════════════${RESET}"
    echo -e "${MAGENTA}${BOLD}  🚀  Starting BugHunter Pro…${RESET}"
    echo -e "${CYAN}${BOLD}══════════════════════════════════════════${RESET}"
    echo ""
    python3 main.py -t "$TARGET" $ARGS_PASSTHROUGH
else
    # Interactive mode — ask user
    echo ""
    echo -e "${BOLD}Enter target domain to scan (or press Enter to exit):${RESET}"
    echo -ne "  ${CYAN}Target: ${RESET}"
    read -r TARGET_INPUT

    if [[ -n "$TARGET_INPUT" ]]; then
        echo ""
        echo -e "${BOLD}Optional: any extra flags? (e.g. --no-nuclei --threads 5)${RESET}"
        echo -e "  ${CYAN}Leave empty for defaults: ${RESET}"
        read -r EXTRA_FLAGS

        echo ""
        echo -e "${CYAN}${BOLD}══════════════════════════════════════════${RESET}"
        echo -e "${MAGENTA}${BOLD}  🚀  Starting BugHunter Pro…${RESET}"
        echo -e "${CYAN}${BOLD}══════════════════════════════════════════${RESET}"
        echo ""
        python3 main.py -t "$TARGET_INPUT" $EXTRA_FLAGS
    else
        info "No target provided. Run manually: ${CYAN}python3 main.py -t TARGET${RESET}"
    fi
fi
