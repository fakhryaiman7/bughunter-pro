# ══════════════════════════════════════════════════════════════
#  BugHunter Pro v2.0 — Windows Auto Installer & Launcher
#  Supports: Windows 10/11 (PowerShell 5+)
#  Usage:
#    .\install.ps1                    # install + run interactive
#    .\install.ps1 -Target example.com  # install + run immediately
#    .\install.ps1 -OnlyInstall       # install only, don't run
# ══════════════════════════════════════════════════════════════

param(
    [string]$Target = "",
    [switch]$OnlyInstall
)

# ── Colors ───────────────────────────────────────────────────
function Write-Green  { param($msg) Write-Host "  [✓] $msg" -ForegroundColor Green }
function Write-Red    { param($msg) Write-Host "  [✗] $msg" -ForegroundColor Red }
function Write-Cyan   { param($msg) Write-Host "  [*] $msg" -ForegroundColor Cyan }
function Write-Yellow { param($msg) Write-Host "  [!] $msg" -ForegroundColor Yellow }
function Write-Step   { param($msg) Write-Host "`n  [→] $msg" -ForegroundColor Magenta }
function Has-Tool     { param($name) return (Get-Command $name -ErrorAction SilentlyContinue) -ne $null }

# ── Banner ───────────────────────────────────────────────────
Write-Host ""
Write-Host "  ██████╗ ██╗   ██╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ " -ForegroundColor Cyan
Write-Host "  ██╔══██╗██║   ██║██╔════╝ ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗" -ForegroundColor Cyan
Write-Host "  ██████╔╝██║   ██║██║  ███╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝" -ForegroundColor Cyan
Write-Host "  ██╔══██╗██║   ██║██║   ██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗" -ForegroundColor Cyan
Write-Host "  ██████╔╝╚██████╔╝╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║" -ForegroundColor Cyan
Write-Host "  ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "  BugHunter Pro v2.0 — Windows Installer" -ForegroundColor White
Write-Host "  ⚠  Use ONLY on targets you have explicit permission to test" -ForegroundColor Yellow
Write-Host ""

# ── 0. System Check ─────────────────────────────────────────
Write-Step "System Check"
$PSVersion = $PSVersionTable.PSVersion.ToString()
Write-Cyan "PowerShell: $PSVersion"

if (-not (Has-Tool "python")) {
    Write-Red "Python not found! Download from https://python.org"
    exit 1
} else {
    $pyVer = python --version 2>&1
    Write-Green "Python: $pyVer"
}

# ── 1. Create Directories ────────────────────────────────────
Write-Step "Creating Directories"
$dirs = @("outputs\knowledge", "outputs\screenshots", "wordlists", "logs")
foreach ($dir in $dirs) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}
Write-Green "Directories created: outputs\, wordlists\, logs\"

# ── 2. Python Virtual Environment ───────────────────────────
Write-Step "Python Virtual Environment"
if (-not (Test-Path "venv")) {
    python -m venv venv
    Write-Green "Virtual environment created: .\venv"
} else {
    Write-Green "Virtual environment already exists"
}

# Activate
& ".\venv\Scripts\Activate.ps1" 2>$null
Write-Green "Virtual environment activated"

# ── 3. Python Dependencies ───────────────────────────────────
Write-Step "Installing Python Dependencies"
pip install --upgrade pip -q
pip install -r requirements.txt -q
Write-Green "Python packages installed"

# ── 4. Check for Go ─────────────────────────────────────────
Write-Step "Go Language Check"
if (Has-Tool "go") {
    $goVer = go version
    Write-Green "Go: $goVer"
} else {
    Write-Yellow "Go not found!"
    Write-Cyan  "Download Go from: https://go.dev/dl/"
    Write-Cyan  "After installing Go, re-run this script to install Go tools"
}

# ── 5. Go Security Tools ─────────────────────────────────────
Write-Step "Installing Go Security Tools"

$GoTools = @{
    "subfinder"   = "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "httpx"       = "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "nuclei"      = "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "dnsx"        = "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "ffuf"        = "github.com/ffuf/ffuf/v2@latest"
    "assetfinder" = "github.com/tomnomnom/assetfinder@latest"
    "gowitness"   = "github.com/sensepost/gowitness@latest"
}

if (Has-Tool "go") {
    foreach ($tool in $GoTools.GetEnumerator()) {
        if (Has-Tool $tool.Key) {
            Write-Green "$($tool.Key) already installed"
        } else {
            Write-Host "  [*] Installing $($tool.Key)..." -NoNewline -ForegroundColor Cyan
            go install $tool.Value 2>$null | Out-Null
            if (Has-Tool $tool.Key) {
                Write-Host " done" -ForegroundColor Green
            } else {
                Write-Host " failed (non-critical)" -ForegroundColor Red
            }
        }
    }

    # Update Nuclei templates
    if (Has-Tool "nuclei") {
        Write-Host "  [*] Updating nuclei templates..." -NoNewline -ForegroundColor Cyan
        nuclei -update-templates -silent 2>$null | Out-Null
        Write-Host " done" -ForegroundColor Green
    }
} else {
    Write-Yellow "Skipping Go tools (Go not installed)"
}

# ── 6. Check Scoop / Nmap (Windows) ─────────────────────────
Write-Step "Checking Optional Tools"
if (Has-Tool "nmap") {
    $nmapVer = nmap --version 2>&1 | Select-Object -First 1
    Write-Green "nmap: $nmapVer"
} else {
    Write-Yellow "nmap not found — install from https://nmap.org/download.html"
    Write-Cyan  "Or via Scoop: scoop install nmap"
}

# ── 7. Verification ─────────────────────────────────────────
Write-Step "Verification"
$allTools = @("subfinder", "httpx", "nuclei", "ffuf", "dnsx", "gowitness", "nmap")
foreach ($tool in $allTools) {
    if (Has-Tool $tool) {
        Write-Green "$tool"
    } else {
        Write-Yellow "$tool (missing — some features will be skipped)"
    }
}

Write-Host ""
Write-Host "  Python packages:" -ForegroundColor White
python -c "
import importlib
pkgs = {'requests':'requests','urllib3':'urllib3','colorama':'colorama','dotenv':'dotenv','dns':'dns'}
for p,m in pkgs.items():
    try:
        importlib.import_module(m)
        print(f'  \033[32m[OK]\033[0m {p}')
    except ImportError:
        print(f'  \033[31m[!!]\033[0m {p} MISSING')
"

# ── 8. Summary ──────────────────────────────────────────────
Write-Host ""
Write-Host "  ══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  ✅  Installation Complete!" -ForegroundColor Green
Write-Host "  ══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Quick Start Examples:" -ForegroundColor White
Write-Host "  python main.py -t example.com" -ForegroundColor Cyan
Write-Host "  python main.py -t example.com -s scope.txt -o .\results" -ForegroundColor Cyan
Write-Host "  python main.py -t example.com --no-nuclei --no-screenshots" -ForegroundColor Cyan
Write-Host ""

# ── 9. Run ───────────────────────────────────────────────────
if ($OnlyInstall) {
    Write-Cyan "Installation only mode — not starting scan"
    exit 0
}

if ($Target -ne "") {
    Write-Host "  ══════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  🚀  Starting BugHunter Pro..." -ForegroundColor Magenta
    Write-Host "  ══════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    python main.py -t $Target
} else {
    Write-Host "  Enter target domain to scan (or press Enter to exit):" -ForegroundColor White
    $TargetInput = Read-Host "  Target"

    if ($TargetInput -ne "") {
        Write-Host "  Optional: extra flags (e.g. --no-nuclei --threads 5) or Enter to skip:" -ForegroundColor White
        $ExtraFlags = Read-Host "  Flags"

        Write-Host ""
        Write-Host "  ══════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "  🚀  Starting BugHunter Pro..." -ForegroundColor Magenta
        Write-Host "  ══════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""

        $cmd = "python main.py -t $TargetInput $ExtraFlags"
        Invoke-Expression $cmd
    } else {
        Write-Cyan "No target. Run manually: python main.py -t TARGET"
    }
}
