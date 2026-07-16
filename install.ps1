# ReconX Framework — Windows Tool Installer
# Installs Go tools, Python packages, and optional extras.
# Requires: Go, Python 3.10+, Git in PATH.

$ErrorActionPreference = "Continue"

function Info($msg)  { Write-Host "  [*] $msg" -ForegroundColor Cyan }
function Ok($msg)    { Write-Host "  [+] $msg" -ForegroundColor Green }
function Err($msg)   { Write-Host "  [-] $msg" -ForegroundColor Red }

$GoBin = if ($env:GOPATH) { Join-Path $env:GOPATH "bin" } else { Join-Path $HOME "go\bin" }

# ── Go tools ──────────────────────────────────────────────────────────
function Install-GoTools {
    Info "Installing Go tools..."

    if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
        Err "Go not found — install from https://go.dev/dl/"
        return
    }

    $tools = @{
        "subfinder"  = "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "dnsx"       = "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        "httpx"      = "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "nuclei"     = "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        "naabu"      = "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        "chaos"      = "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
        "shuffledns" = "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
        "katana"     = "github.com/projectdiscovery/katana/cmd/katana@latest"
        "hakrawler"  = "github.com/hakluke/hakrawler@latest"
        "gauplus"    = "github.com/bp0lr/gauplus@latest"
        "waybackurls"= "github.com/tomnomnom/waybackurls@latest"
        "subjs"      = "github.com/lc/subjs@latest"
        "qsreplace"  = "github.com/tomnomnom/qsreplace@latest"
        "gf"         = "github.com/tomnomnom/gf@latest"
        "subzy"      = "github.com/LukaSikic/subzy@latest"
        "gowitness"  = "github.com/sensepost/gowitness@latest"
        "feroxbuster"= "github.com/epi052/feroxbuster@latest"
    }

    foreach ($tool in $tools.Keys) {
        $installed = Get-Command $tool -ErrorAction SilentlyContinue
        if ($installed) {
            Ok "$tool already installed"
        } else {
            Info "Installing $tool..."
            $result = go install $tools[$tool] 2>&1
            if ($LASTEXITCODE -eq 0) { Ok "$tool installed" } else { Err "$tool failed" }
        }
    }
}

# ── Python packages ───────────────────────────────────────────────────
function Install-PythonPackages {
    Info "Installing Python packages..."
    $result = pip install --user --upgrade rich uro arjun xnlinkfinder jsbeautifier 2>&1
    if ($LASTEXITCODE -eq 0) { Ok "Python packages done" } else { Err "Some pip packages failed" }
}

# ── Nuclei templates ──────────────────────────────────────────────────
function Install-NucleiTemplates {
    if (Get-Command nuclei -ErrorAction SilentlyContinue) {
        Info "Updating Nuclei templates..."
        $null = nuclei -update-templates 2>&1
        Ok "Nuclei templates updated"
    }
}

# ── Resolver list ─────────────────────────────────────────────────────
function Copy-Resolvers {
    $scriptDir = Split-Path -Parent $MyInvocation.PSScriptRoot
    $src = Join-Path $scriptDir "config\resolvers.txt"
    $dst = Join-Path $HOME "resolvers.txt"

    if ((Test-Path $src) -and -not (Test-Path $dst)) {
        Copy-Item $src $dst
        Ok "Resolver list copied to ~\resolvers.txt"
    }
}

# ── Main ──────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ReconX Framework — Windows Installer"
Write-Host "  ─────────────────────────────────────"
Write-Host ""

Install-GoTools
Install-PythonPackages
Install-NucleiTemplates
Copy-Resolvers

# Ensure Go bin is in PATH for this session
if (Test-Path $GoBin) {
    $env:PATH = "$GoBin;$env:PATH"
}

Write-Host ""
Ok "Installation complete!"
Write-Host ""
Write-Host "  Run:  python recon.py --check"
Write-Host "  Note: Add $GoBin to your system PATH permanently"
Write-Host ""
