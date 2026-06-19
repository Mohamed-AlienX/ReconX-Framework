#!/usr/bin/env bash
set -euo pipefail

# ReconX Framework — Tool Installer
# Installs all external tools used by the pipeline.
# Supports Linux (apt) and macOS (brew).

GO_BIN="${GOPATH:-$HOME/go}/bin"
export PATH="$GO_BIN:$PATH"

RED='\033[1;31m'
GREEN='\033[1;32m'
CYAN='\033[1;36m'
RESET='\033[0m'

info()  { echo -e "  ${CYAN}[*]${RESET} $1"; }
ok()    { echo -e "  ${GREEN}[+]${RESET} $1"; }
err()   { echo -e "  ${RED}[-]${RESET} $1"; }

# ---------------------------------------------------------------
# Detect OS
# ---------------------------------------------------------------
OS="$(uname -s)"
info "Detected OS: $OS"

# ---------------------------------------------------------------
# System packages
# ---------------------------------------------------------------
install_system_packages() {
    info "Installing system packages..."
    if [[ "$OS" == "Linux" ]]; then
        sudo apt-get update -qq
        sudo apt-get install -y -qq \
            nmap \
            jq \
            curl \
            git \
            build-essential \
            ruby-full 2>/dev/null || true
    elif [[ "$OS" == "Darwin" ]]; then
        brew install \
            nmap \
            jq \
            curl \
            git 2>/dev/null || true
    fi
    ok "System packages done"
}

# ---------------------------------------------------------------
# Go tools
# ---------------------------------------------------------------
install_go_tools() {
    info "Installing Go tools..."

    # Ensure Go is installed
    if ! command -v go &>/dev/null; then
        err "Go not found — install Go first: https://go.dev/dl/"
        return
    fi

    declare -A GOTOOLS=(
        [subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        [dnsx]="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        [httpx]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
        [nuclei]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        [naabu]="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        [chaos]="github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
        [shuffledns]="github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
        [katana]="github.com/projectdiscovery/katana/cmd/katana@latest"
        [hakrawler]="github.com/hakluke/hakrawler@latest"
        [gauplus]="github.com/bp0lr/gauplus@latest"
        [waybackurls]="github.com/tomnomnom/waybackurls@latest"
        [subjs]="github.com/lc/subjs@latest"
        [qsreplace]="github.com/tomnomnom/qsreplace@latest"
        [gf]="github.com/tomnomnom/gf@latest"
        [subzy]="github.com/LukaSikic/subzy@latest"
        [gowitness]="github.com/sensepost/gowitness@latest"
        [feroxbuster]="github.com/epi052/feroxbuster@latest"
    )

    for tool in "${!GOTOOLS[@]}"; do
        if command -v "$tool" &>/dev/null; then
            ok "$tool already installed"
        else
            info "Installing $tool..."
            go install "${GOTOOLS[$tool]}" && ok "$tool installed" || err "$tool failed"
        fi
    done
}

# ---------------------------------------------------------------
# Python packages (pip3)
# ---------------------------------------------------------------
install_python_packages() {
    info "Installing Python packages..."
    pip3 install --user --upgrade \
        rich \
        uro \
        arjun \
        xnlinkfinder \
        jsbeautifier 2>/dev/null && ok "Python packages done" || err "Some pip packages failed"
}

# ---------------------------------------------------------------
# GF patterns
# ---------------------------------------------------------------
install_gf_patterns() {
    if command -v gf &>/dev/null && [ ! -d "$HOME/.gf" ]; then
        info "Installing GF patterns..."
        git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns "$HOME/Gf-Patterns" 2>/dev/null || true
        mkdir -p "$HOME/.gf"
        cp -r "$HOME/Gf-Patterns/"* "$HOME/.gf/" 2>/dev/null || true
        ok "GF patterns installed"
    fi
}

# ---------------------------------------------------------------
# Nuclei templates
# ---------------------------------------------------------------
install_nuclei_templates() {
    if command -v nuclei &>/dev/null; then
        info "Updating Nuclei templates..."
        nuclei -update-templates 2>/dev/null && ok "Nuclei templates updated" || true
    fi
}

# ---------------------------------------------------------------
# Main
# ---------------------------------------------------------------
echo ""
echo "  ReconX Framework — Installer"
echo "  ─────────────────────────────"
echo ""

install_system_packages
install_go_tools
install_python_packages
install_gf_patterns
install_nuclei_templates

# Copy resolver list
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$SCRIPT_DIR/config/resolvers.txt" ] && [ ! -f "$HOME/resolvers.txt" ]; then
    cp "$SCRIPT_DIR/config/resolvers.txt" "$HOME/resolvers.txt"
    ok "Resolver list copied to ~/resolvers.txt"
fi

# SecLists (optional — better bruteforce wordlist)
if [ ! -d "$HOME/Documents/SecLists" ] && [ ! -d "/usr/share/seclists" ]; then
    echo ""
    info "For better bruteforce results, install SecLists:"
    info "  git clone --depth 1 https://github.com/danielmiessler/SecLists.git ~/Documents/SecLists"
fi

echo ""
ok "Installation complete!"
echo ""
echo "  Run:  python3 recon.py --check"
echo ""

# Add Go bin to PATH recommendation
case "$SHELL" in
    */bash) SHELLRC="$HOME/.bashrc" ;;
    */zsh)  SHELLRC="$HOME/.zshrc" ;;
    *)      SHELLRC="$HOME/.profile" ;;
esac

if ! grep -q 'export PATH=$PATH:$HOME/go/bin' "$SHELLRC" 2>/dev/null; then
    echo ""
    info "Add Go binaries to your PATH:"
    echo "    echo 'export PATH=\$PATH:\$HOME/go/bin' >> $SHELLRC"
    echo "    source $SHELLRC"
fi
