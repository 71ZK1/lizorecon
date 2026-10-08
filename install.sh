#!/usr/bin/env bash
#
# install.sh — installs every tool lizorecon.sh can use.
# Core tools (subfinder, httpx, katana, nuclei) are required.
# Everything else is optional — lizorecon.sh auto-skips anything missing.
#
# Usage:
#   ./install.sh            # installs only what's missing
#   ./install.sh --force    # reinstalls/updates every tool regardless
#
set -uo pipefail

FORCE=false
if [[ "${1:-}" == "--force" ]]; then
    FORCE=true
fi

echo "[*] lizorecon installer"
$FORCE && echo "[*] --force passed: reinstalling/updating every tool regardless of existing install"

if ! command -v go >/dev/null 2>&1; then
    echo "[-] Go is not installed. Install Go 1.21+ first: https://go.dev/doc/install"
    exit 1
fi

export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$PATH:$GOPATH/bin"

install_go_tool() {
    local name="$1"; local pkg="$2"

    if command -v "$name" >/dev/null 2>&1 && ! $FORCE; then
        echo "[=] $name already installed — skipping (use --force to reinstall)"
        return 0
    fi

    echo "[*] Installing $name..."
    if go install "$pkg" 2>/dev/null; then
        echo "[+] $name installed"
    else
        echo "[-] Failed to install $name (continuing)"
    fi
}

# --- Core (required) ---
install_go_tool "subfinder"  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go_tool "httpx"      "github.com/projectdiscovery/httpx/cmd/httpx@latest"
install_go_tool "katana"     "github.com/projectdiscovery/katana/cmd/katana@latest"
install_go_tool "nuclei"     "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

# --- Recommended (optional, improve coverage) ---
install_go_tool "dnsx"         "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
install_go_tool "naabu"        "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
install_go_tool "assetfinder"  "github.com/tomnomnom/assetfinder@latest"
install_go_tool "gau"          "github.com/lc/gau/v2/cmd/gau@latest"
install_go_tool "waybackurls"  "github.com/tomnomnom/waybackurls@latest"
install_go_tool "gf"           "github.com/tomnomnom/gf@latest"
install_go_tool "dalfox"       "github.com/hahwul/dalfox/v2@latest"
install_go_tool "gowitness"    "github.com/sensepost/gowitness@latest"
install_go_tool "anew"         "github.com/tomnomnom/anew@latest"

# amass is heavier; install_go_tool already skips it if present (unless --force)
install_go_tool "amass" "github.com/owasp-amass/amass/v4/...@latest"

# --- gf patterns (required for gf to actually do anything useful) ---
if command -v gf >/dev/null 2>&1; then
    if [[ -d "$HOME/.gf/Gf-Patterns" ]] && ! $FORCE; then
        echo "[=] gf patterns already present — skipping (use --force to re-fetch)"
    else
        echo "[*] Setting up gf patterns..."
        mkdir -p "$HOME/.gf"
        git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns "$HOME/.gf/Gf-Patterns" 2>/dev/null \
            && cp "$HOME/.gf/Gf-Patterns"/*.json "$HOME/.gf/" \
            && echo "[+] gf patterns installed" \
            || echo "[-] Could not fetch gf patterns — clone https://github.com/1ndianl33t/Gf-Patterns into ~/.gf manually"
    fi
fi

# --- nuclei templates ---
if command -v nuclei >/dev/null 2>&1; then
    echo "[*] Updating nuclei templates..."
    nuclei -update-templates -silent 2>/dev/null || true
fi

echo
echo "[+] Install step finished."
echo "    Make sure \$GOPATH/bin (usually ~/go/bin) is in your PATH:"
echo "    export PATH=\$PATH:\$HOME/go/bin"
echo
echo "    Run: ./lizorecon.sh -d example.com"
