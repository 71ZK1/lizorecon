#!/usr/bin/env bash
#
# lizorecon - automated recon pipeline
# subdomains -> live hosts -> crawled/historical URLs -> sorted params -> vuln scan
#
# Usage:
#   ./lizorecon.sh -d example.com
#   ./lizorecon.sh -d example.com --fast     (skip amass + deep katana crawl)
#   ./lizorecon.sh -d example.com --no-scan  (skip nuclei/dalfox vuln scanning)
#
set -uo pipefail
# NOTE: intentionally not using `set -e` globally — recon tools are allowed to
# fail/skip individually without killing the whole run. Each stage is guarded.

# ------------------------------------------------------------------------
# Defaults / args
# ------------------------------------------------------------------------
DOMAIN=""
FAST=false
NO_SCAN=false
THREADS=50
KATANA_DEPTH=3

usage() {
    cat <<EOF
lizorecon - maximum recon pipeline

Usage: $0 -d <domain> [options]

Options:
  -d, --domain <domain>   Target domain (required), e.g. example.com
  --fast                  Skip amass + reduce katana crawl depth (faster, less thorough)
  --no-scan               Skip nuclei/dalfox vulnerability scanning (recon only)
  -t, --threads <n>       Thread count passed to tools that support it (default: 50)
  -h, --help              Show this help

Example:
  $0 -d example.com
EOF
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--domain) DOMAIN="$2"; shift 2 ;;
        --fast) FAST=true; shift ;;
        --no-scan) NO_SCAN=true; shift ;;
        -t|--threads) THREADS="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

if [[ -z "$DOMAIN" ]]; then
    echo "[!] No domain supplied."
    usage
fi

if $FAST; then
    KATANA_DEPTH=2
fi

# ------------------------------------------------------------------------
# Colors / logging
# ------------------------------------------------------------------------
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLUE}[*]${NC} $1"; }
ok()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
err()   { echo -e "${RED}[-]${NC} $1"; }

has_cmd() { command -v "$1" >/dev/null 2>&1; }

# Run a command only if the underlying tool exists; warn + continue otherwise.
# Usage: run_stage "tool_name" "human label" -- actual command...
run_stage() {
    local tool="$1"; local label="$2"; shift 2
    if ! has_cmd "$tool"; then
        warn "$tool not found — skipping: $label"
        return 1
    fi
    info "Running: $label"
    if "$@"; then
        ok "$label done"
        return 0
    else
        err "$label failed (continuing anyway)"
        return 1
    fi
}

# ------------------------------------------------------------------------
# Directory layout
# ------------------------------------------------------------------------
BASE_DIR="$(pwd)/lizorecon-results/${DOMAIN}"
RAW_DIR="${BASE_DIR}/raw"
URLS_DIR="${BASE_DIR}/urls"
PARAMS_DIR="${URLS_DIR}/params"
SCAN_DIR="${BASE_DIR}/scans"
SHOTS_DIR="${BASE_DIR}/screenshots"

mkdir -p "$RAW_DIR" "$URLS_DIR" "$PARAMS_DIR" "$SCAN_DIR" "$SHOTS_DIR"

SUBS_FILE="${RAW_DIR}/subdomains.txt"
RESOLVED_FILE="${RAW_DIR}/resolved.txt"
LIVE_FILE="${RAW_DIR}/live_hosts.txt"
ALL_URLS="${URLS_DIR}/all_urls.txt"
JS_FILES="${URLS_DIR}/js_files.txt"
ENDPOINTS="${URLS_DIR}/endpoints.txt"

info "Target: $DOMAIN"
info "Results will be saved under: $BASE_DIR"
touch "$SUBS_FILE" "$RESOLVED_FILE" "$LIVE_FILE" "$ALL_URLS" "$JS_FILES" "$ENDPOINTS"

# ------------------------------------------------------------------------
# 1. Subdomain enumeration (multiple sources, merged + deduped)
# ------------------------------------------------------------------------
info "== Stage 1: Subdomain enumeration =="

run_stage subfinder "subfinder" subfinder -d "$DOMAIN" -all -silent -o "${RAW_DIR}/subfinder.txt"

run_stage assetfinder "assetfinder" bash -c \
    "assetfinder --subs-only '$DOMAIN' > '${RAW_DIR}/assetfinder.txt'"

if $FAST; then
    warn "Skipping amass (--fast mode)"
else
    run_stage amass "amass (active+passive, this can take a while)" bash -c \
        "amass enum -d '$DOMAIN' -o '${RAW_DIR}/amass.txt'"
fi

# Merge all subdomain sources + the root domain itself, dedupe
cat "${RAW_DIR}"/subfinder.txt "${RAW_DIR}"/assetfinder.txt "${RAW_DIR}"/amass.txt 2>/dev/null \
    | grep -F "$DOMAIN" | sort -u > "$SUBS_FILE" || true
echo "$DOMAIN" >> "$SUBS_FILE"
sort -u -o "$SUBS_FILE" "$SUBS_FILE"

ok "Total unique subdomains: $(wc -l < "$SUBS_FILE")"

# ------------------------------------------------------------------------
# 2. Resolve + probe for live hosts
# ------------------------------------------------------------------------
info "== Stage 2: Resolution + live host probing =="

if has_cmd dnsx; then
    run_stage dnsx "dnsx (resolving)" bash -c \
        "dnsx -l '$SUBS_FILE' -silent -o '$RESOLVED_FILE'"
else
    warn "dnsx not found — passing raw subdomain list to httpx instead"
    cp "$SUBS_FILE" "$RESOLVED_FILE"
fi

run_stage httpx "httpx (live host probing)" bash -c \
    "httpx -l '$RESOLVED_FILE' -silent -title -tech-detect -status-code -o '$LIVE_FILE'"

# httpx with extra flags prints more than a bare URL per line; keep a clean
# URL-only version for tools downstream that just want a host list.
LIVE_CLEAN="${RAW_DIR}/live_hosts_clean.txt"
awk '{print $1}' "$LIVE_FILE" | sort -u > "$LIVE_CLEAN"
ok "Total live hosts: $(wc -l < "$LIVE_CLEAN")"

# Optional: quick port scan of resolved hosts
if has_cmd naabu && ! $FAST; then
    run_stage naabu "naabu (port scan)" bash -c \
        "naabu -l '$RESOLVED_FILE' -silent -o '${RAW_DIR}/open_ports.txt'"
fi

# Optional: screenshots for visual triage
if has_cmd gowitness; then
    run_stage gowitness "gowitness (screenshots)" bash -c \
        "gowitness file -f '$LIVE_CLEAN' -P '$SHOTS_DIR' --no-http-server"
fi

# ------------------------------------------------------------------------
# 3. URL discovery — crawling (katana) + historical (gau / waybackurls)
# ------------------------------------------------------------------------
info "== Stage 3: URL discovery =="

run_stage katana "katana (active crawl, depth $KATANA_DEPTH)" bash -c \
    "katana -list '$LIVE_CLEAN' -d $KATANA_DEPTH -jc -silent -o '${RAW_DIR}/katana.txt'"

run_stage gau "gau (historical URLs)" bash -c \
    "gau --subs '$DOMAIN' > '${RAW_DIR}/gau.txt'"

run_stage waybackurls "waybackurls (wayback machine)" bash -c \
    "cat '$LIVE_CLEAN' | waybackurls > '${RAW_DIR}/wayback.txt'"

# Merge every URL source, dedupe
cat "${RAW_DIR}"/katana.txt "${RAW_DIR}"/gau.txt "${RAW_DIR}"/wayback.txt 2>/dev/null \
    | sort -u > "$ALL_URLS" || true
ok "Total unique URLs discovered: $(wc -l < "$ALL_URLS")"

# Pull out JS files separately (common source of leaked endpoints/secrets)
grep -Ei '\.js(\?|$)' "$ALL_URLS" | sort -u > "$JS_FILES" || true
ok "JS files found: $(wc -l < "$JS_FILES")"

# Everything else (non-JS) goes into a general endpoints file
grep -Eiv '\.js(\?|$)' "$ALL_URLS" | sort -u > "$ENDPOINTS" || true

# ------------------------------------------------------------------------
# 4. Sort URLs by parameter / vuln-class using gf patterns
#    (falls back to plain `grep` matching if gf/patterns aren't installed)
# ------------------------------------------------------------------------
info "== Stage 4: Sorting parameterized URLs =="

# URLs that actually carry a query string — the ones worth testing
grep '=' "$ALL_URLS" | sort -u > "${PARAMS_DIR}/all_params.txt" || true
ok "URLs with parameters: $(wc -l < "${PARAMS_DIR}/all_params.txt")"

if has_cmd gf; then
    declare -a GF_PATTERNS=(xss sqli ssrf redirect lfi rce idor ssti debug_logic)
    for pattern in "${GF_PATTERNS[@]}"; do
        out="${PARAMS_DIR}/${pattern}.txt"
        if cat "$ALL_URLS" | gf "$pattern" 2>/dev/null | sort -u > "$out"; then
            count=$(wc -l < "$out")
            [[ "$count" -gt 0 ]] && ok "  $pattern: $count" || rm -f "$out"
        else
            rm -f "$out"
        fi
    done
else
    warn "gf not found — falling back to basic keyword matching for sorting"
    grep -Ei '(\?|&)(url|redirect|next|dest|return)=' "$ALL_URLS" | sort -u > "${PARAMS_DIR}/redirect.txt" 2>/dev/null
    grep -Ei '(\?|&)(file|path|doc|folder|include)=' "$ALL_URLS" | sort -u > "${PARAMS_DIR}/lfi.txt" 2>/dev/null
    grep -Ei '(\?|&)(id|user|account|number|order)=' "$ALL_URLS" | sort -u > "${PARAMS_DIR}/idor.txt" 2>/dev/null
    grep -Ei '(\?|&)(q|search|query|keyword|s)=' "$ALL_URLS" | sort -u > "${PARAMS_DIR}/xss.txt" 2>/dev/null
    find "$PARAMS_DIR" -maxdepth 1 -type f -empty -delete
fi

# ------------------------------------------------------------------------
# 5. Vulnerability scanning
# ------------------------------------------------------------------------
if $NO_SCAN; then
    warn "Skipping vulnerability scanning (--no-scan)"
else
    info "== Stage 5: Vulnerability scanning =="

    run_stage nuclei "nuclei (vuln scan on live hosts)" bash -c \
        "nuclei -l '$LIVE_CLEAN' -silent -o '${SCAN_DIR}/nuclei_report.txt'"

    if has_cmd dalfox && [[ -s "${PARAMS_DIR}/xss.txt" ]]; then
        run_stage dalfox "dalfox (XSS scan on candidate params)" bash -c \
            "dalfox file '${PARAMS_DIR}/xss.txt' --silence -o '${SCAN_DIR}/dalfox_report.txt'"
    fi
fi

# ------------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------------
echo
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN} lizorecon finished: $DOMAIN${NC}"
echo -e "${GREEN}========================================${NC}"
echo "Subdomains found:   $(wc -l < "$SUBS_FILE" 2>/dev/null || echo 0)"
echo "Live hosts:         $(wc -l < "$LIVE_CLEAN" 2>/dev/null || echo 0)"
echo "Total URLs:         $(wc -l < "$ALL_URLS" 2>/dev/null || echo 0)"
echo "Parameterized URLs: $(wc -l < "${PARAMS_DIR}/all_params.txt" 2>/dev/null || echo 0)"
echo "JS files:           $(wc -l < "$JS_FILES" 2>/dev/null || echo 0)"
echo
echo "Results saved in: $BASE_DIR"
[[ -d "$PARAMS_DIR" ]] && echo "Sorted param categories:" && ls "$PARAMS_DIR" 2>/dev/null | sed 's/^/  - /'
echo
