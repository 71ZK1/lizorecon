# lizorecon
🦎 Automated recon pipeline for bug bounty — chains subfinder, httpx, katana, gau, nuclei &amp; more into one script. Discovers max URLs, auto-sorts params by vuln class (XSS/SQLi/SSRF/LFI/IDOR), fault-tolerant, zero manual setup.
# -lizorecon-

Automated recon pipeline: subdomains → live hosts → crawled + historical URLs → sorted parameters → vulnerability scan — all in one script, output neatly organized on disk.

```
subfinder + assetfinder + amass  →  dnsx + httpx  →  katana + gau + waybackurls  →  gf (sorted by vuln class)  →  nuclei + dalfox
```

## Features

- **Multi-source subdomain enumeration** — subfinder, assetfinder, amass, merged and deduplicated
- **Resolution + live host probing** — dnsx, httpx (with title/tech-detect/status-code)
- **Maximum URL discovery** — katana (active crawl, JS-aware) + gau + waybackurls (historical), merged and deduplicated
- **Automatic sorting** — parameterized URLs are split into categories (XSS, SQLi, SSRF, open redirect, LFI, RCE, IDOR, etc.) using `gf` patterns, with a keyword-based fallback if `gf` isn't installed
- **Vulnerability scanning** — nuclei on live hosts, dalfox on XSS-candidate parameters
- **Screenshots** (optional) — gowitness, if installed
- **Fault-tolerant** — every stage checks whether its tool is installed first; missing tools are skipped with a warning instead of crashing the script
- **Organized output** — everything lands in a clean folder structure per target, ready to grep/review

## Output structure

```
lizorecon-results/<domain>/
├── raw/
│   ├── subfinder.txt / assetfinder.txt / amass.txt
│   ├── subdomains.txt          # merged + deduped
│   ├── resolved.txt
│   ├── live_hosts.txt          # full httpx output (title, tech, status)
│   ├── live_hosts_clean.txt    # URL-only, for piping into other tools
│   ├── open_ports.txt          # if naabu installed
│   ├── katana.txt / gau.txt / wayback.txt
├── urls/
│   ├── all_urls.txt            # every URL found, merged + deduped
│   ├── js_files.txt            # .js files pulled out separately
│   ├── endpoints.txt           # non-JS URLs
│   └── params/
│       ├── all_params.txt      # every URL with a query string
│       ├── xss.txt
│       ├── sqli.txt
│       ├── ssrf.txt
│       ├── redirect.txt
│       ├── lfi.txt
│       ├── idor.txt
│       └── ...                 # only created if matches are found
├── scans/
│   ├── nuclei_report.txt
│   └── dalfox_report.txt
└── screenshots/                # if gowitness installed
```

## Installation

Requires Go 1.21+ and git.

```bash
git clone https://github.com/<your-username>/lizorecon.git
cd lizorecon
chmod +x install.sh lizorecon.sh
./install.sh
```

`install.sh` installs every supported tool via `go install` and sets up `gf` patterns and nuclei templates. Core tools (subfinder, httpx, katana, nuclei) are required for meaningful output; everything else is optional — `lizorecon.sh` detects and skips anything not installed.

Make sure `$GOPATH/bin` (usually `~/go/bin`) is on your `PATH`:

```bash
export PATH=$PATH:$HOME/go/bin
```

## Usage

```bash
./lizorecon.sh -d example.com
```

### Options

| Flag | Description |
|---|---|
| `-d, --domain <domain>` | Target domain (required) |
| `--fast` | Skip amass, reduce katana crawl depth — faster, less thorough |
| `--no-scan` | Recon only, skip nuclei/dalfox vulnerability scanning |
| `-t, --threads <n>` | Thread count passed to supporting tools (default: 50) |
| `-h, --help` | Show help |

### Examples

```bash
# Full run
./lizorecon.sh -d example.com

# Quick pass, no amass, shallower crawl
./lizorecon.sh -d example.com --fast

# Recon only, no vuln scanning
./lizorecon.sh -d example.com --no-scan
```

## Tool list

See [`requirements.txt`](./requirements.txt) for the full list of tools used and their source repos.

## Notes

- This tool only orchestrates publicly available, well-known recon tools (ProjectDiscovery suite, tomnomnom's tools, amass, etc.) — it does not contain any exploit or scanning logic of its own.
- **Only run this against domains/assets you own or are explicitly authorized to test.** Unauthorized scanning may be illegal in your jurisdiction.
- Large targets with amass + deep katana crawling can take a long time — use `--fast` for quicker iteration.

## License

MIT — see [LICENSE](./LICENSE).
