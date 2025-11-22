#!/usr/bin/env bash
# recon-pipeline-setup.sh
# One-shot installer + pipeline scaffold for recon -> detection -> crawl -> blind-xss delivery
# Target: 

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

