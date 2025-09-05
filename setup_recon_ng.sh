#!/bin/bash

# Prompt for username
read -p "Username?: " USERNAME

# Define working directory
HOME="/home/$USERNAME"
RECON_NG="$HOME/Recon_NG"
mkdir -p "$RECON_NG"
VDIR="$RECON_NG/DVIR"
mkdir -p "$VDIR"
TOOLS_DIR="$VDIR/tools"
mkdir -p "$TOOLS_DIR"

# Update and install apt dependencies
echo "[+] Installing apt dependencies..."
sudo apt update && sudo apt install -y \
  git \
  python3-full \
  curl \
  wget \
  unzip \
  build-essential \
  jq \
  libssl-dev \
  libpcap-dev \
  dnsutils \
  whois \
  nmap \
  python3-pip

# Install Go
cd "$TOOLS_DIR"
echo "[+] Installing Go..."
GO_VERSION="1.21.1"
wget "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf /tmp/go.tar.gz
echo "export PATH=\$PATH:/usr/local/go/bin" >> "/home/$USERNAME/.bashrc"
export PATH=$PATH:/usr/local/go/bin

# Clone and build Subjack
echo "[+] Cloning and building Subjack..."
cd "$TOOLS_DIR"
git clone https://github.com/haccer/subjack.git
cd subjack
go build
sudo mv subjack /usr/local/bin/

# Install Subfinder
echo "[+] Installing Subfinder..."
cd "$TOOLS_DIR"
git clone https://github.com/projectdiscovery/subfinder.git
cd subfinder
go build
sudo mv subfinder /usr/local/bin/

# Verify installs
echo "[+] Verifying installations..."
command -v subjack && echo "Subjack installed ✔"
command -v subfinder && echo "Subfinder installed ✔"

echo "[+] Installing dnsx..."
cd "$TOOLS_DIR"
git clone https://github.com/projectdiscovery/dnsx.git
cd dnsx
go build
sudo mv dnsx /usr/local/bin/

echo "[+] Downloading wordlists..."
sudo mkdir -p /usr/share/wordlists
sudo wget https://github.com/danielmiessler/SecLists/raw/master/Discovery/DNS/subdomains-top1million-5000.txt -O /usr/share/wordlists/subdomains.txt
sudo wget https://github.com/koaj/aws-s3-bucket-wordlist/raw/master/common-s3-bucket-names-list.txt -O /usr/share/wordlists/s3_buckets.txt

./recon_tools.sh

echo "[✓] Setup complete. Tools installed in: $TOOLS_DIR"

