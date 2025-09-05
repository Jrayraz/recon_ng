# Install Go and Git
sudo apt update && sudo apt install -y golang-go git

# Set Go environment (add to ~/.bashrc or ~/.zshrc for persistence)
export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin"

# Install Subfinder (subdomain enumeration)
GO111MODULE=on go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Install Subjack (subdomain takeover detection)
GO111MODULE=on go install github.com/haccer/subjack@latest
