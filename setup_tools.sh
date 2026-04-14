#!/bin/bash
# setup_tools.sh — BugHunter Pro Dependency Installer (ProjectDiscovery Tools)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}[*] BugHunter Pro v2.0 Tool Installer${NC}"
echo -e "${CYAN}[*] Targeting: subfinder, nuclei, httpx${NC}\n"

# 1. Check for Go
if ! command -v go &> /dev/null; then
    echo -e "${YELLOW}[!] Go is not installed. Installing Go...${NC}"
    sudo apt-get update
    sudo apt-get install -y golang
else
    echo -e "${GREEN}[✓] Go is already installed.${NC}"
fi

# Ensure go/bin is in PATH
export PATH=$PATH:$(go env GOPATH)/bin
echo "export PATH=\$PATH:\$(go env GOPATH)/bin" >> ~/.bashrc
source ~/.bashrc

# 2. Install Subfinder
echo -e "${CYAN}[*] Installing Subfinder...${NC}"
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# 3. Install Nuclei
echo -e "${CYAN}[*] Installing Nuclei...${NC}"
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# 4. Install Httpx
echo -e "${CYAN}[*] Installing Httpx...${NC}"
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# 5. Install Dnsx
echo -e "${CYAN}[*] Installing Dnsx...${NC}"
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

echo -e "\n${GREEN}[✓] Installation Complete!${NC}"
echo -e "${YELLOW}[!] Please run 'source ~/.bashrc' or restart your terminal before using BugHunter Pro.${NC}"
echo -e "${CYAN}[*] You can now reach 100% scanning efficiency.${NC}"
