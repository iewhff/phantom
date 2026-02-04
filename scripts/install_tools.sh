#!/bin/bash
# Install external security tools

set -e

echo "======================================"
echo "Installing Security Tools"
echo "======================================"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -f /etc/debian_version ]; then
            OS="debian"
        elif [ -f /etc/redhat-release ]; then
            OS="redhat"
        elif [ -f /etc/arch-release ]; then
            OS="arch"
        else
            OS="linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
    else
        echo -e "${RED}Unsupported OS: $OSTYPE${NC}"
        exit 1
    fi
    echo -e "${GREEN}Detected OS: $OS${NC}"
}

# Install Go if needed
install_go() {
    if command -v go &> /dev/null; then
        echo -e "${GREEN}Go already installed${NC}"
        return
    fi
    
    echo -e "${YELLOW}Installing Go...${NC}"
    
    case $OS in
        debian)
            sudo apt-get update
            sudo apt-get install -y golang-go
            ;;
        redhat)
            sudo yum install -y golang
            ;;
        arch)
            sudo pacman -S go
            ;;
        macos)
            brew install go
            ;;
    esac
    
    # Setup Go paths
    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin
    
    echo 'export GOPATH=$HOME/go' >> ~/.bashrc
    echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
}

# Install Nuclei
install_nuclei() {
    echo -e "\n${YELLOW}Installing Nuclei...${NC}"
    
    if command -v nuclei &> /dev/null; then
        echo -e "${GREEN}Nuclei already installed${NC}"
        nuclei -version
        return
    fi
    
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    
    # Update templates
    nuclei -update-templates
    
    echo -e "${GREEN}Nuclei installed${NC}"
}

# Install Subfinder
install_subfinder() {
    echo -e "\n${YELLOW}Installing Subfinder...${NC}"
    
    if command -v subfinder &> /dev/null; then
        echo -e "${GREEN}Subfinder already installed${NC}"
        return
    fi
    
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    
    echo -e "${GREEN}Subfinder installed${NC}"
}

# Install httpx
install_httpx() {
    echo -e "\n${YELLOW}Installing httpx (ProjectDiscovery)...${NC}"
    
    if command -v httpx &> /dev/null; then
        echo -e "${GREEN}httpx already installed${NC}"
        return
    fi
    
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    
    echo -e "${GREEN}httpx installed${NC}"
}

# Install Nmap
install_nmap() {
    echo -e "\n${YELLOW}Installing Nmap...${NC}"
    
    if command -v nmap &> /dev/null; then
        echo -e "${GREEN}Nmap already installed${NC}"
        return
    fi
    
    case $OS in
        debian)
            sudo apt-get update
            sudo apt-get install -y nmap
            ;;
        redhat)
            sudo yum install -y nmap
            ;;
        arch)
            sudo pacman -S nmap
            ;;
        macos)
            brew install nmap
            ;;
    esac
    
    echo -e "${GREEN}Nmap installed${NC}"
}

# Install Amass
install_amass() {
    echo -e "\n${YELLOW}Installing Amass...${NC}"
    
    if command -v amass &> /dev/null; then
        echo -e "${GREEN}Amass already installed${NC}"
        return
    fi
    
    go install -v github.com/owasp-amass/amass/v4/...@master
    
    echo -e "${GREEN}Amass installed${NC}"
}

# Install ffuf
install_ffuf() {
    echo -e "\n${YELLOW}Installing ffuf...${NC}"
    
    if command -v ffuf &> /dev/null; then
        echo -e "${GREEN}ffuf already installed${NC}"
        return
    fi
    
    go install github.com/ffuf/ffuf/v2@latest
    
    echo -e "${GREEN}ffuf installed${NC}"
}

# Install additional tools
install_additional() {
    echo -e "\n${YELLOW}Installing additional tools...${NC}"
    
    case $OS in
        debian)
            sudo apt-get install -y \
                curl \
                wget \
                whois \
                dnsutils \
                netcat-openbsd \
                jq
            ;;
        redhat)
            sudo yum install -y \
                curl \
                wget \
                whois \
                bind-utils \
                nc \
                jq
            ;;
        macos)
            brew install \
                curl \
                wget \
                whois \
                bind \
                netcat \
                jq
            ;;
    esac
}

# Verify installations
verify_installations() {
    echo -e "\n${YELLOW}Verifying installations...${NC}"
    
    tools=("nuclei" "subfinder" "httpx" "nmap" "amass" "ffuf")
    
    for tool in "${tools[@]}"; do
        if command -v $tool &> /dev/null; then
            echo -e "${GREEN}✓ $tool${NC}"
        else
            echo -e "${RED}✗ $tool not found${NC}"
        fi
    done
}

# Main
main() {
    detect_os
    install_go
    install_nmap
    install_nuclei
    install_subfinder
    install_httpx
    install_amass
    install_ffuf
    install_additional
    verify_installations
    
    echo -e "\n${GREEN}======================================"
    echo "Tool installation complete!"
    echo "======================================${NC}"
    echo ""
    echo "You may need to reload your shell or run:"
    echo "  source ~/.bashrc"
}

main "$@"
