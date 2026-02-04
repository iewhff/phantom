#!/bin/bash
# Setup script for AI-Enhanced Pentesting Framework

set -e

echo "======================================"
echo "AI-Enhanced Pentesting Framework Setup"
echo "======================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check Python version
check_python() {
    echo -e "\n${YELLOW}Checking Python version...${NC}"
    
    if command -v python3.11 &> /dev/null; then
        PYTHON_CMD="python3.11"
    elif command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        if [[ $(echo "$PYTHON_VERSION >= 3.11" | bc -l) -eq 1 ]]; then
            PYTHON_CMD="python3"
        else
            echo -e "${RED}Python 3.11+ required. Found: $PYTHON_VERSION${NC}"
            exit 1
        fi
    else
        echo -e "${RED}Python 3 not found. Please install Python 3.11+${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}Using $PYTHON_CMD${NC}"
}

# Create virtual environment
create_venv() {
    echo -e "\n${YELLOW}Creating virtual environment...${NC}"
    
    if [ -d ".venv" ]; then
        echo "Virtual environment already exists"
    else
        $PYTHON_CMD -m venv .venv
        echo -e "${GREEN}Virtual environment created${NC}"
    fi
    
    # Activate
    source .venv/bin/activate
}

# Install dependencies
install_deps() {
    echo -e "\n${YELLOW}Installing Python dependencies...${NC}"
    
    pip install --upgrade pip
    pip install -e ".[dev]"
    
    echo -e "${GREEN}Dependencies installed${NC}"
}

# Create directory structure
create_dirs() {
    echo -e "\n${YELLOW}Creating directory structure...${NC}"
    
    mkdir -p data/reports
    mkdir -p data/checkpoints
    mkdir -p data/logs
    mkdir -p data/knowledge_base
    mkdir -p templates
    
    echo -e "${GREEN}Directories created${NC}"
}

# Setup configuration
setup_config() {
    echo -e "\n${YELLOW}Setting up configuration...${NC}"
    
    if [ ! -f "config/settings.yaml" ]; then
        echo -e "${RED}config/settings.yaml not found!${NC}"
        exit 1
    fi
    
    # Create local override if not exists
    if [ ! -f "config/settings.local.yaml" ]; then
        cp config/settings.yaml config/settings.local.yaml
        echo "Created config/settings.local.yaml for local overrides"
    fi
    
    echo -e "${GREEN}Configuration ready${NC}"
}

# Install external tools
install_tools() {
    echo -e "\n${YELLOW}Checking external tools...${NC}"
    
    # Check for nuclei
    if command -v nuclei &> /dev/null; then
        echo -e "${GREEN}✓ Nuclei found${NC}"
    else
        echo -e "${YELLOW}Installing Nuclei...${NC}"
        if command -v go &> /dev/null; then
            go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
        else
            echo -e "${YELLOW}Go not found. Please install Nuclei manually.${NC}"
            echo "Visit: https://github.com/projectdiscovery/nuclei"
        fi
    fi
    
    # Check for nmap
    if command -v nmap &> /dev/null; then
        echo -e "${GREEN}✓ Nmap found${NC}"
    else
        echo -e "${YELLOW}Nmap not found. Please install: sudo apt install nmap${NC}"
    fi
    
    # Check for subfinder
    if command -v subfinder &> /dev/null; then
        echo -e "${GREEN}✓ Subfinder found${NC}"
    else
        echo -e "${YELLOW}Subfinder not found. Install with: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest${NC}"
    fi
}

# Setup Ollama
setup_ollama() {
    echo -e "\n${YELLOW}Checking Ollama...${NC}"
    
    if command -v ollama &> /dev/null; then
        echo -e "${GREEN}✓ Ollama found${NC}"
        
        # Check if model is available
        if ollama list | grep -q "mistral"; then
            echo -e "${GREEN}✓ Mistral model available${NC}"
        else
            echo -e "${YELLOW}Pulling Mistral model...${NC}"
            ollama pull mistral
        fi
    else
        echo -e "${YELLOW}Ollama not found.${NC}"
        echo "Install from: https://ollama.ai"
        echo "Or use Docker: docker-compose up ollama"
    fi
}

# Main setup
main() {
    check_python
    create_venv
    install_deps
    create_dirs
    setup_config
    install_tools
    setup_ollama
    
    echo -e "\n${GREEN}======================================"
    echo "Setup complete!"
    echo "======================================"
    echo ""
    echo "To activate the environment:"
    echo "  source .venv/bin/activate"
    echo ""
    echo "To run a scan:"
    echo "  pentest scan example.com"
    echo ""
    echo "To check configuration:"
    echo "  pentest config"
    echo ""
    echo -e "For help: pentest --help${NC}"
}

main "$@"
