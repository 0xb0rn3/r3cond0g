#!/usr/bin/env bash
#===============================================================================
# R3COND0G Web Installer
# Can be run directly: curl -sSL https://install.r3cond0g.io | bash
#===============================================================================

set -euo pipefail

# Configuration
REPO_URL="https://github.com/0xb0rn3/r3cond0g.git"
INSTALL_DIR="${HOME}/r3cond0g"
BINARY_NAME="r3cond0g"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Banner
echo -e "${CYAN}"
cat << "EOF"
    ____  _____                      _  ___   ____ 
   |  _ \|___ /  ___ ___  _ __   __| |/ _ \ / ___|
   | |_) | |_ \ / __/ _ \| '_ \ / _` | | | | |  _ 
   |  _ < ___) | (_| (_) | | | | (_| | |_| | |_| |
   |_| \_\____/ \___\___/|_| |_|\__,_|\___/ \____|
                                                   
   Web Installer v3.0.0
EOF
echo -e "${NC}"

# Check if already installed
if [ -d "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}R3COND0G is already installed at $INSTALL_DIR${NC}"
    read -p "Reinstall? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 0
    fi
    rm -rf "$INSTALL_DIR"
fi

# Clone repository
echo -e "${CYAN}[*] Cloning R3COND0G repository...${NC}"
git clone "$REPO_URL" "$INSTALL_DIR" || {
    echo -e "${RED}Failed to clone repository${NC}"
    exit 1
}

# Change to install directory
cd "$INSTALL_DIR"

# Make run script executable
chmod +x run

# Run setup
echo -e "${CYAN}[*] Running setup...${NC}"
./run setup

# Add to PATH
echo -e "${CYAN}[*] Adding to PATH...${NC}"
SHELL_RC="${HOME}/.bashrc"
[ -f "${HOME}/.zshrc" ] && SHELL_RC="${HOME}/.zshrc"

if ! grep -q "r3cond0g" "$SHELL_RC"; then
    echo "" >> "$SHELL_RC"
    echo "# R3COND0G" >> "$SHELL_RC"
    echo "export PATH=\"\$PATH:$INSTALL_DIR\"" >> "$SHELL_RC"
    echo "alias r3cond0g='$INSTALL_DIR/run'" >> "$SHELL_RC"
fi

# Create system-wide symlink (optional)
if command -v sudo >/dev/null 2>&1; then
    read -p "Create system-wide command? (requires sudo) (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo ln -sf "$INSTALL_DIR/run" /usr/local/bin/r3cond0g
    fi
fi

echo -e "${GREEN}"
echo "════════════════════════════════════════════════════════"
echo " ✔ R3COND0G installed successfully!"
echo "════════════════════════════════════════════════════════"
echo -e "${NC}"
echo ""
echo "Installation directory: $INSTALL_DIR"
echo ""
echo "To get started:"
echo "  cd $INSTALL_DIR"
echo "  ./run"
echo ""
echo "Or use the alias:"
echo "  r3cond0g"
echo ""
echo -e "${YELLOW}Note: Restart your terminal or run: source $SHELL_RC${NC}"
