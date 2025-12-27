#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="$SCRIPT_DIR/../certs"
ROOT_CA_FILE="$CERTS_DIR/root-ca.crt"
SYSTEM_CERT_NAME="mtls-test-root-ca.crt"

# Linux paths
LINUX_CERT_DIR="/usr/local/share/ca-certificates"
LINUX_CERT_PATH="$LINUX_CERT_DIR/$SYSTEM_CERT_NAME"

function print_usage() {
    echo -e "${CYAN}Usage:${NC}"
    echo "  $0 install   - Install the root CA in the system trust store"
    echo "  $0 uninstall - Remove the root CA from the system trust store"
    echo ""
}

function install_cert() {
    echo -e "${CYAN}Installing root CA to system trust store...${NC}"

    # Check if cert file exists
    if [ ! -f "$ROOT_CA_FILE" ]; then
        echo -e "${RED}Error: Root CA certificate not found at: $ROOT_CA_FILE${NC}"
        echo -e "${YELLOW}Please run setup-certificates.ps1 first${NC}"
        exit 1
    fi

    # Check if already installed
    if [ -f "$LINUX_CERT_PATH" ]; then
        echo -e "${YELLOW}Root CA already installed in system trust store${NC}"
        read -p "Reinstall? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}Skipping installation${NC}"
            exit 0
        fi
    fi

    # Copy cert to system trust store
    echo -e "${CYAN}Copying certificate to $LINUX_CERT_DIR...${NC}"
    sudo cp "$ROOT_CA_FILE" "$LINUX_CERT_PATH"

    # Update trust store
    echo -e "${CYAN}Updating system trust store...${NC}"
    sudo update-ca-certificates

    echo ""
    echo -e "${GREEN}✅ Root CA successfully installed in system trust store${NC}"
    echo -e "${CYAN}Certificate:${NC} $LINUX_CERT_PATH"
    echo ""
    echo -e "${YELLOW}Note:${NC} You can now remove CustomRootTrust code and use standard OCSP validation"
}

function uninstall_cert() {
    echo -e "${CYAN}Removing root CA from system trust store...${NC}"

    # Check if installed
    if [ ! -f "$LINUX_CERT_PATH" ]; then
        echo -e "${YELLOW}Root CA not found in system trust store${NC}"
        exit 0
    fi

    # Remove cert
    echo -e "${CYAN}Removing certificate from $LINUX_CERT_DIR...${NC}"
    sudo rm -f "$LINUX_CERT_PATH"

    # Update trust store
    echo -e "${CYAN}Updating system trust store...${NC}"
    sudo update-ca-certificates --fresh

    echo ""
    echo -e "${GREEN}✅ Root CA successfully removed from system trust store${NC}"
}

# Main script
case "${1:-}" in
    install)
        install_cert
        ;;
    uninstall)
        uninstall_cert
        ;;
    *)
        echo -e "${RED}Error: Invalid command${NC}"
        echo ""
        print_usage
        exit 1
        ;;
esac
