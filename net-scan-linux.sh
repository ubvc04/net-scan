#!/bin/bash

# NetScan - Network Packet Capture Tool for Linux
# Comprehensive setup, dependency installation, and packet capture starter
# Compatible with all Linux distributions including Arch Linux

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"
PYTHON_EXEC="python3"

# Print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Show banner
show_banner() {
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    NetScan - Linux Edition                  ║"
    echo "║              Network Packet Capture & Analysis              ║"
    echo "║                                                              ║"
    echo "║  Supports 40+ protocols: TCP, UDP, ICMP, ARP, IPv6, DNS,    ║"
    echo "║  DHCP, HTTP, HTTPS, FTP, SSH, SMTP, SNMP, and many more!    ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Check privileges (now optional - can run in normal user mode)
check_privileges() {
    if [[ $EUID -eq 0 ]]; then
        # Get the actual user who invoked sudo
        if [ -n "$SUDO_USER" ]; then
            ACTUAL_USER="$SUDO_USER"
            ACTUAL_HOME="/home/$SUDO_USER"
        else
            ACTUAL_USER="root"
            ACTUAL_HOME="/root"
        fi
        print_success "Running with root privileges (user: $ACTUAL_USER)"
    else
        ACTUAL_USER="$(whoami)"
        ACTUAL_HOME="$HOME"
        print_warning "Running in normal user mode - limited packet capture capabilities"
        print_status "For full packet capture, run with sudo: sudo $0"
    fi
}

# Detect Linux distribution
detect_distro() {
    if [ -f /etc/arch-release ]; then
        DISTRO="arch"
        PACKAGE_MANAGER="pacman"
    elif [ -f /etc/debian_version ]; then
        DISTRO="debian"
        PACKAGE_MANAGER="apt"
    elif [ -f /etc/redhat-release ]; then
        DISTRO="redhat"
        PACKAGE_MANAGER="yum"
    elif [ -f /etc/fedora-release ]; then
        DISTRO="fedora"
        PACKAGE_MANAGER="dnf"
    else
        DISTRO="unknown"
        PACKAGE_MANAGER="unknown"
    fi
    
    print_status "Detected Linux distribution: $DISTRO"
}

# Install system dependencies if needed
install_system_deps() {
    print_status "Checking system dependencies..."
    
    case $DISTRO in
        "arch")
            # Check if python and pip are available
            if ! command -v python3 &> /dev/null; then
                print_status "Installing Python and pip on Arch Linux..."
                pacman -Sy --noconfirm python python-pip
            fi
            ;;
        "debian")
            apt update
            if ! command -v python3 &> /dev/null; then
                print_status "Installing Python and pip on Debian/Ubuntu..."
                apt install -y python3 python3-pip python3-venv
            fi
            ;;
        "redhat"|"fedora")
            if ! command -v python3 &> /dev/null; then
                print_status "Installing Python and pip on RedHat/Fedora..."
                $PACKAGE_MANAGER install -y python3 python3-pip
            fi
            ;;
        *)
            print_warning "Unknown distribution. Assuming Python3 is available."
            ;;
    esac
    
    print_success "System dependencies ready"
}

# Setup Python virtual environment
setup_venv() {
    print_status "Setting up Python virtual environment..."
    
    # Remove existing venv if it exists and is corrupted
    if [ -d "$VENV_DIR" ]; then
        if ! "$VENV_DIR/bin/python" --version &> /dev/null; then
            print_warning "Existing venv appears corrupted. Recreating..."
            rm -rf "$VENV_DIR"
        fi
    fi
    
    # Create virtual environment if it doesn't exist
    if [ ! -d "$VENV_DIR" ]; then
        print_status "Creating new virtual environment..."
        $PYTHON_EXEC -m venv "$VENV_DIR"
    fi
    
    # Verify venv creation
    if [ ! -f "$VENV_DIR/bin/activate" ]; then
        print_error "Failed to create virtual environment"
        exit 1
    fi
    
    print_success "Virtual environment ready at $VENV_DIR"
}

# Install Python dependencies
install_dependencies() {
    print_status "Installing Python dependencies..."
    
    # Use venv pip directly to avoid path issues with sudo
    VENV_PIP="$VENV_DIR/bin/pip"
    VENV_PYTHON="$VENV_DIR/bin/python"
    
    # Upgrade pip first
    $VENV_PIP install --upgrade pip
    
    # Install requirements
    if [ -f "$SCRIPT_DIR/requirements.txt" ]; then
        print_status "Installing from requirements.txt..."
        $VENV_PIP install -r "$SCRIPT_DIR/requirements.txt"
    else
        print_status "Installing core dependencies..."
        $VENV_PIP install scapy rich textual click
    fi
    
    print_success "Dependencies installed successfully"
}

# Verify installation
verify_installation() {
    print_status "Verifying installation..."
    
    VENV_PYTHON="$VENV_DIR/bin/python"
    
    # Test imports
    if $VENV_PYTHON -c "import scapy, rich, textual, click" 2>/dev/null; then
        print_success "All dependencies verified"
    else
        print_error "Dependency verification failed"
        exit 1
    fi
    
    # Check if main.py exists
    if [ ! -f "$SCRIPT_DIR/main.py" ]; then
        print_error "main.py not found in $SCRIPT_DIR"
        exit 1
    fi
    
    print_success "NetScan installation verified"
}

# Show available network interfaces
show_interfaces() {
    print_status "Available network interfaces:"
    ip link show | grep -E "^[0-9]+:" | cut -d: -f2 | sed 's/^ /  - /'
}

# Parse command line arguments
parse_args() {
    INTERFACE=""
    FILTER=""
    ADVANCED_TUI=false
    LIST_INTERFACES=false
    SHOW_HELP=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -i|--interface)
                INTERFACE="$2"
                shift 2
                ;;
            -f|--filter)
                FILTER="$2"
                shift 2
                ;;
            -a|--advanced-tui)
                ADVANCED_TUI=true
                shift
                ;;
            -l|--list-interfaces)
                LIST_INTERFACES=true
                shift
                ;;
            -h|--help)
                SHOW_HELP=true
                shift
                ;;
            *)
                print_error "Unknown argument: $1"
                SHOW_HELP=true
                shift
                ;;
        esac
    done
}

# Show help
show_help() {
    echo "NetScan - Network Packet Capture Tool"
    echo ""
    echo "Usage: sudo $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -i, --interface IFACE    Specify network interface (e.g., eth0, wlan0)"
    echo "  -f, --filter FILTER      Apply BPF filter (e.g., 'tcp port 80')"
    echo "  -a, --advanced-tui       Use advanced Textual-based TUI interface"
    echo "  -l, --list-interfaces    List available network interfaces"
    echo "  -h, --help              Show this help message"
    echo ""
    echo "Examples:"
    echo "  sudo $0                                    # Start with default settings"
    echo "  sudo $0 -i wlan0                         # Capture on wireless interface"
    echo "  sudo $0 -f 'tcp port 80'                 # Filter HTTP traffic"
    echo "  sudo $0 -i eth0 -f 'udp' -a              # UDP on eth0 with advanced TUI"
    echo ""
    echo "Note: Run with sudo for full packet capture capabilities, or use normal mode for limited monitoring"
}

# Start packet capture
start_capture() {
    print_status "Starting NetScan packet capture..."
    
    VENV_PYTHON="$VENV_DIR/bin/python"
    CMD_ARGS=()
    
    if [ -n "$INTERFACE" ]; then
        CMD_ARGS+=("--interface" "$INTERFACE")
    fi
    
    if [ -n "$FILTER" ]; then
        CMD_ARGS+=("--filter" "$FILTER")
    fi
    
    if [ "$ADVANCED_TUI" = true ]; then
        CMD_ARGS+=("--advanced-tui")
    fi
    
    print_success "Launching NetScan with arguments: ${CMD_ARGS[*]}"
    exec "$VENV_PYTHON" "$SCRIPT_DIR/main.py" "${CMD_ARGS[@]}"
}

# Main execution
main() {
    show_banner
    
    # Parse command line arguments
    parse_args "$@"
    
    # Show help if requested
    if [ "$SHOW_HELP" = true ]; then
        show_help
        exit 0
    fi
    
    # List interfaces if requested
    if [ "$LIST_INTERFACES" = true ]; then
        check_privileges
        show_interfaces
        exit 0
    fi
    
    # Main setup and execution flow
    check_privileges
    detect_distro
    install_system_deps
    setup_venv
    install_dependencies
    verify_installation
    
    # Start packet capture
    start_capture
}

# Run main function with all arguments
main "$@"