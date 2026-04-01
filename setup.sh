#!/bin/bash
# AegisOSINT Setup Script
# Detects distribution, installs dependencies, and compiles the project

set -e

# Ephemeral logs for this setup run
BUILD_LOG="$(mktemp /tmp/aegis_build.XXXXXX.log)"
TEST_LOG="$(mktemp /tmp/aegis_test.XXXXXX.log)"
PRESERVE_LOGS=0
cleanup_logs() {
    if [ "$PRESERVE_LOGS" -eq 0 ]; then
        rm -f "$BUILD_LOG" "$TEST_LOG"
    fi
}
trap cleanup_logs EXIT

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m' # No Color

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

print_banner() {
    clear
    echo -e "${CYAN}"
    echo "    ___              _      ____  _____ _____ _   _ _____ "
    echo "   /   | ___  ____ _(_)____/ __ \/ ___//  _/ | / // ___/ "
    echo "  / /| |/ _ \/ __ \`/ / ___/ / / /\__ \ / //  |/ / \__ \  "
    echo " / ___ /  __/ /_/ / (__  ) /_/ /___/ // // /|  / ___/ /  "
    echo "/_/  |_\___/\__, /_/____/\____//____/___/_/ |_/ /____/   "
    echo "           /____/                                        "
    echo -e "${NC}"
    echo -e "${BOLD}Production-grade OSINT for Bug Bounty & Defense${NC}"
    echo -e "${YELLOW}⚠️  AUTHORIZED USE ONLY${NC}"
    echo ""
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

log_step() {
    echo -e "${MAGENTA}[→]${NC} $1"
}

spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " ${CYAN}%c${NC}  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        DISTRO_NAME=$NAME
        VERSION=$VERSION_ID
    elif [ -f /etc/arch-release ]; then
        DISTRO="arch"
        DISTRO_NAME="Arch Linux"
    elif [ -f /etc/debian_version ]; then
        DISTRO="debian"
        DISTRO_NAME="Debian"
    elif [ -f /etc/fedora-release ]; then
        DISTRO="fedora"
        DISTRO_NAME="Fedora"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        DISTRO="darwin"
        DISTRO_NAME="macOS"
    else
        DISTRO="unknown"
        DISTRO_NAME="Unknown"
    fi
}

check_rust() {
    if command -v rustc &> /dev/null; then
        RUST_VERSION=$(rustc --version | cut -d' ' -f2)
        return 0
    else
        return 1
    fi
}

check_cargo() {
    command -v cargo &> /dev/null
}

install_rust() {
    log_step "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    source "$HOME/.cargo/env"
    log_success "Rust installed successfully"
}

install_deps_arch() {
    log_step "Installing dependencies for Arch Linux..."
    sudo pacman -Syu --noconfirm
    sudo pacman -S --needed --noconfirm \
        base-devel \
        sqlite \
        openssl \
        bind \
        whois \
        pkg-config \
        git \
        curl
    log_success "Arch dependencies installed"
}

install_deps_debian() {
    log_step "Installing dependencies for Debian/Ubuntu..."
    sudo apt-get update
    sudo apt-get install -y \
        build-essential \
        libsqlite3-dev \
        libssl-dev \
        dnsutils \
        whois \
        pkg-config \
        git \
        curl \
        ca-certificates
    log_success "Debian/Ubuntu dependencies installed"
}

install_deps_fedora() {
    log_step "Installing dependencies for Fedora/RHEL..."
    sudo dnf update -y
    sudo dnf install -y \
        gcc \
        sqlite-devel \
        openssl-devel \
        bind-utils \
        whois \
        pkgconfig \
        git \
        curl
    log_success "Fedora dependencies installed"
}

install_deps_macos() {
    log_step "Installing dependencies for macOS..."
    if ! command -v brew &> /dev/null; then
        log_warn "Homebrew not found. Installing..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    brew install sqlite openssl pkg-config
    log_success "macOS dependencies installed"
}

install_rust_deps() {
    log_step "Installing Rust toolchain components..."
    
    # Update rustup
    rustup update stable 2>/dev/null || true
    
    # Add common components
    rustup component add clippy 2>/dev/null || true
    rustup component add rustfmt 2>/dev/null || true
    
    log_success "Rust components installed"
}

fetch_cargo_deps() {
    log_step "Fetching Cargo dependencies (this may take a few minutes)..."
    cargo fetch 2>&1 | while read line; do
        echo -ne "\r${DIM}  $line${NC}                    \r"
    done
    echo -e "\r                                                              "
    log_success "Dependencies fetched"
}

build_release() {
    log_step "Compiling release build..."
    echo ""
    
    # Build and capture output while preserving cargo exit status
    cargo build --release 2>&1 | tee "$BUILD_LOG" | while IFS= read -r line; do
        if [[ "$line" == *"Compiling"* ]]; then
            crate=$(echo "$line" | sed 's/.*Compiling \([^ ]*\).*/\1/')
            echo -e "\r  ${DIM}Building: ${crate}${NC}                              \r"
        elif [[ "$line" == *"error"* ]]; then
            echo -e "\n${RED}$line${NC}"
        fi
    done

    local build_status=${PIPESTATUS[0]}
    if [ "$build_status" -eq 0 ]; then
        echo -e "\r                                                              "
        log_success "Build complete!"
        rm -f "$BUILD_LOG"
    else
        PRESERVE_LOGS=1
        echo ""
        log_error "Build failed! See errors above or check $BUILD_LOG"
        echo ""
        tail -30 "$BUILD_LOG"
        log_warn "Full build log preserved at: $BUILD_LOG"
        return 1
    fi
}

verify_build() {
    if [ -f "$SCRIPT_DIR/target/release/aegis" ]; then
        log_success "Binary created: target/release/aegis"
        return 0
    else
        log_error "Build failed - binary not found"
        log_warn "Check build output: cargo build --release 2>&1 | less"
        PRESERVE_LOGS=1
        log_warn "Build log preserved at: $BUILD_LOG"
        return 1
    fi
}

install_globally() {
    log_step "Installing aegis-osint globally..."
    cargo install --path . --force
    log_success "Installed to ~/.cargo/bin/aegis"
}

show_status() {
    echo ""
    echo -e "${BOLD}System Status:${NC}"
    echo -e "─────────────────────────────────────"
    
    # Distribution
    detect_distro
    echo -e "  OS:          ${CYAN}$DISTRO_NAME${NC}"
    
    # Rust
    if check_rust; then
        echo -e "  Rust:        ${GREEN}$RUST_VERSION${NC}"
    else
        echo -e "  Rust:        ${RED}Not installed${NC}"
    fi
    
    # Cargo
    if check_cargo; then
        CARGO_VERSION=$(cargo --version | cut -d' ' -f2)
        echo -e "  Cargo:       ${GREEN}$CARGO_VERSION${NC}"
    else
        echo -e "  Cargo:       ${RED}Not installed${NC}"
    fi
    
    # Binary
    if [ -f "$SCRIPT_DIR/target/release/aegis" ]; then
        echo -e "  Binary:      ${GREEN}Built${NC}"
    else
        echo -e "  Binary:      ${YELLOW}Not built${NC}"
    fi
    
    # Global install
    if command -v aegis &> /dev/null; then
        echo -e "  Installed:   ${GREEN}Yes (global)${NC}"
    else
        echo -e "  Installed:   ${DIM}No${NC}"
    fi
    
    echo ""
}

show_menu() {
    echo -e "${BOLD}Setup Options:${NC}"
    echo -e "─────────────────────────────────────"
    echo -e "  ${CYAN}1${NC}) Full Setup (recommended)"
    echo -e "     ${DIM}Install deps, Rust, compile, and install${NC}"
    echo ""
    echo -e "  ${CYAN}2${NC}) Install System Dependencies"
    echo -e "     ${DIM}SQLite, OpenSSL, pkg-config, etc.${NC}"
    echo ""
    echo -e "  ${CYAN}3${NC}) Install/Update Rust"
    echo -e "     ${DIM}Rustup with stable toolchain${NC}"
    echo ""
    echo -e "  ${CYAN}4${NC}) Compile Project"
    echo -e "     ${DIM}Build release binary${NC}"
    echo ""
    echo -e "  ${CYAN}5${NC}) Install Globally"
    echo -e "     ${DIM}Install to ~/.cargo/bin${NC}"
    echo ""
    echo -e "  ${CYAN}6${NC}) Run Tests"
    echo -e "     ${DIM}Execute test suite${NC}"
    echo ""
    echo -e "  ${CYAN}7${NC}) Launch AegisOSINT"
    echo -e "     ${DIM}Start the interactive menu${NC}"
    echo ""
    echo -e "  ${CYAN}q${NC}) Quit"
    echo ""
}

run_tests() {
    log_step "Running tests..."
    if cargo test --all-features 2>&1 | tee "$TEST_LOG"; then
        log_success "Tests completed successfully"
    else
        PRESERVE_LOGS=1
        log_error "Tests failed. Showing last 40 lines:"
        tail -40 "$TEST_LOG"
        log_warn "Full test log preserved at: $TEST_LOG"
        return 1
    fi
}

full_setup() {
    echo ""
    log_info "Starting full setup..."
    echo ""
    
    # 1. System deps
    detect_distro
    case $DISTRO in
        arch|manjaro|endeavouros)
            install_deps_arch
            ;;
        debian|ubuntu|pop|linuxmint|elementary|kali|parrot|raspbian|mx)
            install_deps_debian
            ;;
        fedora|rhel|centos|rocky|alma)
            install_deps_fedora
            ;;
        darwin)
            install_deps_macos
            ;;
        *)
            log_warn "Unknown distribution: $DISTRO"
            log_warn "Please install manually: build-essential, libsqlite3-dev, libssl-dev, pkg-config"
            ;;
    esac
    
    # 2. Rust
    if ! check_rust; then
        install_rust
    else
        log_success "Rust already installed: $RUST_VERSION"
    fi
    
    # 3. Rust components
    install_rust_deps
    
    # 4. Fetch deps
    fetch_cargo_deps
    
    # 5. Build
    build_release
    
    # 6. Verify
    if verify_build; then
        echo ""
        log_success "Setup complete!"
        echo ""
        echo -e "  Run with: ${CYAN}./target/release/aegis${NC}"
        echo -e "  Or install globally with option ${CYAN}5${NC}"
        echo ""
    fi
}

launch_aegis() {
    if [ -f "$SCRIPT_DIR/target/release/aegis" ]; then
        exec "$SCRIPT_DIR/target/release/aegis" menu
    elif command -v aegis &> /dev/null; then
        exec aegis menu
    else
        log_error "AegisOSINT not built yet. Run option 1 or 4 first."
    fi
}

main() {
    print_banner
    show_status
    
    while true; do
        show_menu
        read -p "$(echo -e ${BOLD}Select option:${NC} )" -n 1 choice
        echo ""
        
        case $choice in
            1)
                full_setup
                read -p "Press Enter to continue..."
                print_banner
                show_status
                ;;
            2)
                echo ""
                detect_distro
                case $DISTRO in
                    arch|manjaro|endeavouros) install_deps_arch ;;
                    debian|ubuntu|pop|linuxmint|elementary|kali|parrot|raspbian|mx) install_deps_debian ;;
                    fedora|rhel|centos|rocky|alma) install_deps_fedora ;;
                    darwin) install_deps_macos ;;
                    *) log_warn "Unknown distro. Install manually." ;;
                esac
                read -p "Press Enter to continue..."
                print_banner
                show_status
                ;;
            3)
                echo ""
                if check_rust; then
                    log_info "Updating Rust..."
                    rustup update stable
                else
                    install_rust
                fi
                install_rust_deps
                read -p "Press Enter to continue..."
                print_banner
                show_status
                ;;
            4)
                echo ""
                fetch_cargo_deps
                build_release
                verify_build
                read -p "Press Enter to continue..."
                print_banner
                show_status
                ;;
            5)
                echo ""
                install_globally
                read -p "Press Enter to continue..."
                print_banner
                show_status
                ;;
            6)
                echo ""
                run_tests
                read -p "Press Enter to continue..."
                print_banner
                show_status
                ;;
            7)
                launch_aegis
                ;;
            q|Q)
                echo ""
                echo -e "${GREEN}Goodbye!${NC}"
                exit 0
                ;;
            *)
                log_warn "Invalid option"
                sleep 1
                print_banner
                show_status
                ;;
        esac
    done
}

# Handle command line args
case "${1:-}" in
    --full|full)
        print_banner
        full_setup
        ;;
    --build|build)
        print_banner
        fetch_cargo_deps
        build_release
        verify_build
        ;;
    --help|-h)
        echo "AegisOSINT Setup Script"
        echo ""
        echo "Usage: ./setup.sh [option]"
        echo ""
        echo "Options:"
        echo "  (none)     Interactive menu"
        echo "  --full     Full unattended setup"
        echo "  --build    Build only (deps must be installed)"
        echo "  --help     Show this help"
        ;;
    *)
        main
        ;;
esac
