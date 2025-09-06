@echo off
REM NetScan - Network Packet Capture Tool for Windows
REM Comprehensive setup, dependency installation, and packet capture starter
REM Compatible with Windows 10/11

setlocal enabledelayedexpansion

REM Set script directory
set "SCRIPT_DIR=%~dp0"
set "VENV_DIR=%SCRIPT_DIR%venv"
set "PYTHON_EXEC=python"

REM Colors for output (Windows doesn't support ANSI by default, so we'll use simple text)
set "INFO_PREFIX=[INFO]"
set "SUCCESS_PREFIX=[SUCCESS]"
set "WARNING_PREFIX=[WARNING]"
set "ERROR_PREFIX=[ERROR]"

goto :main

:print_status
echo %INFO_PREFIX% %~1
goto :eof

:print_success
echo %SUCCESS_PREFIX% %~1
goto :eof

:print_warning
echo %WARNING_PREFIX% %~1
goto :eof

:print_error
echo %ERROR_PREFIX% %~1
goto :eof

:show_banner
echo.
echo ===============================================================
echo                    NetScan - Windows Edition
echo              Network Packet Capture ^& Analysis
echo.
echo  Supports 40+ protocols: TCP, UDP, ICMP, ARP, IPv6, DNS,
echo  DHCP, HTTP, HTTPS, FTP, SSH, SMTP, SNMP, and many more!
echo ===============================================================
echo.
goto :eof

:check_admin
REM Check if running as administrator (optional for normal user mode)
net session >nul 2>&1
if %ERRORLEVEL% == 0 (
    call :print_success "Running with administrator privileges"
) else (
    call :print_warning "Running in normal user mode - limited packet capture capabilities"
    call :print_status "For full packet capture, run as Administrator (right-click and 'Run as administrator')"
    call :print_status "Continuing in normal user mode..."
)
goto :eof

:check_python
call :print_status "Checking Python installation..."

REM Check if Python 3 is available
%PYTHON_EXEC% --version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    call :print_error "Python 3 is not installed or not in PATH"
    call :print_status "Please install Python 3.8+ from https://python.org"
    call :print_status "Make sure to check 'Add Python to PATH' during installation"
    pause
    exit /b 1
)

REM Get Python version
for /f "tokens=2" %%i in ('%PYTHON_EXEC% --version 2^>^&1') do set "PYTHON_VERSION=%%i"
call :print_success "Python %PYTHON_VERSION% found"
goto :eof

:check_npcap
call :print_status "Checking Npcap installation..."

REM Check if Npcap is installed (required for Scapy on Windows)
if exist "C:\Windows\System32\Npcap\wpcap.dll" (
    call :print_success "Npcap is installed"
) else if exist "C:\Windows\System32\wpcap.dll" (
    call :print_success "WinPcap/Npcap compatible library found"
) else (
    call :print_warning "Npcap not found. Packet capture may not work properly."
    call :print_status "Please install Npcap from https://nmap.org/npcap/"
    call :print_status "Choose 'Install Npcap in WinPcap API-compatible Mode' during installation"
    call :print_status "Continuing anyway..."
)
goto :eof

:setup_venv
call :print_status "Setting up Python virtual environment..."

REM Remove existing venv if it's corrupted
if exist "%VENV_DIR%" (
    "%VENV_DIR%\Scripts\python.exe" --version >nul 2>&1
    if !ERRORLEVEL! neq 0 (
        call :print_warning "Existing venv appears corrupted. Recreating..."
        rmdir /s /q "%VENV_DIR%"
    )
)

REM Create virtual environment if it doesn't exist
if not exist "%VENV_DIR%" (
    call :print_status "Creating new virtual environment..."
    %PYTHON_EXEC% -m venv "%VENV_DIR%"
    if !ERRORLEVEL! neq 0 (
        call :print_error "Failed to create virtual environment"
        pause
        exit /b 1
    )
)

REM Verify venv creation
if not exist "%VENV_DIR%\Scripts\activate.bat" (
    call :print_error "Failed to create virtual environment"
    pause
    exit /b 1
)

call :print_success "Virtual environment ready at %VENV_DIR%"
goto :eof

:install_dependencies
call :print_status "Installing Python dependencies..."

set "VENV_PIP=%VENV_DIR%\Scripts\pip.exe"
set "VENV_PYTHON=%VENV_DIR%\Scripts\python.exe"

REM Upgrade pip first
"%VENV_PIP%" install --upgrade pip
if !ERRORLEVEL! neq 0 (
    call :print_error "Failed to upgrade pip"
    pause
    exit /b 1
)

REM Install requirements
if exist "%SCRIPT_DIR%requirements.txt" (
    call :print_status "Installing from requirements.txt..."
    "%VENV_PIP%" install -r "%SCRIPT_DIR%requirements.txt"
) else (
    call :print_status "Installing core dependencies..."
    "%VENV_PIP%" install scapy rich textual click
)

if !ERRORLEVEL! neq 0 (
    call :print_error "Failed to install dependencies"
    pause
    exit /b 1
)

call :print_success "Dependencies installed successfully"
goto :eof

:verify_installation
call :print_status "Verifying installation..."

set "VENV_PYTHON=%VENV_DIR%\Scripts\python.exe"

REM Test imports
"%VENV_PYTHON%" -c "import scapy, rich, textual, click" >nul 2>&1
if !ERRORLEVEL! neq 0 (
    call :print_error "Dependency verification failed"
    pause
    exit /b 1
)

REM Check if main.py exists
if not exist "%SCRIPT_DIR%main.py" (
    call :print_error "main.py not found in %SCRIPT_DIR%"
    pause
    exit /b 1
)

call :print_success "NetScan installation verified"
goto :eof

:show_interfaces
call :print_status "Available network interfaces:"
REM Use ipconfig to show interfaces (Windows equivalent)
ipconfig | findstr /C:"adapter" | findstr /V /C:"Tunnel"
goto :eof

:parse_args
set "INTERFACE="
set "FILTER="
set "ADVANCED_TUI=false"
set "LIST_INTERFACES=false"
set "SHOW_HELP=false"

:parse_loop
if "%~1"=="" goto :parse_done

if /i "%~1"=="-i" (
    set "INTERFACE=%~2"
    shift
    shift
    goto :parse_loop
)
if /i "%~1"=="--interface" (
    set "INTERFACE=%~2"
    shift
    shift
    goto :parse_loop
)
if /i "%~1"=="-f" (
    set "FILTER=%~2"
    shift
    shift
    goto :parse_loop
)
if /i "%~1"=="--filter" (
    set "FILTER=%~2"
    shift
    shift
    goto :parse_loop
)
if /i "%~1"=="-a" (
    set "ADVANCED_TUI=true"
    shift
    goto :parse_loop
)
if /i "%~1"=="--advanced-tui" (
    set "ADVANCED_TUI=true"
    shift
    goto :parse_loop
)
if /i "%~1"=="-l" (
    set "LIST_INTERFACES=true"
    shift
    goto :parse_loop
)
if /i "%~1"=="--list-interfaces" (
    set "LIST_INTERFACES=true"
    shift
    goto :parse_loop
)
if /i "%~1"=="-h" (
    set "SHOW_HELP=true"
    shift
    goto :parse_loop
)
if /i "%~1"=="--help" (
    set "SHOW_HELP=true"
    shift
    goto :parse_loop
)

call :print_error "Unknown argument: %~1"
set "SHOW_HELP=true"
shift
goto :parse_loop

:parse_done
goto :eof

:show_help
echo NetScan - Network Packet Capture Tool
echo.
echo Usage: net-scan-windows.bat [OPTIONS]
echo.
echo Options:
echo   -i, --interface IFACE    Specify network interface name
echo   -f, --filter FILTER      Apply BPF filter (e.g., 'tcp port 80')
echo   -a, --advanced-tui       Use advanced Textual-based TUI interface
echo   -l, --list-interfaces    List available network interfaces
echo   -h, --help              Show this help message
echo.
echo Examples:
echo   net-scan-windows.bat                                # Start with default settings
echo   net-scan-windows.bat -f "tcp port 80"              # Filter HTTP traffic
echo   net-scan-windows.bat -f "udp" -a                   # UDP traffic with advanced TUI
echo.
echo Requirements:
echo   - Windows 10/11
echo   - Python 3.8+
echo   - Npcap (for packet capture)
echo   - Administrator privileges
echo.
echo Note: Run as Administrator for full packet capture, or use normal mode for limited monitoring
goto :eof

:start_capture
call :print_status "Starting NetScan packet capture..."

set "VENV_PYTHON=%VENV_DIR%\Scripts\python.exe"
set "CMD_ARGS="

if defined INTERFACE (
    set "CMD_ARGS=!CMD_ARGS! --interface "!INTERFACE!""
)

if defined FILTER (
    set "CMD_ARGS=!CMD_ARGS! --filter "!FILTER!""
)

if "%ADVANCED_TUI%"=="true" (
    set "CMD_ARGS=!CMD_ARGS! --advanced-tui"
)

call :print_success "Launching NetScan with arguments: !CMD_ARGS!"
"%VENV_PYTHON%" "%SCRIPT_DIR%main.py" !CMD_ARGS!
goto :eof

:main
call :show_banner

REM Parse command line arguments
call :parse_args %*

REM Show help if requested
if "%SHOW_HELP%"=="true" (
    call :show_help
    pause
    exit /b 0
)

REM List interfaces if requested
if "%LIST_INTERFACES%"=="true" (
    call :check_admin
    call :show_interfaces
    pause
    exit /b 0
)

REM Main setup and execution flow
call :check_admin
call :check_python
call :check_npcap
call :setup_venv
call :install_dependencies
call :verify_installation

REM Start packet capture
call :start_capture

pause
exit /b 0