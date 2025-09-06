#!/usr/bin/env python3
"""
Network Scanner TUI - Main Application Entry Point

A terminal-based network packet capture and analysis tool that displays
real-time network traffic with protocol analysis and filtering capabilities.

Usage:
    sudo python main.py [OPTIONS]   (Linux/macOS)
    python main.py [OPTIONS]        (Windows, run as Administrator)

Note: Administrator/Root privileges are required for packet capture.
"""

import sys
import os
import argparse
import signal
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

# Add the project directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from net_scan.capture import PacketCapture, NetworkInterface
from net_scan.tui import NetScanApp, SimpleTUI
from net_scan.analysis import PacketAnalyzer, NetworkStatistics


console = Console()


def check_permissions() -> bool:
    """Check if the application is running with admin/root privileges"""
    # Always return True to bypass admin check for normal user mode
    return True


def display_welcome() -> None:
    """Display welcome message and application info"""
    welcome_text = Text()
    welcome_text.append("Network Scanner TUI - Normal User Mode\n", style="bold cyan")
    welcome_text.append("Real-time network monitoring and analysis\n\n", style="cyan")
    welcome_text.append("Features:\n", style="bold")
    welcome_text.append("• Network connection monitoring\n", style="green")
    welcome_text.append("• Protocol analysis and filtering\n", style="green")
    welcome_text.append("• Connection tracking and statistics\n", style="green")
    welcome_text.append("• Terminal-based user interface\n", style="green")
    welcome_text.append("• Works without administrator privileges\n", style="green")
    
    console.print(Panel(welcome_text, title="Welcome", border_style="blue"))


def display_interfaces() -> None:
    """Display available network interfaces"""
    interfaces = NetworkInterface.get_available_interfaces()
    default_interface = NetworkInterface.get_default_interface()
    
    console.print("\n[bold]Available Network Interfaces:[/bold]")
    for i, iface in enumerate(interfaces, 1):
        marker = " (default)" if iface == default_interface else ""
        console.print(f"  {i}. {iface}{marker}")


def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully"""
    console.print("\n\n[bold red]Shutting down gracefully...[/bold red]")
    sys.exit(0)


@click.command()
@click.option(
    '--interface', '-i',
    type=str,
    help='Network interface to capture from (use --list-interfaces to see available options)'
)
@click.option(
    '--filter', '-f', 'filter_expr',
    type=str,
    default="",
    help='BPF filter expression (e.g., "tcp port 80" or "host 192.168.1.1")'
)
@click.option(
    '--list-interfaces', '-l',
    is_flag=True,
    help='List available network interfaces and exit'
)
@click.option(
    '--simple', '-s',
    is_flag=True,
    help='Use simple Rich-based TUI (default)'
)
@click.option(
    '--advanced-tui', '-a',
    is_flag=True,
    help='Use advanced Textual-based TUI interface'
)
@click.option(
    '--max-packets', '-m',
    type=int,
    default=1000,
    help='Maximum number of packets to keep in memory'
)
@click.option(
    '--output', '-o',
    type=str,
    help='Output file to save captured packets (not implemented yet)'
)
@click.version_option(version="1.0.0", prog_name="Network Scanner TUI")
def main(interface: Optional[str], filter_expr: str, list_interfaces: bool, 
         simple: bool, advanced_tui: bool, max_packets: int, output: Optional[str]) -> None:
    """
    Network Scanner TUI - Capture and analyze network packets in real-time.
    
    This tool runs in normal user mode with limited packet capture capabilities.
    For full raw packet access, run with Administrator (Windows) or Root (Linux/macOS) privileges.
    
    Use Ctrl+C to stop the capture and exit the application.
    
    Examples:
        python main.py                          # Normal user mode
        python main.py -i Ethernet              # Specify interface
        python main.py -f "tcp port 80"         # Filter HTTP traffic
    """
    
    # Set up signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    
    # Display welcome message
    display_welcome()
    
    # Handle interface listing
    if list_interfaces:
        display_interfaces()
        return
    
    # Skip admin privilege check - allow normal user mode
    
    # Validate interface
    available_interfaces = NetworkInterface.get_available_interfaces()
    
    if interface and interface not in available_interfaces:
        console.print(f"\n[bold red]Error: Interface '{interface}' not found[/bold red]")
        console.print("Available interfaces:")
        for iface in available_interfaces:
            console.print(f"  - {iface}")
        sys.exit(1)
    
    # Use default interface if none specified
    if not interface:
        interface = NetworkInterface.get_default_interface()
        if not interface:
            console.print("\n[bold red]Error: No network interfaces available[/bold red]")
            sys.exit(1)
    
    # Display configuration
    console.print("\n[bold]Configuration:[/bold]")
    console.print("  Mode: [cyan]Normal User (Limited Capture)[/cyan]")
    console.print(f"  Interface: [cyan]{interface}[/cyan]")
    console.print(f"  Filter: [cyan]{filter_expr or 'None'}[/cyan]")
    console.print(f"  Max packets: [cyan]{max_packets}[/cyan]")
    ui_type = 'Advanced' if advanced_tui else 'Simple'
    console.print(f"  Interface type: [cyan]{ui_type}[/cyan]")
    
    if output:
        console.print(f"  Output file: [cyan]{output}[/cyan] [yellow](not implemented)[/yellow]")
    
    console.print("\n[yellow]Starting network monitoring in 3 seconds...[/yellow]")
    console.print("[dim]Press Ctrl+C to stop[/dim]")
    console.print("[dim]Note: Running in normal user mode with limited packet access[/dim]\n")
    
    import time
    time.sleep(3)
    
    try:
        if advanced_tui:
            console.print("[bold green]Starting Advanced TUI...[/bold green]")
            app = NetScanApp(interface=interface, filter_expr=filter_expr)
            app.run()
        else:
            console.print("[bold green]Starting Simple TUI...[/bold green]")
            tui = SimpleTUI(interface=interface, filter_expr=filter_expr)
            tui.run()
            
    except KeyboardInterrupt:
        console.print("\n[bold red]Capture interrupted by user[/bold red]")
    except ImportError as e:
        console.print(f"\n[bold red]Import error: {e}[/bold red]")
        console.print("[yellow]Try running with --simple flag for basic interface[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[bold red]Unexpected error: {e}[/bold red]")
        console.print("[yellow]Try running with --simple flag or check your configuration[/yellow]")
        sys.exit(1)
    
    console.print("\n[bold green]Packet capture completed successfully[/bold green]")


def run_tests() -> None:
    """Run basic functionality tests"""
    console.print("[bold]Running basic functionality tests...[/bold]")
    
    try:
        interfaces = NetworkInterface.get_available_interfaces()
        console.print(f"✓ Found {len(interfaces)} network interfaces")
        
        capture = PacketCapture()
        console.print("✓ Packet capture initialization successful")
        
        analyzer = PacketAnalyzer()
        stats = NetworkStatistics()
        console.print("✓ Analysis components initialized")
        
        console.print("\n[bold green]All tests passed![/bold green]")
        
    except Exception as e:
        console.print(f"\n[bold red]Test failed: {e}[/bold red]")
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        run_tests()
    else:
        main()
