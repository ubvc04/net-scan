"""
Terminal User Interface components using Rich and Textual
"""

import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Header, Footer, DataTable, Static, Button, Input, Select, Label
from textual.reactive import reactive
from textual.timer import Timer
from textual import events
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.live import Live
from rich.layout import Layout

from .capture import PacketCapture, PacketInfo, NetworkInterface


class PacketTableWidget(DataTable):
    """Custom DataTable widget for displaying packets"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.packets: List[PacketInfo] = []
        self.max_packets = 1000
        
        # Set up columns
        self.add_column("Time", width=12)
        self.add_column("Protocol", width=8)
        self.add_column("Source", width=20)
        self.add_column("Destination", width=20)
        self.add_column("Size", width=8)
        self.add_column("Flags", width=15)
    
    def add_packet(self, packet: PacketInfo) -> None:
        """Add a packet to the table"""
        self.packets.append(packet)
        
        # Keep only the latest packets
        if len(self.packets) > self.max_packets:
            self.packets = self.packets[-self.max_packets:]
            self.clear()
            for p in self.packets:
                self._add_packet_row(p)
        else:
            self._add_packet_row(packet)
    
    def _add_packet_row(self, packet: PacketInfo) -> None:
        """Add a single packet row to the table"""
        src = packet.src_ip
        if packet.src_port:
            src += f":{packet.src_port}"
        
        dst = packet.dst_ip
        if packet.dst_port:
            dst += f":{packet.dst_port}"
        
        self.add_row(
            packet.timestamp.strftime("%H:%M:%S.%f")[:-3],
            packet.protocol,
            src,
            dst,
            str(packet.size),
            packet.flags[:15]  # Truncate flags if too long
        )
    
    def clear_packets(self) -> None:
        """Clear all packets from the table"""
        self.packets.clear()
        self.clear()
    
    def get_selected_packet(self) -> Optional[PacketInfo]:
        """Get the currently selected packet"""
        if self.cursor_row < len(self.packets):
            return self.packets[self.cursor_row]
        return None


class StatsWidget(Static):
    """Widget to display capture statistics"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.stats = {}
    
    def update_stats(self, stats: Dict[str, Any]) -> None:
        """Update the statistics display"""
        self.stats = stats
        self._render_stats()
    
    def _render_stats(self) -> None:
        """Render the statistics as rich content"""
        console = Console()
        
        # Create statistics table
        table = Table(title="Capture Statistics", show_header=True, header_style="bold magenta")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Status", "Capturing" if self.stats.get("is_capturing", False) else "Stopped")
        table.add_row("Interface", str(self.stats.get("interface", "Unknown")))
        table.add_row("Total Packets", str(self.stats.get("total_packets", 0)))
        table.add_row("Queue Size", str(self.stats.get("queue_size", 0)))
        
        # Protocol breakdown
        protocol_stats = self.stats.get("protocol_stats", {})
        if protocol_stats:
            table.add_row("", "")  # Separator
            for protocol, count in sorted(protocol_stats.items()):
                table.add_row(f"{protocol} Packets", str(count))
        
        self.update(table)


class ControlPanel(Container):
    """Control panel for capture settings"""
    
    def __init__(self, app_instance, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.app_instance = app_instance
    
    def compose(self) -> ComposeResult:
        """Compose the control panel layout"""
        with Horizontal():
            yield Button("Start", id="start_btn", variant="success")
            yield Button("Stop", id="stop_btn", variant="error")
            yield Button("Clear", id="clear_btn", variant="warning")
            yield Button("Quit", id="quit_btn", variant="primary")
        
        with Horizontal():
            yield Label("Interface:")
            yield Select(
                [(iface, iface) for iface in NetworkInterface.get_available_interfaces()],
                id="interface_select",
                value=NetworkInterface.get_default_interface()
            )
        
        with Horizontal():
            yield Label("Filter:")
            yield Input(placeholder="BPF filter expression", id="filter_input")
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses"""
        if event.button.id == "start_btn":
            self.app_instance.start_capture()
        elif event.button.id == "stop_btn":
            self.app_instance.stop_capture()
        elif event.button.id == "clear_btn":
            self.app_instance.clear_capture()
        elif event.button.id == "quit_btn":
            self.app_instance.exit()


class PacketDetailWidget(Static):
    """Widget to display detailed packet information"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.current_packet: Optional[PacketInfo] = None
    
    def show_packet(self, packet: PacketInfo) -> None:
        """Display detailed information about a packet"""
        self.current_packet = packet
        
        # Create detailed packet information
        details = []
        details.append(f"Timestamp: {packet.timestamp}")
        details.append(f"Protocol: {packet.protocol}")
        details.append(f"Size: {packet.size} bytes")
        details.append(f"Source: {packet.src_ip}")
        details.append(f"Destination: {packet.dst_ip}")
        
        if packet.src_port:
            details.append(f"Source Port: {packet.src_port}")
        if packet.dst_port:
            details.append(f"Destination Port: {packet.dst_port}")
        if packet.flags:
            details.append(f"Flags: {packet.flags}")
        
        # Add raw packet summary
        details.append("\nPacket Summary:")
        try:
            details.append(str(packet.raw_packet.summary()))
        except:
            details.append("Unable to display packet summary")
        
        self.update("\n".join(details))
    
    def clear(self) -> None:
        """Clear the packet details"""
        self.current_packet = None
        self.update("Select a packet to view details")


class NetScanApp(App):
    """Main TUI application"""
    
    CSS_PATH = None
    TITLE = "Network Scanner TUI"
    
    def __init__(self, interface: Optional[str] = None, filter_expr: str = ""):
        super().__init__()
        self.packet_capture = PacketCapture(interface, filter_expr)
        self.packet_table: Optional[PacketTableWidget] = None
        self.stats_widget: Optional[StatsWidget] = None
        self.packet_detail_widget: Optional[PacketDetailWidget] = None
        self.update_timer: Optional[Timer] = None
        
        # Add packet callback
        self.packet_capture.add_packet_callback(self._on_packet_captured)
    
    def compose(self) -> ComposeResult:
        """Compose the application layout"""
        yield Header()
        
        with Container():
            # Control panel
            yield ControlPanel(self, id="control_panel")
            
            with Horizontal():
                # Main packet table
                with Vertical():
                    yield Static("Packet List", classes="section-title")
                    self.packet_table = PacketTableWidget(id="packet_table")
                    yield self.packet_table
                
                # Right side panel
                with Vertical():
                    # Statistics
                    yield Static("Statistics", classes="section-title")
                    self.stats_widget = StatsWidget(id="stats_widget")
                    yield self.stats_widget
                    
                    # Packet details
                    yield Static("Packet Details", classes="section-title")
                    self.packet_detail_widget = PacketDetailWidget(id="packet_detail")
                    yield self.packet_detail_widget
        
        yield Footer()
    
    def on_mount(self) -> None:
        """Called when the app is mounted"""
        # Start the update timer
        self.update_timer = self.set_interval(0.5, self._update_display)
        
        # Initialize packet details
        if self.packet_detail_widget:
            self.packet_detail_widget.clear()
    
    def _on_packet_captured(self, packet: PacketInfo) -> None:
        """Callback when a packet is captured"""
        # This will be called from the capture thread
        # The actual UI update happens in _update_display
        pass
    
    def _update_display(self) -> None:
        """Update the display with new packets and statistics"""
        try:
            # Get new packets
            new_packets = self.packet_capture.get_packets()
            if new_packets and self.packet_table:
                for packet in new_packets:
                    self.packet_table.add_packet(packet)
            
            # Update statistics
            if self.stats_widget:
                stats = self.packet_capture.get_statistics()
                self.stats_widget.update_stats(stats)
                
        except Exception as e:
            # Handle any errors silently for now
            pass
    
    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle row selection in the packet table"""
        if self.packet_table and self.packet_detail_widget:
            selected_packet = self.packet_table.get_selected_packet()
            if selected_packet:
                self.packet_detail_widget.show_packet(selected_packet)
    
    def start_capture(self) -> None:
        """Start packet capture"""
        try:
            # Get current settings from UI
            interface_select = self.query_one("#interface_select", Select)
            filter_input = self.query_one("#filter_input", Input)
            
            # Update capture settings
            self.packet_capture.interface = interface_select.value
            self.packet_capture.filter_expr = filter_input.value
            
            self.packet_capture.start_capture()
        except Exception as e:
            # Handle error (in a real app, show error dialog)
            pass
    
    def stop_capture(self) -> None:
        """Stop packet capture"""
        self.packet_capture.stop_capture()
    
    def clear_capture(self) -> None:
        """Clear captured packets and statistics"""
        self.packet_capture.clear_statistics()
        if self.packet_table:
            self.packet_table.clear_packets()
        if self.packet_detail_widget:
            self.packet_detail_widget.clear()
    
    def on_unmount(self) -> None:
        """Clean up when the app is unmounted"""
        if self.update_timer:
            self.update_timer.stop()
        self.packet_capture.stop_capture()


# CSS styling for the application
APP_CSS = """
.section-title {
    background: blue;
    color: white;
    padding: 1;
    margin-bottom: 1;
}

#control_panel {
    height: 6;
    border: solid white;
    margin-bottom: 1;
}

#packet_table {
    height: 1fr;
    border: solid white;
}

#stats_widget {
    height: 15;
    width: 40;
    border: solid white;
    margin-bottom: 1;
}

#packet_detail {
    height: 1fr;
    width: 40;
    border: solid white;
}
"""


class SimpleTUI:
    """Simple Rich-based TUI for systems where Textual might have issues"""
    
    def __init__(self, interface: Optional[str] = None, filter_expr: str = ""):
        self.packet_capture = PacketCapture(interface, filter_expr)
        self.console = Console()
        self.layout = Layout()
        self.packets: List[PacketInfo] = []
        self.max_display_packets = 20
        
        # Setup layout
        self.layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main"),
            Layout(name="footer", size=3)
        )
        
        self.layout["main"].split_row(
            Layout(name="packets"),
            Layout(name="stats", size=40)
        )
        
        # Add packet callback
        self.packet_capture.add_packet_callback(self._on_packet_captured)
    
    def _on_packet_captured(self, packet: PacketInfo) -> None:
        """Handle new packet"""
        self.packets.append(packet)
        if len(self.packets) > self.max_display_packets:
            self.packets = self.packets[-self.max_display_packets:]
    
    def _create_packet_table(self) -> Table:
        """Create the packet display table"""
        table = Table(title="Network Packets (Live)", show_header=True)
        table.add_column("Time", width=12)
        table.add_column("Protocol", width=8)
        table.add_column("Source", width=25)
        table.add_column("Destination", width=25)
        table.add_column("Size", width=8)
        table.add_column("Info", width=15)
        
        for packet in self.packets[-self.max_display_packets:]:
            src = packet.src_ip
            if packet.src_port:
                src += f":{packet.src_port}"
            
            dst = packet.dst_ip
            if packet.dst_port:
                dst += f":{packet.dst_port}"
            
            # Truncate long addresses for display
            if len(src) > 24:
                src = src[:21] + "..."
            if len(dst) > 24:
                dst = dst[:21] + "..."
            
            info = packet.packet_type or packet.flags
            if len(info) > 14:
                info = info[:11] + "..."
            
            table.add_row(
                packet.timestamp.strftime("%H:%M:%S.%f")[:-3],
                packet.protocol,
                src,
                dst,
                str(packet.size),
                info
            )
        
        return table
    
    def _create_stats_panel(self) -> Panel:
        """Create the statistics panel"""
        stats = self.packet_capture.get_statistics()
        
        content = f"""Status: {'Capturing' if stats['is_capturing'] else 'Stopped'}
Interface: {stats['interface'][-20:] if len(stats['interface']) > 20 else stats['interface']}
Total Packets: {stats['total_packets']}
Queue Size: {stats['queue_size']}

Protocol Distribution:"""
        
        for protocol, count in sorted(stats['protocol_stats'].items()):
            percentage = (count / max(stats['total_packets'], 1) * 100)
            content += f"\n{protocol}: {count} ({percentage:.1f}%)"
        
        if stats['total_packets'] == 0:
            content += "\n\nWaiting for network activity..."
            content += "\nNote: Running in connection monitoring mode"
        
        return Panel(content, title="Statistics", border_style="blue")
    
    def run(self) -> None:
        """Run the simple TUI"""
        try:
            self.packet_capture.start_capture()
            
            with Live(self.layout, console=self.console, refresh_per_second=2) as live:
                self.layout["header"].update(
                    Panel("Network Scanner TUI - Press Ctrl+C to exit", style="bold green")
                )
                self.layout["footer"].update(
                    Panel("Capturing packets... Press Ctrl+C to stop", style="bold blue")
                )
                
                while True:
                    self.layout["packets"].update(self._create_packet_table())
                    self.layout["stats"].update(self._create_stats_panel())
                    
                    import time
                    time.sleep(0.5)
                    
        except KeyboardInterrupt:
            pass
        finally:
            self.packet_capture.stop_capture()
            self.console.print("\n[bold red]Capture stopped[/bold red]")