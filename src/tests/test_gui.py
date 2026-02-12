# test_gui.py
import pytest
import time
from unittest.mock import MagicMock
from collections import defaultdict
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt
from gui import NetworkMonitor

# A fixture to create the QApplication instance
@pytest.fixture(scope="session")
def qapp():
    return QApplication([])

@pytest.fixture
def mock_core():
    """Creates a mock of NetworkMonitorCore."""
    core = MagicMock()
    core.protocol_counts = defaultdict(int)
    core.flows = {}
    core.packet_sizes = []
    core.is_paused = False
    core.max_packets = 1000
    
    dummy_packet_data = (time.time(), "10.0.0.1", "10.0.0.2", "UDP", "5000", "6000", "N/A", "Info", "Payload", 1, 64, 64, 0, 0)
    dummy_raw_packet = "raw_packet_obj"
    core.process_queue.return_value = [(dummy_packet_data, dummy_raw_packet)]
    return core

@pytest.fixture
def window(qtbot, mock_core, mocker):
    """Creates an instance of the main window with a mocked core."""
    mocker.patch('network_monitor.NetworkMonitorCore.select_interface', return_value=True)
    
    win = NetworkMonitor()
    win.core = mock_core 
    win.core.iface = 'test_iface'
    win.timer.stop()
    
    qtbot.addWidget(win)
    win.show()
    return win

def test_gui_initialization(window):
    """Tests if the GUI initializes correctly."""
    assert window.windowTitle() == "PortSniffer"
    assert window.table.rowCount() == 0
    assert hasattr(window, 'packet_list')
    assert hasattr(window, 'raw_packets')
    assert len(window.packet_list) == 0

def test_process_queue_adds_row_to_table(window, qtbot):
    """Tests that processing the queue adds a packet to the table and internal lists."""
    assert window.table.rowCount() == 0
    window.process_queue()
    qtbot.wait(50)
    assert window.table.rowCount() == 1
    assert len(window.packet_list) == 1
    assert len(window.raw_packets) == 1
    assert window.table.item(0, 1).text() == "10.0.0.1"

def test_clear_button_clears_data(window, qtbot):
    """Tests if the clear button clears the table and data lists."""
    window.process_queue()
    qtbot.wait(50)
    assert window.table.rowCount() == 1
    
    clear_button = window.control_panel.clear_button
    qtbot.mouseClick(clear_button, Qt.MouseButton.LeftButton)
    
    assert window.table.rowCount() == 0
    assert len(window.packet_list) == 0
    assert len(window.raw_packets) == 0

def test_filter_table_hides_rows(window, qtbot):
    """Tests that the text filter correctly hides and shows rows."""
    # FINAL FIX Part 1: Generate a timestamp guaranteed to be valid by using the widget's own time.
    valid_timestamp = window.control_panel.start_time.dateTime().addSecs(60).toSecsSinceEpoch()

    packet1_data = (valid_timestamp, "1.1.1.1", "2.2.2.2", "HTTP", "80", "12345", "", "", "GET request", 1, 100, 64, 0, 0)
    packet2_data = (valid_timestamp, "3.3.3.3", "4.4.4.4", "DNS", "53", "54321", "", "", "DNS query", 2, 80, 64, 0, 0)
    
    # Manually set up the window state for the test
    window.packet_list = []
    window.raw_packets = []
    window.table.setRowCount(0)
    
    window.packet_list.append(packet1_data)
    window.raw_packets.append("raw1")
    window._add_packet_to_table(packet1_data, "raw1")

    window.packet_list.append(packet2_data)
    window.raw_packets.append("raw2")
    window._add_packet_to_table(packet2_data, "raw2")
    
    assert window.table.rowCount() == 2
    # Ensure rows start visible
    assert window.table.isRowHidden(0) is False
    assert window.table.isRowHidden(1) is False

    # FINAL FIX Part 2: Use setText to directly trigger the filter, avoiding signal timing issues.
    search_box = window.control_panel.search_input
    search_box.setText("DNS")
    
    # A minimal wait for the event to process
    qtbot.wait(50) 
    
    assert window.table.isRowHidden(0) is True
    assert window.table.isRowHidden(1) is False