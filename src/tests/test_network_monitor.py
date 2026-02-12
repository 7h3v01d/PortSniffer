# test_network_monitor.py
import pytest
from unittest.mock import MagicMock
from scapy.all import IP, TCP, Raw
from network_monitor import NetworkMonitorCore

@pytest.fixture
def core():
    """Provides a fresh NetworkMonitorCore instance for each test."""
    return NetworkMonitorCore()

def test_initialization(core):
    """Tests that the core initializes with correct default values."""
    assert not core.is_monitoring
    assert not core.is_paused
    assert core.packet_queue.empty()
    assert isinstance(core.protocol_counts, dict)
    with pytest.raises(AttributeError):
        _ = core.packet_list
    with pytest.raises(AttributeError):
        _ = core.raw_packets

def test_packet_callback_puts_to_queue(core):
    """Tests that the packet_callback correctly processes a packet and puts it on the queue."""
    core.is_monitoring = True
    core.is_paused = False
    
    packet = IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=123, dport=456) / Raw(load="data")
    packet.time = 1234567890.123
    
    core.packet_callback(packet)
    
    assert not core.packet_queue.empty()
    q_item = core.packet_queue.get_nowait()
    assert isinstance(q_item, tuple)
    assert len(q_item) == 2
    
    packet_data, raw_packet = q_item
    assert raw_packet == packet
    assert isinstance(packet_data, tuple)
    assert packet_data[0] == packet.time
    assert packet_data[1] == "1.1.1.1"
    assert packet_data[3] == "TCP"

def test_process_queue_drains_queue(core):
    """Tests that process_queue() returns all items and empties the queue."""
    core.packet_queue.put("packet1")
    core.packet_queue.put("packet2")
    assert core.packet_queue.qsize() == 2
    processed_packets = core.process_queue()
    assert len(processed_packets) == 2
    assert "packet1" in processed_packets
    assert core.packet_queue.empty()

def test_start_stop_monitoring(core, mocker):
    """Tests the start and stop monitoring flags and calls."""
    mock_sniffer_instance = MagicMock()
    mock_sniffer = mocker.patch('network_monitor.AsyncSniffer', return_value=mock_sniffer_instance)
    
    core.iface = 'lo'
    core.start_monitoring()
    assert core.is_monitoring
    mock_sniffer.assert_called_once()
    mock_sniffer_instance.start.assert_called_once()
    
    core.stop_monitoring()
    assert not core.is_monitoring
    mock_sniffer_instance.stop.assert_called_once()

def test_export_to_csv(core, tmp_path):
    """Tests exporting data to a CSV file."""
    dummy_packet_list = [
        (1234567890.123, "1.1.1.1", "2.2.2.2", "TCP", "100", "200", "S", "Info", "Payload", 1, 64, 64, 0, 0)
    ]
    file_path = tmp_path / "test.csv"
    
    # FIX: Corrected typo from export_to_.csv to export_to_csv
    core.export_to_csv(file_path, dummy_packet_list)
    
    assert file_path.exists()
    with open(file_path, 'r') as f:
        content = f.read()
        assert "Source IP" in content
        assert "1.1.1.1" in content