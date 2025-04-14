import time
import threading
import queue
import logging
import numpy as np
import pandas as pd
from collections import defaultdict

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class PacketProcessor:
    def __init__(self, input_queue, output_queue=None, window_size=100, window_time=60):
        """
        Initialize the packet processor
        
        Args:
            input_queue: Queue with packet data from the sniffer
            output_queue: Queue to place processed features for ML models
            window_size: Number of packets to process in a feature window
            window_time: Maximum time window in seconds
        """
        self.input_queue = input_queue
        self.output_queue = output_queue if output_queue else queue.Queue()
        self.window_size = window_size
        self.window_time = window_time
        self.running = False
        self.processor_thread = None
        self.packet_buffer = []
        self.flow_stats = defaultdict(lambda: {"packet_count": 0, "byte_count": 0, "start_time": 0, "protocols": set()})
        
    def start_processing(self):
        """Start the packet processing thread"""
        if self.running:
            logger.warning("Packet processor already running")
            return
            
        self.running = True
        self.processor_thread = threading.Thread(target=self._process_packets)
        self.processor_thread.daemon = True
        self.processor_thread.start()
        
        logger.info(f"Started packet processor with window size {self.window_size} packets / {self.window_time} seconds")
        
    def stop_processing(self):
        """Stop the packet processing thread"""
        if not self.running:
            logger.warning("Packet processor not running")
            return
            
        self.running = False
        if self.processor_thread:
            self.processor_thread.join(2.0)  # Wait up to 2 seconds
            
        # Process remaining packets in buffer
        if self.packet_buffer:
            logger.info(f"Processing remaining {len(self.packet_buffer)} packets in buffer")
            features = self._extract_features(self.packet_buffer)
            if features is not None:
                self.output_queue.put(features)
        
        logger.info("Stopped packet processor")
        
    def _process_packets(self):
        """Main processing loop"""
        window_start_time = time.time()
        
        while self.running:
            try:
                # Get the next packet with a timeout
                packet = self.input_queue.get(block=True, timeout=0.1)
                self.packet_buffer.append(packet)
                
                # Update flow statistics
                if "src_ip" in packet and "dst_ip" in packet:
                    flow_key = (packet["src_ip"], packet["dst_ip"], 
                               packet.get("src_port", 0), packet.get("dst_port", 0))
                    
                    # Initialize flow if needed
                    if self.flow_stats[flow_key]["start_time"] == 0:
                        self.flow_stats[flow_key]["start_time"] = packet["timestamp"]
                        
                    # Update flow stats
                    self.flow_stats[flow_key]["packet_count"] += 1
                    self.flow_stats[flow_key]["byte_count"] += packet["size"]
                    self.flow_stats[flow_key]["protocols"].update(packet["protocols"])
                
                # Process window if we've reached the window size or time limit
                current_time = time.time()
                window_full = len(self.packet_buffer) >= self.window_size
                window_timeout = (current_time - window_start_time) >= self.window_time
                
                if window_full or window_timeout:
                    if self.packet_buffer:
                        features = self._extract_features(self.packet_buffer)
                        if features is not None:
                            self.output_queue.put(features)
                            
                        # Reset for next window
                        self.packet_buffer = []
                        window_start_time = current_time
                        
                        # Cleanup old flows (older than 5 minutes)
                        self._cleanup_flows()
                    
            except queue.Empty:
                pass
            except Exception as e:
                logger.error(f"Error in packet processor: {str(e)}")
                
    def _cleanup_flows(self, max_age=300):
        """Remove old flow statistics"""
        current_time = time.time()
        keys_to_remove = []
        
        for flow_key, stats in self.flow_stats.items():
            if current_time - stats["start_time"] > max_age:
                keys_to_remove.append(flow_key)
                
        for key in keys_to_remove:
            del self.flow_stats[key]
            
    def _extract_features(self, packet_buffer):
        """Extract features from a packet buffer for machine learning"""
        if not packet_buffer:
            return None
            
        # Basic statistical features
        packet_count = len(packet_buffer)
        timestamps = [p["timestamp"] for p in packet_buffer]
        min_time = min(timestamps)
        max_time = max(timestamps)
        duration = max_time - min_time if packet_count > 1 else 0.001  # Avoid division by zero
        
        # Packet sizes
        packet_sizes = [p["size"] for p in packet_buffer]
        avg_size = np.mean(packet_sizes)
        std_size = np.std(packet_sizes)
        min_size = min(packet_sizes)
        max_size = max(packet_sizes)
        
        # Protocol distribution
        protocol_counts = defaultdict(int)
        for packet in packet_buffer:
            for protocol in packet.get("protocols", []):
                protocol_counts[protocol] += 1
                
        tcp_count = protocol_counts.get("TCP", 0)
        udp_count = protocol_counts.get("UDP", 0)
        http_count = protocol_counts.get("HTTP", 0)
        dns_count = protocol_counts.get("DNS", 0)
        
        # Flow statistics
        unique_ips = set()
        unique_ports = set()
        for packet in packet_buffer:
            if "src_ip" in packet:
                unique_ips.add(packet["src_ip"])
            if "dst_ip" in packet:
                unique_ips.add(packet["dst_ip"])
            if "src_port" in packet:
                unique_ports.add(packet["src_port"])
            if "dst_port" in packet:
                unique_ports.add(packet["dst_port"])
                
        # Rates
        packet_rate = packet_count / duration if duration > 0 else 0
        byte_rate = sum(packet_sizes) / duration if duration > 0 else 0
        
        # Assemble feature vector
        features = {
            "timestamp": max_time,
            "duration": duration,
            "packet_count": packet_count,
            "byte_count": sum(packet_sizes),
            "packet_rate": packet_rate,
            "byte_rate": byte_rate,
            "avg_packet_size": avg_size,
            "std_packet_size": std_size,
            "min_packet_size": min_size,
            "max_packet_size": max_size,
            "tcp_ratio": tcp_count / packet_count if packet_count > 0 else 0,
            "udp_ratio": udp_count / packet_count if packet_count > 0 else 0,
            "http_ratio": http_count / packet_count if packet_count > 0 else 0,
            "dns_ratio": dns_count / packet_count if packet_count > 0 else 0,
            "unique_ip_count": len(unique_ips),
            "unique_port_count": len(unique_ports)
        }
        
        return features
        
    def get_stats(self):
        """Get processor statistics"""
        return {
            "status": "running" if self.running else "stopped",
            "packets_in_buffer": len(self.packet_buffer),
            "active_flows": len(self.flow_stats)
        }


if __name__ == "__main__":
    # Simple test
    import json
    from packet_sniffer import PacketSniffer
    
    input_q = queue.Queue()
    output_q = queue.Queue()
    
    # Create and start packet sniffer
    sniffer = PacketSniffer(output_queue=input_q)
    sniffer.start_capture(packet_count=100)
    
    # Create and start packet processor
    processor = PacketProcessor(input_queue=input_q, output_queue=output_q, window_size=20)
    processor.start_processing()
    
    # Wait for some features to be generated
    try:
        while sniffer.running or not output_q.empty():
            try:
                features = output_q.get(block=True, timeout=5)
                print(json.dumps(features, indent=2))
            except queue.Empty:
                break
    finally:
        sniffer.stop_capture()
        processor.stop_processing()