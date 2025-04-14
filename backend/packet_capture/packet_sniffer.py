import os
import time
import threading
from scapy.all import sniff, IP, TCP, UDP, DNS, Raw
import logging
import json
import queue

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class PacketSniffer:
    def __init__(self, interface=None, output_queue=None, filter_str=""):
        """
        Initialize the packet sniffer
        
        Args:
            interface: Network interface to capture on (None = auto-select)
            output_queue: Queue to place captured packets for processing
            filter_str: BPF filter string (e.g., "tcp port 80")
        """
        self.interface = interface
        self.running = False
        self.filter_str = filter_str
        self.output_queue = output_queue if output_queue else queue.Queue()
        self.packet_thread = None
        self.packet_count = 0
        self.start_time = 0
        
    def start_capture(self, packet_count=0, timeout=None):
        """
        Start capturing packets
        
        Args:
            packet_count: Number of packets to capture (0 = infinite)
            timeout: Timeout in seconds (None = no timeout)
        """
        if self.running:
            logger.warning("Packet capture already running")
            return
            
        self.running = True
        self.start_time = time.time()
        self.packet_count = 0
        
        # Start the capture thread
        self.packet_thread = threading.Thread(target=self._capture_packets, 
                                             args=(packet_count, timeout))
        self.packet_thread.daemon = True
        self.packet_thread.start()
        
        logger.info(f"Started packet capture on interface {self.interface or 'default'}")
        if self.filter_str:
            logger.info(f"Using filter: {self.filter_str}")
    
    def stop_capture(self):
        """Stop the packet capture"""
        if not self.running:
            logger.warning("Packet capture not running")
            return
            
        self.running = False
        if self.packet_thread:
            self.packet_thread.join(2.0)  # Wait up to 2 seconds
            
        duration = time.time() - self.start_time
        logger.info(f"Stopped packet capture. Captured {self.packet_count} packets in {duration:.2f} seconds")
        
    def _capture_packets(self, packet_count=0, timeout=None):
        """Internal method to capture packets"""
        try:
            sniff(iface=self.interface,
                  prn=self._process_packet,
                  filter=self.filter_str,
                  count=packet_count if packet_count > 0 else None,
                  timeout=timeout,
                  store=0)
        except Exception as e:
            logger.error(f"Error in packet capture: {str(e)}")
            self.running = False
    
    def _process_packet(self, packet):
        """Process captured packet and add to queue"""
        if not self.running:
            return
            
        self.packet_count += 1
        
        # Extract basic packet info
        packet_info = {
            "timestamp": float(time.time()),
            "packet_number": self.packet_count,
            "size": len(packet),
            "protocols": []
        }
        
        # Handle IP layer
        if IP in packet:
            packet_info["src_ip"] = packet[IP].src
            packet_info["dst_ip"] = packet[IP].dst
            packet_info["protocols"].append("IP")
            
            # Handle TCP layer
            if TCP in packet:
                packet_info["src_port"] = packet[TCP].sport
                packet_info["dst_port"] = packet[TCP].dport
                packet_info["protocols"].append("TCP")
                
                # Check for HTTP
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    if Raw in packet:
                        raw_data = packet[Raw].load.decode('utf-8', 'ignore')
                        if raw_data.startswith(('GET', 'POST', 'HTTP')):
                            packet_info["protocols"].append("HTTP")
                            http_info = self._parse_http(raw_data)
                            packet_info.update(http_info)
            
            # Handle UDP layer
            elif UDP in packet:
                packet_info["src_port"] = packet[UDP].sport
                packet_info["dst_port"] = packet[UDP].dport
                packet_info["protocols"].append("UDP")
                
                # Check for DNS
                if DNS in packet:
                    packet_info["protocols"].append("DNS")
                    dns_info = self._parse_dns(packet[DNS])
                    packet_info.update(dns_info)
        
        # Add packet info to the queue for further processing
        try:
            self.output_queue.put(packet_info, block=False)
        except queue.Full:
            logger.warning("Output queue is full, dropping packet")
    
    def _parse_http(self, raw_data):
        """Parse HTTP data from raw packet"""
        http_info = {"http_type": "unknown"}
        try:
            lines = raw_data.split('\r\n')
            if lines and len(lines) > 0:
                first_line = lines[0]
                if first_line.startswith('GET'):
                    http_info["http_type"] = "request"
                    http_info["http_method"] = "GET"
                    parts = first_line.split()
                    if len(parts) > 1:
                        http_info["http_path"] = parts[1]
                elif first_line.startswith('POST'):
                    http_info["http_type"] = "request"
                    http_info["http_method"] = "POST"
                    parts = first_line.split()
                    if len(parts) > 1:
                        http_info["http_path"] = parts[1]
                elif first_line.startswith('HTTP'):
                    http_info["http_type"] = "response"
                    parts = first_line.split()
                    if len(parts) > 1:
                        http_info["http_status"] = parts[1]
        except Exception as e:
            logger.error(f"Error parsing HTTP data: {str(e)}")
        return http_info
    
    def _parse_dns(self, dns_packet):
        """Parse DNS data from packet"""
        dns_info = {"dns_type": "unknown"}
        try:
            if dns_packet.qr == 0:
                dns_info["dns_type"] = "query"
            else:
                dns_info["dns_type"] = "response"
                
            if dns_packet.ancount > 0:
                dns_info["dns_answers"] = dns_packet.ancount
                
            if hasattr(dns_packet, "qd") and dns_packet.qd:
                dns_info["dns_query"] = dns_packet.qd.qname.decode('utf-8')
        except Exception as e:
            logger.error(f"Error parsing DNS data: {str(e)}")
        return dns_info
    
    def get_stats(self):
        """Get capture statistics"""
        if not self.start_time:
            return {"status": "not started"}
            
        duration = time.time() - self.start_time
        return {
            "status": "running" if self.running else "stopped",
            "packets_captured": self.packet_count,
            "duration_seconds": duration,
            "packets_per_second": self.packet_count / duration if duration > 0 else 0
        }


if __name__ == "__main__":
    # Simple test for the packet sniffer
    def print_packet(pkt):
        print(json.dumps(pkt, indent=2))
    
    q = queue.Queue()
    sniffer = PacketSniffer(output_queue=q)
    sniffer.start_capture(packet_count=10)  # Capture 10 packets
    
    # Process packets as they come in
    while sniffer.running or not q.empty():
        try:
            packet = q.get(block=True, timeout=1)
            print_packet(packet)
        except queue.Empty:
            pass