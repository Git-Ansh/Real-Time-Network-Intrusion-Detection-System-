import time
import threading
import queue
import logging
import socket
from scapy.all import sniff, IP, TCP, UDP, DNS, Raw
from scapy.layers.http import HTTP

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class PacketSniffer:
    def __init__(self, output_queue=None, interface=None, filter_string=""):
        """
        Initialize the packet sniffer
        
        Args:
            output_queue: Queue to place captured packets
            interface: Network interface to sniff on
            filter_string: BPF filter string to apply
        """
        self.output_queue = output_queue if output_queue else queue.Queue()
        self.interface = interface
        self.filter_string = filter_string
        self.running = False
        self.sniffer_thread = None
        self.packet_count = 0
        self.start_time = 0
        self.enable_http_logging = False
        self.enable_dns_logging = True
    
    def start_capture(self):
        """Start packet capture - this is an alias for the start() method to maintain compatibility"""
        return self.start()
    
    def start(self):
        """Start packet capture in a separate thread"""
        if self.running:
            logger.warning("Packet sniffer already running")
            return
        
        self.running = True
        self.start_time = time.time()
        self.packet_count = 0
        self.sniffer_thread = threading.Thread(target=self._sniff_packets, daemon=True)
        self.sniffer_thread.start()
        logger.info(f"Started packet sniffer on interface {self.interface or 'default'}")
        
        if self.filter_string:
            logger.info(f"Using filter: {self.filter_string}")
    
    def stop_capture(self):
        """Stop packet capture - this is an alias for the stop() method to maintain compatibility"""
        return self.stop()
    
    def stop(self):
        """Stop packet capture"""
        self.running = False
        if self.sniffer_thread:
            # Give the thread time to exit gracefully
            time.sleep(0.5)
            self.sniffer_thread = None
        logger.info("Stopped packet sniffer")
    
    def _sniff_packets(self):
        """Perform packet capture and process packets"""
        try:
            logger.info("Starting packet sniffing...")
            # This will run until interrupted or stopped
            sniff(
                iface=self.interface,
                filter=self.filter_string if self.filter_string else None,
                prn=self._process_packet,
                store=0,
                stop_filter=lambda _: not self.running
            )
        except Exception as e:
            logger.error(f"Error in packet sniffer: {str(e)}")
            self.running = False
    
    def _process_packet(self, packet):
        """Process a captured packet"""
        try:
            packet_info = self._extract_packet_info(packet)
            if packet_info:
                self.packet_count += 1
                if self.output_queue:
                    # Don't block if queue is full, just drop the packet
                    try:
                        self.output_queue.put(packet_info, block=False)
                    except queue.Full:
                        pass
        except Exception as e:
            logger.error(f"Error processing packet: {str(e)}")
    
    def _extract_packet_info(self, packet):
        """Extract relevant information from packet"""
        timestamp = time.time()
        protocols = []
        packet_info = {
            'timestamp': timestamp,
            'size': len(packet),
            'protocols': protocols,
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'protocol': None,
        }
        
        # Extract IP layer info if present
        if IP in packet:
            packet_info['src_ip'] = packet[IP].src
            packet_info['dst_ip'] = packet[IP].dst
            packet_info['protocol'] = packet[IP].proto
            protocols.append('IP')
            
            # Extract TCP/UDP layer info if present
            if TCP in packet:
                packet_info['src_port'] = packet[TCP].sport
                packet_info['dst_port'] = packet[TCP].dport
                packet_info['flags'] = packet[TCP].flags
                protocols.append('TCP')
                
                # Look for HTTP in TCP packets
                if self.enable_http_logging:
                    try:
                        if Raw in packet and packet[TCP].dport == 80 or packet[TCP].sport == 80:
                            # Try to parse as HTTP
                            if b'HTTP/' in packet[Raw].load:
                                protocols.append('HTTP')
                                # Don't store raw content - could be large and privacy concerns
                                packet_info['http_detected'] = True
                    except:
                        pass
                        
            elif UDP in packet:
                packet_info['src_port'] = packet[UDP].sport
                packet_info['dst_port'] = packet[UDP].dport
                protocols.append('UDP')
                
                # Look for DNS in UDP packets
                if self.enable_dns_logging and (packet[UDP].sport == 53 or packet[UDP].dport == 53):
                    if DNS in packet:
                        protocols.append('DNS')
                        # Extract DNS query details
                        if packet.haslayer(DNS) and packet[DNS].qr == 0:  # 0 = query
                            try:
                                packet_info['dns_query'] = packet[DNS].qd.qname.decode('utf-8')
                            except:
                                pass
        
        return packet_info
    
    def get_stats(self):
        """Get sniffer statistics"""
        uptime = time.time() - self.start_time if self.start_time > 0 else 0
        pps = self.packet_count / uptime if uptime > 0 else 0
        
        return {
            'status': 'running' if self.running else 'stopped',
            'packet_count': self.packet_count,
            'uptime': uptime,
            'packets_per_second': pps,
            'interface': self.interface or 'default',
            'filter': self.filter_string,
            'http_logging': self.enable_http_logging,
            'dns_logging': self.enable_dns_logging
        }
    
    def get_packet_rate(self):
        """Calculate current packet rate (packets per second)"""
        uptime = time.time() - self.start_time if self.start_time > 0 else 0
        if uptime <= 0:
            return 0
        return self.packet_count / uptime
    
    def update_settings(self, settings):
        """Update sniffer settings"""
        restart_required = False
        
        if 'interface' in settings and settings['interface'] != self.interface:
            self.interface = settings['interface']
            restart_required = True
            
        if 'filter' in settings and settings['filter'] != self.filter_string:
            self.filter_string = settings['filter']
            restart_required = True
            
        if 'enable_http_logging' in settings:
            self.enable_http_logging = settings['enable_http_logging']
            
        if 'enable_dns_logging' in settings:
            self.enable_dns_logging = settings['enable_dns_logging']
        
        return restart_required

if __name__ == "__main__":
    # Test code
    q = queue.Queue()
    sniffer = PacketSniffer(output_queue=q, interface="eth0", filter_string="tcp")
    sniffer.start_capture()
    
    try:
        # Run for 10 seconds
        for i in range(10):
            time.sleep(1)
            print(f"Captured {sniffer.packet_count} packets")
            
            # Print a sample packet if available
            try:
                packet = q.get(block=False)
                print(f"Sample packet: {packet}")
            except queue.Empty:
                pass
                
    finally:
        sniffer.stop_capture()
        print(f"Final stats: {sniffer.get_stats()}")