import time
import threading
import queue
import logging
import numpy as np
from collections import defaultdict, deque

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class PacketProcessor:
    def __init__(self, input_queue=None, output_queue=None, window_size=10):
        """
        Initialize the packet processor
        
        Args:
            input_queue: Queue containing captured packets
            output_queue: Queue to place extracted features
            window_size: Number of packets to aggregate for feature extraction
        """
        self.input_queue = input_queue if input_queue else queue.Queue()
        self.output_queue = output_queue if output_queue else queue.Queue()
        self.running = False
        self.window_size = window_size
        self.processor_thread = None
        self.packet_count = 0
        self.processed_count = 0
        self.start_time = 0
        
        # Flow tracking
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None,
            'intervals': deque(maxlen=5),
            'packet_sizes': deque(maxlen=5),
            'protocol_counts': defaultdict(int)
        })
        
        # Traffic statistics
        self.traffic_stats = {
            'total_packets': 0,
            'total_bytes': 0,
            'protocol_counts': defaultdict(int),
            'port_counts': defaultdict(int)
        }
        
    def start_processing(self):
        """Start processing packets"""
        if self.running:
            logger.warning("Packet processing already running")
            return
            
        self.running = True
        self.start_time = time.time()
        self.packet_count = 0
        self.processed_count = 0
        
        # Start the processing thread
        self.processor_thread = threading.Thread(target=self._process_packets)
        self.processor_thread.daemon = True
        self.processor_thread.start()
        
        logger.info("Started packet processing")
        
    def stop_processing(self):
        """Stop processing packets"""
        if not self.running:
            logger.warning("Packet processing not running")
            return
            
        self.running = False
        
        if self.processor_thread:
            self.processor_thread.join(2.0)  # Wait up to 2 seconds
            
        duration = time.time() - self.start_time
        logger.info(f"Stopped packet processing. Processed {self.processed_count} packets in {duration:.2f} seconds")
    
    def _process_packets(self):
        """Process packets from the input queue"""
        packet_window = []
        
        while self.running:
            try:
                # Get packet with timeout to allow checking 'running' flag
                packet = self.input_queue.get(block=True, timeout=1.0)
                self.packet_count += 1
                
                # Update flow stats
                self._update_flow_stats(packet)
                
                # Add packet to window
                packet_window.append(packet)
                
                # When window is full, extract features and output
                if len(packet_window) >= self.window_size:
                    features = self._extract_features(packet_window)
                    
                    # Add features to output queue
                    try:
                        self.output_queue.put(features, block=False)
                        self.processed_count += 1
                    except queue.Full:
                        logger.warning("Output queue is full, dropping features")
                    
                    # Start a new window, with 50% overlap for better detection
                    packet_window = packet_window[self.window_size // 2:]
            
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error processing packets: {str(e)}")
    
    def _update_flow_stats(self, packet):
        """Update flow statistics with new packet"""
        # Create flow key (bidirectional)
        if 'src_ip' in packet and 'dst_ip' in packet:
            src_ip, dst_ip = packet['src_ip'], packet['dst_ip']
            src_port = packet.get('src_port', 0)
            dst_port = packet.get('dst_port', 0)
            
            # Sort IPs to make flow key bidirectional
            if src_ip < dst_ip:
                flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
            else:
                flow_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
                
            # Update flow stats
            flow = self.flow_stats[flow_key]
            flow['packet_count'] += 1
            flow['byte_count'] += packet.get('size', 0)
            
            current_time = packet.get('timestamp', time.time())
            
            if flow['start_time'] is None:
                flow['start_time'] = current_time
            
            if flow['last_time'] is not None:
                interval = current_time - flow['last_time']
                flow['intervals'].append(interval)
                
            flow['last_time'] = current_time
            flow['packet_sizes'].append(packet.get('size', 0))
            
            # Count protocols
            for protocol in packet.get('protocols', []):
                flow['protocol_counts'][protocol] += 1
                
            # Update global traffic stats
            self.traffic_stats['total_packets'] += 1
            self.traffic_stats['total_bytes'] += packet.get('size', 0)
            
            for protocol in packet.get('protocols', []):
                self.traffic_stats['protocol_counts'][protocol] += 1
                
            if 'dst_port' in packet:
                self.traffic_stats['port_counts'][packet['dst_port']] += 1
    
    def _extract_features(self, packet_window):
        """Extract ML features from a window of packets"""
        # Basic statistical features
        features = {
            'timestamp': time.time(),
            'window_size': len(packet_window),
            'window_duration': 0,
            'packet_rate': 0,
            'byte_rate': 0,
            'mean_packet_size': 0,
            'std_packet_size': 0,
            'min_packet_size': 0,
            'max_packet_size': 0,
            'unique_ips': 0,
            'unique_ports': 0,
            'protocol_features': {},
            'flow_features': {}
        }
        
        # Skip if no packets
        if not packet_window:
            return features
            
        # Compute window timing
        start_time = min(p.get('timestamp', 0) for p in packet_window)
        end_time = max(p.get('timestamp', 0) for p in packet_window)
        features['window_duration'] = end_time - start_time if end_time > start_time else 0.001
        
        # Compute packet sizes
        packet_sizes = [p.get('size', 0) for p in packet_window]
        total_bytes = sum(packet_sizes)
        
        features['mean_packet_size'] = np.mean(packet_sizes)
        features['std_packet_size'] = np.std(packet_sizes)
        features['min_packet_size'] = min(packet_sizes)
        features['max_packet_size'] = max(packet_sizes)
        features['byte_rate'] = total_bytes / features['window_duration'] if features['window_duration'] > 0 else 0
        features['packet_rate'] = len(packet_window) / features['window_duration'] if features['window_duration'] > 0 else 0
        
        # Compute unique IPs and ports
        src_ips = set(p.get('src_ip', '') for p in packet_window if 'src_ip' in p)
        dst_ips = set(p.get('dst_ip', '') for p in packet_window if 'dst_ip' in p)
        src_ports = set(p.get('src_port', 0) for p in packet_window if 'src_port' in p)
        dst_ports = set(p.get('dst_port', 0) for p in packet_window if 'dst_port' in p)
        
        features['unique_ips'] = len(src_ips.union(dst_ips))
        features['unique_ports'] = len(src_ports.union(dst_ports))
        
        # Compute protocol features
        protocol_counts = defaultdict(int)
        for packet in packet_window:
            for protocol in packet.get('protocols', []):
                protocol_counts[protocol] += 1
                
        # Convert to proportions
        for protocol, count in protocol_counts.items():
            features['protocol_features'][f'{protocol}_prop'] = count / len(packet_window)
            
        # Add common protocol flags
        features['protocol_features']['has_http'] = 'HTTP' in protocol_counts
        features['protocol_features']['has_dns'] = 'DNS' in protocol_counts
        features['protocol_features']['has_tcp'] = 'TCP' in protocol_counts
        features['protocol_features']['has_udp'] = 'UDP' in protocol_counts
        
        # Compute flow features
        active_flows = set()
        for packet in packet_window:
            if 'src_ip' in packet and 'dst_ip' in packet:
                src_ip, dst_ip = packet['src_ip'], packet['dst_ip']
                src_port = packet.get('src_port', 0)
                dst_port = packet.get('dst_port', 0)
                
                if src_ip < dst_ip:
                    flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                else:
                    flow_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
                
                active_flows.add(flow_key)
        
        # Compute flow features
        if active_flows:
            flow_packet_counts = [self.flow_stats[f]['packet_count'] for f in active_flows]
            flow_byte_counts = [self.flow_stats[f]['byte_count'] for f in active_flows]
            
            features['flow_features']['num_flows'] = len(active_flows)
            features['flow_features']['mean_flow_packets'] = np.mean(flow_packet_counts)
            features['flow_features']['std_flow_packets'] = np.std(flow_packet_counts)
            features['flow_features']['mean_flow_bytes'] = np.mean(flow_byte_counts)
            features['flow_features']['std_flow_bytes'] = np.std(flow_byte_counts)
            
            # Compute flow intervals (time between packets)
            interval_lists = [list(self.flow_stats[f]['intervals']) for f in active_flows if self.flow_stats[f]['intervals']]
            if interval_lists:
                all_intervals = [interval for sublist in interval_lists for interval in sublist]
                if all_intervals:
                    features['flow_features']['mean_packet_interval'] = np.mean(all_intervals)
                    features['flow_features']['std_packet_interval'] = np.std(all_intervals)
        
        # Return feature dict
        return features
    
    def get_stats(self):
        """Get processor statistics"""
        if not self.start_time:
            return {"status": "not started"}
            
        duration = time.time() - self.start_time
        return {
            "status": "running" if self.running else "stopped",
            "packets_received": self.packet_count,
            "features_produced": self.processed_count,
            "duration_seconds": duration,
            "processing_rate": self.processed_count / duration if duration > 0 else 0,
            "active_flows": len(self.flow_stats),
            "top_protocols": dict(sorted(self.traffic_stats['protocol_counts'].items(), 
                                        key=lambda x: x[1], reverse=True)[:5])
        }


if __name__ == "__main__":
    # Simple test for the processor
    from packet_sniffer import PacketSniffer
    import json
    
    # Create queues and components
    packet_queue = queue.Queue()
    feature_queue = queue.Queue()
    
    sniffer = PacketSniffer(output_queue=packet_queue)
    processor = PacketProcessor(input_queue=packet_queue, output_queue=feature_queue, window_size=5)
    
    # Start components
    sniffer.start_capture()
    processor.start_processing()
    
    # Process features as they come in
    count = 0
    try:
        while count < 5:  # Process 5 feature sets
            try:
                features = feature_queue.get(block=True, timeout=10)
                count += 1
                print(f"Feature set {count}:")
                print(json.dumps(features, indent=2))
            except queue.Empty:
                print("Timeout waiting for features")
                break
    except KeyboardInterrupt:
        print("Interrupted by user")
    finally:
        processor.stop_processing()
        sniffer.stop_capture()