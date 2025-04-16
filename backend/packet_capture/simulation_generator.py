import time
import random
import threading
import queue
import logging
import json
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SimulationGenerator:
    """
    Simulates network traffic for demonstration purposes when running as a web service
    where direct packet capture from visitors is not possible.
    """
    
    def __init__(self, output_queue=None, simulation_speed=1.0, include_attacks=True):
        """
        Initialize the traffic simulation generator
        
        Args:
            output_queue: Queue to place simulated packets
            simulation_speed: Speed multiplier for simulation (higher = faster)
            include_attacks: Whether to include simulated attacks
        """
        self.output_queue = output_queue if output_queue else queue.Queue()
        self.simulation_speed = simulation_speed
        self.include_attacks = include_attacks
        self.running = False
        self.simulator_thread = None
        self.packet_count = 0
        self.start_time = 0
        
        # Simulation parameters
        self.normal_ips = [
            "192.168.1.10", "192.168.1.11", "192.168.1.12", 
            "192.168.1.13", "192.168.1.14", "192.168.1.15",
            "10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8"
        ]
        
        self.external_ips = [
            "203.0.113.5", "203.0.113.10", "198.51.100.7", 
            "198.51.100.15", "192.0.2.4", "192.0.2.8"
        ]
        
        self.common_ports = {
            "HTTP": 80,
            "HTTPS": 443,
            "SSH": 22,
            "DNS": 53,
            "SMTP": 25,
            "POP3": 110,
            "IMAP": 143,
            "RDP": 3389
        }
        
        # Attack scenarios
        self.attack_scenarios = [
            self._simulate_port_scan,
            self._simulate_dos_attack,
            self._simulate_brute_force,
            self._simulate_data_exfiltration
        ]
        
        # Timing of last attack to prevent too frequent attacks
        self.last_attack_time = 0
        self.min_time_between_attacks = 30  # seconds
    
    def start_simulation(self):
        """Start traffic simulation in a separate thread"""
        if self.running:
            logger.warning("Simulation already running")
            return
        
        self.running = True
        self.start_time = time.time()
        self.packet_count = 0
        self.simulator_thread = threading.Thread(target=self._generate_traffic)
        self.simulator_thread.daemon = True
        self.simulator_thread.start()
        logger.info("Started network traffic simulation")
        
    def stop_simulation(self):
        """Stop traffic simulation"""
        self.running = False
        if self.simulator_thread:
            # Give the thread time to exit gracefully
            time.sleep(0.5)
            self.simulator_thread = None
        logger.info("Stopped network traffic simulation")
    
    def _generate_traffic(self):
        """Main simulation loop for generating traffic"""
        try:
            while self.running:
                current_time = time.time()
                
                # Generate regular traffic most of the time
                if not self.include_attacks or random.random() < 0.95 or (current_time - self.last_attack_time) < self.min_time_between_attacks:
                    self._generate_normal_traffic()
                else:
                    # Choose a random attack scenario
                    attack_fn = random.choice(self.attack_scenarios)
                    attack_fn()
                    self.last_attack_time = current_time
                
                # Control simulation speed
                sleep_time = random.uniform(0.01, 0.2) / self.simulation_speed
                time.sleep(sleep_time)
                
        except Exception as e:
            logger.error(f"Error in traffic simulator: {str(e)}")
            self.running = False
    
    def _generate_normal_traffic(self):
        """Generate normal looking network traffic"""
        # Select random source and destination
        src_ip = random.choice(self.normal_ips)
        
        # Determine if this is internal or external traffic
        if random.random() < 0.7:  # 70% external traffic
            dst_ip = random.choice(self.external_ips)
        else:
            dst_ip = random.choice([ip for ip in self.normal_ips if ip != src_ip])
        
        # Select random service
        service = random.choice(list(self.common_ports.keys()))
        
        # Determine direction (outbound or inbound)
        if random.random() < 0.8:  # 80% outbound
            dst_port = self.common_ports[service]
            src_port = random.randint(10000, 65000)
        else:
            src_port = self.common_ports[service]
            dst_port = random.randint(10000, 65000)
        
        # Create packet with common protocols
        protocols = ['IP']
        
        if random.random() < 0.8:  # 80% TCP
            protocols.append('TCP')
            if service == "HTTP":
                protocols.append('HTTP')
        else:
            protocols.append('UDP')
            if service == "DNS":
                protocols.append('DNS')
        
        # Create packet with typical size for the service
        if service == "HTTP" or service == "HTTPS":
            size = random.randint(200, 1500)
        elif service == "DNS":
            size = random.randint(50, 300)
        else:
            size = random.randint(100, 800)
        
        # Generate the packet
        self._generate_packet(src_ip, dst_ip, src_port, dst_port, protocols, size)
    
    def _simulate_port_scan(self):
        """Simulate a port scanning attack"""
        logger.info("Simulating port scan attack")
        
        # Attacker IP (external)
        attacker_ip = "45.33.49." + str(random.randint(1, 254))
        
        # Target is a random internal host
        target_ip = random.choice(self.normal_ips)
        
        # Generate a series of packets to different ports
        scan_ports = list(range(20, 30)) + list(range(79, 85)) + list(range(440, 445))
        
        for port in scan_ports:
            src_port = random.randint(40000, 60000)
            protocols = ['IP', 'TCP']
            
            # Generate a small packet for each scan attempt
            self._generate_packet(attacker_ip, target_ip, src_port, port, protocols, random.randint(40, 60))
            
            # Smaller delay between scan packets
            time.sleep(0.01 / self.simulation_speed)
    
    def _simulate_dos_attack(self):
        """Simulate a Denial of Service attack"""
        logger.info("Simulating DoS attack")
        
        # Multiple attacker IPs (distributed attack)
        attacker_ips = [
            "58.218." + str(random.randint(1, 254)) + "." + str(random.randint(1, 254)),
            "104.152." + str(random.randint(1, 254)) + "." + str(random.randint(1, 254)),
            "91.134." + str(random.randint(1, 254)) + "." + str(random.randint(1, 254))
        ]
        
        # Target is a random internal host and service
        target_ip = random.choice(self.normal_ips)
        target_service = random.choice(["HTTP", "HTTPS", "SSH"])
        target_port = self.common_ports[target_service]
        
        # Generate a burst of packets
        for _ in range(30):
            attacker_ip = random.choice(attacker_ips)
            src_port = random.randint(30000, 65000)
            protocols = ['IP', 'TCP'] if target_service != "DNS" else ['IP', 'UDP']
            
            # Generate large packets for the DoS
            self._generate_packet(attacker_ip, target_ip, src_port, target_port, protocols, random.randint(800, 1500))
            
            # Very small delay between DoS packets
            time.sleep(0.005 / self.simulation_speed)
    
    def _simulate_brute_force(self):
        """Simulate a brute force login attack"""
        logger.info("Simulating brute force attack")
        
        # Attacker IP
        attacker_ip = "176.32." + str(random.randint(1, 254)) + "." + str(random.randint(1, 254))
        
        # Target is a random internal host
        target_ip = random.choice(self.normal_ips)
        
        # Target service (SSH or RDP)
        target_service = random.choice(["SSH", "RDP"])
        target_port = self.common_ports[target_service]
        
        # Generate a series of login attempts
        for _ in range(15):
            src_port = random.randint(40000, 60000)
            protocols = ['IP', 'TCP']
            
            # Generate a small packet for each login attempt
            self._generate_packet(attacker_ip, target_ip, src_port, target_port, protocols, random.randint(100, 200))
            
            # Small delay between login attempts
            time.sleep(0.1 / self.simulation_speed)
    
    def _simulate_data_exfiltration(self):
        """Simulate data exfiltration attack"""
        logger.info("Simulating data exfiltration")
        
        # Source is a compromised internal host
        src_ip = random.choice(self.normal_ips)
        
        # Destination is an external suspicious IP
        dst_ip = "185.156." + str(random.randint(1, 254)) + "." + str(random.randint(1, 254))
        
        # Using HTTPS or DNS for exfiltration
        if random.random() < 0.7:
            protocols = ['IP', 'TCP', 'HTTPS']
            dst_port = 443
        else:
            protocols = ['IP', 'UDP', 'DNS']
            dst_port = 53
        
        src_port = random.randint(10000, 65000)
        
        # Generate a series of suspicious data transfers
        for _ in range(5):
            # Large packet sizes for data exfiltration
            self._generate_packet(src_ip, dst_ip, src_port, dst_port, protocols, random.randint(1000, 1500))
            
            # Delay between exfiltration packets
            time.sleep(0.2 / self.simulation_speed)
    
    def _generate_packet(self, src_ip, dst_ip, src_port, dst_port, protocols, size):
        """Generate a packet with the given parameters"""
        timestamp = time.time()
        
        packet_info = {
            'timestamp': timestamp,
            'size': size,
            'protocols': protocols,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': 6 if 'TCP' in protocols else 17,  # 6=TCP, 17=UDP
        }
        
        # Add TCP-specific fields
        if 'TCP' in protocols:
            packet_info['flags'] = 'PA' if random.random() < 0.8 else 'S'
        
        # Add HTTP-specific fields
        if 'HTTP' in protocols:
            packet_info['http_detected'] = True
        
        # Add DNS-specific fields
        if 'DNS' in protocols and random.random() < 0.8:
            domains = ['example.com', 'google.com', 'microsoft.com', 'github.com', 'amazon.com']
            packet_info['dns_query'] = random.choice(domains)
        
        # Put packet in output queue
        self.packet_count += 1
        try:
            self.output_queue.put(packet_info, block=False)
        except queue.Full:
            # If queue is full, just drop the packet
            pass

    def get_stats(self):
        """Get simulation statistics"""
        uptime = time.time() - self.start_time if self.start_time > 0 else 0
        pps = self.packet_count / uptime if uptime > 0 else 0
        
        return {
            'status': 'running' if self.running else 'stopped',
            'packet_count': self.packet_count,
            'uptime': uptime,
            'packets_per_second': pps,
            'simulation_speed': self.simulation_speed,
            'include_attacks': self.include_attacks
        }
    
    def get_packet_rate(self):
        """Calculate current packet rate (packets per second)"""
        uptime = time.time() - self.start_time if self.start_time > 0 else 0
        if uptime <= 0:
            return 0
        return self.packet_count / uptime
    
    def update_settings(self, settings):
        """Update simulation settings"""
        restart_required = False
        
        if 'simulation_speed' in settings:
            self.simulation_speed = float(settings['simulation_speed'])
            
        if 'include_attacks' in settings:
            self.include_attacks = settings['include_attacks']
            
        return restart_required

# For testing
if __name__ == "__main__":
    # Create output queue and simulator
    output_queue = queue.Queue()
    simulator = SimulationGenerator(output_queue=output_queue, simulation_speed=2.0)
    
    # Start simulation
    simulator.start_simulation()
    
    # Process generated packets
    count = 0
    try:
        print("Simulating network traffic. Press Ctrl+C to stop.")
        while count < 100:  # Process 100 packets for testing
            try:
                packet = output_queue.get(block=True, timeout=1.0)
                count += 1
                print(f"Packet {count}: {packet['src_ip']}:{packet['src_port']} -> {packet['dst_ip']}:{packet['dst_port']} ({', '.join(packet['protocols'])})")
            except queue.Empty:
                pass
    except KeyboardInterrupt:
        print("Stopping simulation...")
    finally:
        simulator.stop_simulation()
        print(f"Simulation stats: {simulator.get_stats()}")