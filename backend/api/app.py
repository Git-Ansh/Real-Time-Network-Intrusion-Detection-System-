import os
import time
import json
import queue
import datetime
import threading
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from dotenv import load_dotenv
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Import our custom modules
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from packet_capture.packet_sniffer import PacketSniffer
from packet_capture.packet_processor import PacketProcessor
from ml_models.anomaly_detector import AnomalyDetector

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configure JWT
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=1)
jwt = JWTManager(app)

# Global queues for communication between components
packet_queue = queue.Queue(maxsize=1000)
feature_queue = queue.Queue(maxsize=1000)
detection_queue = queue.Queue(maxsize=1000)

# Global components
sniffer = None
processor = None
detector = None

# Store recent detections
max_stored_detections = 1000
recent_detections = []
detection_lock = threading.Lock()

# Store recent packets (for visualization)
max_stored_packets = 1000
recent_packets = []
packet_lock = threading.Lock()

# Component status
system_status = {
    "sniffer": "stopped",
    "processor": "stopped",
    "detector": "stopped",
    "start_time": None
}

def initialize_system():
    """Initialize all system components"""
    global sniffer, processor, detector
    
    if sniffer is None:
        sniffer = PacketSniffer(output_queue=packet_queue)
    
    if processor is None:
        processor = PacketProcessor(input_queue=packet_queue, output_queue=feature_queue)
    
    if detector is None:
        detector = AnomalyDetector(input_queue=feature_queue, output_queue=detection_queue)

def detection_collector():
    """Thread to collect detection results"""
    while True:
        try:
            # Get detection with timeout
            detection = detection_queue.get(block=True, timeout=1.0)
            
            # Store in recent detections
            with detection_lock:
                recent_detections.append(detection)
                # Trim list if needed
                if len(recent_detections) > max_stored_detections:
                    recent_detections.pop(0)
                    
        except queue.Empty:
            pass
        except Exception as e:
            logger.error(f"Error in detection collector: {str(e)}")
            
def packet_collector():
    """Thread to collect packet data for visualization"""
    while True:
        try:
            # Try to get packet from queue
            packet = packet_queue.get(block=False)
            
            # Deep copy relevant packet info to avoid storing too much data
            simplified_packet = {
                "timestamp": packet.get("timestamp"),
                "size": packet.get("size"),
                "protocols": packet.get("protocols", []),
                "src_ip": packet.get("src_ip", "unknown"),
                "dst_ip": packet.get("dst_ip", "unknown"),
                "src_port": packet.get("src_port", 0),
                "dst_port": packet.get("dst_port", 0)
            }
            
            # Store packet data
            with packet_lock:
                recent_packets.append(simplified_packet)
                # Trim list if needed
                if len(recent_packets) > max_stored_packets:
                    recent_packets.pop(0)
            
            # Put packet back in queue for processor
            packet_queue.put(packet)
            
        except queue.Empty:
            time.sleep(0.1)  # Sleep briefly to avoid busy waiting
        except Exception as e:
            logger.error(f"Error in packet collector: {str(e)}")

# Start collector threads
def start_collectors():
    """Start background collector threads"""
    detection_thread = threading.Thread(target=detection_collector)
    detection_thread.daemon = True
    detection_thread.start()
    
    packet_thread = threading.Thread(target=packet_collector)
    packet_thread.daemon = True
    packet_thread.start()

# Authentication endpoints
@app.route('/api/auth/login', methods=['POST'])
def login():
    """Login endpoint"""
    try:
        if not request.is_json:
            return jsonify({"error": "Missing JSON in request"}), 400
        
        username = request.json.get('username', None)
        password = request.json.get('password', None)
        
        if not username or not password:
            return jsonify({"error": "Missing username or password"}), 400
        
        # Simple auth for demo purposes
        # In a production app, you'd validate against a database
        admin_user = os.getenv('ADMIN_USER', 'admin')
        admin_pass = os.getenv('ADMIN_PASSWORD', 'password')
        
        logger.info(f"Attempting login for user: {username}")
        
        if username == admin_user and password == admin_pass:
            access_token = create_access_token(identity=username)
            return jsonify({"token": access_token, "user": username}), 200
        else:
            return jsonify({"error": "Invalid credentials"}), 401
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({"error": "Internal server error during login"}), 500

# System control endpoints
@app.route('/api/system/start', methods=['POST'])
@jwt_required()
def start_system():
    """Start the NIDS system"""
    global system_status
    
    try:
        # Initialize if needed
        initialize_system()
        
        # Start sniffer
        if not sniffer.running:
            sniffer.start_capture()
            system_status["sniffer"] = "running"
            
        # Start processor
        if not processor.running:
            processor.start_processing()
            system_status["processor"] = "running"
            
        # Start detector
        if not detector.running:
            detector.start_detection()
            system_status["detector"] = "running"
            
        # Record start time
        if system_status["start_time"] is None:
            system_status["start_time"] = time.time()
            
        logger.info("System started successfully")
        return jsonify({"status": "success", "message": "System started"}), 200
    
    except Exception as e:
        logger.error(f"Error starting system: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/system/stop', methods=['POST'])
@jwt_required()
def stop_system():
    """Stop the NIDS system"""
    global system_status
    
    try:
        # Stop components in reverse order
        if detector and detector.running:
            detector.stop_detection()
            system_status["detector"] = "stopped"
            
        if processor and processor.running:
            processor.stop_processing()
            system_status["processor"] = "stopped"
            
        if sniffer and sniffer.running:
            sniffer.stop_capture()
            system_status["sniffer"] = "stopped"
            
        logger.info("System stopped successfully")
        return jsonify({"status": "success", "message": "System stopped"}), 200
    
    except Exception as e:
        logger.error(f"Error stopping system: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/system/status', methods=['GET'])
@jwt_required()
def get_system_status():
    """Get current system status"""
    global system_status
    
    try:
        # Get component stats
        status = {
            "system": {
                "status": "running" if sniffer and sniffer.running else "stopped",
                "uptime": time.time() - system_status["start_time"] if system_status["start_time"] else 0
            },
            "components": {
                "sniffer": sniffer.get_stats() if sniffer else {"status": "not_initialized"},
                "processor": processor.get_stats() if processor else {"status": "not_initialized"},
                "detector": detector.get_stats() if detector else {"status": "not_initialized"}
            },
            "metrics": {
                "pending_packets": packet_queue.qsize() if packet_queue else 0,
                "pending_features": feature_queue.qsize() if feature_queue else 0,
                "pending_detections": detection_queue.qsize() if detection_queue else 0,
                "stored_detections": len(recent_detections),
                "detection_rate": calculate_detection_rate()
            }
        }
        
        return jsonify(status), 200
    
    except Exception as e:
        logger.error(f"Error getting system status: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

def calculate_detection_rate():
    """Calculate detection rate over the last minute"""
    with detection_lock:
        if not recent_detections:
            return 0
        
        # Get detections from last minute
        current_time = time.time()
        recent = [d for d in recent_detections 
                  if d["timestamp"] > current_time - 60]
        
        # Count anomalies and attacks
        anomaly_count = sum(1 for d in recent if d["is_anomaly"])
        attack_count = sum(1 for d in recent if d["is_attack"])
        
        return {
            "total_detections": len(recent),
            "anomalies": anomaly_count,
            "attacks": attack_count,
            "period_seconds": 60
        }

# Data endpoints
@app.route('/api/data/detections', methods=['GET'])
@jwt_required()
def get_detections():
    """Get recent detections"""
    try:
        # Get query parameters
        limit = min(int(request.args.get('limit', 100)), 1000)
        anomalies_only = request.args.get('anomalies_only', 'false').lower() == 'true'
        attacks_only = request.args.get('attacks_only', 'false').lower() == 'true'
        
        with detection_lock:
            filtered_detections = recent_detections
            
            # Apply filters
            if anomalies_only:
                filtered_detections = [d for d in filtered_detections if d["is_anomaly"]]
            if attacks_only:
                filtered_detections = [d for d in filtered_detections if d["is_attack"]]
                
            # Sort by timestamp (newest first) and limit
            sorted_detections = sorted(filtered_detections, 
                                      key=lambda d: d["timestamp"], 
                                      reverse=True)
            limited_detections = sorted_detections[:limit]
            
        return jsonify(limited_detections), 200
    
    except Exception as e:
        logger.error(f"Error getting detections: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/data/packets', methods=['GET'])
@jwt_required()
def get_packets():
    """Get recent packets for visualization"""
    try:
        # Get query parameters
        limit = min(int(request.args.get('limit', 100)), 1000)
        protocol_filter = request.args.get('protocol', None)
        
        with packet_lock:
            filtered_packets = recent_packets
            
            # Apply protocol filter
            if protocol_filter:
                filtered_packets = [p for p in filtered_packets 
                                  if protocol_filter in p["protocols"]]
                
            # Sort by timestamp (newest first) and limit
            sorted_packets = sorted(filtered_packets, 
                                   key=lambda p: p["timestamp"], 
                                   reverse=True)
            limited_packets = sorted_packets[:limit]
            
        return jsonify(limited_packets), 200
    
    except Exception as e:
        logger.error(f"Error getting packets: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/data/statistics', methods=['GET'])
@jwt_required()
def get_statistics():
    """Get traffic statistics"""
    try:
        with packet_lock:
            # Calculate protocol distribution
            protocol_counts = {}
            for packet in recent_packets:
                for protocol in packet["protocols"]:
                    if protocol not in protocol_counts:
                        protocol_counts[protocol] = 0
                    protocol_counts[protocol] += 1
                    
            # Calculate port distribution
            port_counts = {}
            for packet in recent_packets:
                if "dst_port" in packet:
                    port = packet["dst_port"]
                    if port not in port_counts:
                        port_counts[port] = 0
                    port_counts[port] += 1
            
            # Get top 10 ports
            top_ports = sorted([(port, count) for port, count in port_counts.items()], 
                              key=lambda x: x[1], reverse=True)[:10]
            
        # Calculate traffic over time
        traffic_over_time = calculate_traffic_over_time()
        
        # Build statistics
        stats = {
            "protocol_distribution": protocol_counts,
            "top_ports": dict(top_ports),
            "traffic_over_time": traffic_over_time
        }
        
        return jsonify(stats), 200
    
    except Exception as e:
        logger.error(f"Error getting statistics: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

def calculate_traffic_over_time():
    """Calculate traffic volume over time (last hour in 5-minute buckets)"""
    with packet_lock:
        if not recent_packets:
            return []
            
        # Get current time and earliest packet time
        current_time = time.time()
        earliest_time = current_time - 3600  # 1 hour ago
        
        # Create 5-minute buckets
        buckets = []
        for i in range(12):  # 12 5-minute buckets in an hour
            start_time = earliest_time + (i * 300)
            end_time = start_time + 300
            buckets.append({
                "start_time": start_time,
                "end_time": end_time,
                "packet_count": 0,
                "byte_count": 0
            })
            
        # Count packets in each bucket
        for packet in recent_packets:
            if packet["timestamp"] < earliest_time:
                continue
                
            # Find bucket for this packet
            bucket_index = min(int((packet["timestamp"] - earliest_time) / 300), 11)
            buckets[bucket_index]["packet_count"] += 1
            buckets[bucket_index]["byte_count"] += packet["size"]
            
        return buckets

# API Main
if __name__ == '__main__':
    # Initialize components
    initialize_system()
    
    # Start background collectors
    start_collectors()
    
    # Start the API server
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    
    app.run(host='0.0.0.0', port=port, debug=debug)