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
            # Check if packet queue has data to collect
            if packet_queue.empty():
                time.sleep(0.1)  # Sleep briefly to avoid busy waiting
                continue
            
            # Try to get copy of packet without consuming it
            try:
                packet = packet_queue.queue[0]
            except IndexError:
                continue
                
            # Store packet for visualization
            with packet_lock:
                recent_packets.append(packet)
                # Trim list if needed
                if len(recent_packets) > max_stored_packets:
                    recent_packets.pop(0)
                    
            time.sleep(0.01)  # Small delay to avoid overwhelming CPU
            
        except Exception as e:
            logger.error(f"Error in packet collector: {str(e)}")
            time.sleep(1)  # Longer sleep on error

# Start collector threads
def start_collectors():
    """Start background collector threads"""
    # Start detection collector thread
    detection_thread = threading.Thread(target=detection_collector)
    detection_thread.daemon = True
    detection_thread.start()
    
    # Start packet collector thread
    packet_thread = threading.Thread(target=packet_collector)
    packet_thread.daemon = True
    packet_thread.start()
    
    logger.info("Started collector threads")

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
        # Check if already running
        if sniffer and sniffer.running:
            return jsonify({"status": "already running"}), 200
            
        # Initialize components if needed
        initialize_system()
        
        # Set capture parameters if provided
        if request.is_json:
            if 'interface' in request.json:
                sniffer.interface = request.json['interface']
                
            if 'filter' in request.json:
                sniffer.filter_str = request.json['filter']
                
            # Set detector thresholds if provided
            if 'anomaly_threshold' in request.json:
                detector.set_anomaly_threshold(float(request.json['anomaly_threshold']))
                
            if 'attack_threshold' in request.json:
                detector.set_attack_threshold(float(request.json['attack_threshold']))
        
        # Start components
        sniffer.start_capture()
        processor.start_processing()
        detector.start_detection()
        
        # Update status
        system_status["sniffer"] = "running"
        system_status["processor"] = "running"
        system_status["detector"] = "running"
        system_status["start_time"] = time.time()
        
        logger.info("System started")
        return jsonify({"status": "started"}), 200
        
    except Exception as e:
        logger.error(f"Error starting system: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/system/stop', methods=['POST'])
@jwt_required()
def stop_system():
    """Stop the NIDS system"""
    global system_status
    
    try:
        # Check if components exist and are running
        if sniffer:
            sniffer.stop_capture()
            system_status["sniffer"] = "stopped"
            
        if processor:
            processor.stop_processing()
            system_status["processor"] = "stopped"
            
        if detector:
            detector.stop_detection()
            system_status["detector"] = "stopped"
        
        logger.info("System stopped")
        return jsonify({"status": "stopped"}), 200
        
    except Exception as e:
        logger.error(f"Error stopping system: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/system/status/full', methods=['GET'])
@jwt_required()
def get_system_status_full():
    """Get current detailed system status"""
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
    if not recent_detections:
        return 0
        
    one_minute_ago = time.time() - 60
    recent_count = sum(1 for d in recent_detections if d.get("timestamp", 0) >= one_minute_ago)
    return recent_count / 60  # detections per second

@app.route('/api/system/settings', methods=['POST'])
@jwt_required()
def update_settings():
    """Update system settings"""
    try:
        if not request.is_json:
            return jsonify({"error": "Missing JSON in request"}), 400
            
        settings = request.json
        
        # Initialize components if needed
        initialize_system()
        
        # Update sniffer settings
        if 'interface' in settings and sniffer:
            sniffer.interface = settings['interface']
            logger.info(f"Updated capture interface to: {settings['interface']}")
            
        if 'capture_filter' in settings and sniffer:
            sniffer.filter_str = settings['capture_filter']
            logger.info(f"Updated capture filter to: {settings['capture_filter']}")
        
        # Update detector settings
        if 'anomaly_threshold' in settings and detector:
            detector.set_anomaly_threshold(float(settings['anomaly_threshold']))
            
        if 'attack_threshold' in settings and detector:
            detector.set_attack_threshold(float(settings['attack_threshold']))
        
        # Handle other settings as needed
        
        return jsonify({"status": "success", "message": "Settings updated"}), 200
        
    except Exception as e:
        logger.error(f"Error updating settings: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Data endpoints
@app.route('/api/data/detections', methods=['GET'])
@jwt_required()
def get_detections():
    """Get recent detections"""
    try:
        # Parse optional query parameters
        limit = min(int(request.args.get('limit', 50)), max_stored_detections)
        anomalies_only = request.args.get('anomalies_only', '').lower() == 'true'
        attacks_only = request.args.get('attacks_only', '').lower() == 'true'
        
        with detection_lock:
            # Apply filters
            filtered_detections = recent_detections
            
            if anomalies_only:
                filtered_detections = [d for d in filtered_detections if d.get('is_anomaly', False)]
                
            if attacks_only:
                filtered_detections = [d for d in filtered_detections if d.get('is_attack', False)]
                
            # Sort by timestamp (descending) and limit
            result = sorted(filtered_detections, key=lambda d: d.get('timestamp', 0), reverse=True)[:limit]
        
        return jsonify(result), 200
        
    except Exception as e:
        logger.error(f"Error getting detections: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/data/packets', methods=['GET'])
@jwt_required()
def get_packets():
    """Get recent packets for visualization"""
    try:
        # Parse optional query parameters
        limit = min(int(request.args.get('limit', 100)), max_stored_packets)
        protocol_filter = request.args.get('protocol', '').upper()
        
        with packet_lock:
            # Apply filters
            if protocol_filter:
                filtered_packets = [p for p in recent_packets if protocol_filter in p.get('protocols', [])]
            else:
                filtered_packets = recent_packets
                
            # Sort by timestamp (descending) and limit
            result = sorted(filtered_packets, key=lambda p: p.get('timestamp', 0), reverse=True)[:limit]
        
        return jsonify(result), 200
        
    except Exception as e:
        logger.error(f"Error getting packets: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/data/statistics', methods=['GET'])
@jwt_required()
def get_statistics():
    """Get traffic statistics"""
    try:
        time_range = int(request.args.get('time_range', 300))  # Default: 5 minutes
        
        stats = {
            "packet_count": len(recent_packets),
            "detection_count": len(recent_detections),
            "anomaly_count": sum(1 for d in recent_detections if d.get('is_anomaly', False)),
            "attack_count": sum(1 for d in recent_detections if d.get('is_attack', False)),
            "protocols": {},
            "traffic_over_time": calculate_traffic_over_time(time_range)
        }
        
        # Calculate protocol distribution
        protocols = {}
        for packet in recent_packets:
            for protocol in packet.get('protocols', []):
                protocols[protocol] = protocols.get(protocol, 0) + 1
        
        stats["protocols"] = protocols
        
        return jsonify(stats), 200
        
    except Exception as e:
        logger.error(f"Error getting statistics: {str(e)}")
        return jsonify({"error": str(e)}), 500

def calculate_traffic_over_time(time_range=300, intervals=30):
    """Calculate traffic distribution over time"""
    now = time.time()
    start_time = now - time_range
    interval_length = time_range / intervals
    
    # Initialize intervals
    traffic_intervals = {i: {"packets": 0, "bytes": 0} for i in range(intervals)}
    
    for packet in recent_packets:
        ts = packet.get('timestamp', 0)
        if ts >= start_time:
            # Calculate which interval this packet belongs to
            interval = min(intervals - 1, int((ts - start_time) / interval_length))
            traffic_intervals[interval]["packets"] += 1
            traffic_intervals[interval]["bytes"] += packet.get('size', 0)
    
    # Convert to array form for easier plotting
    result = []
    for i in range(intervals):
        interval_start = start_time + (i * interval_length)
        result.append({
            "time": interval_start,
            "packets": traffic_intervals[i]["packets"],
            "bytes": traffic_intervals[i]["bytes"]
        })
    
    return result

# System status endpoint for dashboard
@app.route('/api/system/metrics', methods=['GET'])
@jwt_required()
def get_system_metrics():
    """Get system metrics for dashboard"""
    try:
        import psutil
        
        # Get system metrics
        metrics = {
            "cpu_percent": psutil.cpu_percent(),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage('/').percent
        }
        
        return jsonify(metrics), 200
        
    except Exception as e:
        logger.error(f"Error getting system metrics: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Simplified status endpoint for dashboard
@app.route('/api/system/status', methods=['GET'])
@jwt_required()
def get_dashboard_status():
    """Get system status for dashboard"""
    global system_status
    
    try:
        # Simplify status for dashboard
        status = {
            "sniffer": system_status["sniffer"],
            "processor": system_status["processor"],
            "detector": system_status["detector"],
            "start_time": system_status["start_time"],
            "packets_captured": sniffer.packet_count if sniffer else 0,
            "packets_per_second": sniffer.get_packet_rate() if sniffer and hasattr(sniffer, 'get_packet_rate') else 0,
            "anomalies_detected": detector.anomaly_count if detector else 0,
            "attacks_detected": detector.attack_count if detector else 0,
            "active_flows": len(processor.flow_stats) if processor and hasattr(processor, 'flow_stats') else 0
        }
        
        return jsonify(status), 200
    
    except Exception as e:
        logger.error(f"Error getting dashboard status: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

# Recent detections endpoint for dashboard alerts
@app.route('/api/detections/recent', methods=['GET'])
@jwt_required()
def get_recent_detections():
    """Get recent detections for dashboard alerts"""
    try:
        limit = min(int(request.args.get('limit', 10)), max_stored_detections)
        
        with detection_lock:
            # Validate detection objects and filter out any that aren't properly formatted
            valid_detections = []
            for detection in recent_detections:
                # Check if detection is a dictionary with at least a timestamp
                if isinstance(detection, dict) and 'timestamp' in detection:
                    valid_detections.append(detection)
                else:
                    logger.warning(f"Invalid detection object found: {type(detection)}")
            
            # Sort by timestamp (descending) and limit
            result = sorted(valid_detections, key=lambda d: d.get('timestamp', 0), reverse=True)[:limit]
        
        return jsonify(result), 200
        
    except Exception as e:
        logger.error(f"Error getting recent detections: {str(e)}")
        # Return empty array instead of error to prevent frontend from breaking
        return jsonify([]), 200

if __name__ == "__main__":
    # Initialize system on startup
    initialize_system()
    
    # Start collector threads
    start_collectors()
    
    # Start Flask app (use waitress or gunicorn in production)
    port = int(os.getenv('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=False)