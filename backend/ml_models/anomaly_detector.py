import os
import time
import threading
import queue
import logging
import json
import numpy as np
import pickle
import joblib
from collections import defaultdict
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AnomalyDetector:
    def __init__(self, input_queue=None, output_queue=None, 
                 models_dir=None, anomaly_threshold=-0.3, attack_threshold=0.7):
        """
        Initialize the anomaly detector
        
        Args:
            input_queue: Queue containing features extracted from network traffic
            output_queue: Queue to place detection results
            models_dir: Directory containing ML models
            anomaly_threshold: Threshold for anomaly detection (-1 to 0, lower = more sensitive)
            attack_threshold: Threshold for attack classification (0 to 1, higher = more specific)
        """
        self.input_queue = input_queue if input_queue else queue.Queue()
        self.output_queue = output_queue if output_queue else queue.Queue()
        self.models_dir = models_dir or os.path.join(os.path.dirname(__file__), '..', 'models')
        self.running = False
        self.detector_thread = None
        self.processed_count = 0
        self.anomaly_count = 0
        self.attack_count = 0
        self.start_time = 0
        self.anomaly_threshold = anomaly_threshold
        self.attack_threshold = attack_threshold
        
        # Load models
        self.isolation_forest = None
        self.random_forest = None
        self.scaler = None
        
        # Feature mapping for models
        self.feature_mapping = None
        self.attack_types = [
            "normal", "port_scan", "dos", "brute_force", "data_exfiltration", 
            "malware_communication", "unknown"
        ]
        
        # Cache for recent scores
        self.recent_scores = []
        self.max_scores_cache = 100
        
        # Try to load models
        self._load_models()
    
    def _load_models(self):
        """Load ML models from disk"""
        try:
            # Create models directory if it doesn't exist
            os.makedirs(self.models_dir, exist_ok=True)
            
            # Load feature mapping
            feature_mapping_path = os.path.join(self.models_dir, 'feature_mapping.json')
            if os.path.exists(feature_mapping_path):
                with open(feature_mapping_path, 'r') as f:
                    self.feature_mapping = json.load(f)
            
            # If no feature mapping, create a default one
            if not self.feature_mapping:
                self.feature_mapping = {
                    'mean_packet_size': 0, 'std_packet_size': 1, 'packet_rate': 2,
                    'byte_rate': 3, 'unique_ips': 4, 'unique_ports': 5,
                    'TCP_prop': 6, 'UDP_prop': 7, 'HTTP_prop': 8, 'DNS_prop': 9,
                    'has_http': 10, 'has_dns': 11, 'has_tcp': 12, 'has_udp': 13,
                    'num_flows': 14, 'mean_flow_packets': 15, 'mean_flow_bytes': 16
                }
                
            # Load isolation forest model for anomaly detection
            isolation_forest_path = os.path.join(self.models_dir, 'isolation_forest.pkl')
            if os.path.exists(isolation_forest_path):
                self.isolation_forest = joblib.load(isolation_forest_path)
            else:
                # Create a new model if one doesn't exist
                logger.info("Creating new Isolation Forest model")
                self.isolation_forest = IsolationForest(
                    n_estimators=100,
                    max_samples='auto',
                    contamination=0.1,  # expected proportion of anomalies
                    random_state=42
                )
                # Will be trained with first batch of data
            
            # Load random forest model for attack classification
            random_forest_path = os.path.join(self.models_dir, 'random_forest.pkl')
            if os.path.exists(random_forest_path):
                self.random_forest = joblib.load(random_forest_path)
            else:
                # Create a new model if one doesn't exist
                logger.info("Creating new Random Forest model")
                self.random_forest = RandomForestClassifier(
                    n_estimators=100,
                    max_depth=10,
                    random_state=42
                )
                # Will be trained with first labeled data (if available)
            
            # Load scaler for feature normalization
            scaler_path = os.path.join(self.models_dir, 'scaler.pkl')
            if os.path.exists(scaler_path):
                self.scaler = joblib.load(scaler_path)
            else:
                # Create a new scaler if one doesn't exist
                logger.info("Creating new scaler")
                self.scaler = StandardScaler()
                # Will be fit with first batch of data
                
            logger.info("Machine learning models loaded successfully")
            
        except Exception as e:
            logger.error(f"Error loading models: {str(e)}")
            # Initialize new models as fallback
            self.isolation_forest = IsolationForest(
                n_estimators=100, 
                contamination=0.1,
                random_state=42
            )
            self.random_forest = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42
            )
            self.scaler = StandardScaler()
        
    def _save_models(self):
        """Save ML models to disk"""
        try:
            # Create models directory if it doesn't exist
            os.makedirs(self.models_dir, exist_ok=True)
            
            # Save feature mapping
            feature_mapping_path = os.path.join(self.models_dir, 'feature_mapping.json')
            with open(feature_mapping_path, 'w') as f:
                json.dump(self.feature_mapping, f)
            
            # Save isolation forest model
            if self.isolation_forest:
                isolation_forest_path = os.path.join(self.models_dir, 'isolation_forest.pkl')
                joblib.dump(self.isolation_forest, isolation_forest_path)
            
            # Save random forest model
            if self.random_forest:
                random_forest_path = os.path.join(self.models_dir, 'random_forest.pkl')
                joblib.dump(self.random_forest, random_forest_path)
            
            # Save scaler
            if self.scaler:
                scaler_path = os.path.join(self.models_dir, 'scaler.pkl')
                joblib.dump(self.scaler, scaler_path)
                
            logger.info("Machine learning models saved successfully")
            
        except Exception as e:
            logger.error(f"Error saving models: {str(e)}")
    
    def start_detection(self):
        """Start anomaly detection"""
        if self.running:
            logger.warning("Anomaly detection already running")
            return
            
        self.running = True
        self.start_time = time.time()
        self.processed_count = 0
        self.anomaly_count = 0
        self.attack_count = 0
        
        # Start the detector thread
        self.detector_thread = threading.Thread(target=self._detect_anomalies)
        self.detector_thread.daemon = True
        self.detector_thread.start()
        
        logger.info("Started anomaly detection")
        
    def stop_detection(self):
        """Stop anomaly detection"""
        if not self.running:
            logger.warning("Anomaly detection not running")
            return
            
        self.running = False
        
        if self.detector_thread:
            self.detector_thread.join(2.0)  # Wait up to 2 seconds
            
        duration = time.time() - self.start_time
        logger.info(f"Stopped anomaly detection. Processed {self.processed_count} feature sets in {duration:.2f} seconds")
        logger.info(f"Detected {self.anomaly_count} anomalies and {self.attack_count} attacks")
        
        # Save models on shutdown
        self._save_models()
    
    def _detect_anomalies(self):
        """Main detection loop"""
        # Buffer for training
        training_buffer = []
        min_samples_for_training = 50
        
        while self.running:
            try:
                # Get features with timeout to allow checking 'running' flag
                features = self.input_queue.get(block=True, timeout=1.0)
                self.processed_count += 1
                
                # Extract features for ML
                feature_vector = self._features_to_vector(features)
                
                # If scaler not fitted or isolation forest not fitted, buffer data
                if not hasattr(self.scaler, 'mean_') or not hasattr(self.isolation_forest, 'offset_'):
                    training_buffer.append(feature_vector)
                    
                    if len(training_buffer) >= min_samples_for_training:
                        # Fit scaler and isolation forest with initial data
                        training_data = np.array(training_buffer)
                        self.scaler.fit(training_data)
                        scaled_data = self.scaler.transform(training_data)
                        self.isolation_forest.fit(scaled_data)
                        
                        logger.info(f"Fitted models with {len(training_buffer)} samples")
                        training_buffer = []  # Clear buffer
                        
                    continue  # Skip detection until models are fitted
                
                # Scale features
                scaled_features = self.scaler.transform([feature_vector])[0]
                
                # Anomaly detection
                anomaly_score = self.isolation_forest.decision_function([scaled_features])[0]
                # Note: decision_function returns high values for normal data, low for anomalies
                # We'll negate it so higher anomaly_score = more anomalous
                anomaly_score = -anomaly_score
                
                # Determine if anomaly based on threshold
                is_anomaly = anomaly_score >= self.anomaly_threshold
                
                # Default attack values
                is_attack = False
                attack_type = None
                attack_probability = 0.0
                
                # Attack classification (if anomaly detected)
                if is_anomaly and hasattr(self.random_forest, 'classes_'):
                    # Only run attack classification if model is trained
                    attack_probabilities = self.random_forest.predict_proba([scaled_features])[0]
                    max_prob_idx = np.argmax(attack_probabilities[1:]) + 1  # Skip 'normal' class
                    attack_probability = attack_probabilities[max_prob_idx]
                    
                    if attack_probability >= self.attack_threshold:
                        is_attack = True
                        attack_type = self.attack_types[max_prob_idx]
                
                # Update counters
                if is_anomaly:
                    self.anomaly_count += 1
                if is_attack:
                    self.attack_count += 1
                
                # Save score in cache
                self.recent_scores.append(anomaly_score)
                if len(self.recent_scores) > self.max_scores_cache:
                    self.recent_scores.pop(0)
                
                # Create detection result
                detection_result = {
                    "timestamp": features.get("timestamp", time.time()),
                    "is_anomaly": is_anomaly,
                    "anomaly_score": float(anomaly_score),
                    "is_attack": is_attack,
                    "attack_type": attack_type,
                    "attack_probability": float(attack_probability),
                    "raw_features": {
                        k: features.get(k) for k in [
                            'mean_packet_size', 'packet_rate', 'byte_rate',
                            'unique_ips', 'unique_ports'
                        ] if k in features
                    }
                }
                
                # Add detection to output queue
                try:
                    self.output_queue.put(detection_result, block=False)
                except queue.Full:
                    logger.warning("Output queue is full, dropping detection result")
                    
                    # Log anomalies and attacks
                    if detection_result["is_anomaly"] or detection_result["is_attack"]:
                        log_msg = f"Detection: Anomaly={detection_result['is_anomaly']}, Attack={detection_result['is_attack']}"
                        if "attack_type" in detection_result and detection_result["attack_type"]:
                            log_msg += f", Type={detection_result['attack_type']}"
                        logger.warning(log_msg)
                        
            except queue.Empty:
                pass
            except Exception as e:
                logger.error(f"Error in anomaly detector: {str(e)}")
    
    def _features_to_vector(self, features):
        """Convert feature dict to vector for ML"""
        # If we don't have a feature mapping, create one from this feature set
        if not self.feature_mapping:
            feature_keys = []
            
            # Add basic features
            for key in ['mean_packet_size', 'std_packet_size', 'packet_rate', 'byte_rate', 
                       'unique_ips', 'unique_ports']:
                if key in features:
                    feature_keys.append(key)
            
            # Add protocol features
            if 'protocol_features' in features:
                for key in features['protocol_features']:
                    feature_keys.append(key)
            
            # Add flow features
            if 'flow_features' in features:
                for key in features['flow_features']:
                    feature_keys.append(key)
            
            # Create mapping
            self.feature_mapping = {key: i for i, key in enumerate(feature_keys)}
        
        # Create feature vector
        vector = np.zeros(len(self.feature_mapping))
        
        # Basic features
        for key, idx in self.feature_mapping.items():
            if key in features:
                vector[idx] = features[key]
            elif 'protocol_features' in features and key in features['protocol_features']:
                vector[idx] = features['protocol_features'][key]
            elif 'flow_features' in features and key in features['flow_features']:
                vector[idx] = features['flow_features'][key]
        
        return vector
    
    def set_anomaly_threshold(self, threshold):
        """Update anomaly detection threshold"""
        self.anomaly_threshold = threshold
        logger.info(f"Anomaly threshold set to {threshold}")
        
    def set_attack_threshold(self, threshold):
        """Update attack classification threshold"""
        self.attack_threshold = threshold
        logger.info(f"Attack threshold set to {threshold}")
    
    def get_stats(self):
        """Get detector statistics"""
        if not self.start_time:
            return {
                "status": "not started",
                "anomaly_threshold": self.anomaly_threshold,
                "attack_threshold": self.attack_threshold
            }
            
        duration = time.time() - self.start_time
        stats = {
            "status": "running" if self.running else "stopped",
            "samples_processed": self.processed_count,
            "anomalies_detected": self.anomaly_count,
            "attacks_detected": self.attack_count,
            "duration_seconds": duration,
            "processing_rate": self.processed_count / duration if duration > 0 else 0,
            "anomaly_threshold": self.anomaly_threshold,
            "attack_threshold": self.attack_threshold
        }
        
        # Add recent anomaly score stats if available
        if self.recent_scores:
            stats["recent_mean_score"] = np.mean(self.recent_scores)
            stats["recent_max_score"] = np.max(self.recent_scores)
            stats["recent_min_score"] = np.min(self.recent_scores)
        
        return stats


if __name__ == "__main__":
    # Simple test for the detector
    from ..packet_capture.packet_sniffer import PacketSniffer
    from ..packet_capture.packet_processor import PacketProcessor
    
    # Create queues and components
    packet_queue = queue.Queue()
    feature_queue = queue.Queue()
    detection_queue = queue.Queue()
    
    sniffer = PacketSniffer(output_queue=packet_queue)
    processor = PacketProcessor(input_queue=packet_queue, output_queue=feature_queue, window_size=5)
    detector = AnomalyDetector(input_queue=feature_queue, output_queue=detection_queue)
    
    # Start components
    sniffer.start_capture()
    processor.start_processing()
    detector.start_detection()
    
    # Process detections as they come in
    count = 0
    try:
        while count < 5:  # Process 5 detections
            try:
                detection = detection_queue.get(block=True, timeout=30)
                count += 1
                print(f"Detection {count}:")
                print(json.dumps(detection, indent=2))
            except queue.Empty:
                print("Timeout waiting for detections")
                break
    except KeyboardInterrupt:
        print("Interrupted by user")
    finally:
        detector.stop_detection()
        processor.stop_processing()
        sniffer.stop_capture()