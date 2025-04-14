import os
import time
import pickle
import threading
import queue
import logging
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from collections import deque

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AnomalyDetector:
    def __init__(self, input_queue, output_queue=None, model_dir='models'):
        """
        Initialize the anomaly detector
        
        Args:
            input_queue: Queue with feature data from processor
            output_queue: Queue to place detection results
            model_dir: Directory to save/load ML models
        """
        self.input_queue = input_queue
        self.output_queue = output_queue if output_queue else queue.Queue()
        self.model_dir = model_dir
        self.running = False
        self.detector_thread = None
        
        # Feature history for online learning
        self.feature_history = deque(maxlen=1000)
        
        # Initialize models
        self.random_forest = None
        self.isolation_forest = None
        self.scaler = StandardScaler()
        
        # Detection thresholds
        self.anomaly_threshold = -0.3  # Isolation Forest threshold
        self.attack_threshold = 0.7    # Random Forest threshold
        
        # Initialize models directory
        os.makedirs(self.model_dir, exist_ok=True)
        
    def start_detection(self):
        """Start the anomaly detection thread"""
        if self.running:
            logger.warning("Anomaly detector already running")
            return
            
        # Load models if available
        self._load_models()
        
        self.running = True
        self.detector_thread = threading.Thread(target=self._detect_anomalies)
        self.detector_thread.daemon = True
        self.detector_thread.start()
        
        logger.info("Started anomaly detector")
        
    def stop_detection(self):
        """Stop the anomaly detection thread"""
        if not self.running:
            logger.warning("Anomaly detector not running")
            return
            
        self.running = False
        if self.detector_thread:
            self.detector_thread.join(2.0)  # Wait up to 2 seconds
            
        # Save models before exit
        self._save_models()
        
        logger.info("Stopped anomaly detector")
        
    def _load_models(self):
        """Load machine learning models from disk if available"""
        rf_path = os.path.join(self.model_dir, 'random_forest.pkl')
        if_path = os.path.join(self.model_dir, 'isolation_forest.pkl')
        scaler_path = os.path.join(self.model_dir, 'scaler.pkl')
        
        try:
            # Try to load Random Forest
            if os.path.exists(rf_path):
                with open(rf_path, 'rb') as f:
                    self.random_forest = pickle.load(f)
                    logger.info("Loaded Random Forest model")
            else:
                self.random_forest = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
                logger.info("Initialized new Random Forest model")
                
            # Try to load Isolation Forest
            if os.path.exists(if_path):
                with open(if_path, 'rb') as f:
                    self.isolation_forest = pickle.load(f)
                    logger.info("Loaded Isolation Forest model")
            else:
                self.isolation_forest = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
                logger.info("Initialized new Isolation Forest model")
                
            # Try to load StandardScaler
            if os.path.exists(scaler_path):
                with open(scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
                    logger.info("Loaded StandardScaler")
        except Exception as e:
            logger.error(f"Error loading models: {str(e)}")
            # Initialize fresh models if loading fails
            self.random_forest = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
            self.isolation_forest = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
            self.scaler = StandardScaler()
            
    def _save_models(self):
        """Save machine learning models to disk"""
        rf_path = os.path.join(self.model_dir, 'random_forest.pkl')
        if_path = os.path.join(self.model_dir, 'isolation_forest.pkl')
        scaler_path = os.path.join(self.model_dir, 'scaler.pkl')
        
        try:
            # Save Random Forest if trained
            if hasattr(self.random_forest, 'classes_'):
                with open(rf_path, 'wb') as f:
                    pickle.dump(self.random_forest, f)
                    
            # Save Isolation Forest if trained
            if hasattr(self.isolation_forest, 'offset_'):
                with open(if_path, 'wb') as f:
                    pickle.dump(self.isolation_forest, f)
                    
            # Save StandardScaler
            with open(scaler_path, 'wb') as f:
                pickle.dump(self.scaler, f)
                
            logger.info("Saved models to disk")
        except Exception as e:
            logger.error(f"Error saving models: {str(e)}")
            
    def _detect_anomalies(self):
        """Main detection loop"""
        # Wait for enough data to perform initial training
        initial_training_done = False
        
        while self.running:
            try:
                # Get the next feature vector with a timeout
                features = self.input_queue.get(block=True, timeout=1.0)
                
                # Store for history/training
                self.feature_history.append(features)
                
                # Check if we have enough data for initial training
                if not initial_training_done and len(self.feature_history) >= 100:
                    self._train_models()
                    initial_training_done = True
                    
                # Periodically retrain models with new data
                if initial_training_done and len(self.feature_history) % 200 == 0:
                    self._train_models()
                
                # Perform detection if models are trained
                if initial_training_done:
                    detection_result = self._evaluate_features(features)
                    
                    # Add timestamp and send to output queue
                    detection_result["timestamp"] = features["timestamp"]
                    self.output_queue.put(detection_result)
                    
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
                
    def _train_models(self):
        """Train or update detection models with current feature history"""
        if not self.feature_history:
            return
            
        try:
            # Convert feature history to DataFrame
            feature_df = pd.DataFrame(list(self.feature_history))
            
            # Remove non-feature columns
            feature_df = feature_df.drop(columns=["timestamp"], errors="ignore")
            
            # Fill any missing values
            feature_df = feature_df.fillna(0)
            
            # Scale features
            X = self.scaler.fit_transform(feature_df)
            
            # Train Isolation Forest for anomaly detection
            self.isolation_forest.fit(X)
            
            # For Random Forest, we need labels for supervised learning
            # In a real system, you'd use labeled data
            # Here we simulate with anomaly scores to create synthetic labels
            anomaly_scores = self.isolation_forest.decision_function(X)
            y = (anomaly_scores < -0.4).astype(int)  # Convert anomaly scores to binary labels
            
            # Add some "attack" labels based on protocol ratios
            for i, features in enumerate(self.feature_history):
                # Label flows with unusually high protocol ratios as potential attacks
                # (This is a simplified example - real detection would use actual labeled data)
                if features.get("tcp_ratio", 0) > 0.95 or features.get("udp_ratio", 0) > 0.95 or \
                   features.get("http_ratio", 0) > 0.8 or features.get("dns_ratio", 0) > 0.8:
                    y[i] = 1
                    
            # Train Random Forest
            self.random_forest.fit(X, y)
            
            logger.info(f"Trained models on {len(self.feature_history)} samples")
            
        except Exception as e:
            logger.error(f"Error training models: {str(e)}")
            
    def _evaluate_features(self, features):
        """
        Evaluate a feature vector for anomalies and attacks
        
        Returns a dict with detection results
        """
        result = {
            "is_anomaly": False,
            "is_attack": False,
            "anomaly_score": 0.0,
            "attack_probability": 0.0,
            "attack_type": None
        }
        
        try:
            # Extract features, removing non-feature columns
            feature_dict = features.copy()
            if "timestamp" in feature_dict:
                del feature_dict["timestamp"]
                
            # Convert to DataFrame and fill any missing values
            feature_df = pd.DataFrame([feature_dict])
            feature_df = feature_df.fillna(0)
            
            # Scale features
            X = self.scaler.transform(feature_df)
            
            # Detect anomalies with Isolation Forest
            anomaly_score = self.isolation_forest.decision_function(X)[0]
            result["anomaly_score"] = float(anomaly_score)
            result["is_anomaly"] = anomaly_score < self.anomaly_threshold
            
            # Classify with Random Forest (if trained)
            if hasattr(self.random_forest, 'classes_'):
                attack_proba = self.random_forest.predict_proba(X)[0]
                attack_probability = attack_proba[1] if len(attack_proba) > 1 else 0.0
                result["attack_probability"] = float(attack_probability)
                result["is_attack"] = attack_probability > self.attack_threshold
                
                # Determine attack type using heuristics
                # (In a real system, you'd have a multi-class classifier for attack types)
                if result["is_attack"]:
                    if features.get("tcp_ratio", 0) > 0.9 and features.get("packet_rate", 0) > 100:
                        result["attack_type"] = "TCP Flood"
                    elif features.get("udp_ratio", 0) > 0.9 and features.get("packet_rate", 0) > 100:
                        result["attack_type"] = "UDP Flood"
                    elif features.get("dns_ratio", 0) > 0.7:
                        result["attack_type"] = "DNS Tunneling"
                    elif features.get("http_ratio", 0) > 0.7:
                        result["attack_type"] = "HTTP Flood"
                    else:
                        result["attack_type"] = "Unknown"
                        
        except Exception as e:
            logger.error(f"Error evaluating features: {str(e)}")
            
        return result
        
    def get_stats(self):
        """Get detector statistics"""
        return {
            "status": "running" if self.running else "stopped",
            "models_trained": hasattr(self.isolation_forest, 'offset_'),
            "feature_history_size": len(self.feature_history)
        }
        
    def set_detection_thresholds(self, anomaly_threshold=None, attack_threshold=None):
        """Update detection thresholds"""
        if anomaly_threshold is not None:
            self.anomaly_threshold = anomaly_threshold
        if attack_threshold is not None:
            self.attack_threshold = attack_threshold
            
        logger.info(f"Updated detection thresholds: anomaly={self.anomaly_threshold}, attack={self.attack_threshold}")


if __name__ == "__main__":
    # Simple test
    import json
    import random
    from collections import defaultdict
    
    # Create queues
    input_q = queue.Queue()
    output_q = queue.Queue()
    
    # Create and start detector
    detector = AnomalyDetector(input_queue=input_q, output_queue=output_q)
    detector.start_detection()
    
    # Generate some synthetic traffic data for testing
    for i in range(150):
        # Normal traffic features
        features = {
            "timestamp": time.time(),
            "duration": random.uniform(0.1, 5.0),
            "packet_count": random.randint(10, 100),
            "byte_count": random.randint(1000, 10000),
            "packet_rate": random.uniform(5, 50),
            "byte_rate": random.uniform(500, 5000),
            "avg_packet_size": random.uniform(50, 200),
            "std_packet_size": random.uniform(10, 50),
            "min_packet_size": random.uniform(20, 60),
            "max_packet_size": random.uniform(100, 1500),
            "tcp_ratio": random.uniform(0.5, 0.8),
            "udp_ratio": random.uniform(0.1, 0.3),
            "http_ratio": random.uniform(0.0, 0.2),
            "dns_ratio": random.uniform(0.0, 0.1),
            "unique_ip_count": random.randint(2, 10),
            "unique_port_count": random.randint(2, 15)
        }
        
        # Add some anomalies
        if i > 120:
            # Simulate a TCP flood attack
            features["tcp_ratio"] = 0.98
            features["packet_rate"] = random.uniform(500, 1000)
            features["byte_rate"] = random.uniform(50000, 100000)
            features["unique_port_count"] = 1
        
        # Send to detector
        input_q.put(features)
        time.sleep(0.05)
    
    # Wait for processing and display results
    time.sleep(2)
    while not output_q.empty():
        result = output_q.get()
        print(json.dumps(result, indent=2))
    
    # Stop the detector
    detector.stop_detection()