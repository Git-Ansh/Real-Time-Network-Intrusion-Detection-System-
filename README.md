# Real-Time Network Intrusion Detection System

A comprehensive Network Intrusion Detection System (NIDS) that monitors and analyzes network traffic in real-time to detect anomalies and potential security threats.

## Features

- **Real-time traffic capture and analysis** with Scapy and PyShark
- **Protocol support** for TCP, UDP, HTTP, and DNS
- **Machine learning-based anomaly detection** using:
  - Random Forest for classification
  - Isolation Forest for anomaly detection
- **Interactive visualization dashboard** built with React.js and D3.js
- **Secure access** through JWT-based authentication
- **Containerized deployment** with Docker and Docker Compose

## System Architecture

The system consists of several key components:

1. **Packet Capture Module**

   - Captures and decodes network packets
   - Extracts relevant features for further analysis
   - Handles various network protocols

2. **Packet Processing & Feature Extraction**

   - Processes captured packets to extract statistical features
   - Computes traffic patterns and flow statistics
   - Prepares data for machine learning models

3. **Anomaly Detection Engine**

   - Uses Isolation Forest for unsupervised anomaly detection
   - Employs Random Forest for classification of known attack patterns
   - Continuously learns from network traffic

4. **API Layer**

   - RESTful API built with Flask
   - JWT authentication for secure access
   - Real-time data streaming

5. **Visualization Dashboard**
   - Interactive network traffic visualization with D3.js
   - Real-time alerts and notifications
   - Traffic pattern analysis tools

## Technology Stack

### Backend

- Python 3.9
- Scapy & PyShark for packet capture
- Scikit-learn for machine learning models
- Flask for REST API
- Flask-JWT-Extended for authentication

### Frontend

- React.js
- D3.js for data visualization
- Recharts for charts and graphs
- Bootstrap for responsive UI
- Axios for API communication

### Deployment

- Docker for containerization
- Nginx as web server
- Docker Compose for orchestration

## Installation and Usage

### Prerequisites

- Docker and Docker Compose
- Network interface with promiscuous mode support (for packet capture)
- Admin/root privileges (required for packet capture)

### Quick Start

1. Clone the repository:

   ```
   git clone https://github.com/yourusername/Real-Time-Network-Intrusion-Detection-System.git
   cd Real-Time-Network-Intrusion-Detection-System
   ```

2. Configure environment variables:

   - Create a `.env` file in the root directory with the following settings:
     ```
     JWT_SECRET_KEY=your_secure_secret_key
     ADMIN_USER=your_admin_username
     ADMIN_PASSWORD=your_admin_password
     ```

3. Start the application:

   ```
   docker-compose up -d
   ```

4. Access the dashboard:
   - Open your browser and navigate to `http://localhost`
   - Login with the admin credentials you specified

### Manual Setup (Without Docker)

#### Backend

1. Install Python dependencies:

   ```
   cd backend
   pip install -r requirements.txt
   ```

2. Start the backend server:
   ```
   cd api
   python app.py
   ```

#### Frontend

1. Install Node.js dependencies:

   ```
   cd frontend
   npm install
   ```

2. Start the development server:
   ```
   npm start
   ```

## Security Considerations

- The system requires promiscuous mode access to network interfaces
- Admin privileges are required for packet capture
- Use strong JWT secrets in production
- Change default admin credentials immediately
- Consider network segmentation for deployment
- Review and understand legal implications of network monitoring in your jurisdiction

## Future Enhancements

- Integration with threat intelligence feeds
- Support for additional network protocols
- Deep packet inspection capabilities
- Advanced machine learning models for better detection
- User management system with role-based access control
- Alerting mechanisms (email, SMS, integrations)
- Distributed deployment for handling larger networks

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Scikit-learn for machine learning libraries
- Scapy and PyShark teams for packet capture capabilities
- React and D3.js communities for visualization tools
