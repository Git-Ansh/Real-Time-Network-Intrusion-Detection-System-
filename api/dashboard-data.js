// API route for fetching dashboard data
import { MongoClient } from "mongodb";
import jwt from "jsonwebtoken";

// Environment variables
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://localhost:27017/nids";
const JWT_SECRET =
  process.env.JWT_SECRET || "local-dev-secret-key-change-in-production";

// Initialize MongoDB connection
let cachedDb = null;

async function connectToDatabase() {
  if (cachedDb) {
    return cachedDb;
  }

  const client = await MongoClient.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });

  const db = client.db();
  cachedDb = db;
  return db;
}

// Authentication middleware
async function verifyToken(req) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    throw new Error("No token provided");
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    return decoded;
  } catch (error) {
    throw new Error("Invalid token");
  }
}

// Main handler
export default async function handler(req, res) {
  // CORS headers
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  // Handle preflight OPTIONS request
  if (req.method === "OPTIONS") {
    res.status(200).end();
    return;
  }

  // Only allow GET method
  if (req.method !== "GET") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    // Verify token
    const tokenData = await verifyToken(req);

    // Get the endpoint requested
    const { endpoint, limit, anomalies_only, attacks_only, protocol } =
      req.query;

    if (!endpoint) {
      return res.status(400).json({ error: "Endpoint parameter is required" });
    }

    const db = await connectToDatabase();

    // Process the request based on the endpoint
    switch (endpoint) {
      case "status":
        return await getSystemStatus(db, tokenData, res);

      case "metrics":
        return await getSystemMetrics(db, tokenData, res);

      case "detections":
        return await getDetections(
          db,
          tokenData,
          parseInt(limit) || 10,
          anomalies_only === "true",
          attacks_only === "true",
          res
        );

      case "packets":
        return await getPackets(
          db,
          tokenData,
          parseInt(limit) || 100,
          protocol,
          res
        );

      case "statistics":
        return await getStatistics(db, tokenData, res);

      default:
        return res.status(400).json({ error: "Invalid endpoint" });
    }
  } catch (error) {
    console.error("Dashboard data error:", error);
    if (
      error.message === "No token provided" ||
      error.message === "Invalid token"
    ) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    return res.status(500).json({ error: "Internal server error" });
  }
}

// Get system status
async function getSystemStatus(db, tokenData, res) {
  try {
    // Find user and their organization
    const user = await db
      .collection("users")
      .findOne({ _id: tokenData.userId });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    let systemStatus = {};

    // Check if organization exists
    if (user.orgId) {
      const orgSystem = await db
        .collection("system_status")
        .findOne({ orgId: user.orgId });

      if (orgSystem) {
        systemStatus = {
          sniffer: orgSystem.sniffer || "stopped",
          processor: orgSystem.processor || "stopped",
          detector: orgSystem.detector || "stopped",
          start_time: orgSystem.start_time || null,
          packets_captured: orgSystem.packets_captured || 0,
          packets_per_second: orgSystem.packets_per_second || 0,
          anomalies_detected: orgSystem.anomalies_detected || 0,
          attacks_detected: orgSystem.attacks_detected || 0,
          active_flows: orgSystem.active_flows || 0,
        };
      } else {
        // Create initial system status
        const initialStatus = {
          orgId: user.orgId,
          sniffer: "stopped",
          processor: "stopped",
          detector: "stopped",
          start_time: null,
          packets_captured: 0,
          packets_per_second: 0,
          anomalies_detected: 0,
          attacks_detected: 0,
          active_flows: 0,
          created_at: new Date(),
          updated_at: new Date(),
        };

        await db.collection("system_status").insertOne(initialStatus);
        systemStatus = initialStatus;
      }
    } else {
      // Default demo status for users without an organization
      systemStatus = {
        sniffer: "running",
        processor: "running",
        detector: "running",
        start_time: Math.floor(Date.now() / 1000) - 3600, // Started 1 hour ago
        packets_captured: 10452,
        packets_per_second: 3,
        anomalies_detected: 24,
        attacks_detected: 3,
        active_flows: 47,
      };
    }

    return res.status(200).json(systemStatus);
  } catch (error) {
    console.error("Error getting system status:", error);
    return res.status(500).json({ error: "Failed to fetch system status" });
  }
}

// Get system metrics
async function getSystemMetrics(db, tokenData, res) {
  try {
    // Find user and their organization
    const user = await db
      .collection("users")
      .findOne({ _id: tokenData.userId });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    let metrics = {};

    // Check if organization exists
    if (user.orgId) {
      const orgMetrics = await db
        .collection("system_metrics")
        .findOne({ orgId: user.orgId }, { sort: { timestamp: -1 } });

      if (orgMetrics) {
        metrics = {
          cpu_percent: orgMetrics.cpu_percent || 0,
          memory_percent: orgMetrics.memory_percent || 0,
          disk_percent: orgMetrics.disk_percent || 0,
          timestamp: orgMetrics.timestamp,
        };
      } else {
        // Return demo metrics if no data
        metrics = {
          cpu_percent: 35.4,
          memory_percent: 42.1,
          disk_percent: 58.7,
          timestamp: new Date(),
        };
      }
    } else {
      // Demo metrics for users without an organization
      metrics = {
        cpu_percent: 35.4,
        memory_percent: 42.1,
        disk_percent: 58.7,
        timestamp: new Date(),
      };
    }

    return res.status(200).json(metrics);
  } catch (error) {
    console.error("Error getting system metrics:", error);
    return res.status(500).json({ error: "Failed to fetch system metrics" });
  }
}

// Get detections/alerts
async function getDetections(
  db,
  tokenData,
  limit,
  anomaliesOnly,
  attacksOnly,
  res
) {
  try {
    // Find user and their organization
    const user = await db
      .collection("users")
      .findOne({ _id: tokenData.userId });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    let detections = [];

    // Build query
    const query = {};
    if (user.orgId) {
      query.orgId = user.orgId;
    }

    if (anomaliesOnly) {
      query.is_anomaly = true;
    }

    if (attacksOnly) {
      query.is_attack = true;
    }

    // Check if organization exists and has detections
    if (user.orgId) {
      detections = await db
        .collection("detections")
        .find(query)
        .sort({ timestamp: -1 })
        .limit(limit)
        .toArray();
    }

    // If no detections found or user has no org, return demo data
    if (detections.length === 0) {
      // Generate demo detections
      detections = generateDemoDetections(limit, anomaliesOnly, attacksOnly);
    }

    return res.status(200).json(detections);
  } catch (error) {
    console.error("Error getting detections:", error);
    return res.status(500).json({ error: "Failed to fetch detections" });
  }
}

// Get packets for visualization
async function getPackets(db, tokenData, limit, protocolFilter, res) {
  try {
    // Find user and their organization
    const user = await db
      .collection("users")
      .findOne({ _id: tokenData.userId });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    let packets = [];

    // Build query
    const query = {};
    if (user.orgId) {
      query.orgId = user.orgId;
    }

    if (protocolFilter) {
      query.protocols = protocolFilter;
    }

    // Check if organization exists and has packets
    if (user.orgId) {
      packets = await db
        .collection("packets")
        .find(query)
        .sort({ timestamp: -1 })
        .limit(limit)
        .toArray();
    }

    // If no packets found or user has no org, return demo data
    if (packets.length === 0) {
      // Generate demo packets
      packets = generateDemoPackets(limit, protocolFilter);
    }

    return res.status(200).json(packets);
  } catch (error) {
    console.error("Error getting packets:", error);
    return res.status(500).json({ error: "Failed to fetch packets" });
  }
}

// Get statistics
async function getStatistics(db, tokenData, res) {
  try {
    // Find user and their organization
    const user = await db
      .collection("users")
      .findOne({ _id: tokenData.userId });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Build statistics object
    let stats = {
      packet_count: 0,
      detection_count: 0,
      anomaly_count: 0,
      attack_count: 0,
      protocols: {},
      traffic_over_time: [],
    };

    // Get real stats if organization exists
    if (user.orgId) {
      // Get system status
      const systemStatus = await db
        .collection("system_status")
        .findOne({ orgId: user.orgId });
      if (systemStatus) {
        stats.packet_count = systemStatus.packets_captured || 0;
        stats.detection_count =
          systemStatus.anomalies_detected + systemStatus.attacks_detected || 0;
        stats.anomaly_count = systemStatus.anomalies_detected || 0;
        stats.attack_count = systemStatus.attacks_detected || 0;
      }

      // Get protocol distribution
      const protocolStats = await db
        .collection("protocol_stats")
        .findOne({ orgId: user.orgId });
      if (protocolStats) {
        stats.protocols = protocolStats.distribution || {};
      }

      // Get traffic over time
      const timeTraffic = await db
        .collection("traffic_stats")
        .find({ orgId: user.orgId })
        .sort({ timestamp: -1 })
        .limit(30)
        .toArray();

      if (timeTraffic.length > 0) {
        stats.traffic_over_time = timeTraffic.map((t) => ({
          timestamp: t.timestamp,
          packets: t.packet_count,
          bytes: t.byte_count,
        }));
      }
    }

    // If no stats found or user has no org, return demo data
    if (!stats.traffic_over_time.length) {
      // Demo statistics
      stats = generateDemoStatistics();
    }

    return res.status(200).json(stats);
  } catch (error) {
    console.error("Error getting statistics:", error);
    return res.status(500).json({ error: "Failed to fetch statistics" });
  }
}

// Demo data generators
function generateDemoDetections(limit, anomaliesOnly, attacksOnly) {
  const now = Math.floor(Date.now() / 1000);
  const detections = [];

  // Attack types for demo
  const attackTypes = [
    "port_scan",
    "dos_attempt",
    "brute_force",
    "sql_injection",
    null,
  ];

  for (let i = 0; i < limit; i++) {
    let isAnomaly = Math.random() > 0.5;
    let isAttack = Math.random() > 0.7;

    // Respect filters
    if (anomaliesOnly && !isAnomaly) isAnomaly = true;
    if (attacksOnly && !isAttack) isAttack = true;

    // Make sure at least one is true if both filters are on
    if (anomaliesOnly && attacksOnly) {
      isAnomaly = true;
      isAttack = true;
    }

    // Create detection
    detections.push({
      timestamp: now - Math.floor(Math.random() * 86400), // Last 24 hours
      src_ip: `192.168.1.${Math.floor(Math.random() * 254) + 1}`,
      dst_ip: `10.0.0.${Math.floor(Math.random() * 254) + 1}`,
      src_port: Math.floor(Math.random() * 65535),
      dst_port: [80, 443, 22, 21, 3389, 8080][Math.floor(Math.random() * 6)],
      protocol: ["TCP", "UDP", "HTTP", "DNS"][Math.floor(Math.random() * 4)],
      is_anomaly: isAnomaly,
      is_attack: isAttack,
      anomaly_score: isAnomaly
        ? -0.5 - Math.random() * 0.5
        : -0.2 - Math.random() * 0.1,
      attack_type: isAttack
        ? attackTypes[Math.floor(Math.random() * attackTypes.length)]
        : null,
      confidence: isAttack ? 0.7 + Math.random() * 0.3 : null,
    });
  }

  // Sort by timestamp (descending)
  return detections.sort((a, b) => b.timestamp - a.timestamp);
}

function generateDemoPackets(limit, protocolFilter) {
  const now = Math.floor(Date.now() / 1000);
  const packets = [];

  // Common source and destination IPs
  const srcIPs = [
    "192.168.1.10",
    "192.168.1.15",
    "192.168.1.20",
    "192.168.1.25",
  ];
  const dstIPs = [
    "10.0.0.1",
    "10.0.0.2",
    "10.0.0.3",
    "10.0.0.4",
    "8.8.8.8",
    "1.1.1.1",
  ];

  for (let i = 0; i < limit; i++) {
    // Generate random protocols
    const allProtocols = ["IP"];

    // Add TCP or UDP
    const isTCP = Math.random() > 0.3;
    if (isTCP) {
      allProtocols.push("TCP");

      // Some TCP packets might be HTTP
      if (Math.random() > 0.6) {
        allProtocols.push("HTTP");
      }
    } else {
      allProtocols.push("UDP");

      // Some UDP packets might be DNS
      if (Math.random() > 0.5) {
        allProtocols.push("DNS");
      }
    }

    // Skip this packet if filtering is enabled and it doesn't match
    if (protocolFilter && !allProtocols.includes(protocolFilter)) {
      i--; // Try again
      continue;
    }

    // Create packet
    packets.push({
      timestamp: now - Math.floor(Math.random() * 300), // Last 5 minutes
      src_ip: srcIPs[Math.floor(Math.random() * srcIPs.length)],
      dst_ip: dstIPs[Math.floor(Math.random() * dstIPs.length)],
      src_port: Math.floor(Math.random() * 65535),
      dst_port: isTCP
        ? allProtocols.includes("HTTP")
          ? [80, 443][Math.floor(Math.random() * 2)]
          : Math.floor(Math.random() * 65535)
        : allProtocols.includes("DNS")
        ? 53
        : Math.floor(Math.random() * 65535),
      protocols: allProtocols,
      size: Math.floor(Math.random() * 1400) + 60,
      ttl: 64,
      flags: isTCP ? ["ACK", "PSH"][Math.floor(Math.random() * 2)] : null,
    });
  }

  // Sort by timestamp (descending)
  return packets.sort((a, b) => b.timestamp - a.timestamp);
}

function generateDemoStatistics() {
  const now = Math.floor(Date.now() / 1000);
  const stats = {
    packet_count: 10452,
    detection_count: 27,
    anomaly_count: 24,
    attack_count: 3,
    protocols: {
      IP: 10452,
      TCP: 7845,
      UDP: 2607,
      HTTP: 4231,
      DNS: 1873,
      HTTPS: 3614,
    },
    traffic_over_time: [],
  };

  // Generate traffic over time (30 minute intervals)
  for (let i = 0; i < 30; i++) {
    stats.traffic_over_time.push({
      timestamp: now - (30 - i) * 60,
      packets: Math.floor(Math.random() * 300) + 100,
      bytes: Math.floor(Math.random() * 500000) + 50000,
    });
  }

  return stats;
}
