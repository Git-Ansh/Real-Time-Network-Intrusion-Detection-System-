// API route for browser metrics ingestion
import { MongoClient } from "mongodb";

// Environment variables
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://localhost:27017/nids";
const MAX_BATCH_SIZE = parseInt(process.env.MAX_BATCH_SIZE, 10) || 1000;
const API_KEYS_VALIDATION = process.env.DISABLE_API_KEY_VALIDATION !== "true";

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

// Validate API key
async function validateApiKey(db, apiKey) {
  if (!API_KEYS_VALIDATION) {
    return { valid: true, orgId: "test-org" };
  }

  try {
    const apiKeyDoc = await db.collection("apiKeys").findOne({ key: apiKey });
    if (!apiKeyDoc) {
      return { valid: false };
    }

    return {
      valid: true,
      orgId: apiKeyDoc.orgId,
      restrictions: apiKeyDoc.restrictions || {},
    };
  } catch (error) {
    console.error("API key validation error:", error);
    return { valid: false };
  }
}

// Check if a metric might be malicious
function checkForMaliciousPatterns(metric) {
  // Skip null or undefined metrics
  if (!metric) return false;

  // Check for suspicious properties that could indicate an attack
  const suspiciousMetricPatterns = [
    // SQL injection patterns
    /('|"|;|--|\/\*|\*\/|@@|@|\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b|\bDROP\b|\bALTER\b|\bDELETE\b|\bFROM\b)/i,
    // XSS patterns
    /<script>|<\/script>|javascript:|on\w+=/i,
    // Command injection patterns
    /;|\||&|`|\$\(|\(\)|\{|\}/,
    // Path traversal
    /\.\.\/|\.\.\\|~\/|~\\/,
  ];

  // Convert metric to string for pattern matching
  const metricStr = JSON.stringify(metric).toLowerCase();

  // Check if any suspicious patterns match
  return suspiciousMetricPatterns.some((pattern) => pattern.test(metricStr));
}

// Run metric through anomaly detection
async function detectAnomalies(metric, db, orgId) {
  // Simple initial checks
  let anomalyDetected = false;
  let attackDetected = false;
  const alerts = [];

  try {
    // Check for malicious patterns in the metric
    if (checkForMaliciousPatterns(metric)) {
      attackDetected = true;
      alerts.push({
        type: "attack",
        severity: "high",
        description: "Potential malicious pattern detected in browser metrics",
        timestamp: new Date(),
        source: "browser-agent",
        metricId: metric._id,
      });
    }

    // Check for network timing anomalies (overly long requests could indicate attacks)
    if (
      metric.type === "request" &&
      metric.totalTime &&
      metric.totalTime > 10000
    ) {
      anomalyDetected = true;
      alerts.push({
        type: "anomaly",
        severity: "medium",
        description: "Unusually long request time detected",
        timestamp: new Date(),
        source: "browser-agent",
        metricId: metric._id,
      });
    }

    // Check for errors that might indicate security issues
    if (metric.error && typeof metric.error === "string") {
      if (
        metric.error.includes("security") ||
        metric.error.includes("forbidden") ||
        metric.error.includes("unauthorized") ||
        metric.error.includes("permission")
      ) {
        anomalyDetected = true;
        alerts.push({
          type: "anomaly",
          severity: "medium",
          description: "Security-related error detected in browser request",
          timestamp: new Date(),
          source: "browser-agent",
          metricId: metric._id,
        });
      }
    }

    // For production, integrate with ML model here
    // Example: const mlResults = await callAnomalyDetectionModel(metric);

    // Save any alerts to the database
    if (alerts.length > 0) {
      await db.collection("alerts").insertMany(
        alerts.map((alert) => ({
          ...alert,
          orgId,
          acknowledged: false,
        }))
      );
    }

    return {
      anomalyDetected,
      attackDetected,
      alerts: alerts.length > 0 ? alerts : null,
    };
  } catch (error) {
    console.error("Anomaly detection error:", error);
    return {
      anomalyDetected: false,
      attackDetected: false,
      error: "Failed to process anomaly detection",
    };
  }
}

// Process metrics for storage and analysis
async function processMetrics(metrics, db, orgId) {
  if (!metrics || !Array.isArray(metrics) || metrics.length === 0) {
    return { success: true, processed: 0 };
  }

  // Limit batch size for performance
  const metricsToProcess = metrics.slice(0, MAX_BATCH_SIZE);

  try {
    // Enrich metrics with organization ID and timestamp
    const enrichedMetrics = metricsToProcess.map((metric) => ({
      ...metric,
      orgId,
      receivedAt: new Date(),
      processedAt: new Date(),
    }));

    // Handle different metric types differently if needed
    const requestMetrics = enrichedMetrics.filter((m) => m.type === "request");
    const customMetrics = enrichedMetrics.filter((m) => m.type === "custom");

    // Process for anomalies
    const anomalyPromises = enrichedMetrics.map((metric) =>
      detectAnomalies(metric, db, orgId)
    );

    const anomalyResults = await Promise.all(anomalyPromises);

    // Mark metrics with detected anomalies
    enrichedMetrics.forEach((metric, i) => {
      metric.anomalyDetected = anomalyResults[i].anomalyDetected;
      metric.attackDetected = anomalyResults[i].attackDetected;
    });

    // Store metrics in database
    if (enrichedMetrics.length > 0) {
      await db.collection("browserMetrics").insertMany(enrichedMetrics);
    }

    // Calculate summary stats
    const anomaliesDetected = anomalyResults.filter(
      (r) => r.anomalyDetected
    ).length;
    const attacksDetected = anomalyResults.filter(
      (r) => r.attackDetected
    ).length;

    return {
      success: true,
      processed: enrichedMetrics.length,
      anomaliesDetected,
      attacksDetected,
    };
  } catch (error) {
    console.error("Metrics processing error:", error);
    return {
      success: false,
      error: "Failed to process metrics",
      processed: 0,
    };
  }
}

export default async function handler(req, res) {
  // CORS headers
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  // Handle preflight OPTIONS request
  if (req.method === "OPTIONS") {
    res.status(200).end();
    return;
  }

  // Only allow POST method
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const db = await connectToDatabase();

    // Validate request format
    if (!req.body || typeof req.body !== "object") {
      return res.status(400).json({ error: "Invalid request body" });
    }

    const { metrics, apiKey } = req.body;

    // Validate API key
    if (!apiKey) {
      return res.status(401).json({ error: "API key is required" });
    }

    const apiKeyValidation = await validateApiKey(db, apiKey);
    if (!apiKeyValidation.valid) {
      return res.status(401).json({ error: "Invalid API key" });
    }

    // Process metrics
    const processResult = await processMetrics(
      metrics,
      db,
      apiKeyValidation.orgId
    );

    if (!processResult.success) {
      return res.status(500).json({
        error: processResult.error || "Failed to process metrics",
      });
    }

    // Return success with summary
    return res.status(200).json({
      success: true,
      processed: processResult.processed,
      anomaly_detected: processResult.anomaliesDetected > 0,
      attack_detected: processResult.attacksDetected > 0,
      message: `Processed ${processResult.processed} metrics`,
    });
  } catch (error) {
    console.error("Browser ingest API error:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
}
