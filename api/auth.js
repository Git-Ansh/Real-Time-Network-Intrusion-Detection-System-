// API route for authentication
import { MongoClient } from "mongodb";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

// Environment variables
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://localhost:27017/nids";
const JWT_SECRET =
  process.env.JWT_SECRET || "local-dev-secret-key-change-in-production";
const JWT_EXPIRY = process.env.JWT_EXPIRY || "24h";

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
    const { action, email, password, token } = req.body;

    if (!action) {
      return res.status(400).json({ error: "Action is required" });
    }

    const db = await connectToDatabase();

    // Handle different authentication actions
    switch (action) {
      case "login":
        return await login(db, email, password, res);

      case "register":
        return await register(db, email, password, res);

      case "verify":
        return await verifyToken(db, token, res);

      case "logout":
        // Client-side logout doesn't require server action
        return res.status(200).json({ message: "Logged out successfully" });

      default:
        return res.status(400).json({ error: "Invalid action" });
    }
  } catch (error) {
    console.error("Authentication error:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
}

// Login handler
async function login(db, email, password, res) {
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  try {
    // Find user by email
    const user = await db
      .collection("users")
      .findOne({ email: email.toLowerCase() });

    if (!user) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    // Compare passwords
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    // Generate JWT token
    const token = jwt.sign(
      {
        userId: user._id,
        email: user.email,
        role: user.role || "user",
      },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRY }
    );

    // Return user info and token
    return res.status(200).json({
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name || email.split("@")[0],
        role: user.role || "user",
        orgId: user.orgId,
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({ error: "Login failed" });
  }
}

// Register handler
async function register(db, email, password, res) {
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  if (password.length < 8) {
    return res
      .status(400)
      .json({ error: "Password must be at least 8 characters" });
  }

  try {
    // Check if email already exists
    const existingUser = await db
      .collection("users")
      .findOne({ email: email.toLowerCase() });

    if (existingUser) {
      return res.status(409).json({ error: "Email already registered" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const result = await db.collection("users").insertOne({
      email: email.toLowerCase(),
      password: hashedPassword,
      name: email.split("@")[0],
      role: "user",
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    // Generate JWT token
    const user = {
      _id: result.insertedId,
      email: email.toLowerCase(),
      role: "user",
    };

    const token = jwt.sign(
      {
        userId: user._id,
        email: user.email,
        role: user.role,
      },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRY }
    );

    // Return user info and token
    return res.status(201).json({
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name || email.split("@")[0],
        role: user.role,
      },
    });
  } catch (error) {
    console.error("Registration error:", error);
    return res.status(500).json({ error: "Registration failed" });
  }
}

// Verify token handler
async function verifyToken(db, token, res) {
  if (!token) {
    return res.status(401).json({ error: "No token provided" });
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);

    // Check if user exists
    const user = await db.collection("users").findOne({ _id: decoded.userId });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Return user info
    return res.status(200).json({
      user: {
        id: user._id,
        email: user.email,
        name: user.name || user.email.split("@")[0],
        role: user.role || "user",
        orgId: user.orgId,
      },
    });
  } catch (error) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}
