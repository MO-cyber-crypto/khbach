// server.js
const express = require("express");
const session = require("express-session");
const path = require("path");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
const multer = require('multer');
const { Pool } = require('pg');
require('dotenv').config();

// Initialize App
const app = express();
const PORT = process.env.PORT || 3000;

// 1️⃣ Middleware Configuration
app.set('trust proxy', 1); // Required for proxy environments

// Basic middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiter);

// Multer configuration for file uploads
const quizFileUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|webp/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    if (extname && mimetype) return cb(null, true);
    cb(new Error('Only image files (JPEG, PNG, GIF, WEBP) are allowed!'));
  }
});

// Import routes
const { router: authRoutes, authenticateUser, authenticateProfessor } = require('./routes/auth_clean');
app.use('/', authRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).send('Something broke! ' + (err.message || ''));
});

// 2️⃣ PostgreSQL setup for Railway
async function createApp() {
  try {
    if (!process.env.DATABASE_URL) {
      console.error('❌ DATABASE_URL is missing!');
      process.exit(1);
    }

    const pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
    });

    // Test connection
    const client = await pool.connect();
    console.log("✅ Connected to PostgreSQL database.");
    client.release();

    app.locals.db = pool;
    return app;
  } catch (err) {
    console.error('❌ Failed to connect to PostgreSQL:', err);
    process.exit(1);
  }
}

// 3️⃣ Start server
if (require.main === module) {
  createApp().then(() => {
    app.listen(PORT, () => {
      console.log(`Server listening on port ${PORT}`);
    });
  }).catch((err) => {
    console.error("Failed to start server:", err);
    process.exit(1);
  });
}

// 4️⃣ Export app for serverless or testing
module.exports = { createApp, app };
