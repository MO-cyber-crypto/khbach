// server.js

// 1. Load Modules
const express = require("express");
const session = require("express-session");
const { Pool } = require("pg");
const pgSession = require("connect-pg-simple")(session);
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const multer = require("multer");
const rateLimit = require("express-rate-limit");
const { createClient } = require("@supabase/supabase-js");

// 2. Initialize App and Database
const app = express();
const PORT = process.env.PORT || 5000;
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
    console.error("ERROR: DATABASE_URL environment variable is not set!");
    process.exit(1);
}

const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// 3. Initialize Supabase Client for Storage
const SUPABASE_URL = process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

let supabase = null;
if (SUPABASE_URL && SUPABASE_ANON_KEY) {
    supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
    console.log("Supabase Storage initialized successfully.");
} else {
    console.warn("WARNING: Supabase credentials not found. File uploads will fail.");
    console.warn("Please set SUPABASE_URL and SUPABASE_ANON_KEY environment variables.");
}

// --- FILE UPLOAD CONFIGURATION (MULTER) ---
// Using memory storage for Supabase cloud uploads
const quizFileUpload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: 5 * 1024 * 1024, // 5MB limit
    },
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif|webp/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);

        if (extname && mimetype) {
            return cb(null, true);
        } else {
            cb(new Error("Only image files (JPEG, PNG, GIF, WEBP) are allowed!"));
        }
    },
});

// Helper function to upload file to Supabase Storage
async function uploadToSupabase(fileBuffer, fileName, mimeType) {
    if (!supabase) {
        throw new Error("Supabase is not initialized. Please configure SUPABASE_URL and SUPABASE_ANON_KEY.");
    }

    const { data, error } = await supabase.storage
        .from('quiz-images')
        .upload(fileName, fileBuffer, {
            contentType: mimeType,
            upsert: false
        });

    if (error) {
        throw new Error(`Supabase upload failed: ${error.message}`);
    }

    // Get public URL
    const { data: urlData } = supabase.storage
        .from('quiz-images')
        .getPublicUrl(data.path);

    return urlData.publicUrl;
}

// Helper function to delete file from Supabase Storage
async function deleteFromSupabase(filePath) {
    if (!supabase || !filePath) {
        return;
    }

    // Extract filename from URL
    const fileName = filePath.split('/').pop();
    
    const { error } = await supabase.storage
        .from('quiz-images')
        .remove([fileName]);

    if (error) {
        console.error(`Failed to delete file from Supabase: ${error.message}`);
    }
}

// --- HELPER FUNCTIONS ---
function hashPassword(password, salt) {
    return crypto
        .pbkdf2Sync(password, salt, 10000, 64, "sha512")
        .toString("hex");
}

function validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

function validatePassword(password) {
    if (password.length < 8) {
        return { valid: false, message: "Password must be at least 8 characters long." };
    }
    if (!/[A-Z]/.test(password)) {
        return { valid: false, message: "Password must contain at least one uppercase letter." };
    }
    if (!/[a-z]/.test(password)) {
        return { valid: false, message: "Password must contain at least one lowercase letter." };
    }
    if (!/[0-9]/.test(password)) {
        return { valid: false, message: "Password must contain at least one number." };
    }
    return { valid: true };
}

// Function to initialize DB schema (from Step 2)
async function initializeDatabase() {
    const createTablesSQL = `
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL, 
            salt TEXT NOT NULL, 
            role TEXT NOT NULL CHECK (role IN ('professor', 'student'))
        );

        CREATE TABLE IF NOT EXISTS quizzes (
            id SERIAL PRIMARY KEY,
            title TEXT NOT NULL,
            subject TEXT NOT NULL,
            year INTEGER,
            professor_id INTEGER REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS questions (
            id SERIAL PRIMARY KEY,
            quiz_id INTEGER NOT NULL REFERENCES quizzes(id) ON DELETE CASCADE,
            question_number INTEGER NOT NULL, 
            question_text TEXT NOT NULL,
            question_type TEXT NOT NULL CHECK (question_type IN ('qcm_single', 'qcm_multiple', 'short_answer')),
            options_json TEXT, 
            correct_answers_json TEXT NOT NULL, 
            question_image_path TEXT,
            UNIQUE (quiz_id, question_number) 
        );

        CREATE TABLE IF NOT EXISTS justifications (
            id SERIAL PRIMARY KEY,
            question_id INTEGER NOT NULL REFERENCES questions(id) ON DELETE CASCADE,
            justification_text TEXT, 
            image_path TEXT, 
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, 
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS attempts (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            quiz_id INTEGER NOT NULL REFERENCES quizzes(id) ON DELETE CASCADE,
            submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            score_20 REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS answers (
            id SERIAL PRIMARY KEY,
            attempt_id INTEGER NOT NULL REFERENCES attempts(id) ON DELETE CASCADE,
            question_id INTEGER NOT NULL REFERENCES questions(id) ON DELETE CASCADE,
            answer_json TEXT NOT NULL, 
            is_correct BOOLEAN NOT NULL
        );

        CREATE TABLE IF NOT EXISTS session (
            sid VARCHAR NOT NULL COLLATE "default" PRIMARY KEY,
            sess JSON NOT NULL,
            expire TIMESTAMP(6) NOT NULL
        );

        CREATE INDEX IF NOT EXISTS IDX_session_expire ON session (expire);
    `;

    try {
        await pool.query(createTablesSQL);
        console.log("Database schema initialized successfully.");

        // --- PROFESSOR SEEDING ---
        const result = await pool.query(
            `SELECT COUNT(*) as count FROM users WHERE role = 'professor'`
        );
        
        if (result.rows[0].count == 0) {
            const salt = crypto.randomBytes(16).toString("hex");
            const hashedPassword = hashPassword("professorpass", salt);
            
            await pool.query(
                `INSERT INTO users (name, email, password, salt, role) VALUES ($1, $2, $3, $4, $5)`,
                ["Dr. Admin", "prof@app.com", hashedPassword, salt, "professor"]
            );
            console.log("Default professor user created (Hashed): prof@app.com / professorpass");
        }
        // --- END SEEDING ---
    } catch (err) {
        console.error("Error creating tables:", err.message);
    }
}

// 3. Configure Database Connection and Initialization
async function setupApp() {
    try {
        const client = await pool.connect();
        console.log("Connected to PostgreSQL database.");
        client.release();
        
        // Initialize database schema first
        await initializeDatabase();
        
        // Expose the database pool
        app.locals.db = pool;

        // 4. Configure Middleware
        app.use(express.static(path.join(__dirname, "public")));
        app.use("/uploads", express.static(UPLOADS_DIR));
        app.use(express.urlencoded({ extended: true }));
        app.use(express.json());

        app.set("view engine", "ejs");

        const SESSION_SECRET = process.env.SESSION_SECRET || (() => {
            const randomSecret = crypto.randomBytes(32).toString('hex');
            console.error("\n\n" + "=".repeat(80));
            console.error("CRITICAL SECURITY WARNING: SESSION_SECRET environment variable is NOT SET!");
            console.error("Generated a random session secret for this instance.");
            console.error("This means sessions will not persist across server restarts.");
            console.error("For production, you MUST set SESSION_SECRET as an environment variable!");
            console.error("=".repeat(80) + "\n");
            return randomSecret;
        })();

        app.use(
            session({
                store: new pgSession({
                    pool: pool,
                    tableName: 'session'
                }),
                secret: SESSION_SECRET,
                resave: false,
                saveUninitialized: false,
                cookie: {
                    maxAge: 1000 * 60 * 60 * 24,
                    httpOnly: true,
                    secure: process.env.NODE_ENV === 'production',
                    sameSite: 'strict'
                },
            }),
        );
    } catch (err) {
        console.error("Error connecting to PostgreSQL database:", err.message);
        process.exit(1);
    }
}

// Call setup before defining routes
setupApp().then(() => {
    console.log("App setup complete, routes are being configured...");

// --- RATE LIMITING ---
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: "Too many login attempts. Please try again after 15 minutes.",
    standardHeaders: true,
    legacyHeaders: false,
});

const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 3,
    message: "Too many registration attempts. Please try again after 1 hour.",
    standardHeaders: true,
    legacyHeaders: false,
});

// --- AUTHENTICATION MIDDLEWARE ---
const requireLogin = (req, res, next) => {
    if (!req.session.userId) {
        return res.redirect("/");
    }
    next();
};

const requireProfessor = (req, res, next) => {
    if (!req.session.userId || req.session.role !== "professor") {
        return res
            .status(403)
            .send("Access Denied: Professor account required.");
    }
    next();
};

const requireStudent = (req, res, next) => {
    if (!req.session.userId || req.session.role !== "student") {
        return res.status(403).send("Access Denied: Student account required.");
    }
    next();
};

// 5. Authentication & Basic Routes

app.get("/", (req, res) => {
    if (req.session.userId) {
        return res.redirect(
            req.session.role === "professor"
                ? "/professor/dashboard"
                : "/student/dashboard",
        );
    }
    res.render("login", { error: null });
});

// POST /register - to process registration
app.post("/register", registerLimiter, express.urlencoded({ extended: true }), (req, res) => {
    const db = req.app.locals.db;
    const { name, email, password, role = "student" } = req.body;

    if (!name || !email || !password || !role) {
        return res.render("login", {
            error: "All fields are required for registration.",
        });
    }

    if (!validateEmail(email)) {
        return res.render("login", {
            error: "Please provide a valid email address.",
        });
    }

    const passwordValidation = validatePassword(password);
    if (!passwordValidation.valid) {
        return res.render("login", {
            error: passwordValidation.message,
        });
    }

    if (!["student", "professor"].includes(role)) {
        return res.render("login", {
            error: "Invalid role selected.",
        });
    }

    const salt = crypto.randomBytes(16).toString("hex");
    const hashedPassword = hashPassword(password, salt);

    db.query(
        "INSERT INTO users (name, email, password, salt, role) VALUES ($1, $2, $3, $4, $5)",
        [name, email, hashedPassword, salt, role],
        (err) => {
            if (err) {
                return res.render("login", {
                    error: "Registration failed. The email may already be in use.",
                });
            }
            req.session.success =
                "Account created successfully! Please log in.";
            res.redirect("/");
        },
    );
});

// POST /login - to process login form submissions
app.post("/login", authLimiter, express.urlencoded({ extended: true }), (req, res) => {
    const db = req.app.locals.db;
    const { email, password } = req.body;

    if (!email || !password) {
        return res.render("login", {
            error: "Email and password are required.",
        });
    }

    if (!validateEmail(email)) {
        return res.render("login", {
            error: "Please provide a valid email address.",
        });
    }

    db.query(
        "SELECT id, name, password, salt, role FROM users WHERE email = $1",
        [email],
        (err, result) => {
            if (err || !result.rows || result.rows.length === 0) {
                return res.render("login", {
                    error: "Invalid email or password.",
                });
            }

            const user = result.rows[0];
            const hashedPassword = hashPassword(password, user.salt);

            if (hashedPassword === user.password) {
                req.session.userId = user.id;
                req.session.name = user.name;
                req.session.role = user.role;

                if (user.role === "professor") {
                    res.redirect("/professor/dashboard");
                } else {
                    res.redirect("/student/dashboard");
                }
            } else {
                res.render("login", { error: "Invalid email or password." });
            }
        },
    );
});

// GET /logout - to log users out
app.get("/logout", (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error("Error destroying session:", err);
        }
        res.redirect("/");
    });
});

// 6. Professor Dashboard & Quiz Metadata Management

// GET /professor/dashboard
app.get("/professor/dashboard", requireProfessor, (req, res) => {
    const db = req.app.locals.db;
    const userId = req.session.userId;
    const search = req.query.search ? req.query.search.trim() : "";

    let sql = `SELECT * FROM quizzes WHERE professor_id = $1`;
    const params = [userId];

    if (search) {
        sql += ` AND (title LIKE $2 OR subject LIKE $3 OR CAST(year AS TEXT) LIKE $4)`;
        const searchTerm = `%${search}%`;
        params.push(searchTerm, searchTerm, searchTerm);
    }

    sql += ` ORDER BY id DESC`;

    db.query(sql, params, (err, result) => {
        if (err) {
            console.error("Error fetching quizzes for professor:", err.message);
            return res.render("professor_dashboard", {
                user: req.session,
                quizzes: [],
                search: search,
                error: "Database error fetching quizzes.",
            });
        }
        res.render("professor_dashboard", {
            user: req.session,
            quizzes: result.rows,
            search: search,
            error: req.query.error || null,
            success: req.query.success || null,
        });
    });
});

// GET /professor/quizzes/create - Render create/edit form
app.get("/professor/quizzes/create", requireProfessor, (req, res) => {
    res.render("quiz_edit", {
        user: req.session,
        quiz: {
            id: null,
            title: "",
            subject: "",
            year: new Date().getFullYear(),
            questions: [],
        },
        questions: [],
        error: null,
        success: null,
    });
});

// GET /professor/quizzes/:quizId/edit - Render edit form with existing data
app.get("/professor/quizzes/:quizId/edit", requireProfessor, (req, res) => {
    const db = req.app.locals.db;
    const quizId = req.params.quizId;
    const professorId = req.session.userId;

    // 1. Get Quiz Metadata
    db.query(
        "SELECT * FROM quizzes WHERE id = $1 AND professor_id = $2",
        [quizId, professorId],
        (err, result) => {
            if (err || !result.rows || result.rows.length === 0) {
                return res.redirect("/professor/dashboard");
            }

            const quiz = result.rows[0];

            // 2. Get all Questions and their Justifications for this quiz
            const questionsSql = `
            SELECT 
                q.*, 
                j.justification_text, 
                j.image_path,
                j.id AS justification_id
            FROM questions q
            LEFT JOIN justifications j ON q.id = j.question_id
            WHERE q.quiz_id = $1
            ORDER BY q.question_number ASC`;

            db.query(questionsSql, [quizId], (err, result) => {
                if (err) {
                    console.error("Error fetching questions:", err.message);
                    return res.redirect("/professor/dashboard");
                }

                const questions = result.rows;
                const structuredQuestions = questions.map((q) => ({
                    id: q.id,
                    quiz_id: q.quiz_id,
                    question_number: q.question_number,
                    question_text: q.question_text,
                    question_type: q.question_type,
                    options: q.options_json ? JSON.parse(q.options_json) : [],
                    correct_answers: JSON.parse(q.correct_answers_json),
                    justification: {
                        id: q.justification_id,
                        text: q.justification_text,
                        image_path: q.image_path,
                    },
                }));

                res.render("quiz_edit", {
                    user: req.session,
                    quiz: quiz,
                    questions: structuredQuestions,
                    error: req.query.error || null,
                    success: req.query.success || null,
                });
            });
        },
    );
});

// POST /professor/questions/save
app.post(
    "/professor/questions/save",
    requireProfessor,
    quizFileUpload.fields([
        { name: "question_image", maxCount: 1 },
        { name: "justification_image", maxCount: 1 },
    ]),
    (req, res, next) => {
        const db = req.app.locals.db;
        const {
            quizId,
            questionId,
            question_number,
            question_text,
            question_type,
            options_text,
            correct_answers_text,
            justification_text,
            justification_id,
        } = req.body;
        const professorId = req.session.userId;

        // --- FILE UPLOAD SAFES AND PATH DEFINITION ---
        // Safely retrieve the files object. The error is likely occurring because
        // the Multer middleware failed, leaving req.files undefined.
        const files = req.files || {};

        const questionImageFile = files.question_image
            ? files.question_image[0]
            : null;
        const justificationImageFile = files.justification_image
            ? files.justification_image[0]
            : null;

        // Define the paths. Your storage setup uses the 'uploads' directory.
        const questionImagePath = questionImageFile
            ? `/uploads/${path.basename(questionImageFile.path)}`
            : null;

        const justificationImagePath = justificationImageFile
            ? `/uploads/${path.basename(justificationImageFile.path)}`
            : null;
        // --- END FILE UPLOAD ---

        db.query(
            "SELECT id FROM quizzes WHERE id = $1 AND professor_id = $2",
            [quizId, professorId],
            (err, result) => {
                if (err || !result.rows || result.rows.length === 0) {
                    // Cleanup any files uploaded before redirecting
                    if (questionImageFile)
                        fs.unlinkSync(questionImageFile.path);
                    if (justificationImageFile)
                        fs.unlinkSync(justificationImageFile.path);
                    return res
                        .status(403)
                        .send("Quiz not found or unauthorized access.");
                }

                let optionsJson = null;
                let correctAnswersJson = null;

                // 2. Process Options and Correct Answers
                try {
                    const trimmedAnswers = correct_answers_text
                        .split(",")
                        .map((o) => o.trim())
                        .filter((o) => o.length > 0);
                    if (trimmedAnswers.length === 0)
                        throw new Error(
                            "Question requires at least one correct answer/keyword.",
                        );
                    if (question_type.startsWith("qcm")) {
                        const options = options_text
                            .split(",")
                            .map((o) => o.trim())
                            .filter((o) => o.length > 0);
                        if (options.length < 2)
                            throw new Error("QCM needs at least two options.");
                        if (
                            question_type === "qcm_single" &&
                            trimmedAnswers.length > 1
                        )
                            throw new Error(
                                "QCM Single must have exactly one correct answer.",
                            );
                        optionsJson = JSON.stringify(options);
                        correctAnswersJson = JSON.stringify(trimmedAnswers);
                    } else if (question_type === "short_answer") {
                        optionsJson = null;
                        correctAnswersJson = JSON.stringify(trimmedAnswers);
                    }
                } catch (e) {
                    console.error("Question data processing error:", e.message);
                    // Cleanup any files uploaded before redirecting
                    if (questionImageFile)
                        fs.unlinkSync(questionImageFile.path);
                    if (justificationImageFile)
                        fs.unlinkSync(justificationImageFile.path);
                    return res.redirect(
                        `/professor/quizzes/${quizId}/edit?error=Question data error: ${e.message}`,
                    );
                }

                let questionSql;
                let questionData;

                if (questionId) {
                    // 3. UPDATE existing question
                    questionSql =
                        "UPDATE questions SET question_text = $1, question_type = $2, options_json = $3, correct_answers_json = $4, question_number = $5, question_image_path = $6 WHERE id = $7 AND quiz_id = $8";
                    questionData = [
                        question_text,
                        question_type,
                        optionsJson,
                        correctAnswersJson,
                        question_number,
                        questionImagePath,
                        questionId,
                        quizId
                    ];
                } else {
                    // 3. INSERT new question with RETURNING clause
                    questionSql =
                        "INSERT INTO questions (question_text, question_type, options_json, correct_answers_json, question_number, question_image_path, quiz_id) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id";
                    questionData = [
                        question_text,
                        question_type,
                        optionsJson,
                        correctAnswersJson,
                        question_number,
                        questionImagePath,
                        quizId
                    ];
                }

                db.query(questionSql, questionData, (questionErr, questionResult) => {
                    if (questionErr) {
                        console.error(
                            "Question save error:",
                            questionErr.message,
                        );
                        // Cleanup files on database error
                        if (questionImageFile)
                            fs.unlinkSync(questionImageFile.path);
                        if (justificationImageFile)
                            fs.unlinkSync(justificationImageFile.path);
                        let errorMsg = "Failed to save question.";
                        if (
                            questionErr.message.includes(
                                "unique constraint",
                            ) || questionErr.message.includes("duplicate key")
                        ) {
                            errorMsg = `Question number ${question_number} already exists in this quiz.`;
                        }
                        return res.redirect(
                            `/professor/quizzes/${quizId}/edit?error=${errorMsg}`,
                        );
                    }

                    const finalQuestionId = questionId || questionResult.rows[0].id;

                    // 4. Insert/Update Justification
                    const finalJustificationText = justification_text || null;
                    const finalJustificationImagePath = justificationImagePath; // Use the path from the multer upload

                    if (justification_id) {
                        // Update Justification (including image path)
                        db.query(
                            "UPDATE justifications SET justification_text = $1, image_path = $2, user_id = $3 WHERE id = $4 AND question_id = $5",
                            [
                                finalJustificationText,
                                finalJustificationImagePath,
                                professorId,
                                justification_id,
                                finalQuestionId,
                            ],
                            (jErr) => {
                                if (jErr)
                                    console.error(
                                        "Justification update error:",
                                        jErr.message,
                                    );
                                res.redirect(
                                    `/professor/quizzes/${quizId}/edit?success=Question and Justification updated successfully.`,
                                );
                            },
                        );
                    } else if (
                        finalJustificationText ||
                        finalJustificationImagePath
                    ) {
                        // Insert New Justification
                        db.query(
                            "INSERT INTO justifications (question_id, justification_text, image_path, user_id) VALUES ($1, $2, $3, $4)",
                            [
                                finalQuestionId,
                                finalJustificationText,
                                finalJustificationImagePath,
                                professorId,
                            ],
                            (jErr) => {
                                if (jErr)
                                    console.error(
                                        "Justification insert error:",
                                        jErr.message,
                                    );
                                res.redirect(
                                    `/professor/quizzes/${quizId}/edit?success=Question and Justification added successfully.`,
                                );
                            },
                        );
                    } else {
                        res.redirect(
                            `/professor/quizzes/${quizId}/edit?success=Question saved successfully.`,
                        );
                    }
                });
            },
        );
    },
);

// GET /professor/quizzes/:quizId/results - Display aggregate results for a quiz
app.get("/professor/quizzes/:quizId/results", requireProfessor, (req, res) => {
    const db = req.app.locals.db;
    const quizId = req.params.quizId;
    const professorId = req.session.userId;

    // 1. Get Quiz Metadata and Check Ownership
    db.query(
        "SELECT * FROM quizzes WHERE id = $1 AND professor_id = $2",
        [quizId, professorId],
        (err, result) => {
            if (err || !result.rows || result.rows.length === 0) {
                return res.redirect(
                    "/professor/dashboard?error=Quiz not found or unauthorized.",
                );
            }

            const quiz = result.rows[0];

            // 2. Fetch all student attempts for this quiz
            const attemptsSql = `
            SELECT 
                u.name AS student_name, 
                t.score_20, 
                t.submitted_at, 
                t.id AS attempt_id
            FROM attempts t
            JOIN users u ON t.user_id = u.id
            WHERE t.quiz_id = $1
            ORDER BY t.submitted_at DESC
        `;

            db.query(attemptsSql, [quizId], (err, result) => {
                if (err) {
                    console.error("Error fetching results:", err.message);
                    return res.redirect(
                        "/professor/dashboard?error=Database error fetching results.",
                    );
                }

                const attempts = result.rows;

                // Group attempts by student name to find the latest submission
                const latestAttemptsMap = new Map();
                attempts.forEach((a) => {
                    // If the student name is not in the map, add this attempt (it will be the latest because of ORDER BY DESC)
                    if (!latestAttemptsMap.has(a.student_name)) {
                        latestAttemptsMap.set(a.student_name, a);
                    }
                });
                const latestAttempts = Array.from(latestAttemptsMap.values());

                // Calculate summary statistics
                const summary = {
                    totalAttempts: latestAttempts.length, // Total number of unique students who submitted
                    averageScore:
                        latestAttempts.length > 0
                            ? latestAttempts.reduce(
                                  (sum, a) => sum + a.score_20,
                                  0,
                              ) / latestAttempts.length
                            : 0,
                };

                res.render("professor_quiz_results", {
                    user: req.session,
                    quiz: quiz,
                    summary: summary,
                    attempts: latestAttempts,
                    error: null,
                });
            });
        },
    );
});
// GET /professor/quizzes/:quizId/export - Export quiz structure as JSON
app.get("/professor/quizzes/:quizId/export", requireProfessor, (req, res) => {
    const db = req.app.locals.db;
    const quizId = req.params.quizId;
    const professorId = req.session.userId;

    // 1. Get Quiz Metadata
    db.query(
        "SELECT id, title, subject, year FROM quizzes WHERE id = $1 AND professor_id = $2",
        [quizId, professorId],
        (err, result) => {
            if (err || !result.rows || result.rows.length === 0) {
                return res.status(404).send("Quiz not found or unauthorized.");
            }

            const quiz = result.rows[0];

            // 2. Get all Questions, including correct answers and justification
            const questionsSql = `
            SELECT 
                q.question_number, 
                q.question_text, 
                q.question_type, 
                q.options_json,
                q.correct_answers_json,
                j.justification_text, 
                j.image_path
            FROM questions q
            LEFT JOIN justifications j ON q.id = j.question_id
            WHERE q.quiz_id = $1
            ORDER BY q.question_number ASC`;

            db.query(questionsSql, [quizId], (err, result) => {
                if (err) {
                    console.error("Error exporting questions:", err.message);
                    return res
                        .status(500)
                        .send("Database error during export.");
                }

                const questions = result.rows;

                // 3. Structure the data into a single export object
                const exportObject = {
                    quiz_metadata: {
                        title: quiz.title,
                        subject: quiz.subject,
                        year: quiz.year,
                        exported_by: req.session.name,
                        export_date: new Date().toISOString(),
                    },
                    questions: questions.map((q) => ({
                        number: q.question_number,
                        text: q.question_text,
                        type: q.question_type,
                        options: q.options_json
                            ? JSON.parse(q.options_json)
                            : undefined,
                        correct_answers: JSON.parse(q.correct_answers_json),
                        justification: {
                            text: q.justification_text,
                            image_path: q.image_path, // Note: image file is not exported, only the path reference
                        },
                    })),
                };

                // 4. Send the JSON file as a download
                res.setHeader(
                    "Content-disposition",
                    `attachment; filename=quiz-${quizId}-${quiz.title.replace(/\s/g, "_")}.json`,
                );
                res.setHeader("Content-type", "application/json");
                res.send(JSON.stringify(exportObject, null, 2));
            });
        },
    );
});
// POST /professor/quizzes/import - Import multiple quizzes from structured JSON file
app.post(
    "/professor/quizzes/import",
    requireProfessor,
    quizFileUpload.single("quiz_file"), // ← USE .single() instead
    (req, res) => {
        const db = req.app.locals.db;
        const professorId = req.session.userId;

        if (!req.file) {
            return res.redirect("/professor/dashboard?error=No file uploaded.");
        }

        let importData;
        try {
            const fileContent = fs.readFileSync(req.file.path, "utf8");
            importData = JSON.parse(fileContent);

            // Cleanup the temporary uploaded file immediately
            fs.unlinkSync(req.file.path);

            // Validate the new multi-quiz structure
            if (
                !importData.exam_title ||
                !importData.quizzes ||
                !Array.isArray(importData.quizzes) ||
                importData.quizzes.length === 0
            ) {
                throw new Error(
                    "Invalid JSON structure. Expecting 'exam_title' and a non-empty 'quizzes' array.",
                );
            }
        } catch (e) {
            console.error("JSON Import Error:", e.message);
            // Ensure file is deleted even on JSON parse error
            if (req.file && fs.existsSync(req.file.path)) {
                fs.unlinkSync(req.file.path);
            }
            return res.redirect(
                `/professor/dashboard?error=Import failed: ${e.message}`,
            );
        }

        const { exam_title, quizzes } = importData;
        let firstNewQuizId = null; // To redirect after import

        // --- Database Transaction for Multi-Quiz Import ---
        (async () => {
            try {
                await db.query("BEGIN");

                // Process each quiz sequentially
                for (const quizDefinition of quizzes) {
                    const { subject, year, questions } = quizDefinition;

                    if (
                        !subject ||
                        !questions ||
                        !Array.isArray(questions)
                    ) {
                        throw new Error(
                            `Quiz definition error: Subject or questions array missing for a quiz.`,
                        );
                    }

                    // 1. Insert Quiz Metadata
                    const quizResult = await db.query(
                        "INSERT INTO quizzes (title, subject, year, professor_id) VALUES ($1, $2, $3, $4) RETURNING id",
                        [
                            exam_title,
                            subject,
                            year || new Date().getFullYear(),
                            professorId,
                        ]
                    );
                    const newQuizId = quizResult.rows[0].id;
                    if (firstNewQuizId === null) {
                        firstNewQuizId = newQuizId;
                    }

                    // 2. Insert Questions
                    for (const q of questions) {
                        const q_num = q.number || 0;
                        if (q_num === 0) {
                            throw new Error(
                                `Question missing explicit number in subject: ${subject}`,
                            );
                        }
                        const q_text = q.text || `Question ${q_num}`;
                        const q_type = q.type || "qcm_single";
                        const q_options = q.options
                            ? JSON.stringify(q.options)
                            : null;
                        const q_correct = JSON.stringify(
                            q.correct_answers || [],
                        );
                        const q_image_path = q.image_url || null;

                        const questionResult = await db.query(
                            "INSERT INTO questions (quiz_id, question_number, question_text, question_type, options_json, correct_answers_json, question_image_path) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
                            [
                                newQuizId,
                                q_num,
                                q_text,
                                q_type,
                                q_options,
                                q_correct,
                                q_image_path,
                            ]
                        );
                        const newQuestionId = questionResult.rows[0].id;

                        // 3. Insert Justification
                        if (
                            q.justification &&
                            (q.justification.text ||
                                q.justification.image_path)
                        ) {
                            await db.query(
                                "INSERT INTO justifications (question_id, justification_text, user_id) VALUES ($1, $2, $3)",
                                [
                                    newQuestionId,
                                    q.justification.text || "",
                                    professorId,
                                ]
                            );
                        }
                    }
                }

                await db.query("COMMIT");
                const redirectId = firstNewQuizId || "/professor/dashboard";
                res.redirect(
                    `/professor/quizzes/${redirectId}/edit?success=Multi-Quiz Import successful! ${quizzes.length} quizzes created.`,
                );
            } catch (e) {
                await db.query("ROLLBACK");
                console.error("Multi-Quiz Import Failed:", e.message);
                res.redirect(
                    `/professor/dashboard?error=Import failed (Transaction rolled back): ${e.message}`,
                );
            }
        })();
    },
);

// 7. Question Management Routes

// POST /professor/questions/save
app.post(
    "/professor/questions/save",
    requireProfessor,
    quizFileUpload.fields([
        { name: "question_image", maxCount: 1 },
        { name: "justification_image", maxCount: 1 },
    ]),
    async (req, res, next) => {
        const db = req.app.locals.db;
        const {
            quizId,
            questionId,
            question_number,
            question_text,
            question_type,
            options_text,
            correct_answers_text,
            justification_text,
            justification_id,
        } = req.body;
        const professorId = req.session.userId;

        // 1. UPLOAD FILES TO SUPABASE
        const files = req.files || {};
        const questionImageFile = files.question_image && files.question_image[0];
        const justificationImageFile = files.justification_image && files.justification_image[0];

        let questionImagePath = null;
        let justificationImagePath = null;

        try {
            // Upload question image if present
            if (questionImageFile) {
                const fileName = `${Date.now()}-${crypto.randomBytes(4).toString('hex')}-${questionImageFile.originalname}`;
                questionImagePath = await uploadToSupabase(
                    questionImageFile.buffer,
                    fileName,
                    questionImageFile.mimetype
                );
            }

            // Upload justification image if present
            if (justificationImageFile) {
                const fileName = `${Date.now()}-${crypto.randomBytes(4).toString('hex')}-${justificationImageFile.originalname}`;
                justificationImagePath = await uploadToSupabase(
                    justificationImageFile.buffer,
                    fileName,
                    justificationImageFile.mimetype
                );
            }
        } catch (uploadError) {
            console.error("File upload error:", uploadError.message);
            return res.redirect(
                `/professor/quizzes/${quizId}/edit?error=File upload failed: ${uploadError.message}`
            );
        }

        db.query(
            "SELECT id FROM quizzes WHERE id = $1 AND professor_id = $2",
            [quizId, professorId],
            async (err, result) => {
                if (err || !result.rows || result.rows.length === 0) {
                    // Delete uploaded files from Supabase if quiz validation fails
                    if (questionImagePath) await deleteFromSupabase(questionImagePath);
                    if (justificationImagePath) await deleteFromSupabase(justificationImagePath);
                    return res
                        .status(403)
                        .send("Quiz not found or unauthorized access.");
                }

                let optionsJson = null;
                let correctAnswersJson = null;

                // 2. Process Options and Correct Answers
                try {
                    const trimmedAnswers = correct_answers_text
                        .split(",")
                        .map((o) => o.trim())
                        .filter((o) => o.length > 0);
                    if (trimmedAnswers.length === 0)
                        throw new Error(
                            "Question requires at least one correct answer/keyword.",
                        );
                    if (question_type.startsWith("qcm")) {
                        const options = options_text
                            .split(",")
                            .map((o) => o.trim())
                            .filter((o) => o.length > 0);
                        if (options.length < 2)
                            throw new Error("QCM needs at least two options.");
                        if (
                            question_type === "qcm_single" &&
                            trimmedAnswers.length > 1
                        )
                            throw new Error(
                                "QCM Single must have exactly one correct answer.",
                            );
                        optionsJson = JSON.stringify(options);
                        correctAnswersJson = JSON.stringify(trimmedAnswers);
                    } else if (question_type === "short_answer") {
                        optionsJson = null;
                        correctAnswersJson = JSON.stringify(trimmedAnswers);
                    }
                } catch (e) {
                    console.error("Question data processing error:", e.message);
                    // Delete uploaded files from Supabase on validation error
                    if (questionImagePath) await deleteFromSupabase(questionImagePath);
                    if (justificationImagePath) await deleteFromSupabase(justificationImagePath);
                    return res.redirect(
                        `/professor/quizzes/${quizId}/edit?error=Question data error: ${e.message}`,
                    );
                }

                let questionSql;
                let questionData;

                if (questionId) {
                    // 3. UPDATE existing question
                    questionSql =
                        "UPDATE questions SET question_text = $1, question_type = $2, options_json = $3, correct_answers_json = $4, question_number = $5, question_image_path = $6 WHERE id = $7 AND quiz_id = $8";
                    questionData = [
                        question_text,
                        question_type,
                        optionsJson,
                        correctAnswersJson,
                        question_number,
                        questionImagePath,
                        questionId,
                        quizId
                    ];
                } else {
                    // 3. INSERT new question
                    questionSql =
                        "INSERT INTO questions (question_text, question_type, options_json, correct_answers_json, question_number, question_image_path, quiz_id) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id";
                    questionData = [
                        question_text,
                        question_type,
                        optionsJson,
                        correctAnswersJson,
                        question_number,
                        questionImagePath,
                        quizId
                    ];
                }

                db.query(questionSql, questionData, async (questionErr, questionResult) => {
                    if (questionErr) {
                        console.error(
                            "Question save error:",
                            questionErr.message,
                        );
                        // Delete uploaded files from Supabase on database error
                        if (questionImagePath) await deleteFromSupabase(questionImagePath);
                        if (justificationImagePath) await deleteFromSupabase(justificationImagePath);
                        let errorMsg = "Failed to save question.";
                        if (
                            questionErr.message.includes(
                                "unique constraint",
                            ) || questionErr.message.includes("duplicate key")
                        ) {
                            errorMsg = `Question number ${question_number} already exists in this quiz.`;
                        }
                        return res.redirect(
                            `/professor/quizzes/${quizId}/edit?error=${errorMsg}`,
                        );
                    }

                    const finalQuestionId = questionId || questionResult.rows[0].id;

                    // 4. Insert/Update Justification
                    const finalJustificationText = justification_text || null;
                    const finalJustificationImagePath = justificationImagePath; // Use the path from the multer upload

                    if (justification_id) {
                        // Update Justification (including image path)
                        db.query(
                            "UPDATE justifications SET justification_text = $1, image_path = $2, user_id = $3 WHERE id = $4 AND question_id = $5",
                            [
                                finalJustificationText,
                                finalJustificationImagePath,
                                professorId,
                                justification_id,
                                finalQuestionId,
                            ],
                            (jErr) => {
                                if (jErr)
                                    console.error(
                                        "Justification update error:",
                                        jErr.message,
                                    );
                                res.redirect(
                                    `/professor/quizzes/${quizId}/edit?success=Question and Justification updated successfully.`,
                                );
                            },
                        );
                    } else if (
                        finalJustificationText ||
                        finalJustificationImagePath
                    ) {
                        // Insert New Justification
                        db.query(
                            "INSERT INTO justifications (question_id, justification_text, image_path, user_id) VALUES ($1, $2, $3, $4)",
                            [
                                finalQuestionId,
                                finalJustificationText,
                                finalJustificationImagePath,
                                professorId,
                            ],
                            (jErr) => {
                                if (jErr)
                                    console.error(
                                        "Justification insert error:",
                                        jErr.message,
                                    );
                                res.redirect(
                                    `/professor/quizzes/${quizId}/edit?success=Question and Justification added successfully.`,
                                );
                            },
                        );
                    } else {
                        res.redirect(
                            `/professor/quizzes/${quizId}/edit?success=Question saved successfully.`,
                        );
                    }
                });
            },
        );
    },
);

// POST /professor/questions/:questionId/delete
app.post(
    "/professor/questions/:questionId/delete",
    requireProfessor,
    async (req, res) => {
        const db = req.app.locals.db;
        const questionId = req.params.questionId;
        const { quizId } = req.body;

        try {
            // 1. Get image paths for deletion from both questions and justifications
            const result = await db.query(
                "SELECT q.question_image_path, j.image_path as justification_image_path FROM questions q LEFT JOIN justifications j ON q.id = j.question_id WHERE q.id = $1",
                [questionId]
            );

            // Delete images from Supabase if they exist
            if (result.rows && result.rows.length > 0) {
                const row = result.rows[0];
                if (row.question_image_path) {
                    await deleteFromSupabase(row.question_image_path);
                }
                if (row.justification_image_path) {
                    await deleteFromSupabase(row.justification_image_path);
                }
            }

            // 2. Delete question (cascade deletes justifications/answers)
            await db.query("DELETE FROM questions WHERE id = $1", [questionId]);
            
            res.redirect(
                `/professor/quizzes/${quizId}/edit?success=Question deleted successfully.`
            );
        } catch (err) {
            console.error("Question deletion error:", err.message);
            res.redirect(
                `/professor/quizzes/${quizId}/edit?error=Failed to delete question.`
            );
        }
    },
);

// POST /professor/questions/reorder
app.post("/professor/questions/reorder", requireProfessor, (req, res) => {
    const db = req.app.locals.db;
    const { quizId, questionId, direction, currentNumber } = req.body;
    const currentNum = parseInt(currentNumber);
    const professorId = req.session.userId;

    let targetNum;

    if (direction === "up") {
        targetNum = currentNum - 1;
    } else if (direction === "down") {
        targetNum = currentNum + 1;
    } else {
        return res.redirect(
            `/professor/quizzes/${quizId}/edit?error=Invalid reorder direction.`,
        );
    }

    db.query(
        "SELECT id FROM quizzes WHERE id = $1 AND professor_id = $2",
        [quizId, professorId],
        (err, result) => {
            if (err || !result.rows || result.rows.length === 0) {
                return res
                    .status(403)
                    .send("Quiz not found or unauthorized access.");
            }

            db.query(
                "SELECT id FROM questions WHERE quiz_id = $1 AND question_number = $2",
                [quizId, targetNum],
                async (err, result) => {
                    if (err || !result.rows || result.rows.length === 0) {
                        return res.redirect(
                            `/professor/quizzes/${quizId}/edit`,
                        );
                    }

                    const targetQuestion = result.rows[0];

                    try {
                        await db.query("BEGIN");

                        await db.query(
                            "UPDATE questions SET question_number = $1 WHERE id = $2 AND quiz_id = $3",
                            [targetNum, questionId, quizId]
                        );

                        await db.query(
                            "UPDATE questions SET question_number = $1 WHERE id = $2 AND quiz_id = $3",
                            [currentNum, targetQuestion.id, quizId]
                        );

                        await db.query("COMMIT");
                        res.redirect(
                            `/professor/quizzes/${quizId}/edit?success=Question order updated.`,
                        );
                    } catch (err) {
                        await db.query("ROLLBACK");
                        console.error("Reorder error:", err.message);
                        res.redirect(
                            `/professor/quizzes/${quizId}/edit?error=Failed to reorder questions.`,
                        );
                    }
                },
            );
        },
    );
});

// 8. Student Quiz Interaction Routes

// GET /student/dashboard
app.get("/student/dashboard", requireStudent, (req, res) => {
    const db = req.app.locals.db;
    const userId = req.session.userId;
    const search = req.query.search ? req.query.search.trim() : "";

    let sql = `
        SELECT 
            q.id,
            q.title,
            q.subject,
            q.year,
            p.name AS professor_name,
            (SELECT MAX(score_20) FROM attempts WHERE quiz_id = q.id AND user_id = $1) AS highest_score
        FROM quizzes q
        JOIN users p ON q.professor_id = p.id
    `;
    const params = [userId];

    if (search) {
        sql += ` 
            WHERE q.title LIKE $2 OR 
            q.subject LIKE $3 OR 
            CAST(q.year AS TEXT) LIKE $4
        `;
        const searchTerm = `%${search}%`;
        params.push(searchTerm, searchTerm, searchTerm);
    }

    sql += ` ORDER BY q.id DESC`;

    db.query(sql, params, (err, result) => {
        if (err) {
            console.error("Error fetching quizzes for student:", err.message);
            return res.render("student_dashboard", {
                user: req.session,
                quizzes: [],
                search: search,
                error: "Could not fetch quizzes due to a database error.",
            });
        }

        res.render("student_dashboard", {
            user: req.session,
            quizzes: result.rows,
            search: search,
            error: req.query.error || null,
        });
    });
});

// GET /student/quizzes/:quizId/take - Render the quiz form
app.get("/student/quizzes/:quizId/take", requireStudent, (req, res) => {
    const db = req.app.locals.db;
    const quizId = req.params.quizId;

    // 1. Get Quiz Metadata
    db.query("SELECT * FROM quizzes WHERE id = $1", [quizId], (err, result) => {
        if (err || !result.rows || result.rows.length === 0) {
            return res.redirect("/student/dashboard?error=Quiz not found.");
        }

        const quiz = result.rows[0];

        // 2. Get Questions (excluding correct answers for the quiz form)
        const questionsSql = `
            SELECT 
                id, 
                question_number, 
                question_text, 
                question_type, 
                options_json,
                question_image_path 
            FROM questions
            WHERE quiz_id = $1
            ORDER BY question_number ASC`;

        db.query(questionsSql, [quizId], (err, result) => {
            if (err) {
                console.error("Error fetching quiz questions:", err.message);
                return res.redirect(
                    "/student/dashboard?error=Error loading quiz questions.",
                );
            }

            const questions = result.rows;

            const structuredQuestions = questions.map((q) => ({
                id: q.id,
                question_number: q.question_number,
                question_text: q.question_text,
                question_type: q.question_type,
                options: q.options_json ? JSON.parse(q.options_json) : null,
                question_image_path: q.question_image_path,
            }));

            if (structuredQuestions.length === 0) {
                return res.redirect(
                    "/student/dashboard?error=Quiz is empty (no questions added yet).",
                );
            }

            res.render("quiz_take", {
                user: req.session,
                quiz: quiz,
                questions: structuredQuestions,
                error: null,
            });
        });
    });
});

// POST /student/quizzes/:quizId/submit - Score and save the attempt
app.post("/student/quizzes/:quizId/submit", requireStudent, (req, res) => {
    const db = req.app.locals.db;
    const quizId = req.params.quizId;
    const userId = req.session.userId;
    const studentAnswers = req.body;

    // 1. Fetch all questions with correct answers
    db.query(
        "SELECT id, correct_answers_json, question_type FROM questions WHERE quiz_id = $1",
        [quizId],
        async (err, result) => {
            if (err || !result.rows || result.rows.length === 0) {
                console.error(
                    "Submission error: Cannot fetch questions.",
                    err ? err.message : "",
                );
                return res.redirect(
                    "/student/dashboard?error=Error processing submission.",
                );
            }

            const questions = result.rows;
            let correctCount = 0;
            const totalQuestions = questions.length;
            const answersToSave = [];

            // 2. Scoring Logic
            questions.forEach((q) => {
                const questionId = q.id;
                const correctAnswers = JSON.parse(q.correct_answers_json);
                const questionType = q.question_type;
                let studentAnswerRaw = studentAnswers[`answer_${questionId}`];
                let isCorrect = false;
                let studentAnswerProcessed;

                if (!studentAnswerRaw) {
                    studentAnswerProcessed = [];
                } else if (Array.isArray(studentAnswerRaw)) {
                    studentAnswerProcessed = studentAnswerRaw.map((a) =>
                        a.trim(),
                    );
                } else {
                    studentAnswerProcessed = [studentAnswerRaw.trim()];
                }

                // A. Scoring QCM (Single and Multiple)
                if (questionType.startsWith("qcm")) {
                    const studentSet = new Set(studentAnswerProcessed);
                    const correctSet = new Set(correctAnswers);

                    // Check if sets are equal (same size and all elements match)
                    if (studentSet.size === correctSet.size) {
                        isCorrect = [...studentSet].every((answer) =>
                            correctSet.has(answer),
                        );
                    }
                }
                // B. Scoring Short Answer
                else if (questionType === "short_answer") {
                    if (studentAnswerProcessed.length > 0) {
                        const submitted =
                            studentAnswerProcessed[0].toLowerCase();
                        isCorrect = correctAnswers.some(
                            (correct) => submitted === correct.toLowerCase(),
                        );
                    }
                }

                if (isCorrect) {
                    correctCount++;
                }

                answersToSave.push({
                    question_id: questionId,
                    answer_json: JSON.stringify(studentAnswerProcessed),
                    is_correct: isCorrect,
                });
            });

            // 3. Normalize Score to /20
            const score20 = (correctCount / totalQuestions) * 20;

            // 4. Save Attempt and Answers in a Transaction
            try {
                await db.query("BEGIN");

                const attemptResult = await db.query(
                    "INSERT INTO attempts (user_id, quiz_id, score_20) VALUES ($1, $2, $3) RETURNING id",
                    [userId, quizId, score20]
                );
                const attemptId = attemptResult.rows[0].id;

                // Insert all answers
                for (const ans of answersToSave) {
                    await db.query(
                        "INSERT INTO answers (attempt_id, question_id, answer_json, is_correct) VALUES ($1, $2, $3, $4)",
                        [attemptId, ans.question_id, ans.answer_json, ans.is_correct]
                    );
                }

                await db.query("COMMIT");
                // 5. Redirect to results page
                res.redirect(`/student/quizzes/${quizId}/results`);
            } catch (err) {
                await db.query("ROLLBACK");
                console.error("Submission transaction error:", err.message);
                return res.redirect(
                    "/student/dashboard?error=Failed to save quiz attempt.",
                );
            }
        },
    );
});

// GET /student/quizzes/:quizId/results - Display quiz results and justifications
app.get("/student/quizzes/:quizId/results", requireStudent, (req, res) => {
    const db = req.app.locals.db;
    const quizId = req.params.quizId;
    const userId = req.session.userId;

    // 1. Get the latest attempt and overall score
    db.query(
        "SELECT id, score_20, submitted_at FROM attempts WHERE user_id = $1 AND quiz_id = $2 ORDER BY submitted_at DESC LIMIT 1",
        [userId, quizId],
        (err, result) => {
            if (err || !result.rows || result.rows.length === 0) {
                return res.redirect(
                    `/student/dashboard?error=No completed attempt found for this quiz.`,
                );
            }

            const attempt = result.rows[0];
            const attemptId = attempt.id;

            // 2. Get quiz metadata, question details, student answer, and justification
            const resultsSql = `
            SELECT 
                q.question_number, 
                q.question_text, 
                q.question_type,
                q.options_json,
                q.correct_answers_json,
                a.answer_json AS student_answer_json,
                a.is_correct,
                j.justification_text,
                j.image_path,
                qz.title AS quiz_title,
                qz.subject,
                qz.year
            FROM answers a
            JOIN questions q ON a.question_id = q.id
            JOIN quizzes qz ON q.quiz_id = qz.id
            LEFT JOIN justifications j ON q.id = j.question_id
            WHERE a.attempt_id = $1
            ORDER BY q.question_number ASC
        `;

            db.query(resultsSql, [attemptId], (err, result) => {
                if (err || !result.rows || result.rows.length === 0) {
                    console.error(
                        "Error fetching results details:",
                        err ? err.message : "",
                    );
                    return res.redirect(
                        `/student/dashboard?error=Error fetching result details.`,
                    );
                }

                const results = result.rows;

                const structuredResults = results.map((r) => ({
                    question_number: r.question_number,
                    question_text: r.question_text,
                    question_type: r.question_type,
                    options: r.options_json ? JSON.parse(r.options_json) : null,
                    correct_answers: JSON.parse(r.correct_answers_json),
                    student_answer: JSON.parse(r.student_answer_json),
                    is_correct: r.is_correct,
                    justification: {
                        text: r.justification_text,
                        image_path: r.image_path,
                    },
                }));

                const quizInfo = {
                    title: results[0].quiz_title,
                    subject: results[0].subject,
                    year: results[0].year,
                };

                res.render("quiz_results", {
                    user: req.session,
                    quiz: quizInfo,
                    attempt: attempt,
                    results: structuredResults,
                    error: null,
                });
            });
        },
    );
});
// GET /student/quizzes/:quizId/history - Display all past attempts for a quiz
app.get("/student/quizzes/:quizId/history", requireStudent, (req, res) => {
    const db = req.app.locals.db;
    const quizId = req.params.quizId;
    const userId = req.session.userId;

    // 1. Get Quiz Metadata
    db.query(
        "SELECT id, title, subject FROM quizzes WHERE id = $1",
        [quizId],
        (err, result) => {
            if (err || !result.rows || result.rows.length === 0) {
                return res.redirect("/student/dashboard?error=Quiz not found.");
            }

            const quiz = result.rows[0];

            // 2. Get all attempts for this user and quiz, ordered from newest to oldest
            db.query(
                "SELECT id, score_20, submitted_at FROM attempts WHERE user_id = $1 AND quiz_id = $2 ORDER BY submitted_at DESC",
                [userId, quizId],
                (err, result) => {
                    if (err) {
                        console.error(
                            "Error fetching attempt history:",
                            err.message,
                        );
                        return res.redirect(
                            "/student/dashboard?error=Error loading quiz history.",
                        );
                    }

                    const attempts = result.rows;

                    // Calculate basic summary statistics
                    const summary = {
                        totalAttempts: attempts.length,
                        highestScore:
                            attempts.length > 0
                                ? Math.max(...attempts.map((a) => a.score_20))
                                : 0,
                        averageScore:
                            attempts.length > 0
                                ? attempts.reduce(
                                      (sum, a) => sum + a.score_20,
                                      0,
                                  ) / attempts.length
                                : 0,
                    };

                    res.render("student_quiz_history", {
                        user: req.session,
                        quiz: quiz,
                        attempts: attempts,
                        summary: summary,
                        error: null,
                    });
                },
            );
        },
    );
});

// 9. Professor User Management Routes

// GET /professor/users - Render User Management Dashboard
app.get("/professor/users", requireProfessor, (req, res) => {
    const db = req.app.locals.db;

    // Fetch all users
    db.query(
        "SELECT id, name, email, role FROM users ORDER BY role, name ASC",
        [],
        (err, result) => {
            if (err) {
                console.error("Error fetching users:", err.message);
                return res.render("professor_user_management", {
                    user: req.session,
                    users: [],
                    error: "Database error fetching users.",
                    success: null,
                });
            }

            res.render("professor_user_management", {
                user: req.session,
                users: result.rows,
                error: req.query.error || null,
                success: req.query.success || null,
            });
        },
    );
});

// POST /professor/users/create - Create a new user (Professor or Student)
app.post("/professor/users/create", requireProfessor, (req, res) => {
    const db = req.app.locals.db;
    const { name, email, password, role } = req.body;

    if (!name || !email || !password || !role) {
        return res.redirect("/professor/users?error=All fields are required.");
    }

    if (!validateEmail(email)) {
        return res.redirect("/professor/users?error=Please provide a valid email address.");
    }

    const passwordValidation = validatePassword(password);
    if (!passwordValidation.valid) {
        return res.redirect(`/professor/users?error=${encodeURIComponent(passwordValidation.message)}`);
    }

    if (role !== "professor" && role !== "student") {
        return res.redirect("/professor/users?error=Invalid role specified.");
    }

    const salt = crypto.randomBytes(16).toString("hex");
    const hashedPassword = hashPassword(password, salt);

    db.query(
        "INSERT INTO users (name, email, password, salt, role) VALUES ($1, $2, $3, $4, $5)",
        [name, email, hashedPassword, salt, role],
        (err) => {
            if (err) {
                console.error("Error creating user:", err.message);
                return res.redirect(
                    "/professor/users?error=Failed to create user. Email may already be in use.",
                );
            }
            res.redirect(
                `/professor/users?success=${role.charAt(0).toUpperCase() + role.slice(1)} ${name} created successfully.`,
            );
        },
    );
});
// POST /professor/quizzes/:quizId/delete
app.post("/professor/quizzes/:quizId/delete", requireProfessor, async (req, res) => {
    const db = req.app.locals.db;
    const quizId = req.params.quizId;
    const professorId = req.session.userId;

    try {
        // 1. Get all image paths for this quiz before deletion
        const result = await db.query(
            `SELECT q.question_image_path, j.image_path as justification_image_path 
             FROM questions q 
             LEFT JOIN justifications j ON q.id = j.question_id 
             WHERE q.quiz_id = $1`,
            [quizId]
        );

        // 2. Delete all associated images from Supabase
        if (result.rows && result.rows.length > 0) {
            for (const row of result.rows) {
                if (row.question_image_path) {
                    await deleteFromSupabase(row.question_image_path);
                }
                if (row.justification_image_path) {
                    await deleteFromSupabase(row.justification_image_path);
                }
            }
        }

        // 3. Delete quiz (cascade deletes questions, justifications, attempts, answers)
        await db.query(
            "DELETE FROM quizzes WHERE id = $1 AND professor_id = $2",
            [quizId, professorId]
        );

        res.redirect(
            "/professor/dashboard?success=Quiz deleted successfully."
        );
    } catch (err) {
        console.error("Quiz deletion error:", err.message);
        res.redirect(
            "/professor/dashboard?error=Failed to delete quiz."
        );
    }
});
// POST /professor/users/delete - Delete a user
app.post("/professor/users/delete", requireProfessor, (req, res) => {
    const db = req.app.locals.db;
    const userIdToDelete = req.body.user_id;

    // SECURITY CHECK: Prevent a professor from deleting themselves (ID must not match session ID)
    if (parseInt(userIdToDelete) === req.session.userId) {
        return res.redirect(
            "/professor/users?error=You cannot delete your own account.",
        );
    }

    // 1. Delete all attempts associated with the user
    db.query(
        "DELETE FROM attempts WHERE user_id = $1",
        [userIdToDelete],
        (err) => {
            if (err) {
                console.error("Error deleting attempts:", err.message);
                return res.redirect(
                    "/professor/users?error=Error deleting user attempts.",
                );
            }

            // 2. Delete the user
            db.query(
                "DELETE FROM users WHERE id = $1",
                [userIdToDelete],
                (err, result) => {
                    if (err) {
                        console.error("Error deleting user:", err.message);
                        return res.redirect(
                            "/professor/users?error=Error deleting user.",
                        );
                    }
                    if (result.rowCount === 0) {
                        return res.redirect(
                            "/professor/users?error=User not found or already deleted.",
                        );
                    }

                    res.redirect(
                        "/professor/users?success=User and all associated data successfully deleted.",
                    );
                },
            );
        },
    );
});

// --- ERROR HANDLING MIDDLEWARE ---
app.use((err, req, res, next) => {
    // Note: No local file cleanup needed as we use Supabase cloud storage with memory buffers
    
    if (err instanceof multer.MulterError) {
        console.error('Multer error:', err.code, err.message);
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).send('File too large! Maximum size is 5MB. Please choose a smaller image.');
        }
        if (err.code === 'LIMIT_UNEXPECTED_FILE') {
            return res.status(400).send('Unexpected file field. Please check your upload form.');
        }
        return res.status(400).send(`File upload error: ${err.message}`);
    } else if (err && err.message && err.message.includes('image files')) {
        console.error('File type validation error:', err.message);
        return res.status(400).send(err.message);
    } else if (err) {
        console.error('Server error:', err.message);
        console.error(err.stack);
        return res.status(500).send('An unexpected error occurred. Please try again later.');
    }
    next();
});

// 10. Start the Server
    app.listen(PORT, () => {
        console.log(`Server listening on port ${PORT}`);
    });
}).catch((err) => {
    console.error("Failed to setup app:", err);
    process.exit(1);
});
