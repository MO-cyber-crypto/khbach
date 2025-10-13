// server.js

// 1. Load Modules
const express = require("express");
const session = require("express-session");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const multer = require("multer");
const rateLimit = require("express-rate-limit");

// 2. Initialize App and Database
const app = express();
const PORT = process.env.PORT || 5000;
const DB_PATH = path.join(__dirname, "quiz_app.db");

// --- FILE UPLOAD CONFIGURATION (MULTER) ---
const UPLOADS_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOADS_DIR)) {
    fs.mkdirSync(UPLOADS_DIR);
}

// Set up storage for uploaded images
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, UPLOADS_DIR);
    },
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname);
        cb(
            null,
            Date.now() + "-" + crypto.randomBytes(4).toString("hex") + ext,
        );
    },
});

const quizFileUpload = multer({
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024,
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
function initializeDatabase(db) {
    const createTablesSQL = `
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL, 
            salt TEXT NOT NULL, 
            role TEXT NOT NULL CHECK (role IN ('professor', 'student'))
        );

        CREATE TABLE IF NOT EXISTS quizzes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            subject TEXT NOT NULL,
            year INTEGER,
            professor_id INTEGER,
            FOREIGN KEY (professor_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS questions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            quiz_id INTEGER NOT NULL,
            question_number INTEGER NOT NULL, 
            question_text TEXT NOT NULL,
            question_type TEXT NOT NULL CHECK (question_type IN ('qcm_single', 'qcm_multiple', 'short_answer')),
            options_json TEXT, 
            correct_answers_json TEXT NOT NULL, 
            question_image_path TEXT,
            FOREIGN KEY (quiz_id) REFERENCES quizzes(id) ON DELETE CASCADE,
            UNIQUE (quiz_id, question_number) 
        );

        CREATE TABLE IF NOT EXISTS justifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            question_id INTEGER NOT NULL,
            justification_text TEXT, 
            image_path TEXT, 
            user_id INTEGER NOT NULL, 
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            quiz_id INTEGER NOT NULL,
            submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            score_20 REAL NOT NULL, 
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (quiz_id) REFERENCES quizzes(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS answers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attempt_id INTEGER NOT NULL,
            question_id INTEGER NOT NULL,
            answer_json TEXT NOT NULL, 
            is_correct BOOLEAN NOT NULL,
            FOREIGN KEY (attempt_id) REFERENCES attempts(id) ON DELETE CASCADE,
            FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE
        );
    `;

    db.exec(createTablesSQL, (err) => {
        if (err) {
            console.error("Error creating tables:", err.message);
        } else {
            console.log("Database schema initialized successfully.");

            // --- PROFESSOR SEEDING ---
            db.get(
                `SELECT COUNT(*) as count FROM users WHERE role = 'professor'`,
                (err, row) => {
                    if (row && row.count === 0) {
                        const salt = crypto.randomBytes(16).toString("hex");
                        const hashedPassword = hashPassword(
                            "professorpass",
                            salt,
                        );
                        const defaultProfessor = [
                            "Dr. Admin",
                            "prof@app.com",
                            hashedPassword,
                            salt,
                            "professor",
                        ];
                        db.run(
                            `INSERT INTO users (name, email, password, salt, role) VALUES (?, ?, ?, ?, ?)`,
                            defaultProfessor,
                            (insertErr) => {
                                if (insertErr) {
                                    console.error(
                                        "Error inserting default professor:",
                                        insertErr.message,
                                    );
                                } else {
                                    console.log(
                                        "Default professor user created (Hashed): prof@app.com / professorpass",
                                    );
                                }
                            },
                        );
                    }
                },
            );
            // --- END SEEDING ---
        }
    });
}

// 3. Configure Database Connection and Initialization
const db = new sqlite3.Database(DB_PATH, (err) => {
    if (err) {
        console.error("Error opening database:", err.message);
    } else {
        console.log("Connected to the SQLite database.");
        initializeDatabase(db);
    }
});

// Expose the database object
app.locals.db = db;

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

    db.run(
        "INSERT INTO users (name, email, password, salt, role) VALUES (?, ?, ?, ?, ?)",
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

    db.get(
        "SELECT id, name, password, salt, role FROM users WHERE email = ?",
        [email],
        (err, user) => {
            if (err || !user) {
                return res.render("login", {
                    error: "Invalid email or password.",
                });
            }

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

    let sql = `SELECT * FROM quizzes WHERE professor_id = ?`;
    const params = [userId];

    if (search) {
        sql += ` AND (title LIKE ? OR subject LIKE ? OR CAST(year AS TEXT) LIKE ?)`;
        const searchTerm = `%${search}%`;
        params.push(searchTerm, searchTerm, searchTerm);
    }

    sql += ` ORDER BY id DESC`;

    db.all(sql, params, (err, quizzes) => {
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
            quizzes: quizzes,
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
    db.get(
        "SELECT * FROM quizzes WHERE id = ? AND professor_id = ?",
        [quizId, professorId],
        (err, quiz) => {
            if (err || !quiz) {
                return res.redirect("/professor/dashboard");
            }

            // 2. Get all Questions and their Justifications for this quiz
            const questionsSql = `
            SELECT 
                q.*, 
                j.justification_text, 
                j.image_path,
                j.id AS justification_id
            FROM questions q
            LEFT JOIN justifications j ON q.id = j.question_id
            WHERE q.quiz_id = ?
            ORDER BY q.question_number ASC`;

            db.all(questionsSql, [quizId], (err, questions) => {
                if (err) {
                    console.error("Error fetching questions:", err.message);
                    return res.redirect("/professor/dashboard");
                }

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

        db.get(
            "SELECT id FROM quizzes WHERE id = ? AND professor_id = ?",
            [quizId, professorId],
            (err, quiz) => {
                if (err || !quiz) {
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
                let questionData = [
                    question_text,
                    question_type,
                    optionsJson,
                    correctAnswersJson,
                    question_number,
                    questionImagePath,
                ];

                if (questionId) {
                    // 3. UPDATE existing question
                    questionSql =
                        "UPDATE questions SET question_text = ?, question_type = ?, options_json = ?, correct_answers_json = ?, question_number = ?, question_image_path = ? WHERE id = ? AND quiz_id = ?";
                    questionData.push(questionId, quizId);
                } else {
                    // 3. INSERT new question
                    questionSql =
                        "INSERT INTO questions (question_text, question_type, options_json, correct_answers_json, question_number, question_image_path, quiz_id) VALUES (?, ?, ?, ?, ?, ?, ?)";
                    questionData.push(quizId);
                }

                db.run(questionSql, questionData, function (questionErr) {
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
                                "UNIQUE constraint failed",
                            )
                        ) {
                            errorMsg = `Question number ${question_number} already exists in this quiz.`;
                        }
                        return res.redirect(
                            `/professor/quizzes/${quizId}/edit?error=${errorMsg}`,
                        );
                    }

                    const finalQuestionId = questionId || this.lastID;

                    // 4. Insert/Update Justification
                    const finalJustificationText = justification_text || null;
                    const finalJustificationImagePath = justificationImagePath; // Use the path from the multer upload

                    if (justification_id) {
                        // Update Justification (including image path)
                        db.run(
                            "UPDATE justifications SET justification_text = ?, image_path = ?, user_id = ? WHERE id = ? AND question_id = ?",
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
                        db.run(
                            "INSERT INTO justifications (question_id, justification_text, image_path, user_id) VALUES (?, ?, ?, ?)",
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
    db.get(
        "SELECT * FROM quizzes WHERE id = ? AND professor_id = ?",
        [quizId, professorId],
        (err, quiz) => {
            if (err || !quiz) {
                return res.redirect(
                    "/professor/dashboard?error=Quiz not found or unauthorized.",
                );
            }

            // 2. Fetch all student attempts for this quiz
            const attemptsSql = `
            SELECT 
                u.name AS student_name, 
                t.score_20, 
                t.submitted_at, 
                t.id AS attempt_id
            FROM attempts t
            JOIN users u ON t.user_id = u.id
            WHERE t.quiz_id = ?
            ORDER BY t.submitted_at DESC
        `;

            db.all(attemptsSql, [quizId], (err, attempts) => {
                if (err) {
                    console.error("Error fetching results:", err.message);
                    return res.redirect(
                        "/professor/dashboard?error=Database error fetching results.",
                    );
                }

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
    db.get(
        "SELECT id, title, subject, year FROM quizzes WHERE id = ? AND professor_id = ?",
        [quizId, professorId],
        (err, quiz) => {
            if (err || !quiz) {
                return res.status(404).send("Quiz not found or unauthorized.");
            }

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
            WHERE q.quiz_id = ?
            ORDER BY q.question_number ASC`;

            db.all(questionsSql, [quizId], (err, questions) => {
                if (err) {
                    console.error("Error exporting questions:", err.message);
                    return res
                        .status(500)
                        .send("Database error during export.");
                }

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
        db.serialize(() => {
            db.run("BEGIN TRANSACTION;");

            // We use a promise chain to handle the asynchronous inserts within the transaction
            const importPromises = quizzes.map(
                (quizDefinition) =>
                    new Promise((resolve, reject) => {
                        const { subject, year, questions } = quizDefinition;

                        if (
                            !subject ||
                            !questions ||
                            !Array.isArray(questions)
                        ) {
                            return reject(
                                new Error(
                                    `Quiz definition error: Subject or questions array missing for a quiz.`,
                                ),
                            );
                        }

                        // 1. Insert Quiz Metadata
                        db.run(
                            "INSERT INTO quizzes (title, subject, year, professor_id) VALUES (?, ?, ?, ?)",
                            [
                                exam_title,
                                subject,
                                year || new Date().getFullYear(),
                                professorId,
                            ],
                            function (err) {
                                if (err) return reject(err);
                                const newQuizId = this.lastID;
                                if (firstNewQuizId === null) {
                                    firstNewQuizId = newQuizId;
                                }

                                // 2. Insert Questions (using a nested promise chain)
                                const questionPromises = questions.map(
                                    (q) =>
                                        new Promise((qResolve, qReject) => {
                                            const q_num = q.number || 0;
                                            if (q_num === 0) {
                                                return qReject(
                                                    new Error(
                                                        `Question missing explicit number in subject: ${subject}`,
                                                    ),
                                                );
                                            }
                                            const q_text =
                                                q.text || `Question ${q_num}`;
                                            const q_type =
                                                q.type || "qcm_single";
                                            const q_options = q.options
                                                ? JSON.stringify(q.options)
                                                : null;
                                            const q_correct = JSON.stringify(
                                                q.correct_answers || [],
                                            );
                                            const q_image_path =
                                                q.image_url || null;

                                            db.run(
                                                "INSERT INTO questions (quiz_id, question_number, question_text, question_type, options_json, correct_answers_json, question_image_path) VALUES (?, ?, ?, ?, ?, ?, ?)",
                                                [
                                                    newQuizId,
                                                    q_num,
                                                    q_text,
                                                    q_type,
                                                    q_options,
                                                    q_correct,
                                                    q_image_path,
                                                ],
                                                function (qErr) {
                                                    if (qErr)
                                                        return qReject(qErr);
                                                    const newQuestionId =
                                                        this.lastID;

                                                    // 3. Insert Justification
                                                    if (
                                                        q.justification &&
                                                        (q.justification.text ||
                                                            q.justification
                                                                .image_path)
                                                    ) {
                                                        db.run(
                                                            "INSERT INTO justifications (question_id, justification_text, user_id) VALUES (?, ?, ?)",
                                                            [
                                                                newQuestionId,
                                                                q.justification
                                                                    .text || "",
                                                                professorId,
                                                            ],
                                                            (jErr) => {
                                                                if (jErr)
                                                                    return qReject(
                                                                        jErr,
                                                                    );
                                                                qResolve();
                                                            },
                                                        );
                                                    } else {
                                                        qResolve();
                                                    }
                                                },
                                            );
                                        }),
                                );

                                // Wait for all questions in this quiz to finish
                                Promise.all(questionPromises)
                                    .then(resolve)
                                    .catch(reject);
                            },
                        );
                    }),
            );

            // Execute all quiz imports
            Promise.all(importPromises)
                .then(() => {
                    db.run("COMMIT;", () => {
                        const redirectId =
                            firstNewQuizId || "/professor/dashboard";
                        res.redirect(
                            `/professor/quizzes/${redirectId}/edit?success=Multi-Quiz Import successful! ${quizzes.length} quizzes created.`,
                        );
                    });
                })
                .catch((e) => {
                    db.run("ROLLBACK;", () => {
                        console.error("Multi-Quiz Import Failed:", e.message);
                        res.redirect(
                            `/professor/dashboard?error=Import failed (Transaction rolled back): ${e.message}`,
                        );
                    });
                });
        });
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

        // 1. SAFELY DETERMINE IMAGE PATHS (Fix for potential TypeError)
        // req.files is guaranteed to be an object when using upload.fields, but we make the access safe anyway.
        const quizFile = req.file;

        // QUESTION IMAGE PATH
        const questionImageFile =
            files.question_image && files.question_image[0];
        const questionImagePath = questionImageFile
            ? `/uploads/${questionImageFile.filename}`
            : null;

        // JUSTIFICATION IMAGE PATH (Note: This logic is for the *justification* image path, which is separate)
        const justificationImageFile =
            files.justification_image && files.justification_image[0];
        const justificationImagePath = justificationImageFile
            ? `/uploads/${justificationImageFile.filename}`
            : null;

        db.get(
            "SELECT id FROM quizzes WHERE id = ? AND professor_id = ?",
            [quizId, professorId],
            (err, quiz) => {
                if (err || !quiz) {
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

                // 2. Process Options and Correct Answers (Keep existing validation logic)
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
                let questionData = [
                    question_text,
                    question_type,
                    optionsJson,
                    correctAnswersJson,
                    question_number,
                    questionImagePath,
                ]; // **NEW: questionImagePath included**

                if (questionId) {
                    // 3. UPDATE existing question
                    questionSql =
                        "UPDATE questions SET question_text = ?, question_type = ?, options_json = ?, correct_answers_json = ?, question_number = ?, question_image_path = ? WHERE id = ? AND quiz_id = ?"; // **NEW: question_image_path in UPDATE query**

                    questionData.push(questionId, quizId);
                } else {
                    // 3. INSERT new question
                    questionSql =
                        "INSERT INTO questions (question_text, question_type, options_json, correct_answers_json, question_number, question_image_path, quiz_id) VALUES (?, ?, ?, ?, ?, ?, ?)"; // **NEW: question_image_path in INSERT query**

                    questionData.push(quizId);
                }

                db.run(questionSql, questionData, function (questionErr) {
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
                                "UNIQUE constraint failed",
                            )
                        ) {
                            errorMsg = `Question number ${question_number} already exists in this quiz.`;
                        }
                        return res.redirect(
                            `/professor/quizzes/${quizId}/edit?error=${errorMsg}`,
                        );
                    }

                    const finalQuestionId = questionId || this.lastID;

                    // 4. Insert/Update Justification
                    const finalJustificationText = justification_text || null;
                    const finalJustificationImagePath = justificationImagePath; // Use the path from the multer upload

                    if (justification_id) {
                        // Update Justification (including image path)
                        db.run(
                            "UPDATE justifications SET justification_text = ?, image_path = ?, user_id = ? WHERE id = ? AND question_id = ?",
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
                        db.run(
                            "INSERT INTO justifications (question_id, justification_text, image_path, user_id) VALUES (?, ?, ?, ?)",
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
    (req, res) => {
        const db = req.app.locals.db;
        const questionId = req.params.questionId;
        const { quizId } = req.body;

        // 1. Get image path for deletion
        db.get(
            "SELECT j.image_path FROM questions q LEFT JOIN justifications j ON q.id = j.question_id WHERE q.id = ?",
            [questionId],
            (err, row) => {
                if (row && row.image_path) {
                    const imagePath = path.join(
                        UPLOADS_DIR,
                        path.basename(row.image_path),
                    );
                    if (fs.existsSync(imagePath)) {
                        fs.unlink(imagePath, (e) => {
                            if (e)
                                console.error(
                                    "Could not delete justification image:",
                                    e.message,
                                );
                        });
                    }
                }

                // 2. Delete question (and cascade delete justifications/answers)
                db.run(
                    "DELETE FROM questions WHERE id = ?",
                    [questionId],
                    (delErr) => {
                        if (delErr) {
                            console.error(
                                "Question deletion error:",
                                delErr.message,
                            );
                            return res.redirect(
                                `/professor/quizzes/${quizId}/edit?error=Failed to delete question.`,
                            );
                        }
                        res.redirect(
                            `/professor/quizzes/${quizId}/edit?success=Question deleted successfully.`,
                        );
                    },
                );
            },
        );
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

    db.get(
        "SELECT id FROM quizzes WHERE id = ? AND professor_id = ?",
        [quizId, professorId],
        (err, quiz) => {
            if (err || !quiz) {
                return res
                    .status(403)
                    .send("Quiz not found or unauthorized access.");
            }

            db.get(
                "SELECT id FROM questions WHERE quiz_id = ? AND question_number = ?",
                [quizId, targetNum],
                (err, targetQuestion) => {
                    if (err || !targetQuestion) {
                        return res.redirect(
                            `/professor/quizzes/${quizId}/edit`,
                        );
                    }

                    db.serialize(() => {
                        db.run("BEGIN TRANSACTION;");

                        db.run(
                            "UPDATE questions SET question_number = ? WHERE id = ? AND quiz_id = ?",
                            [targetNum, questionId, quizId],
                            (err) => {
                                if (err) db.run("ROLLBACK;");
                            },
                        );

                        db.run(
                            "UPDATE questions SET question_number = ? WHERE id = ? AND quiz_id = ?",
                            [currentNum, targetQuestion.id, quizId],
                            (err) => {
                                if (err) db.run("ROLLBACK;");
                                else
                                    db.run("COMMIT;", () => {
                                        res.redirect(
                                            `/professor/quizzes/${quizId}/edit?success=Question order updated.`,
                                        );
                                    });
                            },
                        );
                    });
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
            (SELECT MAX(score_20) FROM attempts WHERE quiz_id = q.id AND user_id = ?) AS highest_score
        FROM quizzes q
        JOIN users p ON q.professor_id = p.id
    `;
    const params = [userId];

    if (search) {
        sql += ` 
            WHERE q.title LIKE ? OR 
            q.subject LIKE ? OR 
            CAST(q.year AS TEXT) LIKE ?
        `;
        const searchTerm = `%${search}%`;
        params.push(searchTerm, searchTerm, searchTerm);
    }

    sql += ` ORDER BY q.id DESC`;

    db.all(sql, params, (err, quizzes) => {
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
            quizzes: quizzes,
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
    db.get("SELECT * FROM quizzes WHERE id = ?", [quizId], (err, quiz) => {
        if (err || !quiz) {
            return res.redirect("/student/dashboard?error=Quiz not found.");
        }

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
            WHERE quiz_id = ?
            ORDER BY question_number ASC`;

        db.all(questionsSql, [quizId], (err, questions) => {
            if (err) {
                console.error("Error fetching quiz questions:", err.message);
                return res.redirect(
                    "/student/dashboard?error=Error loading quiz questions.",
                );
            }

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
    db.all(
        "SELECT id, correct_answers_json, question_type FROM questions WHERE quiz_id = ?",
        [quizId],
        (err, questions) => {
            if (err || questions.length === 0) {
                console.error(
                    "Submission error: Cannot fetch questions.",
                    err ? err.message : "",
                );
                return res.redirect(
                    "/student/dashboard?error=Error processing submission.",
                );
            }

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
                    is_correct: isCorrect ? 1 : 0,
                });
            });

            // 3. Normalize Score to /20
            const score20 = (correctCount / totalQuestions) * 20;

            // 4. Save Attempt and Answers in a Transaction
            db.serialize(() => {
                db.run("BEGIN TRANSACTION;");

                db.run(
                    "INSERT INTO attempts (user_id, quiz_id, score_20) VALUES (?, ?, ?)",
                    [userId, quizId, score20],
                    function (attemptErr) {
                        if (attemptErr) {
                            console.error(
                                "Attempt insert error:",
                                attemptErr.message,
                            );
                            db.run("ROLLBACK;");
                            return res.redirect(
                                "/student/dashboard?error=Failed to save quiz attempt.",
                            );
                        }

                        const attemptId = this.lastID;

                        const answerPlaceholder = "(?, ?, ?, ?)";
                        const answerInserts = answersToSave
                            .map(() => answerPlaceholder)
                            .join(", ");
                        const answerSql = `INSERT INTO answers (attempt_id, question_id, answer_json, is_correct) VALUES ${answerInserts}`;

                        const answerParams = [];
                        answersToSave.forEach((ans) => {
                            answerParams.push(
                                attemptId,
                                ans.question_id,
                                ans.answer_json,
                                ans.is_correct,
                            );
                        });

                        db.run(answerSql, answerParams, (answerErr) => {
                            if (answerErr) {
                                console.error(
                                    "Answers insert error:",
                                    answerErr.message,
                                );
                                db.run("ROLLBACK;");
                                return res.redirect(
                                    "/student/dashboard?error=Failed to save individual answers.",
                                );
                            }

                            db.run("COMMIT;", () => {
                                // 5. Redirect to results page
                                res.redirect(
                                    `/student/quizzes/${quizId}/results`,
                                );
                            });
                        });
                    },
                );
            });
        },
    );
});

// GET /student/quizzes/:quizId/results - Display quiz results and justifications
app.get("/student/quizzes/:quizId/results", requireStudent, (req, res) => {
    const db = req.app.locals.db;
    const quizId = req.params.quizId;
    const userId = req.session.userId;

    // 1. Get the latest attempt and overall score
    db.get(
        "SELECT id, score_20, submitted_at FROM attempts WHERE user_id = ? AND quiz_id = ? ORDER BY submitted_at DESC LIMIT 1",
        [userId, quizId],
        (err, attempt) => {
            if (err || !attempt) {
                return res.redirect(
                    `/student/dashboard?error=No completed attempt found for this quiz.`,
                );
            }

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
            WHERE a.attempt_id = ?
            ORDER BY q.question_number ASC
        `;

            db.all(resultsSql, [attemptId], (err, results) => {
                if (err || results.length === 0) {
                    console.error(
                        "Error fetching results details:",
                        err ? err.message : "",
                    );
                    return res.redirect(
                        `/student/dashboard?error=Error fetching result details.`,
                    );
                }

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
    db.get(
        "SELECT id, title, subject FROM quizzes WHERE id = ?",
        [quizId],
        (err, quiz) => {
            if (err || !quiz) {
                return res.redirect("/student/dashboard?error=Quiz not found.");
            }

            // 2. Get all attempts for this user and quiz, ordered from newest to oldest
            db.all(
                "SELECT id, score_20, submitted_at FROM attempts WHERE user_id = ? AND quiz_id = ? ORDER BY submitted_at DESC",
                [userId, quizId],
                (err, attempts) => {
                    if (err) {
                        console.error(
                            "Error fetching attempt history:",
                            err.message,
                        );
                        return res.redirect(
                            "/student/dashboard?error=Error loading quiz history.",
                        );
                    }

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
    db.all(
        "SELECT id, name, email, role FROM users ORDER BY role, name ASC",
        [],
        (err, users) => {
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
                users: users,
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

    db.run(
        "INSERT INTO users (name, email, password, salt, role) VALUES (?, ?, ?, ?, ?)",
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
// POST /professor/quizzes/1/delete
app.post("/professor/quizzes/:quizId/delete", requireProfessor, (req, res) => {
    const db = req.app.locals.db;
    const quizId = req.params.quizId;
    const professorId = req.session.userId;

    db.run(
        "DELETE FROM quizzes WHERE id = ? AND professor_id = ?",
        [quizId, professorId],
        function (err) {
            if (err) {
                return res.redirect(
                    "/professor/dashboard?error=Failed to delete quiz.",
                );
            }
            res.redirect(
                "/professor/dashboard?success=Quiz deleted successfully.",
            );
        },
    );
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
    db.run(
        "DELETE FROM attempts WHERE user_id = ?",
        [userIdToDelete],
        (err) => {
            if (err) {
                console.error("Error deleting attempts:", err.message);
                return res.redirect(
                    "/professor/users?error=Error deleting user attempts.",
                );
            }

            // 2. Delete the user
            db.run(
                "DELETE FROM users WHERE id = ?",
                [userIdToDelete],
                function (err) {
                    if (err) {
                        console.error("Error deleting user:", err.message);
                        return res.redirect(
                            "/professor/users?error=Error deleting user.",
                        );
                    }
                    if (this.changes === 0) {
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
    if (req.files) {
        const files = Array.isArray(req.files) ? req.files : Object.values(req.files).flat();
        files.forEach(file => {
            if (file.path && fs.existsSync(file.path)) {
                fs.unlinkSync(file.path);
            }
        });
    }
    
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
