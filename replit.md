# Quiz Justification App

## Overview

A collaborative web application for creating and taking quizzes with justification features. The application allows users to register, create quizzes with questions (including image uploads), take quizzes, and provide justifications for their answers. Built with a simple Node.js/Express backend using PostgreSQL (Supabase) for data persistence.

**Deployment Status:** The application has been migrated from SQLite to PostgreSQL to support cloud deployment on Vercel with Supabase database backend.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture

**Technology Stack:**
- **Template Engine:** EJS (Embedded JavaScript) for server-side rendering
- **Styling Framework:** Bootstrap 5.3.x for responsive UI components
- **Static Assets:** Served via Express static middleware

**Design Decision:**
The application uses server-side rendering with EJS templates rather than a modern SPA framework. This choice prioritizes simplicity and reduces complexity, making the codebase easier to understand and maintain. Bootstrap provides consistent, responsive styling without requiring custom CSS frameworks.

### Backend Architecture

**Technology Stack:**
- **Runtime:** Node.js
- **Web Framework:** Express 4.x
- **Session Management:** express-session middleware

**Design Patterns:**
- MVC-like structure with routes handling business logic
- Session-based authentication for user management
- Middleware pipeline for request processing (session, static files, body parsing)

**Rationale:**
Express provides a minimal, flexible framework ideal for this medium-sized application. The server-side rendering approach keeps the frontend simple while maintaining full control over the user experience.

### Data Storage

**Database:** PostgreSQL (Supabase) - **UPDATED October 2025**
- **Schema:** Relational database with foreign key constraints
- **Tables:** Users, quizzes, questions, justifications, attempts, answers, session
- **Connection:** Cloud-hosted PostgreSQL via DATABASE_URL environment variable
- **Session Storage:** PostgreSQL-backed sessions using connect-pg-simple

**Migration from SQLite (October 2025):**
The application was migrated from SQLite to PostgreSQL to support cloud deployment on Vercel. This migration included:
- Converting all database queries from SQLite to PostgreSQL syntax
- Updating schema to use PostgreSQL data types (SERIAL, TIMESTAMP, BOOLEAN)
- Implementing async/await patterns for database operations
- Adding PostgreSQL session storage for distributed deployments

**Design Decision:**
PostgreSQL provides better support for production deployments with concurrent users and cloud platforms like Vercel. Supabase integration simplifies database management and provides additional features like real-time subscriptions and built-in authentication (not currently used).

**Trade-offs:**
- **Pros:** Better concurrency, cloud-ready, production-grade, scalable
- **Cons:** Requires external database service, slightly more complex setup than SQLite
- **Previous Version:** Used SQLite for local development simplicity

### Authentication & Security

**Authentication Mechanism:**
- Password-based authentication with cryptographic hashing
- **Hashing Algorithm:** PBKDF2 with SHA-512 (10,000 iterations)
- Salt-based password storage for security
- Session-based user state management with secure cookie settings

**Design Decision:**
PBKDF2 with a high iteration count provides strong password security without external dependencies. Session-based authentication is appropriate for a server-rendered application and simpler than JWT-based approaches.

**Security Enhancements (October 2025):**
- **Environment Variable Support:** SESSION_SECRET now uses environment variables with fallback warning
- **Input Validation:** 
  - Email format validation using regex
  - Password strength requirements (min 8 chars, uppercase, lowercase, number)
  - Role validation to prevent invalid user types
- **Rate Limiting:** 
  - Login attempts limited to 5 per 15 minutes
  - Registration limited to 3 per hour
  - Prevents brute force attacks
- **Secure Session Configuration:**
  - httpOnly cookies to prevent XSS attacks
  - Secure flag enabled in production
  - SameSite=strict to prevent CSRF
- **File Upload Security:**
  - 5MB file size limit
  - Image-only file type validation (JPEG, PNG, GIF, WEBP)
  - Proper error handling for upload failures

**Security Considerations:**
- Passwords are never stored in plain text
- Each password uses a unique salt
- Sessions are managed server-side via express-session
- All user inputs are validated before processing
- Rate limiting protects against brute force attacks
- File uploads are restricted and validated

### File Upload Management

**Library:** Multer 1.4.x
- **Storage:** Disk storage in `uploads/` directory
- **File Naming:** Timestamp + random hex suffix to prevent collisions
- **Use Case:** Quiz question images

**Design Decision:**
Multer provides straightforward file upload handling for Express applications. Local disk storage is suitable for this application's scale, avoiding the complexity and cost of cloud storage solutions.

**Rationale:**
For quiz creation features requiring images, local file storage is simple to implement and maintain. Files are given unique names to prevent overwrites and maintain organization.

## External Dependencies

### Core Framework Dependencies
- **express (^4.18.2):** Web application framework for routing and middleware
- **ejs (^3.1.9):** Template engine for server-side HTML generation
- **express-session (^1.17.3):** Session middleware for user authentication state
- **express-rate-limit (^7.x):** Rate limiting middleware for API protection

### Data & Storage
- **pg (^8.x):** PostgreSQL database driver for Node.js - **UPDATED October 2025**
- **connect-pg-simple (^9.x):** PostgreSQL session store for express-session - **ADDED October 2025**
- **@supabase/supabase-js (^2.75.0):** Supabase client library (installed but not actively used)
- **multer (^1.4.5-lts.1 | ^2.0.2):** Middleware for handling multipart/form-data file uploads with security features

### UI Framework
- **bootstrap (^5.3.3):** Frontend CSS framework for responsive design

### Built-in Node.js Modules
- **crypto:** For password hashing (PBKDF2) and random token generation
- **path:** File path manipulation
- **fs:** File system operations (directory creation for uploads)

### Development Considerations
All dependencies are production dependencies with no separate development tooling configured. The application can be started directly with `node server.js` or via the npm start script.