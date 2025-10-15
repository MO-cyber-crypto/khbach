# Deployment Guide - Quiz Application

## Migration Summary (October 2025)

This application has been successfully migrated from SQLite to PostgreSQL and from local file storage to Supabase cloud storage to support cloud deployment on Vercel.

## Environment Variables Required

For deployment on Vercel, you need to set the following environment variables:

### Required
- `DATABASE_URL`: Your Supabase PostgreSQL connection string
  - Format: `postgresql://user:password@host:port/database`
  - Get this from your Supabase project settings → Database → Connection String
  - Use the "Connection Pooling" URL for better performance

- `SUPABASE_URL` (or `NEXT_PUBLIC_SUPABASE_URL`): Your Supabase project URL
  - Format: `https://xxxxx.supabase.co`
  - Get this from your Supabase project settings → API → Project URL

- `SUPABASE_ANON_KEY` (or `NEXT_PUBLIC_SUPABASE_ANON_KEY`): Your Supabase anonymous key
  - Get this from your Supabase project settings → API → Project API keys → anon public

### Recommended
- `SESSION_SECRET`: A random 32+ character string for session encryption
  - Generate with: `openssl rand -hex 32`
  - If not set, a random secret is generated (sessions won't persist across restarts)

### Optional
- `NODE_ENV`: Set to `production` for production deployments
  - This enables secure cookies and other production optimizations

## Vercel Deployment Steps

### 1. Set Up Supabase Project

#### A. Create Supabase Project
- Go to https://supabase.com and create a new project
- Note down your project URL and anon key from Settings → API

#### B. Set Up Supabase Storage Bucket
1. Go to Storage in your Supabase dashboard
2. Click "New Bucket"
3. Name it `quiz-images`
4. Choose **Public** bucket (for image access)
5. Click "Create Bucket"

#### C. Configure Storage Policies
1. Go to Storage → Policies → quiz-images bucket
2. Click "New Policy"
3. Create a policy to allow uploads:
   - Policy Name: "Allow public uploads"
   - Policy Definition: SELECT, INSERT, UPDATE, DELETE
   - For testing, you can allow all operations (refine for production)

### 2. Set Environment Variables in Vercel
   - Go to your Vercel project settings
   - Navigate to Environment Variables
   - Add the following variables:
     - `DATABASE_URL` = Your Supabase PostgreSQL connection string
     - `SUPABASE_URL` = Your Supabase project URL
     - `SUPABASE_ANON_KEY` = Your Supabase anonymous key
     - `SESSION_SECRET` = A secure random string (generate with `openssl rand -hex 32`)
     - `NODE_ENV` = `production`

### 3. Deploy to Vercel
   - Push your code to GitHub
   - Connect your repository to Vercel
   - Vercel will automatically deploy
   - The database schema will be created automatically on first run

### 4. Initial Setup
   - The first time the app runs, it will:
     - Create all necessary database tables
     - Seed a default professor account:
       - Email: `prof@app.com`
       - Password: `professorpass`
   - **Important**: Change the default professor password after first login!

## Database Schema

The application automatically creates these tables:
- `users` - User accounts (professors and students)
- `quizzes` - Quiz metadata
- `questions` - Quiz questions with answer keys
- `justifications` - Question justifications and explanations
- `attempts` - Student quiz attempts and scores
- `answers` - Individual question answers
- `session` - Session storage for user authentication

## Key Migration Changes

### Database Connection
- **Before**: SQLite file-based database (`quiz_app.db`)
- **After**: PostgreSQL connection pool using `DATABASE_URL`

### File Storage (October 2025)
- **Before**: Local disk storage in `uploads/` directory
- **After**: Supabase cloud storage in `quiz-images` bucket
- **Upload Method**: Memory buffers → Supabase Storage API
- **File Access**: Local paths → Public Supabase URLs

### SQL Syntax Updates
- Parameter placeholders: `?` → `$1, $2, $3...`
- Auto-increment: `AUTOINCREMENT` → `SERIAL`
- Timestamps: `DATETIME` → `TIMESTAMP`
- Boolean: `BOOLEAN` (explicit type)
- INSERT with ID: `this.lastID` → `RETURNING id` clause

### Session Storage
- **Before**: In-memory session storage
- **After**: PostgreSQL-backed sessions using `connect-pg-simple`

### Transaction Handling
- **Before**: `db.serialize()` with callbacks
- **After**: `async/await` with `pool.query()`

## Testing Locally

To test the PostgreSQL version locally:

1. Set up environment variables:
   ```bash
   export DATABASE_URL="your_supabase_connection_string"
   export SESSION_SECRET="your_random_secret"
   ```

2. Run the server:
   ```bash
   npm start
   ```

3. Test login:
   - Professor: `prof@app.com` / `professorpass`
   - Create new student accounts via registration

## Troubleshooting

### "Access Denied: Professor account required"
- This occurs if the database tables weren't created or the professor account wasn't seeded
- Check Vercel logs for database connection errors
- Verify DATABASE_URL is correctly set in Vercel environment variables
- Ensure your Supabase database is accessible (check firewall/network settings)

### Session issues (not staying logged in)
- Set SESSION_SECRET environment variable
- Ensure cookies are enabled in production (NODE_ENV=production)
- Check that connect-pg-simple session table was created

### Database connection errors
- Verify DATABASE_URL format is correct
- Use Supabase "Connection Pooling" URL for better performance
- Check that your Supabase project is running and accessible

### File upload errors
- **"Supabase is not initialized"**: Check that SUPABASE_URL and SUPABASE_ANON_KEY are set
- **"Supabase upload failed"**: Verify the `quiz-images` bucket exists in Supabase Storage
- **"Permission denied"**: Check storage policies allow INSERT/UPDATE operations
- **Images not displaying**: Ensure the bucket is set to **Public**, not Private

### Storage Policy Issues
If images upload but don't display:
1. Go to Supabase → Storage → quiz-images → Policies
2. Ensure you have a policy allowing SELECT (read) operations
3. For public access, create a policy that allows SELECT for all users

## Support

For issues specific to:
- **Database**: Check Supabase dashboard → Database logs
- **Storage**: Check Supabase dashboard → Storage → quiz-images bucket
- **Deployment**: Check Vercel deployment logs
- **File Uploads**: Check browser console for errors and Vercel function logs
- **Application**: Check server logs in Vercel Functions tab
