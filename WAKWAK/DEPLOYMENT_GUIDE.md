# Deployment Guide - Quiz Application

## Migration Summary (October 2025)

This application has been successfully migrated from SQLite to PostgreSQL to support cloud deployment on Vercel with Supabase database.

## Environment Variables Required

For deployment on Vercel, you need to set the following environment variables:

### Required
- `DATABASE_URL`: Your Supabase PostgreSQL connection string
  - Format: `postgresql://user:password@host:port/database`
  - Get this from your Supabase project settings

### Recommended
- `SESSION_SECRET`: A random 32+ character string for session encryption
  - Generate with: `openssl rand -hex 32`
  - If not set, a random secret is generated (sessions won't persist across restarts)

### Optional
- `NODE_ENV`: Set to `production` for production deployments
  - This enables secure cookies and other production optimizations

## Vercel Deployment Steps

1. **Connect Your Supabase Database**
   - Create a Supabase project at https://supabase.com
   - Get your DATABASE_URL from Project Settings > Database > Connection String
   - Use the "Connection Pooling" URL for better performance

2. **Set Environment Variables in Vercel**
   - Go to your Vercel project settings
   - Navigate to Environment Variables
   - Add `DATABASE_URL` with your Supabase connection string
   - Add `SESSION_SECRET` with a secure random string
   - Add `NODE_ENV` set to `production`

3. **Deploy**
   - Push your code to GitHub
   - Vercel will automatically deploy
   - The database schema will be created automatically on first run

4. **Initial Setup**
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

## Support

For issues specific to:
- **Database**: Check Supabase dashboard and logs
- **Deployment**: Check Vercel deployment logs
- **Application**: Check server logs in Vercel Functions tab
