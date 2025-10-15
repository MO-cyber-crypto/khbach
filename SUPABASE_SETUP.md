# Supabase Storage Setup Guide

This guide explains how to set up Supabase Storage for the Quiz Application.

## Prerequisites

- A Supabase account (sign up at https://supabase.com)
- A Supabase project created

## Step-by-Step Setup

### 1. Create Storage Bucket

1. Open your Supabase project dashboard
2. Navigate to **Storage** in the left sidebar
3. Click **"New Bucket"** button
4. Configure the bucket:
   - **Name**: `quiz-images`
   - **Public bucket**: ✅ **Checked** (allows public read access)
   - **File size limit**: Leave default or set to 5MB
5. Click **"Create Bucket"**

### 2. Configure Storage Policies

#### Option A: Simple Public Access (Recommended for Development)

1. Go to **Storage** → Click on `quiz-images` bucket
2. Click on **"Policies"** tab
3. Click **"New Policy"**
4. Select **"For full customization"**
5. Configure the policy:
   ```sql
   Policy Name: Allow all operations for authenticated users
   
   Target Roles: public
   
   Policy Definition (SQL):
   (storage.foldername() = 'quiz-images'::text)
   
   Allowed Operations: 
   ✅ SELECT (read files)
   ✅ INSERT (upload files)
   ✅ UPDATE (update files)
   ✅ DELETE (delete files)
   ```

#### Option B: Template-Based Policy (Easier)

1. Click **"New Policy"**
2. Select a template: **"Allow public access"**
3. This creates policies for all CRUD operations
4. Click **"Review"** and **"Save Policy"**

### 3. Get API Credentials

1. Go to **Settings** → **API** in your Supabase dashboard
2. Copy the following values:
   - **Project URL** (format: `https://xxxxxxxxxxxxx.supabase.co`)
   - **anon public** key (under "Project API keys")

### 4. Set Environment Variables

Add these to your `.env` file or deployment platform:

```bash
# Supabase Storage Configuration
SUPABASE_URL=https://xxxxxxxxxxxxx.supabase.co
SUPABASE_ANON_KEY=your_anon_key_here

# Alternative format (Vercel-compatible)
NEXT_PUBLIC_SUPABASE_URL=https://xxxxxxxxxxxxx.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=your_anon_key_here
```

### 5. Verify Setup

1. Start your application
2. Log in as professor (`prof@app.com` / `professorpass`)
3. Create or edit a quiz question
4. Try uploading an image
5. Check that the image displays correctly

If successful, you should see the image URL in the format:
```
https://xxxxxxxxxxxxx.supabase.co/storage/v1/object/public/quiz-images/[filename]
```

## Troubleshooting

### Error: "Supabase is not initialized"
- **Cause**: Environment variables not set
- **Fix**: Ensure `SUPABASE_URL` and `SUPABASE_ANON_KEY` are configured

### Error: "Supabase upload failed: new row violates row-level security policy"
- **Cause**: Storage policies not configured correctly
- **Fix**: 
  1. Go to Storage → quiz-images → Policies
  2. Ensure INSERT policy exists and allows public access
  3. Or use the "Allow all operations" policy from Option A above

### Images Upload but Don't Display
- **Cause**: Bucket is private or SELECT policy missing
- **Fix**:
  1. Ensure bucket is marked as **Public**
  2. Add a SELECT policy allowing public access
  3. Or recreate bucket as public

### Error: "The resource was not found"
- **Cause**: Bucket name mismatch
- **Fix**: Ensure bucket is named exactly `quiz-images` (case-sensitive)

## Security Considerations

### For Production:

1. **Authenticated Uploads Only**:
   ```sql
   -- Only allow authenticated users to upload
   (auth.role() = 'authenticated')
   ```

2. **File Size Limits**: 
   - Set bucket file size limit to 5MB
   - Application already enforces 5MB limit via Multer

3. **File Type Restrictions**:
   - Application only allows: JPEG, PNG, GIF, WEBP
   - Consider adding storage-level MIME type restrictions

4. **Rate Limiting**:
   - Use Supabase rate limiting features
   - Application already has rate limiting on routes

## Testing Storage

### Test Upload
```bash
curl -X POST http://localhost:5000/professor/questions/save \
  -F "quizId=1" \
  -F "question_text=Test Question" \
  -F "question_type=qcm_single" \
  -F "options_text=A,B,C,D" \
  -F "correct_answers_text=A" \
  -F "question_image=@test-image.jpg"
```

### Verify in Supabase
1. Go to Storage → quiz-images
2. You should see uploaded files listed
3. Click on a file to get its public URL
4. Open URL in browser to verify accessibility

## Migration from Local Storage

If migrating from local storage:
1. Existing local files in `uploads/` directory are NOT automatically migrated
2. New uploads will go to Supabase Storage
3. Old image paths in database still point to local files
4. Consider:
   - Manually uploading old images to Supabase
   - Updating database paths to point to new URLs
   - Or accept that old quizzes may have broken image links
