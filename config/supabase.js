const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
const supabaseServiceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

let supabase = null;
let supabaseAdmin = null;

if (!supabaseUrl) {
    console.warn('⚠️ NEXT_PUBLIC_SUPABASE_URL is not set — Supabase clients will be disabled.');
} else {
    try {
        // Public client (for storage operations)
        if (supabaseAnonKey) {
            supabase = createClient(supabaseUrl, supabaseAnonKey);
            console.log('✅ Supabase public client initialized');
        } else {
            console.warn('⚠️ SUPABASE_ANON_KEY not set — public client disabled.');
        }

        // Admin client (for database operations that bypass RLS)
        if (supabaseServiceRoleKey) {
            supabaseAdmin = createClient(supabaseUrl, supabaseServiceRoleKey, {
                auth: {
                    autoRefreshToken: false,
                    persistSession: false
                }
            });
            console.log('✅ Supabase admin client initialized');
        } else {
            console.warn('⚠️ SUPABASE_SERVICE_ROLE_KEY not set — admin client disabled.');
            console.warn('   Get it from: Supabase Dashboard → Settings → API → service_role key');
        }
    } catch (err) {
        console.error('❌ Failed to initialize Supabase clients:', err && err.message ? err.message : err);
        supabase = null;
        supabaseAdmin = null;
    }
}

// Validate that we have at least the admin client for database operations
if (!supabaseAdmin && supabaseUrl) {
    console.error('⚠️⚠️⚠️ CRITICAL: supabaseAdmin is not initialized!');
    console.error('   The application will NOT work without SUPABASE_SERVICE_ROLE_KEY');
    console.error('   Please add it to your environment variables');
}

module.exports = { supabase, supabaseAdmin };