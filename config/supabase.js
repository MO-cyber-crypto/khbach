const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;
const supabaseServiceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

let supabase = null;
let supabaseAdmin = null;

if (!supabaseUrl) {
	console.warn('SUPABASE_URL is not set — Supabase clients will be disabled. Set SUPABASE_URL and keys in environment to enable Supabase features.');
} else {
	try {
		if (supabaseAnonKey) {
			supabase = createClient(supabaseUrl, supabaseAnonKey);
		} else {
			console.warn('SUPABASE_ANON_KEY not set — public client will be disabled.');
		}

		if (supabaseServiceRoleKey) {
			supabaseAdmin = createClient(supabaseUrl, supabaseServiceRoleKey);
		} else {
			console.warn('SUPABASE_SERVICE_ROLE_KEY not set — admin client will be disabled.');
		}
	} catch (err) {
		console.error('Failed to initialize Supabase clients:', err && err.message ? err.message : err);
		supabase = null;
		supabaseAdmin = null;
	}
}

module.exports = { supabase, supabaseAdmin };