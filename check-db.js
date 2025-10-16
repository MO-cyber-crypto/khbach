require('dotenv').config();
const { supabaseAdmin } = require('./config/supabase');

async function checkDatabaseSetup() {
  try {
    // Check if we can connect to the database and query the users table
    const { data, error } = await supabaseAdmin
      .from('users')
      .select('email, role')
      .eq('email', 'prof@app.com')
      .single();

    if (error) {
      console.error('Error checking database:', error);
      return;
    }

    if (data) {
      console.log('✅ Database connection successful');
      console.log('✅ Users table exists');
      console.log('✅ Default professor account found:', data);
    } else {
      console.log('❌ Default professor account not found');
    }
  } catch (error) {
    console.error('Error:', error.message);
  }
}

checkDatabaseSetup();