require('dotenv').config();
const { supabaseAdmin } = require('../config/supabase');

// Using top-level await since we're in a module
(async () => {
  try {
    // Check if default professor account exists
    const { data: existingUser, error: checkError } = await supabaseAdmin
      .from('users')
      .select('*')
      .eq('email', process.env.DEFAULT_ADMIN_EMAIL)
      .single();

    // If we get a specific error, it means the table doesn't exist
    if (tableCheckError && tableCheckError.code === 'PGRST205') {
      console.log('Users table not found. Please create it in the Supabase dashboard with the following SQL:');
      console.log(`
        create table public.users (
          id uuid default uuid_generate_v4() primary key,
          email text unique not null,
          password text not null,
          role text not null,
          created_at timestamp with time zone default timezone('utc'::text, now())
        );

        -- Set up Row Level Security (RLS)
        alter table public.users enable row level security;

        -- Create policies
        create policy "Users can view their own data" on public.users
          for select using (auth.uid() = id);

        create policy "Users can update their own data" on public.users
          for update using (auth.uid() = id);
      `);
      return;
    }

    // Check if default professor account exists
    const { data: existingUser, error: checkError } = await supabaseAdmin
      .from('users')
      .select('*')
      .eq('email', process.env.DEFAULT_ADMIN_EMAIL)
      .single();

    if (checkError && checkError.code !== 'PGRST116') {
      console.error('Error checking for existing user:', checkError);
      return;
    }

    // Create default professor account if it doesn't exist
    if (!existingUser) {
      const { error: createUserError } = await supabaseAdmin
        .from('users')
        .insert([
          {
            email: process.env.DEFAULT_ADMIN_EMAIL,
            password: process.env.DEFAULT_ADMIN_PASSWORD,
            role: 'professor'
          }
        ]);

      if (createUserError) {
        console.error('Error creating default professor:', createUserError);
        return;
      }

      console.log('Default professor account created successfully');
    } else {
      console.log('Default professor account already exists');
    }
  } catch (error) {
    console.error('Initialization error:', error);
  }
}

// Run initialization
initializeDatabase();

    // Check if default professor account exists
    const { data: existingUser, error: checkError } = await supabaseAdmin
      .from('users')
      .select('*')
      .eq('email', process.env.DEFAULT_ADMIN_EMAIL)
      .single();

    if (checkError && checkError.code !== 'PGRST116') {
      console.error('Error checking for existing user:', checkError);
      return;
    }

    // Create default professor account if it doesn't exist
    if (!existingUser) {
      const { error: createUserError } = await supabaseAdmin
        .from('users')
        .insert([
          {
            email: process.env.DEFAULT_ADMIN_EMAIL,
            password: process.env.DEFAULT_ADMIN_PASSWORD,
            role: 'professor'
          }
        ]);

      if (createUserError) {
        console.error('Error creating default professor:', createUserError);
        return;
      }

      console.log('Default professor account created successfully');
    } else {
      console.log('Default professor account already exists');
    }
  } catch (error) {
    console.error('Initialization error:', error);
  }
}

// Run initialization
initializeDatabase();