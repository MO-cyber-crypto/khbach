const express = require('express');
const router = express.Router();
const { supabaseAdmin } = require('../config/supabase');

// Authentication middleware
const authenticateUser = (req, res, next) => {
  if (!req.session || !req.session.user) return res.redirect('/login');
  next();
};

const authenticateProfessor = (req, res, next) => {
  if (!req.session || !req.session.user || req.session.user.role !== 'professor') return res.redirect('/login');
  next();
};

// Routes
router.get('/', (req, res) => res.redirect('/login'));

router.get('/login', (req, res) => {
  if (req.session && req.session.user) {
    const redirectUrl = req.session.user.role === 'professor' ? '/professor/dashboard' : '/student/dashboard';
    return res.redirect(redirectUrl);
  }
  
  try {
    res.render('login', { 
      error: req.query.error || null,
      user: null 
    });
  } catch (err) {
    console.error('View rendering error:', err);
    res.status(500).send('Error loading login page. Please check server configuration.');
  }
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.redirect('/login?error=Email and password are required');
  }

  try {
    if (!supabaseAdmin) {
      console.error('supabaseAdmin client is not configured.');
      return res.status(500).send('Server configuration error');
    }

    const { data: user, error } = await supabaseAdmin
      .from('users')
      .select('id, email, role')
      .eq('email', email)
      .eq('password', password)
      .single();

    if (error || !user) {
      console.error('Login error:', error);
      return res.redirect('/login?error=Invalid credentials');
    }

    // Create new session
    req.session.regenerate((err) => {
      if (err) {
        console.error('Session regeneration error:', err);
        return res.redirect('/login?error=Session error');
      }

      // Set user data in session
      req.session.user = {
        id: user.id,
        email: user.email,
        role: user.role
      };

      // Save session
      req.session.save((err) => {
        if (err) {
          console.error('Session save error:', err);
          return res.redirect('/login?error=Session error');
        }

        // Redirect based on role
        const redirectUrl = user.role === 'professor' ? '/professor/dashboard' : '/student/dashboard';
        return res.redirect(redirectUrl);
      });
    });
  } catch (err) {
    console.error('Login error:', err);
    return res.redirect('/login?error=Server error occurred');
  }
});

router.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

module.exports = {
  router,
  authenticateUser,
  authenticateProfessor,
};
