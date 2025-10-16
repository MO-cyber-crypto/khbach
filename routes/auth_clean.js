const express = require('express');
const router = express.Router();
const { supabaseAdmin } = require('../config/supabase');

// Authentication middleware
const authenticateUser = (req, res, next) => {
  if (!req.session.user) return res.redirect('/login');
  next();
};

const authenticateProfessor = (req, res, next) => {
  if (!req.session.user || req.session.user.role !== 'professor') return res.redirect('/login');
  next();
};

// Routes
router.get('/', (req, res) => res.redirect('/login'));

router.get('/login', (req, res) => {
  if (req.session.user) return res.redirect(req.session.user.role === 'professor' ? '/professor/dashboard' : '/student/dashboard');
  res.render('login', { error: req.query.error || null });
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    if (!supabaseAdmin) {
      console.error('supabaseAdmin client is not configured.');
      return res.status(500).render('login', { error: 'Server not configured. Please set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY.' });
    }
    const { data: user, error } = await supabaseAdmin
      .from('users')
      .select('*')
      .eq('email', email)
      .eq('password', password)
      .single();

    if (error || !user) return res.redirect('/login?error=Invalid credentials');

    req.session.user = { id: user.id, email: user.email, role: user.role };
    return res.redirect(user.role === 'professor' ? '/professor/dashboard' : '/student/dashboard');
  } catch (err) {
    console.error('Login error:', err);
    return res.redirect('/login?error=Server error');
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
