const db = require('../config/database');

// Admin Login
const login = async (req, res) => {
  const { email, password } = req.body;

  try {
    const [rows] = await db.query(
      'SELECT * FROM admins WHERE email = ?',
      [email]
    );

    if (
      !rows.length ||
      rows[0].password !== password
    ) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    req.session.adminId = rows[0].id;

    res.json({
      success: true
    });

  } catch (err) {
    console.error('Admin login error:', err);

    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};


// Admin Session
const getAdminSession = (req, res) => {
  if (req.session.adminId) {
    return res.json({
      loggedIn: true,
      adminId: req.session.adminId
    });
  }

  res.json({
    loggedIn: false
  });
};


module.exports = {
  login,
  getAdminSession
};