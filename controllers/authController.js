const db = require('../config/database');
const { validateAndHashPassword } = require('../utils/passwords');
const { sendVerificationCode } = require('../utils/emails');
const bcrypt = require('bcryptjs');

// User Login
const login = async (req, res) => {
  const { email, password } = req.body;

  try {
    const [rows] = await db.execute(
      'SELECT * FROM users WHERE email = ?',
      [email]
    );

    if (
      !rows.length ||
      !(await bcrypt.compare(password, rows[0].password))
    ) {
      return res.json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    const user = rows[0];

    req.session.userId = user.id;
    req.session.firstName = user.first_name;
    req.session.lastName = user.last_name;
    req.session.email = user.email;
    req.session.userName = `${user.first_name} ${user.last_name}`;

    res.json({ success: true });

  } catch (err) {
    console.error('Login error:', err);

    res.json({
      success: false,
      message: 'Server error'
    });
  }
};


// Registration
const register = async (req, res) => {
  const {
    first_name,
    last_name,
    email,
    phone,
    password
  } = req.body;

  try {
    const [existing] = await db.execute(
      'SELECT id FROM users WHERE email = ?',
      [email]
    );

    if (existing.length) {
      return res.status(400).json({
        success: false,
        message: 'Email already registered'
      });
    }

    const result = await validateAndHashPassword(password);

    if (!result.success) {
      return res.status(400).json({
        success: false,
        message: result.message
      });
    }

    const [insert] = await db.execute(
      `
      INSERT INTO users
      (first_name, last_name, email, phone, password, created_at)
      VALUES (?, ?, ?, ?, ?, NOW())
      `,
      [
        first_name,
        last_name,
        email,
        phone,
        result.hash
      ]
    );

    req.session.userId = insert.insertId;
    req.session.userName = `${first_name} ${last_name}`;
    req.session.email = email;

    res.json({ success: true });

  } catch (err) {
    console.error('Registration error:', err);

    res.status(500).json({
      success: false,
      message: 'Registration failed'
    });
  }
};


// Request Password Reset
const requestPasswordReset = async (req, res) => {
  const { email, newPassword } = req.body;

  if (!email || !newPassword) {
    return res.status(400).json({
      success: false,
      message: 'Email and new password required.'
    });
  }

  try {
    const [rows] = await db.execute(
      'SELECT password FROM users WHERE email = ?',
      [email]
    );

    if (!rows.length) {
      return res.status(400).json({
        success: false,
        message: 'Email not found.'
      });
    }

    const result = await validateAndHashPassword(
      newPassword,
      rows[0].password
    );

    if (!result.success) {
      return res.status(400).json({
        success: false,
        message: result.message
      });
    }

    const code = Math.floor(
      100000 + Math.random() * 900000
    );

    req.session.resetEmail = email;
    req.session.resetHash = result.hash;
    req.session.resetCode = code;
    req.session.resetExpires =
      Date.now() + 10 * 60 * 1000;

    await sendVerificationCode(email, code);

    res.json({
      success: true,
      message: 'Verification code sent.'
    });

  } catch (err) {
    console.error('Password reset request error:', err);

    res.status(500).json({
      success: false,
      message: 'Server error.'
    });
  }
};


// Verify Password Reset Code
const verifyResetCode = async (req, res) => {
  const { code } = req.body;
  const session = req.session;

  if (
    !session.resetCode ||
    !session.resetEmail ||
    !session.resetHash ||
    !session.resetExpires
  ) {
    return res.status(400).json({
      success: false,
      message: 'Invalid session.'
    });
  }

  if (Date.now() > session.resetExpires) {
    return res.status(400).json({
      success: false,
      message: 'Code expired.'
    });
  }

  if (parseInt(code) !== parseInt(session.resetCode)) {
    return res.status(400).json({
      success: false,
      message: 'Incorrect code.'
    });
  }

  try {
    await db.execute(
      'UPDATE users SET password = ? WHERE email = ?',
      [
        session.resetHash,
        session.resetEmail
      ]
    );

    delete session.resetCode;
    delete session.resetEmail;
    delete session.resetHash;
    delete session.resetExpires;

    res.json({
      success: true,
      message: 'Password reset successful.'
    });

  } catch (err) {
    console.error('Password reset error:', err);

    res.status(500).json({
      success: false,
      message: 'Server error.'
    });
  }
};


// Session Info
const getSession = (req, res) => {
  if (req.session.userId) {
    return res.json({
      loggedIn: true,
      userId: req.session.userId,
      firstName: req.session.firstName,
      lastName: req.session.lastName,
      email: req.session.email
    });
  }

  res.json({
    loggedIn: false
  });
};


// Logout
// Logout
const logout = (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error('❌ Session destruction error:', err);

      return res.status(500).json({
        success: false,
        message: 'Logout failed'
      });
    }

    res.clearCookie('connect.sid');

    res.json({
      success: true
    });
  });
};


module.exports = {
  login,
  register,
  requestPasswordReset,
  verifyResetCode,
  getSession,
  logout
};