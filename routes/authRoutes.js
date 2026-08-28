const express = require('express');

const {
  login,
  register,
  requestPasswordReset,
  verifyResetCode,
  getSession,
  logout
} = require('../controllers/authController');

const router = express.Router();

router.post('/login', login);

router.post('/register', register);

router.post(
  '/api/request-password-reset',
  requestPasswordReset
);

router.post(
  '/api/verify-reset-code',
  verifyResetCode
);

router.get('/session', getSession);

router.post('/logout', logout);

module.exports = router;