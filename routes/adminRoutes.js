const express = require('express');

const {
  login,
  getAdminSession
} = require('../controllers/adminController');

const router = express.Router();

router.post('/adminlogin', login);

router.get('/admin/session', getAdminSession);

module.exports = router;